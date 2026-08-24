/**
 * Postgres access and versioned migrations.
 *
 * Every service in the estate ships a hand-rolled `STEPS[]` of `CREATE TABLE IF NOT EXISTS`
 * executed inline in `index.ts` before `listen()`. There is no version table, no down path, no
 * advisory lock, and a failure calls `process.exit(1)`.
 *
 * That design has three consequences, in increasing order of seriousness:
 *
 *   1. A slow migration stalls the whole estate, because everything `depends_on` something.
 *   2. There is no way to know what schema a database is at, so there is no way to review a
 *      change or to roll one back.
 *   3. **Two replicas booting together race on `pg_type`/`pg_class`, one raises 23505, and that
 *      replica crash-loops.** Scaling up is not slow — it is impossible.
 *
 * This package fixes all three: migrations are numbered files, applied inside a transaction
 * under `pg_advisory_lock`, recorded in `schema_migrations`, and run by a one-shot migrator that
 * is not the service process.
 *
 * **Expand/contract is mandatory, not advisory.** A rolling deploy always runs two versions of a
 * service against one schema. Add a column, deploy code that writes both, backfill, deploy code
 * that reads the new one, then drop the old one — four releases, never one.
 */

export interface Sql {
  <T extends readonly unknown[] = readonly Record<string, unknown>[]>(
    template: TemplateStringsArray,
    ...args: unknown[]
  ): Promise<T>
  unsafe(query: string, params?: unknown[]): Promise<unknown>
  /**
   * Take a connection out of the pool and hold it.
   *
   * Migrations **require** this. `pg_advisory_lock` is session-scoped, so the lock, the DDL and
   * the unlock must all run on one connection. Against a pool they land on whichever connection
   * is free: the lock is taken on one, the work runs unprotected on another, and the unlock
   * targets a third that never held it — which both defeats the lock and can exhaust the pool
   * with blocked waiters. This was a live bug in this package, caught by the concurrency test.
   */
  reserve?: () => Promise<Sql & { release: () => void }>
}

export interface Migration {
  /** Monotonic. Gaps are allowed; duplicates are refused. */
  readonly version: number
  readonly name: string
  readonly up: string
  /**
   * Set when a statement cannot run inside a transaction — `CREATE INDEX CONCURRENTLY` is the
   * only common case. Such a migration is not atomic, so it must be independently idempotent.
   */
  readonly noTransaction?: boolean
}

export interface MigrateResult {
  readonly applied: ReadonlyArray<{ version: number; name: string; durationMs: number }>
  readonly alreadyAt: number
  readonly nowAt: number
}

export class MigrationError extends Error {
  readonly version: number
  override readonly cause: unknown
  constructor(migration: Migration, cause: unknown) {
    super(`migration ${migration.version} (${migration.name}) failed: ${messageOf(cause)}`)
    this.name = 'MigrationError'
    this.version = migration.version
    this.cause = cause
  }
}

const LEDGER_SQL = `
create table if not exists schema_migrations (
  version     bigint      primary key,
  name        text        not null,
  applied_at  timestamptz not null default now(),
  duration_ms integer     not null default 0,
  checksum    text        not null
);
`

/**
 * A 64-bit advisory lock key derived from the service name.
 *
 * **Prior art, and why this differs from it.** Nimbus already solved this, and solved it well:
 * `platform/services/nimbus/src/db/migrate.ts` takes `pg_advisory_xact_lock` with a
 * comment explaining the choice of the transaction-scoped form because it is released
 * automatically, even if the process dies mid-migration. That is the better choice when every
 * migration is transactional, and it is the reason Nimbus is the one service in the estate that
 * survives two replicas booting together.
 *
 * This package uses the **session-scoped** form instead, for one reason: a `noTransaction`
 * migration — in practice `CREATE INDEX CONCURRENTLY`, which Postgres refuses inside a
 * transaction — has no transaction to scope a lock to. Holding one session lock across the
 * whole run is what makes a mixed set of transactional and concurrent migrations safe.
 *
 * The cost is that the lock must be released explicitly and must be held on one connection,
 * which is why `migrate()` reserves one. A crashed migrator holds the lock until its connection
 * drops; Postgres releases it on disconnect, so the failure mode is a delay rather than a
 * deadlock. If a service never needs a concurrent index, the Nimbus approach is simpler and
 * should be preferred.
 */
export function lockKeyFor(service: string): bigint {
  // FNV-1a, 64-bit, folded into a signed bigint — Postgres advisory keys are signed.
  let hash = 0xcbf29ce484222325n
  for (const byte of Buffer.from(service, 'utf8')) {
    hash ^= BigInt(byte)
    hash = BigInt.asUintN(64, hash * 0x100000001b3n)
  }
  return BigInt.asIntN(64, hash)
}

export function checksumOf(migration: Migration): string {
  // Deliberately whitespace-insensitive at the edges only: reformatting a migration should not
  // trip the guard, but changing a statement must.
  const normalised = migration.up.trim().replace(/\r\n/g, '\n')
  let h1 = 0x811c9dc5
  for (let i = 0; i < normalised.length; i++) {
    h1 ^= normalised.charCodeAt(i)
    h1 = Math.imul(h1, 0x01000193) >>> 0
  }
  return h1.toString(16).padStart(8, '0')
}

export interface MigrateOptions {
  /** Names the advisory lock. Use the service name; two services must not share one. */
  readonly service: string
  /**
   * Treat every migration at or below this version as already applied, without running it.
   *
   * This is the bridge out of boot-time DDL: an existing database already has the tables, so the
   * first migration records the schema it is *at* rather than trying to create it again. Only
   * has an effect on a database with no `schema_migrations` rows.
   */
  readonly baselineVersion?: number
  readonly onLog?: (message: string, fields?: Record<string, unknown>) => void
}

/**
 * Apply pending migrations. Safe to run concurrently from N processes: the advisory lock
 * serialises them and the losers observe an empty pending set.
 */
export async function migrate(
  pool: Sql,
  migrations: readonly Migration[],
  options: MigrateOptions,
): Promise<MigrateResult> {
  const log = options.onLog ?? (() => {})
  const ordered = [...migrations].sort((a, b) => a.version - b.version)

  const seen = new Set<number>()
  for (const m of ordered) {
    if (seen.has(m.version)) throw new Error(`duplicate migration version ${m.version}`)
    seen.add(m.version)
  }

  // Everything below must run on one connection — see the note on `Sql.reserve`.
  const reserved = pool.reserve ? await pool.reserve() : null
  const sql: Sql = reserved ?? pool

  const lockKey = lockKeyFor(options.service)
  await sql.unsafe(`select pg_advisory_lock($1)`, [lockKey.toString()])
  log('migration lock acquired', { service: options.service })

  try {
    await sql.unsafe(LEDGER_SQL)

    const rows = (await sql.unsafe(
      `select version, name, checksum from schema_migrations order by version`,
    )) as Array<{ version: string | number; name: string; checksum: string }>

    const applied = new Map(rows.map((r) => [Number(r.version), r]))
    const alreadyAt = rows.length > 0 ? Math.max(...rows.map((r) => Number(r.version))) : 0

    // A migration whose text changed after it was applied means two databases now disagree about
    // what "version 7" is. Refusing is the only safe answer; the fix is a new migration.
    for (const m of ordered) {
      const row = applied.get(m.version)
      if (row && row.checksum !== checksumOf(m)) {
        throw new Error(
          `migration ${m.version} (${m.name}) was modified after it was applied — ` +
            `add a new migration instead of editing a released one`,
        )
      }
    }

    if (applied.size === 0 && options.baselineVersion) {
      const baselined = ordered.filter((m) => m.version <= options.baselineVersion!)
      for (const m of baselined) {
        await sql.unsafe(
          `insert into schema_migrations (version, name, duration_ms, checksum)
           values ($1, $2, 0, $3) on conflict do nothing`,
          [m.version, `${m.name} (baselined)`, checksumOf(m)],
        )
        applied.set(m.version, { version: m.version, name: m.name, checksum: checksumOf(m) })
      }
      if (baselined.length > 0) {
        log('baselined existing schema', { throughVersion: options.baselineVersion })
      }
    }

    const pending = ordered.filter((m) => !applied.has(m.version))
    const results: Array<{ version: number; name: string; durationMs: number }> = []

    for (const m of pending) {
      const startedAt = Date.now()
      try {
        if (m.noTransaction) {
          await sql.unsafe(m.up)
          await sql.unsafe(
            `insert into schema_migrations (version, name, duration_ms, checksum) values ($1,$2,$3,$4)`,
            [m.version, m.name, Date.now() - startedAt, checksumOf(m)],
          )
        } else {
          // The DDL and its ledger row commit together, so a crash mid-migration cannot leave a
          // database that claims to be at a version it is not at.
          //
          // Explicit BEGIN/COMMIT rather than the driver's `begin()` helper: the helper acquires
          // its own connection from the pool, which would run the DDL somewhere other than the
          // connection holding the advisory lock — reintroducing exactly the bug the reservation
          // above exists to fix.
          await sql.unsafe('begin')
          try {
            await sql.unsafe(m.up)
            await sql.unsafe(
              `insert into schema_migrations (version, name, duration_ms, checksum) values ($1,$2,$3,$4)`,
              [m.version, m.name, Date.now() - startedAt, checksumOf(m)],
            )
            await sql.unsafe('commit')
          } catch (err) {
            await sql.unsafe('rollback').catch(() => {})
            throw err
          }
        }
      } catch (err) {
        throw new MigrationError(m, err)
      }
      const durationMs = Date.now() - startedAt
      results.push({ version: m.version, name: m.name, durationMs })
      log('migration applied', { version: m.version, name: m.name, durationMs })
    }

    const nowAt = ordered.length > 0 ? Math.max(alreadyAt, ...ordered.map((m) => m.version)) : alreadyAt
    return { applied: results, alreadyAt, nowAt: results.length > 0 ? nowAt : alreadyAt }
  } finally {
    await sql.unsafe(`select pg_advisory_unlock($1)`, [lockKey.toString()])
    log('migration lock released', { service: options.service })
    reserved?.release()
  }
}

/**
 * Assert the database is at or beyond an expected version.
 *
 * A service calls this at boot. It does **not** migrate — that is the migrator job's task — so a
 * service that starts against an un-migrated database fails loudly instead of silently serving
 * against a schema it does not understand.
 */
export async function assertSchemaAtLeast(sql: Sql, expected: number): Promise<void> {
  const rows = (await sql.unsafe(
    `select coalesce(max(version), 0)::bigint as v from schema_migrations`,
  )) as Array<{ v: string | number }>
  const actual = Number(rows[0]?.v ?? 0)
  if (actual < expected) {
    throw new Error(
      `database schema is at version ${actual} but this build requires ${expected} — ` +
        `run the migrator before starting the service`,
    )
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/* ── ONE SERVICE, TWO NETWORKS, TWO DATABASES ─────────────────────────────────────────────────────
 *
 * The estate ran as two of everything — `cloudsforge-estate` and `cf-testnet`, the same services
 * twice, each with its own postgres. Consolidating onto one set of pods (micro-deploy
 * `docs/network-consolidation.md`) makes one process serve both, so one process now holds two
 * handles and has to pick between them per request.
 *
 * ── WHY THE BOUNDARY IS A WHOLE DATABASE, AND NOT A `network` COLUMN ────────────────────────────
 *
 * Because a column is enforced by every query, and a database is enforced by the connection. The
 * estate's isolation between networks is the coarsest one postgres offers — `ledger` and
 * `ledger_testnet` are different databases, so a mainnet handle CANNOT reach a testnet row however
 * wrong the WHERE clause is. A `network` column would put that guarantee in the hands of every
 * query anybody writes from now on, which is the same trade the apex consolidation refused when it
 * composed mounts at accessors rather than at call sites.
 *
 * This type deliberately declares its own two-value union rather than importing one from
 * `@cloudsforge/http`. `db` has no business depending on the HTTP layer, and the unions are
 * structurally identical, so a value crosses freely. The duplication is two words; the dependency
 * edge would be forever.
 */

/** The two networks the estate has. */
export type Network = 'mainnet' | 'testnet'

const NETWORK_ORDER: readonly Network[] = ['mainnet', 'testnet']

/** Asked for a network this process holds no handle for. Never resolved by substituting another. */
export class NetworkNotConfiguredError extends Error {
  override readonly name = 'NetworkNotConfiguredError'
  constructor(message: string) {
    super(message)
  }
}

export interface NetworkSql {
  /**
   * The handle for one network.
   *
   * Throws when this process holds none — the single most important line in this file. A merged
   * pod that answers a testnet request with the mainnet handle does not fail: it succeeds, writes
   * testnet rows into mainnet tables, and looks like ordinary traffic until somebody reconciles
   * months later. Refusing turns that into a 500 on the first request.
   */
  for(network: Network): Sql
  /** The networks this process actually holds handles for, in a stable order. */
  readonly networks: readonly Network[]
  /**
   * Run something once per configured network.
   *
   * Two callers, one shape. A WORKER has no request to take a network from, so it does its pass
   * per network. A MIGRATOR must apply a schema change to `<db>` and `<db>_testnet` in the SAME
   * job — miss one and the databases drift, which surfaces as the next deploy failing against
   * whichever was skipped.
   *
   * Sequential, not parallel: two migrations racing for the same advisory lock is exactly the
   * contention this package was written to remove, and a worker pass that saturates the pool for
   * one network starves the other.
   */
  each(fn: (sql: Sql, network: Network) => Promise<void>): Promise<void>
}

/**
 * A per-network selector over already-constructed handles.
 *
 * Takes handles rather than DSNs on purpose: this package has never owned pool construction (see
 * `Sql`), services build their own with whatever pool sizing they need, and a factory here would
 * quietly become the place connection limits are decided for the whole estate.
 */
export function networkSql(handles: Partial<Record<Network, Sql>>): NetworkSql {
  const networks = NETWORK_ORDER.filter((n) => handles[n] !== undefined)
  if (networks.length === 0) {
    throw new NetworkNotConfiguredError(
      'networkSql() was given no handles — a selector over nothing cannot serve any request, and failing at boot beats failing on the first one',
    )
  }
  return {
    networks,
    for(network: Network): Sql {
      const sql = handles[network]
      if (sql === undefined) {
        throw new NetworkNotConfiguredError(
          `this process holds no database handle for ${network} (it has ${networks.join(', ')}) — refusing rather than using another network's`,
        )
      }
      return sql
    },
    async each(fn: (sql: Sql, network: Network) => Promise<void>): Promise<void> {
      for (const network of networks) {
        try {
          await fn(handles[network] as Sql, network)
        } catch (err) {
          // WHICH network failed, in the message. With two of everything, "migration failed" or
          // "sweep failed" sends whoever is paged to read logs to find out which half of the
          // estate is broken.
          const message = err instanceof Error ? err.message : String(err)
          const wrapped = new Error(`[${network}] ${message}`)
          if (err instanceof Error && err.stack) wrapped.stack = err.stack
          throw wrapped
        }
      }
    },
  }
}
