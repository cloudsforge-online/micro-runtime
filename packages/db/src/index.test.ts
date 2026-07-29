import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import postgres from 'postgres'
import {
  MigrationError,
  assertSchemaAtLeast,
  checksumOf,
  lockKeyFor,
  migrate,
  type Migration,
  type Sql,
} from './index.ts'

const url = process.env['RUNTIME_TEST_DATABASE_URL']
const enabled = Boolean(url && /test/i.test(url))
const skip = enabled ? false : 'set RUNTIME_TEST_DATABASE_URL (name must contain "test")'

let sql: ReturnType<typeof postgres>
const asSql = () => sql as unknown as Sql

before(async () => {
  if (!enabled) return
  sql = postgres(url!, { max: 8, onnotice: () => {} })
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await sql.unsafe('drop table if exists schema_migrations, widgets, gadgets cascade')
})

const M = (version: number, name: string, up: string, noTransaction = false): Migration =>
  noTransaction ? { version, name, up, noTransaction } : { version, name, up }

test('lock keys are deterministic, in range, and differ per service', () => {
  assert.equal(lockKeyFor('ledger'), lockKeyFor('ledger'))
  assert.notEqual(lockKeyFor('ledger'), lockKeyFor('wallet'))
  for (const s of ['ledger', 'wallet', 'custody', 'indexer']) {
    const k = lockKeyFor(s)
    assert.ok(k >= -(2n ** 63n) && k < 2n ** 63n, `${s} key out of signed 64-bit range`)
  }
})

test('checksums ignore surrounding whitespace but not content', () => {
  assert.equal(checksumOf(M(1, 'a', 'select 1')), checksumOf(M(1, 'a', '  select 1\n')))
  assert.notEqual(checksumOf(M(1, 'a', 'select 1')), checksumOf(M(1, 'a', 'select 2')))
})

test('duplicate versions are refused before anything runs', { skip }, async () => {
  await assert.rejects(
    () =>
      migrate(asSql(), [M(1, 'a', 'select 1'), M(1, 'b', 'select 1')], { service: 'dup' }),
    /duplicate migration version 1/,
  )
})

test('applies pending migrations in order and records them', { skip }, async () => {
  const result = await migrate(
    asSql(),
    [
      M(1, 'create widgets', 'create table widgets (id int primary key)'),
      M(2, 'add label', 'alter table widgets add column label text'),
    ],
    { service: 'test' },
  )
  assert.equal(result.applied.length, 2)
  assert.equal(result.nowAt, 2)

  const cols = (await sql.unsafe(
    `select column_name from information_schema.columns where table_name='widgets' order by 1`,
  )) as Array<{ column_name: string }>
  assert.deepEqual(cols.map((c) => c.column_name), ['id', 'label'])
})

test('a second run applies nothing', { skip }, async () => {
  const migrations = [M(1, 'create widgets', 'create table widgets (id int primary key)')]
  await migrate(asSql(), migrations, { service: 'test' })
  const second = await migrate(asSql(), migrations, { service: 'test' })
  assert.equal(second.applied.length, 0)
  assert.equal(second.alreadyAt, 1)
})

test('THE RACE: concurrent migrators apply each migration exactly once', { skip }, async () => {
  // This is the defect that makes scale-up impossible today: two replicas booting together race
  // on pg_class, one raises 23505 and crash-loops.
  const migrations = [
    M(1, 'create widgets', 'create table widgets (id int primary key)'),
    M(2, 'create gadgets', 'create table gadgets (id int primary key)'),
  ]
  const runs = await Promise.all(
    Array.from({ length: 5 }, () => migrate(asSql(), migrations, { service: 'race' })),
  )
  const totalApplied = runs.reduce((n, r) => n + r.applied.length, 0)
  assert.equal(totalApplied, 2, 'exactly one migrator applied each migration')

  const rows = (await sql.unsafe(`select count(*)::int as n from schema_migrations`)) as Array<{
    n: number
  }>
  assert.equal(rows[0]?.n, 2)
})

test('a failing migration rolls back its DDL and its ledger row together', { skip }, async () => {
  await assert.rejects(
    () =>
      migrate(
        asSql(),
        [
          M(1, 'good', 'create table widgets (id int primary key)'),
          M(2, 'bad', 'create table gadgets (id int primary key); select nonexistent_fn()'),
        ],
        { service: 'test' },
      ),
    MigrationError,
  )

  const applied = (await sql.unsafe(
    `select version from schema_migrations order by version`,
  )) as Array<{ version: string }>
  assert.deepEqual(applied.map((r) => Number(r.version)), [1], 'the failed migration left no row')

  const gadgets = (await sql.unsafe(
    `select to_regclass('gadgets') is not null as present`,
  )) as Array<{ present: boolean }>
  assert.equal(gadgets[0]?.present, false, 'and left no table')
})

test('editing an applied migration is refused', { skip }, async () => {
  await migrate(asSql(), [M(1, 'create widgets', 'create table widgets (id int primary key)')], {
    service: 'test',
  })
  await assert.rejects(
    () =>
      migrate(asSql(), [M(1, 'create widgets', 'create table widgets (id bigint primary key)')], {
        service: 'test',
      }),
    /was modified after it was applied/,
  )
})

test('baseline adopts an existing hand-built schema without re-creating it', { skip }, async () => {
  // The bridge out of boot-time DDL: the tables already exist, so version 1 must be recorded
  // rather than run. Running it would fail on the existing table.
  await sql.unsafe('create table widgets (id int primary key)')

  const result = await migrate(
    asSql(),
    [
      M(1, 'legacy schema', 'create table widgets (id int primary key)'),
      M(2, 'add label', 'alter table widgets add column label text'),
    ],
    { service: 'test', baselineVersion: 1 },
  )

  assert.equal(result.applied.length, 1, 'only the genuinely new migration ran')
  assert.equal(result.applied[0]?.version, 2)

  const rows = (await sql.unsafe(
    `select version, name from schema_migrations order by version`,
  )) as Array<{ version: string; name: string }>
  assert.equal(rows.length, 2)
  assert.match(rows[0]!.name, /baselined/)
})

test('baseline is ignored once any migration has been recorded', { skip }, async () => {
  const first = [M(1, 'create widgets', 'create table widgets (id int primary key)')]
  await migrate(asSql(), first, { service: 'test' })

  const result = await migrate(
    asSql(),
    [...first, M(2, 'add label', 'alter table widgets add column label text')],
    { service: 'test', baselineVersion: 2 },
  )
  assert.equal(result.applied.length, 1, 'baseline must not skip a real migration on a live database')
})

test('a noTransaction migration still records its version', { skip }, async () => {
  await migrate(asSql(), [M(1, 'widgets', 'create table widgets (id int primary key)')], {
    service: 'test',
  })
  const result = await migrate(
    asSql(),
    [
      M(1, 'widgets', 'create table widgets (id int primary key)'),
      M(2, 'index', 'create index concurrently if not exists widgets_id_idx on widgets (id)', true),
    ],
    { service: 'test' },
  )
  assert.equal(result.applied.length, 1)
  assert.equal(result.applied[0]?.version, 2)
})

test('assertSchemaAtLeast refuses to start against an un-migrated database', { skip }, async () => {
  await migrate(asSql(), [M(1, 'widgets', 'create table widgets (id int primary key)')], {
    service: 'test',
  })
  await assertSchemaAtLeast(asSql(), 1)
  await assert.rejects(
    () => assertSchemaAtLeast(asSql(), 2),
    /requires 2 — run the migrator before starting the service/,
  )
})

test('the advisory lock is released even when a migration fails', { skip }, async () => {
  await assert.rejects(
    () => migrate(asSql(), [M(1, 'bad', 'select nonexistent_fn()')], { service: 'lockcheck' }),
    MigrationError,
  )
  // If the lock leaked, this would block forever rather than complete.
  const result = await migrate(
    asSql(),
    [M(1, 'good', 'create table widgets (id int primary key)')],
    { service: 'lockcheck' },
  )
  assert.equal(result.applied.length, 1)
})
