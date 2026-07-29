/**
 * A leased job table over Postgres.
 *
 * The estate runs eight `setInterval` timers doing real work across three services, each guarded
 * only by a module-local boolean — a variable that is, by construction, invisible to a second
 * process. There is no distributed lock, no leader election and no queue anywhere:
 *
 *     $ grep -rn "pg_advisory\|SKIP LOCKED" repos/  →  (no matches)
 *
 * The consequences are not theoretical. Two withdrawal workers on one chain sign concurrently
 * against the same nonce and one payment is permanently lost. Two settlement sweeps mint two
 * different idempotency keys for the same fee and the customer is billed twice. Two world ticks
 * double every player's XP.
 *
 * **The lease key names the contended resource, not the row.** That single decision is where the
 * correctness lives, and it is the thing most likely to be got wrong by someone extending this:
 *
 *   | Work              | Key            | Why                                                  |
 *   |-------------------|----------------|------------------------------------------------------|
 *   | chain.withdraw    | chain:network  | The contended resource is the chain's nonce, not the |
 *   |                   |                | withdrawal row. Keying on the row lets two different |
 *   |                   |                | withdrawals sign against one nonce.                  |
 *   | chain.sweep       | chain:network  | Same treasury, same reason.                          |
 *   | bot.settle        | bot:period     | Deterministic, so one settlement yields one key.     |
 *   | world.tick        | world_id       | One resolution per world per day.                    |
 *   | address.scan      | address_id     | Genuinely parallel; the row is the resource.         |
 *   | price.refresh     | global         | One quote set for the whole estate.                  |
 *
 * No broker. Postgres has `SKIP LOCKED` and transactions, and the event volume does not justify
 * a second stateful system. See docs/ecosystem/02-target-architecture.md AD-10 for the four
 * measured conditions that would change that.
 */

/** The subset of `postgres` (postgres.js) this package needs. Keeps it testable and swappable. */
export interface Sql {
  <T extends readonly unknown[] = readonly Record<string, unknown>[]>(
    template: TemplateStringsArray,
    ...args: unknown[]
  ): Promise<T>
  unsafe(query: string, params?: unknown[]): Promise<unknown>
}

export interface JobRow {
  readonly id: string
  readonly kind: string
  readonly key: string
  readonly run_at: Date
  readonly attempts: number
  readonly max_attempts: number
  readonly payload: Record<string, unknown>
  readonly last_error: string | null
}

export interface Job<P = Record<string, unknown>> {
  readonly id: string
  readonly kind: string
  readonly key: string
  readonly attempts: number
  readonly maxAttempts: number
  readonly payload: P
}

export interface EnqueueOptions {
  readonly kind: string
  /** The contended resource. Unique per kind; enqueueing the same pair again does not duplicate. */
  readonly key: string
  readonly payload?: Record<string, unknown>
  readonly runAt?: Date
  readonly maxAttempts?: number
  /**
   * What to do when this (kind, key) is already queued.
   * - `keep`     leave the existing row alone. The default, and the right choice for a
   *              recurring tick: three enqueues before the first runs should produce one run.
   * - `earliest` pull the schedule forward if this request is sooner.
   * - `replace`  overwrite payload and schedule.
   */
  readonly onConflict?: 'keep' | 'earliest' | 'replace'
}

/** DDL for the jobs table. Ship it as a migration file; do not run it at boot. */
export const JOBS_SCHEMA_SQL = `
create table if not exists jobs (
  id            uuid        primary key default gen_random_uuid(),
  kind          text        not null,
  key           text        not null,
  run_at        timestamptz not null default now(),
  locked_by     text,
  locked_until  timestamptz,
  attempts      integer     not null default 0,
  max_attempts  integer     not null default 5,
  last_error    text,
  payload       jsonb       not null default '{}'::jsonb,
  dead          boolean     not null default false,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint jobs_kind_key_uniq unique (kind, key)
);

-- The claim query's access path. Partial on the live set so the index stays small even when a
-- dead-letter backlog accumulates.
create index if not exists jobs_claimable_idx
  on jobs (run_at)
  where dead = false;

create index if not exists jobs_locked_idx
  on jobs (locked_until)
  where locked_until is not null;
`

export interface QueueOptions {
  /** Identifies this process in `locked_by`. Use the hostname or container id. */
  readonly owner: string
  /**
   * How long a claim is held before another worker may take it.
   *
   * Must exceed the longest expected run of the slowest handler, or two workers will process one
   * job. Handlers that can exceed it must call `heartbeat()`.
   */
  readonly leaseMs?: number
  readonly maxAttempts?: number
  readonly now?: () => Date
}

export class JobQueue {
  readonly #sql: Sql
  readonly #owner: string
  readonly #leaseMs: number
  readonly #maxAttempts: number

  constructor(sql: Sql, options: QueueOptions) {
    this.#sql = sql
    this.#owner = options.owner
    this.#leaseMs = options.leaseMs ?? 60_000
    this.#maxAttempts = options.maxAttempts ?? 5
  }

  async enqueue(options: EnqueueOptions): Promise<void> {
    const runAt = options.runAt ?? new Date()
    const payload = options.payload ?? {}
    const maxAttempts = options.maxAttempts ?? this.#maxAttempts
    const mode = options.onConflict ?? 'keep'

    // A recurring producer enqueues the same (kind, key) every tick. `keep` collapses those into
    // one pending run, which is what makes an at-least-once producer safe to call freely.
    const conflict =
      mode === 'keep'
        ? 'do nothing'
        : mode === 'earliest'
          ? `do update set run_at = least(jobs.run_at, excluded.run_at), updated_at = now()`
          : `do update set run_at = excluded.run_at, payload = excluded.payload,
                           max_attempts = excluded.max_attempts, dead = false, updated_at = now()`

    await this.#sql.unsafe(
      `insert into jobs (kind, key, run_at, payload, max_attempts)
       values ($1, $2, $3, $4::jsonb, $5)
       on conflict (kind, key) ${conflict}`,
      [options.kind, options.key, runAt.toISOString(), JSON.stringify(payload), maxAttempts],
    )
  }

  /**
   * Claim up to `limit` due jobs.
   *
   * `for update skip locked` is what makes this safe with N workers: a row already being claimed
   * by another transaction is skipped rather than waited on, so workers never serialise and never
   * hand the same row to two processes.
   */
  async claim(limit = 1, kinds?: readonly string[]): Promise<Job[]> {
    const rows = (await this.#sql.unsafe(
      `update jobs
          set locked_by = $1,
              locked_until = now() + ($2 || ' milliseconds')::interval,
              attempts = attempts + 1,
              updated_at = now()
        where id in (
          select id from jobs
           where dead = false
             and run_at <= now()
             and (locked_until is null or locked_until < now())
             and ($4::text[] is null or kind = any($4::text[]))
           order by run_at
           limit $3
           for update skip locked
        )
      returning id, kind, key, attempts, max_attempts, payload`,
      [this.#owner, String(this.#leaseMs), limit, kinds ? (kinds as string[]) : null],
    )) as Array<{
      id: string
      kind: string
      key: string
      attempts: number
      max_attempts: number
      payload: Record<string, unknown>
    }>

    return rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      key: r.key,
      attempts: r.attempts,
      maxAttempts: r.max_attempts,
      // Driver-dependent: a parameterised `unsafe` query returns jsonb as text, while the
      // tagged-template path returns it already parsed. Normalising here means a handler is
      // never handed a payload whose type depends on how the query was issued.
      payload: typeof r.payload === 'string' ? (JSON.parse(r.payload) as Record<string, unknown>) : r.payload,
    }))
  }

  /** Extend a lease for a handler that legitimately runs long — a 180-second chain deploy. */
  async heartbeat(jobId: string): Promise<boolean> {
    const rows = (await this.#sql.unsafe(
      `update jobs
          set locked_until = now() + ($2 || ' milliseconds')::interval, updated_at = now()
        where id = $1 and locked_by = $3
      returning id`,
      [jobId, String(this.#leaseMs), this.#owner],
    )) as unknown[]
    return rows.length > 0
  }

  /** Success. The row is removed; the work is recorded by the handler's own domain writes. */
  async complete(jobId: string): Promise<void> {
    await this.#sql.unsafe(`delete from jobs where id = $1`, [jobId])
  }

  /**
   * Failure. Reschedules with exponential backoff, or dead-letters once attempts are exhausted.
   *
   * A dead job is retained rather than deleted: the row is the only durable record that the work
   * was requested and never done, and an operator needs to be able to find it.
   */
  async fail(jobId: string, error: unknown, backoffMs?: number): Promise<'retry' | 'dead'> {
    const message = (error instanceof Error ? error.message : String(error)).slice(0, 2_000)
    const rows = (await this.#sql.unsafe(
      `update jobs
          set locked_by = null,
              locked_until = null,
              last_error = $2,
              dead = (attempts >= max_attempts),
              run_at = case when attempts >= max_attempts then run_at
                            else now() + ($3 || ' milliseconds')::interval end,
              updated_at = now()
        where id = $1
      returning dead`,
      [jobId, message, String(backoffMs ?? 0)],
    )) as Array<{ dead: boolean }>
    return rows[0]?.dead ? 'dead' : 'retry'
  }

  /** Release a claim without counting a failure — used when a worker drains mid-job. */
  async release(jobId: string): Promise<void> {
    await this.#sql.unsafe(
      `update jobs
          set locked_by = null, locked_until = null,
              attempts = greatest(0, attempts - 1), updated_at = now()
        where id = $1 and locked_by = $2`,
      [jobId, this.#owner],
    )
  }

  async stats(): Promise<{ pending: number; running: number; dead: number; overdue: number }> {
    const rows = (await this.#sql.unsafe(
      `select
         count(*) filter (where dead = false and (locked_until is null or locked_until < now()))::int as pending,
         count(*) filter (where dead = false and locked_until >= now())::int as running,
         count(*) filter (where dead)::int as dead,
         count(*) filter (where dead = false and run_at < now() - interval '5 minutes'
                            and (locked_until is null or locked_until < now()))::int as overdue
       from jobs`,
    )) as Array<{ pending: number; running: number; dead: number; overdue: number }>
    return rows[0] ?? { pending: 0, running: 0, dead: 0, overdue: 0 }
  }
}

/** Exponential backoff with full jitter, capped. Exported so a handler can override per kind. */
export function backoffFor(attempt: number, random: () => number = Math.random): number {
  const cap = Math.min(1_000 * 2 ** Math.max(0, attempt - 1), 5 * 60_000)
  return Math.floor(cap * (0.5 + 0.5 * random()))
}

export type Handler<P = Record<string, unknown>> = (
  job: Job<P>,
  ctx: { heartbeat: () => Promise<boolean>; signal: AbortSignal },
) => Promise<void>

export interface RunnerOptions {
  readonly queue: JobQueue
  /** Maximum jobs in flight in this process. */
  readonly concurrency?: number
  readonly pollMs?: number
  /** Consulted before every claim. Wire it to Lifecycle.claimingJobs so a drain stops new work. */
  readonly shouldClaim?: () => boolean
  readonly onEvent?: (event: RunnerEvent) => void
  readonly random?: () => number
}

export interface RunnerEvent {
  readonly type: 'claimed' | 'completed' | 'failed' | 'dead' | 'error'
  readonly kind?: string
  readonly key?: string
  readonly jobId?: string
  readonly attempts?: number
  readonly durationMs?: number
  readonly error?: string
}

/**
 * Polls for due jobs and runs them.
 *
 * Deliberately a poller rather than a listener. `LISTEN/NOTIFY` would cut latency and would also
 * introduce a connection whose loss silently stops all work; polling degrades to "slower" rather
 * than "stopped", which is the correct failure mode for a queue that moves money.
 */
export class JobRunner {
  readonly #handlers = new Map<string, Handler<never>>()
  readonly #o: Required<Omit<RunnerOptions, 'onEvent' | 'shouldClaim'>> &
    Pick<RunnerOptions, 'onEvent' | 'shouldClaim'>
  #timer: NodeJS.Timeout | null = null
  #inFlight = 0
  #stopping = false
  #claiming = false
  #abort = new AbortController()

  constructor(options: RunnerOptions) {
    this.#o = {
      queue: options.queue,
      concurrency: options.concurrency ?? 4,
      pollMs: options.pollMs ?? 1_000,
      random: options.random ?? Math.random,
      ...(options.onEvent ? { onEvent: options.onEvent } : {}),
      ...(options.shouldClaim ? { shouldClaim: options.shouldClaim } : {}),
    }
  }

  register<P = Record<string, unknown>>(kind: string, handler: Handler<P>): this {
    if (this.#handlers.has(kind)) throw new Error(`handler already registered for ${kind}`)
    this.#handlers.set(kind, handler as Handler<never>)
    return this
  }

  get inFlight(): number {
    return this.#inFlight
  }

  start(): void {
    if (this.#timer) return
    this.#stopping = false
    this.#abort = new AbortController()
    const loop = () => {
      void this.tick().finally(() => {
        if (!this.#stopping) {
          this.#timer = setTimeout(loop, this.#o.pollMs)
          this.#timer.unref?.()
        }
      })
    }
    this.#timer = setTimeout(loop, 0)
    this.#timer.unref?.()
  }

  /** One poll. Exposed so tests drive the runner deterministically instead of sleeping. */
  async tick(): Promise<number> {
    if (this.#stopping) return 0
    if (this.#o.shouldClaim && !this.#o.shouldClaim()) return 0

    // Only one claim may be in flight per process. Without this, two overlapping ticks each read
    // `inFlight` before either has started a handler, both see full capacity, and the process
    // runs 2× concurrency. The database lease still prevents two *workers* taking one job; this
    // guard is what stops one worker exceeding its own limit.
    if (this.#claiming) return 0
    this.#claiming = true

    let jobs: Job[]
    try {
      const capacity = this.#o.concurrency - this.#inFlight
      if (capacity <= 0) return 0
      jobs = await this.#o.queue.claim(capacity, [...this.#handlers.keys()])
    } catch (err) {
      this.#emit({ type: 'error', error: messageOf(err) })
      return 0
    } finally {
      this.#claiming = false
    }

    await Promise.all(jobs.map((job) => this.#run(job)))
    return jobs.length
  }

  async #run(job: Job): Promise<void> {
    const handler = this.#handlers.get(job.kind)
    if (!handler) {
      // Claimed by kind, so this is only reachable if a handler was removed between the claim
      // and the dispatch. Give the job back rather than counting an attempt against it.
      await this.#o.queue.release(job.id)
      return
    }

    this.#inFlight += 1
    const startedAt = Date.now()
    this.#emit({ type: 'claimed', kind: job.kind, key: job.key, jobId: job.id, attempts: job.attempts })

    try {
      await (handler as Handler)(job, {
        heartbeat: () => this.#o.queue.heartbeat(job.id),
        signal: this.#abort.signal,
      })
      await this.#o.queue.complete(job.id)
      this.#emit({
        type: 'completed',
        kind: job.kind,
        key: job.key,
        jobId: job.id,
        durationMs: Date.now() - startedAt,
      })
    } catch (err) {
      const outcome = await this.#o.queue
        .fail(job.id, err, backoffFor(job.attempts, this.#o.random))
        .catch(() => 'retry' as const)
      this.#emit({
        type: outcome === 'dead' ? 'dead' : 'failed',
        kind: job.kind,
        key: job.key,
        jobId: job.id,
        attempts: job.attempts,
        durationMs: Date.now() - startedAt,
        error: messageOf(err),
      })
    } finally {
      this.#inFlight -= 1
    }
  }

  /** Stop claiming, then wait for in-flight handlers. Call from a Lifecycle shutdown hook. */
  async stop(timeoutMs = 30_000): Promise<boolean> {
    this.#stopping = true
    if (this.#timer) {
      clearTimeout(this.#timer)
      this.#timer = null
    }
    const deadline = Date.now() + timeoutMs
    while (this.#inFlight > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25))
    }
    if (this.#inFlight > 0) {
      this.#abort.abort()
      return false
    }
    return true
  }

  #emit(event: RunnerEvent): void {
    this.#o.onEvent?.(event)
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
