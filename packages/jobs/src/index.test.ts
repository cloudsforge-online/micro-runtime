import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import postgres from 'postgres'
import { JOBS_SCHEMA_SQL, JobQueue, JobRunner, backoffFor, type Sql } from './index.ts'

/**
 * These tests need a real Postgres, because the properties under test are properties of
 * `for update skip locked` and of a unique constraint — not of TypeScript. Mocking the database
 * here would test the mock.
 */
const url = process.env['RUNTIME_TEST_DATABASE_URL']
const enabled = Boolean(url && /test/i.test(url))
const skip = enabled ? false : 'set RUNTIME_TEST_DATABASE_URL (name must contain "test")'

let sql: ReturnType<typeof postgres>

before(async () => {
  if (!enabled) return
  sql = postgres(url!, { max: 8, onnotice: () => {} })
  await sql.unsafe(JOBS_SCHEMA_SQL)
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await sql.unsafe('truncate table jobs')
})

const queue = (owner: string, leaseMs = 60_000) =>
  new JobQueue(sql as unknown as Sql, { owner, leaseMs })

test('backoff grows and is jittered within the cap', () => {
  assert.equal(backoffFor(1, () => 0), 500)
  assert.equal(backoffFor(1, () => 1), 1_000)
  assert.equal(backoffFor(3, () => 1), 4_000)
  assert.equal(backoffFor(99, () => 1), 300_000, 'capped at five minutes')
  assert.ok(backoffFor(2, () => 0.5) > backoffFor(1, () => 0.5))
})

test('enqueue then claim returns the job', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'world-1', payload: { day: 3 } })
  const claimed = await q.claim(10)
  assert.equal(claimed.length, 1)
  assert.equal(claimed[0]?.kind, 'world.tick')
  assert.deepEqual(claimed[0]?.payload, { day: 3 })
  assert.equal(claimed[0]?.attempts, 1)
})

test('enqueueing the same (kind, key) twice produces one job', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'price.refresh', key: 'global' })
  await q.enqueue({ kind: 'price.refresh', key: 'global' })
  await q.enqueue({ kind: 'price.refresh', key: 'global' })
  const claimed = await q.claim(10)
  assert.equal(claimed.length, 1, 'a recurring producer must not build a backlog of itself')
})

test('THE LEASE: two workers claiming concurrently never get the same job', { skip }, async () => {
  const a = queue('worker-a')
  const b = queue('worker-b')
  // One job per chain, which is exactly how the withdrawal worker is keyed.
  for (const chain of ['ember:testnet', 'eth:mainnet', 'xrp:mainnet']) {
    await a.enqueue({ kind: 'chain.withdraw', key: chain })
  }

  const [claimedA, claimedB] = await Promise.all([a.claim(10), b.claim(10)])
  const ids = [...claimedA, ...claimedB].map((j) => j.id)
  assert.equal(ids.length, 3, 'every job is claimed exactly once')
  assert.equal(new Set(ids).size, 3, 'no job is handed to two workers — this is the lost-payment fix')
})

test('a claimed job is invisible to another worker until the lease expires', { skip }, async () => {
  const a = queue('worker-a', 60_000)
  const b = queue('worker-b', 60_000)
  await a.enqueue({ kind: 'chain.withdraw', key: 'ember:testnet' })
  assert.equal((await a.claim(10)).length, 1)
  assert.equal((await b.claim(10)).length, 0, 'the chain nonce is held')
})

test('an expired lease is reclaimable, so a crashed worker does not strand work', { skip }, async () => {
  const a = queue('worker-a', 1)
  const b = queue('worker-b', 60_000)
  await a.enqueue({ kind: 'bot.tick', key: 'bot-9' })
  assert.equal((await a.claim(1)).length, 1)
  await new Promise((r) => setTimeout(r, 40))
  const reclaimed = await b.claim(1)
  assert.equal(reclaimed.length, 1)
  assert.equal(reclaimed[0]?.attempts, 2, 'the retry is counted')
})

test('heartbeat extends a lease for legitimately long work', { skip }, async () => {
  const a = queue('worker-a', 120)
  const b = queue('worker-b', 60_000)
  await a.enqueue({ kind: 'mint.deploy', key: 'order-1' })
  const [job] = await a.claim(1)
  assert.ok(job)

  await new Promise((r) => setTimeout(r, 80))
  assert.equal(await a.heartbeat(job.id), true)
  await new Promise((r) => setTimeout(r, 80))
  assert.equal((await b.claim(1)).length, 0, 'a 180-second chain deploy keeps its lease')
})

test('heartbeat from a worker that does not hold the lease is refused', { skip }, async () => {
  const a = queue('worker-a')
  const b = queue('worker-b')
  await a.enqueue({ kind: 'mint.deploy', key: 'order-2' })
  const [job] = await a.claim(1)
  assert.ok(job)
  assert.equal(await b.heartbeat(job.id), false)
})

test('complete removes the job', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1' })
  const [job] = await q.claim(1)
  assert.ok(job)
  await q.complete(job.id)
  const stats = await q.stats()
  assert.equal(stats.pending + stats.running + stats.dead, 0)
})

test('failure reschedules with backoff and records the error', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1', maxAttempts: 3 })
  const [job] = await q.claim(1)
  assert.ok(job)
  const outcome = await q.fail(job.id, new Error('database went away'), 50)
  assert.equal(outcome, 'retry')

  assert.equal((await q.claim(1)).length, 0, 'not due yet')
  await new Promise((r) => setTimeout(r, 70))
  const again = await q.claim(1)
  assert.equal(again.length, 1)
  assert.equal(again[0]?.attempts, 2)
})

test('a job dead-letters after max attempts and is retained, not deleted', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1', maxAttempts: 2 })

  for (let i = 0; i < 2; i++) {
    const [job] = await q.claim(1)
    assert.ok(job, `claim ${i}`)
    await q.fail(job.id, new Error('still broken'), 0)
  }

  const stats = await q.stats()
  assert.equal(stats.dead, 1, 'the row is the only durable record that the work was never done')
  assert.equal((await q.claim(1)).length, 0, 'a dead job is not retried')
})

test('release gives a job back without counting an attempt', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1' })
  const [job] = await q.claim(1)
  assert.ok(job)
  assert.equal(job.attempts, 1)
  await q.release(job.id)
  const again = await q.claim(1)
  assert.equal(again[0]?.attempts, 1, 'draining mid-job must not burn a retry')
})

test('claim respects the kind filter, so a runner only takes work it can do', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1' })
  await q.enqueue({ kind: 'chain.withdraw', key: 'ember:testnet' })
  const claimed = await q.claim(10, ['chain.withdraw'])
  assert.equal(claimed.length, 1)
  assert.equal(claimed[0]?.kind, 'chain.withdraw')
})

test('a job scheduled in the future is not claimed early', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1', runAt: new Date(Date.now() + 60_000) })
  assert.equal((await q.claim(10)).length, 0)
})

test('onConflict earliest pulls a schedule forward', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'world.tick', key: 'w1', runAt: new Date(Date.now() + 60_000) })
  await q.enqueue({ kind: 'world.tick', key: 'w1', runAt: new Date(), onConflict: 'earliest' })
  assert.equal((await q.claim(10)).length, 1)
})

test('the runner completes a job and removes it', { skip }, async () => {
  const q = queue('runner-1')
  const seen: string[] = []
  const runner = new JobRunner({ queue: q, pollMs: 5 })
  runner.register('world.tick', async (job) => {
    seen.push(job.key)
  })
  await q.enqueue({ kind: 'world.tick', key: 'w1' })
  await runner.tick()
  assert.deepEqual(seen, ['w1'])
  assert.equal((await q.stats()).pending, 0)
})

test('a throwing handler fails the job rather than killing the runner', { skip }, async () => {
  const q = queue('runner-1')
  const events: string[] = []
  const runner = new JobRunner({
    queue: q,
    onEvent: (e) => void events.push(e.type),
  })
  runner.register('world.tick', async () => {
    throw new Error('resolve failed')
  })
  await q.enqueue({ kind: 'world.tick', key: 'w1', maxAttempts: 3 })
  await runner.tick()
  assert.ok(events.includes('failed'))
  const stats = await q.stats()
  assert.equal(stats.pending + stats.running, 1, 'still queued for retry')
})

test('the runner stops claiming when shouldClaim is false — the drain hook', { skip }, async () => {
  const q = queue('runner-1')
  let claiming = false
  const runner = new JobRunner({ queue: q, shouldClaim: () => claiming })
  runner.register('world.tick', async () => {})
  await q.enqueue({ kind: 'world.tick', key: 'w1' })

  assert.equal(await runner.tick(), 0)
  claiming = true
  assert.equal(await runner.tick(), 1)
})

test('the runner honours its concurrency limit', { skip }, async () => {
  const q = queue('runner-1')
  let peak = 0
  let live = 0
  const runner = new JobRunner({ queue: q, concurrency: 2 })
  runner.register('slow', async () => {
    live += 1
    peak = Math.max(peak, live)
    await new Promise((r) => setTimeout(r, 20))
    live -= 1
  })
  for (let i = 0; i < 6; i++) await q.enqueue({ kind: 'slow', key: `k${i}` })
  await Promise.all([runner.tick(), runner.tick(), runner.tick()])
  assert.ok(peak <= 2, `concurrency exceeded: ${peak}`)
})

test('stats separate pending, running and dead', { skip }, async () => {
  const q = queue('worker-a')
  await q.enqueue({ kind: 'a', key: '1' })
  await q.enqueue({ kind: 'b', key: '2' })
  await q.claim(1, ['a'])
  const stats = await q.stats()
  assert.equal(stats.running, 1)
  assert.equal(stats.pending, 1)
  assert.equal(stats.dead, 0)
})
