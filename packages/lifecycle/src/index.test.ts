import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from './index.ts'

const passing = (name: string, kind: 'hard' | 'soft' = 'hard') => ({
  name,
  kind,
  async check() {
    return { state: 'pass' as const }
  },
})

const failing = (name: string, kind: 'hard' | 'soft' = 'hard') => ({
  name,
  kind,
  async check() {
    return { state: 'fail' as const, detail: 'nope' }
  },
})

test('is not ready before markReady, even with every probe passing', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(passing('db'))
  const report = await lc.readyz()
  assert.equal(report.ready, false)
  assert.equal(report.state, 'starting')
})

test('becomes ready once boot completes', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(passing('db'))
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, true)
  assert.equal(report.state, 'ready')
})

test('a hard probe failure makes the service unready — the bug this package exists for', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(failing('postgres', 'hard'))
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, false, 'a replica that cannot reach its database must not be served traffic')
  assert.equal(report.state, 'degraded')
})

test('a soft probe failure degrades but keeps serving', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(passing('db', 'hard'))
  lc.addProbe(failing('pricing', 'soft'))
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, true, 'one non-essential upstream must not remove a product from the balancer')
  assert.equal(report.state, 'degraded')
  assert.equal(report.checks.find((c) => c.name === 'pricing')?.state, 'fail')
})

test('livez stays true while unready — they answer different questions', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(failing('db'))
  lc.markReady()
  assert.equal((await lc.readyz()).ready, false)
  assert.equal(lc.livez().ok, true, 'a service with a broken dependency should not be restarted in a loop')
})

test('a probe that hangs fails rather than hanging readiness', async () => {
  const lc = new Lifecycle({ cacheMs: 0, probeTimeoutMs: 20 })
  lc.addProbe({
    name: 'slow',
    kind: 'hard',
    check: (signal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')))
      }),
  })
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, false)
  assert.equal(report.checks[0]?.detail, 'probe timed out')
})

test('a probe that IGNORES the abort signal still times out', async () => {
  // Regression, found by the service template: aborting the signal only asks a probe to stop.
  // A driver that ignores it left `/readyz` pending forever, which a load balancer cannot
  // distinguish from slow. The race, not the signal, is what guarantees an answer.
  const lc = new Lifecycle({ cacheMs: 0, probeTimeoutMs: 20 })
  lc.addProbe({
    name: 'stubborn',
    kind: 'hard',
    check: () => new Promise<never>(() => {}), // never settles, never listens
  })
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, false)
  assert.equal(report.checks[0]?.detail, 'probe timed out')
})

test('a probe that throws is a failure, not a crash', async () => {
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe({
    name: 'boom',
    kind: 'hard',
    async check() {
      throw new Error('connection refused')
    },
  })
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, false)
  assert.equal(report.checks[0]?.detail, 'connection refused')
})

test('results are cached so balancer polling does not hammer upstreams', async () => {
  let calls = 0
  const lc = new Lifecycle({ cacheMs: 10_000 })
  lc.addProbe({
    name: 'counted',
    kind: 'hard',
    async check() {
      calls += 1
      return { state: 'pass' as const }
    },
  })
  lc.markReady()
  await lc.readyz()
  await lc.readyz()
  await lc.readyz()
  assert.equal(calls, 1)
})

test('draining reports unready immediately and never reports ready again', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  lc.addProbe(passing('db'))
  lc.markReady()
  assert.equal((await lc.readyz()).ready, true)

  const done = lc.shutdown()
  assert.equal(lc.state, 'draining')
  const duringDrain = await lc.readyz()
  assert.equal(duringDrain.ready, false)
  assert.equal(duringDrain.state, 'draining')
  await done
  assert.equal((await lc.readyz()).state, 'stopped')
})

test('drain waits for in-flight work — a 180-second chain deploy is not cut off', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 1_000, cacheMs: 0 })
  lc.markReady()

  const release = lc.track()
  assert.equal(lc.inFlight, 1)

  let finished = false
  const shutdown = lc.shutdown().then((r) => {
    finished = true
    return r
  })

  await new Promise((r) => setTimeout(r, 30))
  assert.equal(finished, false, 'shutdown must not complete while work is in flight')

  release()
  const result = await shutdown
  assert.equal(finished, true)
  assert.equal(result.forced, false)
})

test('drain gives up after the timeout rather than hanging forever', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 20, cacheMs: 0 })
  lc.markReady()
  lc.track() // never released
  const result = await lc.shutdown()
  assert.equal(result.forced, true)
})

test('the job runner stops claiming before HTTP stops accepting', async () => {
  const lc = new Lifecycle({ drainDelayMs: 50, cacheMs: 0 })
  lc.markReady()
  assert.equal(lc.claimingJobs, true)
  const done = lc.shutdown()
  assert.equal(lc.claimingJobs, false, 'no new background work once draining')
  assert.equal(lc.accepting, false)
  await done
})

test('shutdown hooks run in reverse registration order', async () => {
  const order: string[] = []
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  lc.onShutdown(() => void order.push('db'))
  lc.onShutdown(() => void order.push('server'))
  lc.markReady()
  await lc.shutdown()
  assert.deepEqual(order, ['server', 'db'], 'close the server before the pool it depends on')
})

test('a failing shutdown hook does not prevent the others', async () => {
  const order: string[] = []
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  lc.onShutdown(() => void order.push('db'))
  lc.onShutdown(() => {
    throw new Error('server refused to close')
  })
  lc.markReady()
  await lc.shutdown()
  assert.deepEqual(order, ['db'], 'losing the pool because the server hung is not an improvement')
})

test('shutdown is idempotent', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  lc.markReady()
  await lc.shutdown()
  const second = await lc.shutdown()
  assert.equal(second.drainedMs, 0)
})

test('track release is idempotent — a double finally does not underflow', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  const release = lc.track()
  release()
  release()
  assert.equal(lc.inFlight, 0)
})

test('state changes are observable', async () => {
  const seen: string[] = []
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0, onStateChange: (s) => void seen.push(s) })
  lc.markReady()
  await lc.shutdown()
  assert.deepEqual(seen, ['ready', 'draining', 'stopped'])
})

test('SIGTERM drains and exits zero', async () => {
  const lc = new Lifecycle({ drainDelayMs: 0, cacheMs: 0 })
  lc.markReady()
  let code: number | undefined
  const uninstall = installSignalHandlers(lc, { exit: (c) => void (code = c) })
  process.emit('SIGTERM')
  await new Promise((r) => setTimeout(r, 30))
  uninstall()
  assert.equal(code, 0)
  assert.equal(lc.state, 'stopped')
})

test('postgresProbe reports the query failure rather than swallowing it', async () => {
  const probe = postgresProbe('db', async () => {
    throw new Error('ECONNREFUSED')
  })
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(probe)
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.checks[0]?.detail, 'ECONNREFUSED')
})

test('httpProbe treats a non-2xx as a failure and defaults to soft', async () => {
  const probe = httpProbe('peer', 'http://peer/livez', {
    fetch: async () => new Response('no', { status: 503 }),
  })
  assert.equal(probe.kind, 'soft')
  const lc = new Lifecycle({ cacheMs: 0 })
  lc.addProbe(probe)
  lc.markReady()
  const report = await lc.readyz()
  assert.equal(report.ready, true)
  assert.equal(report.checks[0]?.detail, 'HTTP 503')
})
