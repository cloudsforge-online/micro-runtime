import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  Logger,
  Metrics,
  newRequestId,
  redactValue,
  registerHttpMetrics,
  registerJobMetrics,
} from './index.ts'

function capture(options: Partial<ConstructorParameters<typeof Logger>[0]> = {}) {
  const lines: Record<string, unknown>[] = []
  const logger = new Logger({
    service: 'ledger',
    level: 'debug',
    now: () => '2026-07-30T00:00:00.000Z',
    sink: (line) => void lines.push(JSON.parse(line) as Record<string, unknown>),
    ...options,
  })
  return { logger, lines }
}

test('a line carries service, level, message and time', () => {
  const { logger, lines } = capture()
  logger.info('posted', { entryId: 'e-1' })
  assert.equal(lines[0]?.['service'], 'ledger')
  assert.equal(lines[0]?.['level'], 'info')
  assert.equal(lines[0]?.['msg'], 'posted')
  assert.equal(lines[0]?.['entryId'], 'e-1')
})

test('level threshold suppresses quieter lines', () => {
  const { logger, lines } = capture({ level: 'warn' })
  logger.debug('a')
  logger.info('b')
  logger.warn('c')
  logger.error('d')
  assert.deepEqual(lines.map((l) => l['msg']), ['c', 'd'])
})

test('child loggers inherit fields', () => {
  const { logger, lines } = capture()
  logger.child({ requestId: 'r-1' }).info('handled')
  assert.equal(lines[0]?.['requestId'], 'r-1')
})

test('REDACTION: known secret keys never reach the sink, at any depth', () => {
  const { logger, lines } = capture()
  logger.info('boot', {
    config: {
      databaseUrl: 'ok',
      masterSecret: 'super-secret-value',
      nested: { privateKey: '0xdeadbeef', serviceToken: 'abc123' },
    },
  })
  const text = JSON.stringify(lines[0])
  assert.ok(!text.includes('super-secret-value'))
  assert.ok(!text.includes('abc123'))
  assert.match(text, /\[redacted\]/)
})

test('REDACTION: the password-reset token is not logged — it is an account-takeover credential', () => {
  const { logger, lines } = capture()
  logger.info('reset issued', { resetToken: 'a-live-credential', userId: 'u-1' })
  assert.equal(lines[0]?.['resetToken'], '[redacted]')
  assert.equal(lines[0]?.['userId'], 'u-1', 'the useful field survives')
})

test('REDACTION: secrets in free text are scrubbed whatever key they arrive under', () => {
  const { logger, lines } = capture()
  logger.error('connect failed', {
    detail: 'postgres://user:hunter2@db:5432/pay refused',
    header: 'Bearer eyJhbGciOiJSUzI1NiJ9.payloadpayloadpayload.sig',
    note: 'key 0x' + 'a'.repeat(64),
  })
  const text = JSON.stringify(lines[0])
  assert.ok(!text.includes('hunter2'), 'a DSN password reached the sink')
  assert.ok(!text.includes('eyJhbGciOiJSUzI1NiJ9'), 'a JWT reached the sink')
  assert.ok(!text.includes('a'.repeat(64)), 'a private key reached the sink')
})

test('REDACTION applies to the message itself, not only to fields', () => {
  const { logger, lines } = capture()
  logger.warn('failed to reach postgres://user:pw@db/x')
  assert.ok(!String(lines[0]?.['msg']).includes('pw@db'))
})

test('an Error is serialised with a bounded stack', () => {
  const { logger, lines } = capture()
  logger.error('boom', { err: new Error('it broke') })
  const err = lines[0]?.['err'] as Record<string, unknown>
  assert.equal(err['message'], 'it broke')
  assert.ok(String(err['stack']).split('\n').length <= 12)
})

test('a circular structure does not throw and does not lose the line', () => {
  const { logger, lines } = capture()
  const a: Record<string, unknown> = { name: 'a' }
  a['self'] = a
  logger.info('cyclic', { a })
  assert.equal(lines.length, 1, 'an observability failure must not become an outage')
})

test('depth and breadth are bounded so one field cannot flood the pipeline', () => {
  const { logger, lines } = capture()
  let deep: Record<string, unknown> = { end: true }
  for (let i = 0; i < 20; i++) deep = { deep }
  logger.info('deep', { deep })
  assert.match(JSON.stringify(lines[0]), /depth-limit/)

  const { logger: l2, lines: lines2 } = capture()
  l2.info('wide', { items: Array.from({ length: 500 }, (_, i) => i) })
  assert.equal((lines2[0]?.['items'] as unknown[]).length, 100)
})

test('a very long string is truncated', () => {
  const { logger, lines } = capture()
  logger.info('long', { blob2: 'x'.repeat(10_000) })
  assert.ok(String(lines[0]?.['blob2']).length < 5_000)
})

test('bigint is stringified rather than throwing', () => {
  const { logger, lines } = capture()
  logger.info('amount', { wei: 10n ** 24n })
  assert.equal(lines[0]?.['wei'], '1000000000000000000000000')
})

test('redactValue is exported and usable on its own', () => {
  const out = redactValue({ token: 'x', keep: 1 }, new Set(['token'])) as Record<string, unknown>
  assert.equal(out['token'], '[redacted]')
  assert.equal(out['keep'], 1)
})

test('counters accumulate per label set', () => {
  const m = new Metrics()
  registerHttpMetrics(m)
  m.increment('http_requests_total', { method: 'GET', route: '/wallet', status: '200' })
  m.increment('http_requests_total', { method: 'GET', route: '/wallet', status: '200' })
  m.increment('http_requests_total', { method: 'GET', route: '/wallet', status: '500' })
  const text = m.render()
  assert.match(text, /http_requests_total\{method="GET",route="\/wallet",status="200"\} 2/)
  assert.match(text, /http_requests_total\{method="GET",route="\/wallet",status="500"\} 1/)
})

test('gauges replace rather than accumulate', () => {
  const m = new Metrics()
  registerJobMetrics(m)
  m.set('jobs_pending', 5)
  m.set('jobs_pending', 2)
  assert.match(m.render(), /jobs_pending 2/)
})

test('histograms are cumulative, as Prometheus requires', () => {
  const m = new Metrics()
  m.register({
    name: 'lat',
    help: 'latency',
    kind: 'histogram',
    labels: ['route'],
    buckets: [10, 100],
  })
  m.observe('lat', 5, { route: '/a' })
  m.observe('lat', 50, { route: '/a' })
  m.observe('lat', 500, { route: '/a' })
  const text = m.render()
  assert.match(text, /lat_bucket\{route="\/a",le="10"\} 1/)
  assert.match(text, /lat_bucket\{route="\/a",le="100"\} 2/, 'buckets must be cumulative')
  assert.match(text, /lat_bucket\{route="\/a",le="\+Inf"\} 3/)
  assert.match(text, /lat_count\{route="\/a"\} 3/)
  assert.match(text, /lat_sum\{route="\/a"\} 555/)
})

test('exposition includes HELP and TYPE for every metric', () => {
  const m = new Metrics()
  registerHttpMetrics(m)
  const text = m.render()
  assert.match(text, /# HELP http_requests_total/)
  assert.match(text, /# TYPE http_request_duration_ms histogram/)
})

test('label values are escaped so a route cannot break the format', () => {
  const m = new Metrics()
  m.register({ name: 'x', help: 'x', kind: 'counter', labels: ['route'] })
  m.increment('x', { route: 'a"b\\c' })
  assert.match(m.render(), /route="a\\"b\\\\c"/)
})

test('registering the same metric twice is refused', () => {
  const m = new Metrics()
  m.register({ name: 'x', help: 'x', kind: 'counter' })
  assert.throws(() => m.register({ name: 'x', help: 'x', kind: 'counter' }), /already registered/)
})

/**
 * ── A DISCARDED MEASUREMENT IS NOT AN ABSENCE ─────────────────────────────────────────────────
 *
 * Both discards below are correct — a registry must not invent series, and a Prometheus metric may
 * not vary its label set between samples — and both used to happen in silence, which at the
 * `/metrics` endpoint is indistinguishable from a thing that never happened.
 *
 * What it cost, measured 2026-08-11: `ledger` increments `ledger_indexer_calls_total`
 * `{ outcome }` on every indexer call and registers that name nowhere. It is the estate's only
 * counter carrying an outbound call's outcome — the label whose `token_unavailable` value exists
 * so a dead service credential can be told apart from an unreachable peer (micro-org#351) — and
 * every write of it has been dropped on this method's first line since it was written.
 */
test('an unregistered metric reports why it was dropped, and still does not throw', () => {
  const dropped: unknown[] = []
  const m = new Metrics({ onDropped: (d) => void dropped.push(d) })
  m.increment('never_registered')
  assert.equal(m.render().trim(), '', 'a registry must still not invent a series')
  // KILLS: restoring the bare `if (!series) return` in `increment` — the write vanishes again.
  assert.deepEqual(dropped, [{ metric: 'never_registered', reason: 'unregistered_metric' }])
})

test('a label the spec does not declare is reported by NAME, and never by value', () => {
  const dropped: Array<Record<string, unknown>> = []
  const m = new Metrics({ onDropped: (d) => void dropped.push(d as never) })
  m.register({ name: 'calls_total', help: 'calls', kind: 'counter', labels: [] })
  m.increment('calls_total', { outcome: 'token_unavailable' })

  // KILLS: removing the undeclared-label loop from `#labelKey`, which is the exact shape of the
  // ledger defect above — the counter exists, the reason code is passed, and the series is one
  // undifferentiated number an operator cannot alert on.
  assert.deepEqual(dropped, [{ metric: 'calls_total', reason: 'undeclared_label', label: 'outcome' }])
  assert.doesNotMatch(
    JSON.stringify(dropped),
    /token_unavailable/,
    'a label VALUE can carry anything a caller put in it and must not be echoed',
  )
  assert.match(m.render(), /calls_total 1/, 'and the count itself is still recorded')
})

test('increment on a histogram is reported as the wrong kind, not as a missing metric', () => {
  const dropped: Array<Record<string, unknown>> = []
  const m = new Metrics({ onDropped: (d) => void dropped.push(d as never) })
  m.register({ name: 'lat', help: 'latency', kind: 'histogram' })
  m.increment('lat')
  // KILLS: collapsing `#dropped` into a single `unregistered_metric` reason. The remedies differ —
  // one wants a `register(...)`, the other wants the other method — and a shared reason code is
  // the defect micro-org#351 is about.
  assert.deepEqual(dropped, [{ metric: 'lat', reason: 'wrong_kind', registeredKind: 'histogram' }])
})

test('a dropped write is reported once per distinct problem, not once per write', () => {
  const dropped: Array<Record<string, unknown>> = []
  const m = new Metrics({ onDropped: (d) => void dropped.push(d as never) })
  for (let i = 0; i < 1_000; i++) m.increment('never_registered')
  m.increment('also_never_registered')
  // KILLS: removing the `#reported` set. These are raised from per-request seams, and a report
  // that floods gets deleted again — which is how the silence came back the first time.
  assert.equal(dropped.length, 2)
})

test('a reporting sink that throws cannot take the process down', () => {
  const m = new Metrics({
    onDropped: () => {
      throw new Error('the log shipper is down')
    },
  })
  // KILLS: removing the try/catch in `#report`. Rule 3 of this file — observability failing must
  // never become an outage — and a metric write is on every hot path in the estate.
  assert.doesNotThrow(() => m.increment('never_registered'))
})

test('request ids are short, sortable-safe and unambiguous to read aloud', () => {
  const id = newRequestId()
  assert.equal(id.length, 16)
  assert.match(id, /^[0-9abcdefghjkmnpqrstvwxyz]+$/, 'no i, l, o or u — they are misread')
  assert.notEqual(newRequestId(), newRequestId())
})

/* ── THE NETWORK IS A LABEL ON THE SERIES, NOT ON THE SCRAPE JOB ──────────────────────────────────
 *
 * Prometheus stamped `network` per TARGET, because each network had its own pods to point a job at.
 * After the consolidation one target serves both (micro-deploy `docs/network-consolidation.md`), so
 * a target-level label would relabel testnet traffic as mainnet — which is micro-org#398 again,
 * except that the previous time it was recoverable by fixing a scrape config and this time the
 * information would never have existed.
 */

test('constant labels are stamped on every series, so a single-network service says which it is', () => {
  const m = new Metrics({ constantLabels: { network: 'testnet' } })
  m.register({ name: 'x_total', help: 'x', kind: 'counter', labels: ['route'] })
  m.increment('x_total', { route: '/v1/a' })
  const text = m.render()
  assert.match(text, /x_total\{[^}]*network="testnet"[^}]*\}/)
  assert.match(text, /x_total\{[^}]*route="\/v1\/a"[^}]*\}/)
})

test('a per-write label beats a constant one, which is how a merged pod reports both networks', () => {
  // The whole point. One process, one registry, two networks in the output — impossible if the
  // network could only be set once at construction.
  const m = new Metrics({ constantLabels: { network: 'mainnet' } })
  m.register({ name: 'y_total', help: 'y', kind: 'counter', labels: ['network'] })
  m.increment('y_total', { network: 'testnet' })
  m.increment('y_total', {})
  const text = m.render()
  assert.match(text, /y_total\{network="testnet"\} 1/)
  assert.match(text, /y_total\{network="mainnet"\} 1/)
})

test('a constant label is NOT reported as undeclared, however the spec was written', () => {
  // Constant labels are the registry's own, not the caller's. Reporting them as a mistake would
  // put a permanent line on stderr for every metric in the process.
  const dropped: string[] = []
  const m = new Metrics({ constantLabels: { network: 'mainnet' }, onDropped: (d) => dropped.push(d.reason) })
  m.register({ name: 'z_total', help: 'z', kind: 'counter', labels: ['route'] })
  m.increment('z_total', { route: '/v1/z' })
  assert.deepEqual(dropped, [])
})

test('the standard http and job metrics carry network, so nothing has to remember to add it', () => {
  const http = registerHttpMetrics(new Metrics())
  const jobs = registerJobMetrics(new Metrics())
  http.increment('http_requests_total', { method: 'GET', route: '/v1/a', status: '200', network: 'testnet' })
  jobs.increment('jobs_claimed_total', { kind: 'sweep', network: 'testnet' })
  assert.match(http.render(), /http_requests_total\{[^}]*network="testnet"/)
  assert.match(jobs.render(), /jobs_claimed_total\{[^}]*network="testnet"/)
})
