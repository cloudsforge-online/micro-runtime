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

/* ── A VIEW STAMPS LABELS; IT DOES NOT FORK THE REGISTRY ──────────────────────────────────────────
 *
 * `registerJobMetrics` names queues by `kind`, and the names a service picks are generic on
 * purpose. Merge `lantern` with `analytics` and both modules' `kind="rollup"` job is one series.
 * `jobs_pending` and `jobs_overdue` carry no `kind` at all, so the two modules' samples land on the
 * identical series and overwrite each other — a wedged queue then reads as absent rather than as
 * high, which is the failure mode nobody goes looking for. `activity`+`notify` and
 * `emberkin`+`aetherholm` collide the same way.
 */

test('THE COLLISION: two modules sample jobs_pending, and without a view the second erases the first', () => {
  // The defect first, on a bare registry — this is what a merged process does today.
  const bare = registerJobMetrics(new Metrics())
  bare.set('jobs_pending', 11, { network: 'mainnet' }) // lantern's queue
  bare.set('jobs_pending', 4, { network: 'mainnet' }) // analytics', a moment later
  assert.deepEqual(
    bare.render().match(/^jobs_pending\{.*$/gm),
    ['jobs_pending{network="mainnet"} 4'],
    'one series, one depth: the 11 is gone and nothing at /metrics records that it ever existed',
  )

  // The same two writers through views. Both depths survive, in one exposition.
  const m = registerJobMetrics(new Metrics())
  m.withLabels({ module: 'lantern' }).set('jobs_pending', 11, { network: 'mainnet' })
  m.withLabels({ module: 'analytics' }).set('jobs_pending', 4, { network: 'mainnet' })
  const lines = m.render().match(/^jobs_pending\{.*$/gm) ?? []
  assert.equal(lines.length, 2, 'a wedged queue must not go invisible because its neighbour sampled last')
  assert.ok(lines.includes('jobs_pending{module="lantern",network="mainnet"} 11'))
  assert.ok(lines.includes('jobs_pending{module="analytics",network="mainnet"} 4'))
})

test('jobs_failed_total{kind="rollup"} from two modules is two series, not a sum', () => {
  const m = registerJobMetrics(new Metrics())
  const lantern = m.withLabels({ module: 'lantern' })
  const analytics = m.withLabels({ module: 'analytics' })
  lantern.increment('jobs_failed_total', { kind: 'rollup', network: 'mainnet' })
  lantern.increment('jobs_failed_total', { kind: 'rollup', network: 'mainnet' })
  analytics.increment('jobs_failed_total', { kind: 'rollup', network: 'mainnet' })
  const text = m.render()
  assert.match(text, /jobs_failed_total\{module="lantern",kind="rollup",network="mainnet"\} 2/)
  assert.match(text, /jobs_failed_total\{module="analytics",kind="rollup",network="mainnet"\} 1/)
  // KILLS: dropping the constant labels out of `#labelKey`'s series key. A single `…} 3` is the
  // sum of two unrelated queues — a number with no meaning that an alert would still fire on, and
  // which no operator could take apart afterwards.
  assert.doesNotMatch(text, /jobs_failed_total\{kind="rollup",network="mainnet"\} 3/)
})

test('a per-write label still beats one a view stamps', () => {
  // The precedence `#labelKey` already had, and for the same reason: whoever knows the value at
  // the moment of writing wins. A merged pod stamps its module once and passes its network per
  // request, and both have to work at the same time.
  const m = new Metrics()
  m.register({ name: 'q_total', help: 'q', kind: 'counter', labels: ['network'] })
  const view = m.withLabels({ module: 'lantern', network: 'mainnet' })
  view.increment('q_total', { network: 'testnet' })
  view.increment('q_total')
  const text = m.render()
  assert.match(text, /q_total\{module="lantern",network="testnet"\} 1/)
  assert.match(text, /q_total\{module="lantern",network="mainnet"\} 1/)
})

test('the label a view stamps is NOT reported as undeclared — no spec in the estate declares module', () => {
  const dropped: Array<Record<string, unknown>> = []
  const m = registerJobMetrics(new Metrics({ onDropped: (d) => void dropped.push(d as never) }))
  const view = m.withLabels({ module: 'lantern' })
  view.increment('jobs_failed_total', { kind: 'rollup', network: 'mainnet' })
  view.set('jobs_pending', 3, { network: 'mainnet' })
  // KILLS: checking `#constant` against the spec's declared `labels`. Widening all seven job specs
  // is the change this facility exists to avoid, and a permanent stderr line under every job
  // metric in the process is how reporting gets deleted again.
  assert.deepEqual(dropped, [])

  view.increment('never_registered')
  assert.deepEqual(
    dropped,
    [{ metric: 'never_registered', reason: 'unregistered_metric' }],
    'while a genuine mistake made through a view still reaches the sink the registry was built with',
  )
})

test('views compose, and a view of a view carries both labels', () => {
  const m = new Metrics()
  m.register({ name: 'c_total', help: 'c', kind: 'counter', labels: [] })
  m.withLabels({ module: 'lantern' }).withLabels({ shard: 'a' }).increment('c_total')
  assert.match(m.render(), /c_total\{module="lantern",shard="a"\} 1/)
})

test('a view shares the registry rather than copying it, in both directions', () => {
  const m = registerHttpMetrics(new Metrics())
  const view = m.withLabels({ module: 'analytics' })

  // Registered through the view; written and rendered through the original.
  view.register({ name: 'analytics_rollups_total', help: 'rollups', kind: 'counter', labels: [] })
  m.increment('analytics_rollups_total')
  assert.match(m.render(), /analytics_rollups_total 1/, 'the original knows a spec the view registered')

  // Registered before the view existed; written through it.
  view.increment('http_requests_total', { method: 'GET', route: '/v1/a', status: '200', network: 'mainnet' })
  assert.match(
    m.render(),
    /http_requests_total\{module="analytics",[^}]*route="\/v1\/a"/,
    'and render() on the ORIGINAL carries what was written through the view',
  )

  // KILLS: giving the view its own `#specs`/`#values`/`#histograms`. A merged process serves ONE
  // /metrics; a view that forked the registry would put half the series behind each object, and
  // whichever one the route happened to call would expose only its own half.
  assert.throws(
    () => view.register({ name: 'analytics_rollups_total', help: 'x', kind: 'counter' }),
    /already registered/,
    'a forked spec map would have accepted this and then rendered the name twice',
  )
  assert.equal(view.render(), m.render(), 'one registry, seen twice')
})

/**
 * ── NOTHING THAT DOES NOT CALL `withLabels` MOVES BY A BYTE ───────────────────────────────────────
 *
 * Adding the facility meant reworking `Metrics`'s fields from initialisers to constructor
 * assignment, and a registry's exposition is a wire format that dashboards, recording rules and
 * alerts are all written against. Every service in the estate builds its registry the way the
 * fixture below does — see `lantern/src/index.ts:49` — and none of them calls `withLabels`.
 *
 * So this is a frozen copy of the exact bytes that composition rendered BEFORE the change, not a
 * set of patterns that would still pass if the label order, the bucket set, the HELP/TYPE ordering
 * or the trailing newline moved. If it fails, an existing dashboard broke.
 */

/** Mirrors `lantern/src/server.ts` `registerServiceMetrics`: the shapes a service really declares. */
function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({ name: 'lantern_up', help: 'Always 1.', kind: 'gauge', labels: [] })
    .register({
      name: 'lantern_events_ingested_total',
      help: 'Log events stored, by source and severity.',
      kind: 'counter',
      labels: ['source', 'severity'],
    })
    .register({ name: 'lantern_issues_upserted_total', help: 'Issue upserts.', kind: 'counter', labels: [] })
    .register({ name: 'lantern_issues_open', help: 'Open issues by severity.', kind: 'gauge', labels: ['severity'] })
}

const EXPOSITION_BEFORE_WITH_LABELS = `# HELP http_requests_total HTTP requests handled
# TYPE http_requests_total counter
http_requests_total{method="GET",route="/v1/issues",status="200",network="mainnet"} 2
http_requests_total{method="POST",route="/v1/ingest",status="500",network="testnet"} 1
# HELP http_request_duration_ms HTTP request duration in milliseconds
# TYPE http_request_duration_ms histogram
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="5"} 0
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="10"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="25"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="50"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="100"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="250"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="500"} 1
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="1000"} 2
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="2500"} 2
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="5000"} 2
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="10000"} 2
http_request_duration_ms_bucket{method="GET",route="/v1/issues",network="mainnet",le="+Inf"} 2
http_request_duration_ms_sum{method="GET",route="/v1/issues",network="mainnet"} 647
http_request_duration_ms_count{method="GET",route="/v1/issues",network="mainnet"} 2
# HELP http_requests_in_flight HTTP requests currently being handled
# TYPE http_requests_in_flight gauge
http_requests_in_flight{network="mainnet"} 3
# HELP jobs_claimed_total Jobs claimed
# TYPE jobs_claimed_total counter
jobs_claimed_total{kind="rollup",network="mainnet"} 1
# HELP jobs_completed_total Jobs completed
# TYPE jobs_completed_total counter
jobs_completed_total{kind="rollup",network="mainnet"} 1
# HELP jobs_failed_total Jobs failed
# TYPE jobs_failed_total counter
jobs_failed_total{kind="rollup",network="mainnet"} 1
# HELP jobs_dead_total Jobs dead-lettered
# TYPE jobs_dead_total counter
jobs_dead_total{kind="retention",network="testnet"} 1
# HELP jobs_duration_ms Job handler duration
# TYPE jobs_duration_ms histogram
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="5"} 0
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="10"} 0
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="25"} 0
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="50"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="100"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="250"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="500"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="1000"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="2500"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="5000"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="10000"} 1
jobs_duration_ms_bucket{kind="rollup",network="mainnet",le="+Inf"} 1
jobs_duration_ms_sum{kind="rollup",network="mainnet"} 42
jobs_duration_ms_count{kind="rollup",network="mainnet"} 1
# HELP jobs_pending Jobs waiting to be claimed
# TYPE jobs_pending gauge
jobs_pending{network="mainnet"} 11
# HELP jobs_overdue Jobs due more than five minutes ago
# TYPE jobs_overdue gauge
jobs_overdue{network="mainnet"} 2
# HELP lantern_up Always 1.
# TYPE lantern_up gauge
lantern_up 1
# HELP lantern_events_ingested_total Log events stored, by source and severity.
# TYPE lantern_events_ingested_total counter
lantern_events_ingested_total{source="pay",severity="error"} 1
# HELP lantern_issues_upserted_total Issue upserts.
# TYPE lantern_issues_upserted_total counter
lantern_issues_upserted_total 1
# HELP lantern_issues_open Open issues by severity.
# TYPE lantern_issues_open gauge
lantern_issues_open{severity="warn"} 4
`

test('a service registry that never calls withLabels renders exactly what it rendered before', () => {
  const m = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))

  m.increment('http_requests_total', { method: 'GET', route: '/v1/issues', status: '200', network: 'mainnet' })
  m.increment('http_requests_total', { method: 'GET', route: '/v1/issues', status: '200', network: 'mainnet' })
  m.increment('http_requests_total', { method: 'POST', route: '/v1/ingest', status: '500', network: 'testnet' })
  m.observe('http_request_duration_ms', 7, { method: 'GET', route: '/v1/issues', network: 'mainnet' })
  m.observe('http_request_duration_ms', 640, { method: 'GET', route: '/v1/issues', network: 'mainnet' })
  m.set('http_requests_in_flight', 3, { network: 'mainnet' })

  m.increment('jobs_claimed_total', { kind: 'rollup', network: 'mainnet' })
  m.increment('jobs_completed_total', { kind: 'rollup', network: 'mainnet' })
  m.increment('jobs_failed_total', { kind: 'rollup', network: 'mainnet' })
  m.increment('jobs_dead_total', { kind: 'retention', network: 'testnet' })
  m.observe('jobs_duration_ms', 42, { kind: 'rollup', network: 'mainnet' })
  m.set('jobs_pending', 11, { network: 'mainnet' })
  m.set('jobs_overdue', 2, { network: 'mainnet' })

  m.set('lantern_up', 1)
  m.increment('lantern_events_ingested_total', { source: 'pay', severity: 'error' })
  m.increment('lantern_issues_upserted_total')
  m.set('lantern_issues_open', 4, { severity: 'warn' })

  // KILLS: stamping anything by default, reordering the label names in `#labelKey`, or letting a
  // view's state leak into the registry it came from.
  assert.equal(m.render(), EXPOSITION_BEFORE_WITH_LABELS)
})

test('taking a view does not change what the registry it came from renders', () => {
  const build = () => registerJobMetrics(registerHttpMetrics(new Metrics()))
  const untouched = build()
  untouched.increment('jobs_claimed_total', { kind: 'sweep', network: 'mainnet' })

  const withAView = build()
  withAView.withLabels({ module: 'lantern' }) // taken and never written through
  withAView.increment('jobs_claimed_total', { kind: 'sweep', network: 'mainnet' })

  assert.equal(withAView.render(), untouched.render())
})
