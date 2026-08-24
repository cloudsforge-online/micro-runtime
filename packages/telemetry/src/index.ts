/**
 * Structured logging, redaction, trace correlation and a metrics facade.
 *
 * This replaces `src/obs.ts` — 375 lines, **byte-identical in five services** (md5 `2fcb6c10…`),
 * plus a divergent 428-line fork in Nimbus, plus `src/lib/obs.tsx` at 261 lines byte-identical in
 * six frontends. The file carries a comment declaring itself the "CANONICAL COPY", to be
 * re-copied into siblings by hand when it changes. With one repository per service that stops
 * being untidy and becomes structural: a redaction fix would be forty pull requests.
 *
 * Three properties are preserved from the original because they are load-bearing:
 *
 *   1. **Redaction is by key path and by content.** A secret reaches a log through a field nobody
 *      predicted at least as often as through one they did, so free text is scrubbed too.
 *   2. **`x-request-id` survives.** "Paste the id the user quoted and get their exact request
 *      across nimbus, pay and keyvault in order" is a workflow that already works in Lantern.
 *      W3C `traceparent` is added alongside it, not instead of it.
 *   3. **A log line is never allowed to throw.** An observability failure must not become an
 *      outage; the estate has already been burned by a malformed record stopping ingest.
 */

import { context, trace } from '@opentelemetry/api'

export type Level = 'debug' | 'info' | 'warn' | 'error' | 'fatal'

const LEVEL_VALUE: Record<Level, number> = { debug: 20, info: 30, warn: 40, error: 50, fatal: 60 }

export interface LogFields {
  readonly [key: string]: unknown
}

export interface LoggerOptions {
  readonly service: string
  readonly level?: Level
  readonly version?: string
  readonly env?: string
  /** Where a finished line goes. Default: one JSON object per line on stdout. */
  readonly sink?: (line: string) => void
  readonly now?: () => string
  /** Extra key names to redact, in addition to the defaults. */
  readonly redactKeys?: readonly string[]
}

/**
 * Key names whose values never appear in a log, at any depth.
 *
 * Carried forward from the estate's existing redaction list, which is good and was arrived at
 * the hard way — the password-reset token was being logged, and it is a live account-takeover
 * credential that Lantern stores and every backup carries.
 */
const DEFAULT_REDACT_KEYS = [
  'password',
  'passwordHash',
  'privateKey',
  'secretKey',
  'secret',
  'mnemonic',
  'seed',
  'blob',
  'ciphertext',
  'keyEnc',
  'masterSecret',
  'serviceToken',
  'token',
  'accessToken',
  'refreshToken',
  'resetToken',
  'authorization',
  'cookie',
  'setCookie',
  'apiKey',
  'signature',
  'wif',
  'idempotencyKey',
]

/** Free-text patterns scrubbed from any string value, whatever key it arrived under. */
const CONTENT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/postgres(?:ql)?:\/\/[^\s"']+/gi, 'postgres://[redacted]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/gi, 'Bearer [redacted]'],
  [/\bsk-[A-Za-z0-9_-]{12,}/g, 'sk-[redacted]'],
  [/\bghp_[A-Za-z0-9]{20,}/g, 'ghp_[redacted]'],
  [/\b0x[a-fA-F0-9]{64}\b/g, '0x[redacted-key]'],
  [/\beyJ[A-Za-z0-9._-]{20,}/g, '[redacted-jwt]'],
]

const MAX_DEPTH = 6
const MAX_STRING = 4_000

export function redactValue(value: unknown, redactKeys: ReadonlySet<string>, depth = 0): unknown {
  if (value == null) return value
  if (typeof value === 'string') return scrubText(value)
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'bigint') return value.toString()
  if (value instanceof Date) return value.toISOString()
  if (value instanceof Error) {
    return {
      name: value.name,
      message: scrubText(value.message),
      stack: value.stack ? scrubText(value.stack).split('\n').slice(0, 12).join('\n') : undefined,
    }
  }
  if (depth >= MAX_DEPTH) return '[depth-limit]'
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((v) => redactValue(v, redactKeys, depth + 1))
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactKeys.has(k.toLowerCase()) ? '[redacted]' : redactValue(v, redactKeys, depth + 1)
    }
    return out
  }
  return String(value)
}

function scrubText(input: string): string {
  let out = input.length > MAX_STRING ? `${input.slice(0, MAX_STRING)}…[truncated]` : input
  for (const [pattern, replacement] of CONTENT_PATTERNS) out = out.replace(pattern, replacement)
  return out
}

export class Logger {
  readonly #service: string
  readonly #threshold: number
  readonly #base: LogFields
  readonly #sink: (line: string) => void
  readonly #now: () => string
  readonly #redactKeys: ReadonlySet<string>

  constructor(options: LoggerOptions, base: LogFields = {}) {
    this.#service = options.service
    this.#threshold = LEVEL_VALUE[options.level ?? 'info']
    this.#sink = options.sink ?? ((line) => process.stdout.write(`${line}\n`))
    this.#now = options.now ?? (() => new Date().toISOString())
    this.#redactKeys = new Set(
      [...DEFAULT_REDACT_KEYS, ...(options.redactKeys ?? [])].map((k) => k.toLowerCase()),
    )
    this.#base = {
      service: options.service,
      ...(options.version ? { version: options.version } : {}),
      ...(options.env ? { env: options.env } : {}),
      ...base,
    }
    this.#options = options
  }

  readonly #options: LoggerOptions

  /** A child logger carrying extra fields — typically a request id and a route. */
  child(fields: LogFields): Logger {
    return new Logger(this.#options, { ...this.#base, ...fields })
  }

  debug(message: string, fields?: LogFields): void {
    this.#write('debug', message, fields)
  }
  info(message: string, fields?: LogFields): void {
    this.#write('info', message, fields)
  }
  warn(message: string, fields?: LogFields): void {
    this.#write('warn', message, fields)
  }
  error(message: string, fields?: LogFields): void {
    this.#write('error', message, fields)
  }
  fatal(message: string, fields?: LogFields): void {
    this.#write('fatal', message, fields)
  }

  #write(level: Level, message: string, fields?: LogFields): void {
    if (LEVEL_VALUE[level] < this.#threshold) return
    try {
      const span = trace.getSpan(context.active())
      const spanContext = span?.spanContext()
      const record = {
        time: this.#now(),
        level,
        msg: scrubText(message),
        ...(this.#base as Record<string, unknown>),
        // The join key that makes the whole telemetry stack work: click a slow trace, get its
        // logs; open a Lantern issue, jump to the trace.
        ...(spanContext ? { trace_id: spanContext.traceId, span_id: spanContext.spanId } : {}),
        ...(fields ? (redactValue(fields, this.#redactKeys) as Record<string, unknown>) : {}),
      }
      this.#sink(JSON.stringify(record))
    } catch (err) {
      // An observability failure must never become an outage. Emit the smallest possible
      // fallback and carry on.
      try {
        this.#sink(
          JSON.stringify({
            time: this.#now(),
            level: 'error',
            msg: 'log serialisation failed',
            service: this.#service,
            reason: err instanceof Error ? err.message : String(err),
          }),
        )
      } catch {
        /* nothing further can be done here */
      }
    }
  }
}

/* ------------------------------------------------------------------------ metrics */

export type MetricKind = 'counter' | 'gauge' | 'histogram'

export interface MetricSpec {
  readonly name: string
  readonly help: string
  readonly kind: MetricKind
  readonly labels?: readonly string[]
  /** Histogram bucket upper bounds, in the metric's own unit. */
  readonly buckets?: readonly number[]
}

const DEFAULT_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000]

/**
 * Why a write was thrown away.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A DISCARDED MEASUREMENT USED TO BE AN ABSENCE.** `increment`, `set` and `observe` each began
 * with a guard that returned on an unknown name, and `labelKey` filtered out every label the spec
 * had not declared. Both are the right behaviour — a registry must not invent series, and a
 * Prometheus metric may not vary its label set between samples — but both were performed in
 * silence, and a silent discard is indistinguishable at the `/metrics` endpoint from a thing that
 * simply never happened.
 *
 * What that cost, measured 2026-08-11: `ledger` writes
 * `metrics.increment('ledger_indexer_calls_total', { outcome: event.outcome })` on every indexer
 * call, and `ledger_indexer_calls_total` is registered nowhere. It is the estate's ONLY counter
 * carrying the outcome of an outbound call — the label whose `token_unavailable` value exists
 * precisely so a dead service credential can be told apart from an unreachable peer (micro-org#351)
 * — and every increment of it has been dropped on the first line of this method since it was
 * written. The reason code was added, and remained unalertable, because nothing said so.
 *
 * The two mistakes are separated rather than merged, because the remedies are different: an
 * unregistered name wants a `register(...)` beside the other specs, and an undeclared label wants
 * that spec's `labels` widened. Reporting them as one "bad metric write" would put an operator
 * back where a shared reason code always puts them.
 *
 * **Reported, never thrown.** Rule 3 of this file: a log line is never allowed to throw, and a
 * metric is the same bargain — observability failing must not become an outage.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export interface DroppedMetricWrite {
  readonly metric: string
  readonly reason: 'unregistered_metric' | 'wrong_kind' | 'undeclared_label'
  /** The label NAME for `undeclared_label`. Never the value — a label value can carry anything. */
  readonly label?: string
  /** What the spec says it is, when that is the disagreement. */
  readonly registeredKind?: MetricKind
}

export interface MetricsOptions {
  /**
   * Where a dropped write is reported. Default: one line on stderr per DISTINCT problem.
   *
   * Deduplicated because these are raised from the hot path — an unregistered counter on a
   * per-request seam would otherwise turn one missing `register` call into a log flood, which is
   * its own outage and would get the reporting removed again.
   */
  readonly onDropped?: (dropped: DroppedMetricWrite) => void
  /**
   * Labels stamped on every series this registry emits, unless the write names them itself.
   *
   * ── WHY `network` HAD TO STOP BEING A SCRAPE-JOB LABEL ──────────────────────────────────────
   *
   * Prometheus labelled `network` per TARGET, which worked only while each network had its own
   * pods to point a job at. The consolidation (micro-deploy `docs/network-consolidation.md`) puts
   * both networks behind one target, and a target-level label would then relabel testnet traffic
   * as mainnet — micro-org#398 a second time, except that the first time was recoverable by
   * editing a scrape config and this time the distinction would never have been recorded at all.
   *
   * So the network is stamped by whoever knows it. A single-network service knows at boot and
   * sets it here once. A merged service knows per request and passes it per write, which beats
   * the constant — see `#labelKey`.
   */
  readonly constantLabels?: Readonly<Record<string, string>>
}

/**
 * A small Prometheus-format registry.
 *
 * Beacon already exposes Prometheus text explicitly so that "adopting a scraper costs a scrape
 * config rather than a rewrite" — and nothing has ever scraped it. This gives every service the
 * same shape so the scrape config is the only remaining work.
 */
export class Metrics {
  readonly #specs = new Map<string, MetricSpec>()
  readonly #values = new Map<string, Map<string, number>>()
  readonly #histograms = new Map<string, Map<string, { counts: number[]; sum: number; count: number }>>()
  readonly #onDropped: (dropped: DroppedMetricWrite) => void
  readonly #constant: Readonly<Record<string, string>>
  readonly #reported = new Set<string>()

  constructor(options: MetricsOptions = {}) {
    this.#onDropped = options.onDropped ?? reportDroppedToStderr
    this.#constant = options.constantLabels ?? {}
  }

  register(spec: MetricSpec): this {
    if (this.#specs.has(spec.name)) throw new Error(`metric already registered: ${spec.name}`)
    this.#specs.set(spec.name, spec)
    if (spec.kind === 'histogram') this.#histograms.set(spec.name, new Map())
    else this.#values.set(spec.name, new Map())
    return this
  }

  increment(name: string, labels: Record<string, string> = {}, by = 1): void {
    const series = this.#values.get(name)
    if (!series) return this.#dropped(name)
    const key = this.#labelKey(this.#specs.get(name), labels)
    series.set(key, (series.get(key) ?? 0) + by)
  }

  set(name: string, value: number, labels: Record<string, string> = {}): void {
    const series = this.#values.get(name)
    if (!series) return this.#dropped(name)
    series.set(this.#labelKey(this.#specs.get(name), labels), value)
  }

  observe(name: string, value: number, labels: Record<string, string> = {}): void {
    const spec = this.#specs.get(name)
    const series = this.#histograms.get(name)
    if (!spec || !series) return this.#dropped(name)
    const key = this.#labelKey(spec, labels)
    const buckets = spec.buckets ?? DEFAULT_BUCKETS
    let entry = series.get(key)
    if (!entry) {
      entry = { counts: new Array(buckets.length).fill(0), sum: 0, count: 0 }
      series.set(key, entry)
    }
    entry.sum += value
    entry.count += 1
    for (let i = 0; i < buckets.length; i++) {
      if (value <= buckets[i]!) entry.counts[i] = (entry.counts[i] ?? 0) + 1
    }
  }

  /** Prometheus text exposition. Served at `/metrics`. */
  render(): string {
    const lines: string[] = []
    for (const spec of this.#specs.values()) {
      lines.push(`# HELP ${spec.name} ${spec.help}`)
      lines.push(`# TYPE ${spec.name} ${spec.kind === 'gauge' ? 'gauge' : spec.kind === 'counter' ? 'counter' : 'histogram'}`)
      if (spec.kind === 'histogram') {
        const buckets = spec.buckets ?? DEFAULT_BUCKETS
        for (const [key, entry] of this.#histograms.get(spec.name) ?? []) {
          const base = key ? key : ''
          for (let i = 0; i < buckets.length; i++) {
            lines.push(`${spec.name}_bucket{${joinLabels(base, `le="${buckets[i]}"`)}} ${entry.counts[i] ?? 0}`)
          }
          lines.push(`${spec.name}_bucket{${joinLabels(base, 'le="+Inf"')}} ${entry.count}`)
          lines.push(`${spec.name}_sum${base ? `{${base}}` : ''} ${entry.sum}`)
          lines.push(`${spec.name}_count${base ? `{${base}}` : ''} ${entry.count}`)
        }
      } else {
        for (const [key, value] of this.#values.get(spec.name) ?? []) {
          lines.push(`${spec.name}${key ? `{${key}}` : ''} ${value}`)
        }
      }
    }
    return `${lines.join('\n')}\n`
  }

  /**
   * A name this registry does not know. Split into "never registered" and "registered as another
   * kind", because `increment` on a histogram lands in the same `if (!series)` as a typo and the
   * two are fixed in different places.
   */
  #dropped(name: string): void {
    const spec = this.#specs.get(name)
    this.#report(
      spec
        ? { metric: name, reason: 'wrong_kind', registeredKind: spec.kind }
        : { metric: name, reason: 'unregistered_metric' },
    )
  }

  #labelKey(spec: MetricSpec | undefined, labels: Record<string, string>): string {
    const allowed = spec?.labels ?? []
    for (const name of Object.keys(labels)) {
      if (!allowed.includes(name)) {
        this.#report({ metric: spec?.name ?? '(unregistered)', reason: 'undeclared_label', label: name })
      }
    }
    // CONSTANT LABELS ARE NOT THE CALLER'S, so they are neither checked against `labels` nor
    // reported as undeclared: they belong to the registry, and a spec written before they existed
    // cannot have declared them. Reporting them would put a permanent stderr line under every
    // metric in the process, which is how reporting gets deleted.
    //
    // A PER-WRITE VALUE WINS. That precedence is the consolidation: a single-network service sets
    // `network` once at construction, and a merged one — which cannot know at construction which
    // network a request belongs to — passes it per write and overrides.
    const effective = { ...this.#constant, ...labels }
    const names = [...new Set([...Object.keys(this.#constant), ...allowed])]
    return names
      .filter((l) => effective[l] !== undefined)
      .map((l) => `${l}="${escapeLabel(effective[l]!)}"`)
      .join(',')
  }

  /** Once per distinct problem, and never allowed to throw — see `DroppedMetricWrite`. */
  #report(dropped: DroppedMetricWrite): void {
    // The separator is `\u0000` ESCAPED rather than typed. A raw NUL byte in a source file makes
    // the file binary to everything that reads sources as text: git stops diffing it, and the
    // estate's static sweeps refuse it outright — `ledger-accounts` failed with "could not be
    // read as UTF-8 source: a NUL byte at offset 15631" and took estate-ci red with it from
    // c5eed0d (2026-08-11) until this line was written out. The escape compiles to the same
    // character, which is the point: nothing about the key changes, only how it is spelled.
    const key = `${dropped.reason}\u0000${dropped.metric}\u0000${dropped.label ?? ''}`
    if (this.#reported.has(key)) return
    this.#reported.add(key)
    try {
      this.#onDropped(dropped)
    } catch {
      /* an observability failure must not become an outage */
    }
  }
}

/**
 * The default sink. Deliberately `process.stderr` rather than a `Logger`: `Metrics` is constructed
 * before a logger exists in several composition roots, and a dropped write is a deployment defect
 * an operator should see in `docker logs` whether or not log shipping is working.
 */
function reportDroppedToStderr(dropped: DroppedMetricWrite): void {
  const remedy =
    dropped.reason === 'unregistered_metric'
      ? `register it: metrics.register({ name: '${dropped.metric}', ... })`
      : dropped.reason === 'wrong_kind'
        ? `it is registered as a ${dropped.registeredKind ?? 'different'}; use the matching method`
        : `add '${dropped.label}' to that metric's spec labels, or stop passing it`
  process.stderr.write(
    `${JSON.stringify({
      level: 'warn',
      msg: 'metric write dropped',
      metric: dropped.metric,
      reason: dropped.reason,
      ...(dropped.label ? { label: dropped.label } : {}),
      remedy,
    })}\n`,
  )
}

function joinLabels(base: string, extra: string): string {
  return base ? `${base},${extra}` : extra
}

function escapeLabel(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')
}

/* ------------------------------------------------------------------------ request ids */

/**
 * A request id that is short, sortable and safe to quote down a phone line.
 *
 * Not a UUID: users read these out, and Lantern's primary workflow is pasting one back.
 */
export function newRequestId(random: () => number = Math.random): string {
  const alphabet = '0123456789abcdefghjkmnpqrstvwxyz'
  let out = ''
  for (let i = 0; i < 16; i++) out += alphabet[Math.floor(random() * alphabet.length)]
  return out
}

/** The standard RED metric set every service registers. */
export function registerHttpMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'http_requests_total',
      help: 'HTTP requests handled',
      kind: 'counter',
      labels: ['method', 'route', 'status', 'network'],
    })
    .register({
      name: 'http_request_duration_ms',
      help: 'HTTP request duration in milliseconds',
      kind: 'histogram',
      labels: ['method', 'route', 'network'],
    })
    .register({
      name: 'http_requests_in_flight',
      help: 'HTTP requests currently being handled',
      kind: 'gauge',
      labels: ['network'],
    })
}

/** The standard job-runner metric set, which is what makes a stuck queue visible. */
export function registerJobMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({ name: 'jobs_claimed_total', help: 'Jobs claimed', kind: 'counter', labels: ['kind', 'network'] })
    .register({ name: 'jobs_completed_total', help: 'Jobs completed', kind: 'counter', labels: ['kind', 'network'] })
    .register({ name: 'jobs_failed_total', help: 'Jobs failed', kind: 'counter', labels: ['kind', 'network'] })
    .register({ name: 'jobs_dead_total', help: 'Jobs dead-lettered', kind: 'counter', labels: ['kind', 'network'] })
    .register({ name: 'jobs_duration_ms', help: 'Job handler duration', kind: 'histogram', labels: ['kind', 'network'] })
    .register({ name: 'jobs_pending', help: 'Jobs waiting to be claimed', kind: 'gauge', labels: ['network'] })
    .register({ name: 'jobs_overdue', help: 'Jobs due more than five minutes ago', kind: 'gauge', labels: ['network'] })
}
