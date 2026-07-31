/**
 * Outbound HTTP for service-to-service calls.
 *
 * What this replaces, and why each part is here:
 *
 * - **Nimbus's two admin proxies call bare `fetch`** (`routes/vault.ts:61`, `routes/pay.ts:73`).
 *   On undici there is no total-request timeout by default, so a hung ForgeKeyvault pins the
 *   identity service indefinitely — a denial of service on authentication for the whole estate,
 *   reachable by making one downstream slow. It is the worst call in the current codebase, in
 *   the service every other service depends on.
 * - **There are zero retries anywhere in the estate**, and no circuit breaker. A transient 502
 *   from a peer is a failed user operation.
 * - **Deadlines do not propagate.** A 10-second budget is spent in full at each of three hops,
 *   so a caller with a 10-second timeout waits 30.
 *
 * Two rules this enforces that are easy to get wrong:
 *
 * 1. **Only idempotent requests are retried by default.** Retrying a POST that debits a wallet
 *    is how a user gets charged twice. A POST is retried only when it carries an idempotency
 *    key, which is what makes the retry safe.
 * 2. **A deadline is absolute, not per-attempt.** Retries spend the same budget as the first
 *    attempt, so `deadlineMs` is a real ceiling on wall-clock time.
 */

export class HttpError extends Error {
  readonly status: number
  readonly body: string
  readonly requestId: string | undefined
  readonly url: string
  readonly method: string

  constructor(args: {
    status: number
    body: string
    url: string
    method: string
    requestId?: string | undefined
  }) {
    super(`${args.method} ${redactUrl(args.url)} → ${args.status}`)
    this.name = 'HttpError'
    this.status = args.status
    this.body = args.body
    this.url = args.url
    this.method = args.method
    this.requestId = args.requestId
  }

  /** 4xx means the peer decided. 5xx and transport faults mean we do not know. */
  get peerDecided(): boolean {
    return this.status >= 400 && this.status < 500
  }
}

export class TimeoutError extends Error {
  readonly url: string
  constructor(url: string, ms: number) {
    super(`timed out after ${ms}ms calling ${redactUrl(url)}`)
    this.name = 'TimeoutError'
    this.url = url
  }
}

export class CircuitOpenError extends Error {
  readonly upstream: string
  readonly retryAfterMs: number
  constructor(upstream: string, retryAfterMs: number) {
    super(`circuit open for ${upstream}, retry in ${retryAfterMs}ms`)
    this.name = 'CircuitOpenError'
    this.upstream = upstream
    this.retryAfterMs = retryAfterMs
  }
}

export interface RequestOptions {
  readonly method?: string
  readonly headers?: Record<string, string>
  readonly body?: unknown
  /** Absolute wall-clock ceiling across all attempts. */
  readonly deadlineMs?: number
  readonly retries?: number
  /**
   * Required to retry a non-idempotent method. Sent as `Idempotency-Key`.
   * Without it a POST is attempted exactly once, whatever `retries` says.
   */
  readonly idempotencyKey?: string
  readonly signal?: AbortSignal
  /** Correlates this call with the inbound request that caused it. */
  readonly requestId?: string
  /** W3C trace context, forwarded verbatim. */
  readonly traceparent?: string
  readonly accept?: 'json' | 'text'
}

export interface ClientOptions {
  readonly baseUrl: string
  /** Names the upstream in errors, metrics and the circuit breaker. */
  readonly name: string
  readonly defaultDeadlineMs?: number
  readonly defaultRetries?: number
  readonly headers?: Record<string, string>
  /** Called for the `Authorization` header. Async so a short-TTL service token can be refreshed. */
  readonly token?: () => Promise<string | undefined> | string | undefined
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
  readonly sleep?: (ms: number) => Promise<void>
  readonly circuit?: CircuitOptions
  readonly onResult?: (event: ResultEvent) => void
  /** Deterministic jitter for tests. Returns 0..1. */
  readonly random?: () => number
}

export interface ResultEvent {
  readonly upstream: string
  readonly method: string
  readonly path: string
  readonly status: number | null
  readonly durationMs: number
  readonly attempt: number
  readonly outcome: 'ok' | 'peer_error' | 'server_error' | 'timeout' | 'transport_error' | 'circuit_open'
}

export interface CircuitOptions {
  /** Consecutive failures before the circuit opens. */
  readonly threshold?: number
  /** How long it stays open before allowing one probe request. */
  readonly resetMs?: number
}

const RETRIABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504])
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'])

type CircuitState = 'closed' | 'open' | 'half_open'

/**
 * One breaker per upstream. Deliberately per-process: a shared breaker would need a shared store,
 * and the failure it guards against — a peer that is down — is visible from every replica anyway.
 */
class Circuit {
  #failures = 0
  #openedAt = 0
  #state: CircuitState = 'closed'
  readonly #threshold: number
  readonly #resetMs: number
  readonly #now: () => number

  constructor(options: CircuitOptions, now: () => number) {
    this.#threshold = options.threshold ?? 5
    this.#resetMs = options.resetMs ?? 10_000
    this.#now = now
  }

  get state(): CircuitState {
    if (this.#state === 'open' && this.#now() - this.#openedAt >= this.#resetMs) {
      this.#state = 'half_open'
    }
    return this.#state
  }

  get retryAfterMs(): number {
    return Math.max(0, this.#resetMs - (this.#now() - this.#openedAt))
  }

  succeeded(): void {
    this.#failures = 0
    this.#state = 'closed'
  }

  /**
   * Only faults that mean "the peer is unwell" trip the breaker. A 404 or a 400 is the peer
   * answering correctly, and counting those would open the circuit on a caller's own bad input.
   */
  failed(): void {
    this.#failures += 1
    if (this.#failures >= this.#threshold) {
      this.#state = 'open'
      this.#openedAt = this.#now()
    }
  }
}

export class HttpClient {
  readonly #o: ClientOptions
  readonly #fetch: typeof globalThis.fetch
  readonly #now: () => number
  readonly #sleep: (ms: number) => Promise<void>
  readonly #random: () => number
  readonly #circuit: Circuit

  constructor(options: ClientOptions) {
    this.#o = options
    this.#fetch = options.fetch ?? globalThis.fetch
    this.#now = options.now ?? (() => Date.now())
    this.#sleep = options.sleep ?? defaultSleep
    this.#random = options.random ?? Math.random
    this.#circuit = new Circuit(options.circuit ?? {}, this.#now)
  }

  get circuitState(): CircuitState {
    return this.#circuit.state
  }

  get<T>(path: string, options: RequestOptions = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'GET' })
  }

  post<T>(path: string, body: unknown, options: RequestOptions = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'POST', body })
  }

  put<T>(path: string, body: unknown, options: RequestOptions = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'PUT', body })
  }

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const method = (options.method ?? 'GET').toUpperCase()
    const deadlineMs = options.deadlineMs ?? this.#o.defaultDeadlineMs ?? 10_000
    const startedAt = this.#now()
    const expiresAt = startedAt + deadlineMs
    const url = joinUrl(this.#o.baseUrl, path)

    const retriable = IDEMPOTENT_METHODS.has(method) || options.idempotencyKey !== undefined
    const maxAttempts = retriable ? 1 + (options.retries ?? this.#o.defaultRetries ?? 2) : 1

    if (this.#circuit.state === 'open') {
      this.#emit({
        upstream: this.#o.name,
        method,
        path,
        status: null,
        durationMs: 0,
        attempt: 0,
        outcome: 'circuit_open',
      })
      throw new CircuitOpenError(this.#o.name, this.#circuit.retryAfterMs)
    }

    let lastError: unknown
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const remaining = expiresAt - this.#now()
      if (remaining <= 0) break

      const attemptStarted = this.#now()
      try {
        const result = await this.#attempt<T>(url, method, options, remaining)
        this.#circuit.succeeded()
        this.#emit({
          upstream: this.#o.name,
          method,
          path,
          status: result.status,
          durationMs: this.#now() - attemptStarted,
          attempt,
          outcome: 'ok',
        })
        return result.value
      } catch (err) {
        lastError = err
        const outcome = classify(err)
        this.#emit({
          upstream: this.#o.name,
          method,
          path,
          status: err instanceof HttpError ? err.status : null,
          durationMs: this.#now() - attemptStarted,
          attempt,
          outcome,
        })

        // A 4xx is the peer deciding. Retrying it produces the same answer and wastes budget.
        if (err instanceof HttpError && err.peerDecided && !RETRIABLE_STATUS.has(err.status)) {
          this.#circuit.succeeded()
          throw err
        }
        if (outcome !== 'peer_error') this.#circuit.failed()

        // The caller gave up, or the caller's own deadline passed. Neither is our business.
        if (options.signal?.aborted) throw err
        if (attempt === maxAttempts) break

        const backoff = this.#backoff(attempt)
        if (this.#now() + backoff >= expiresAt) break
        await this.#sleep(backoff)
      }
    }
    throw lastError ?? new TimeoutError(url, deadlineMs)
  }

  /** Exponential with full jitter: 100ms, 200ms, 400ms … each randomised across [0, cap]. */
  #backoff(attempt: number): number {
    const cap = Math.min(100 * 2 ** (attempt - 1), 2_000)
    return Math.floor(cap * this.#random())
  }

  async #attempt<T>(
    url: string,
    method: string,
    options: RequestOptions,
    remainingMs: number,
  ): Promise<{ value: T; status: number }> {
    // `AbortSignal.any` rather than a manual listener, because a caller signal that is *already*
    // aborted when the attempt begins must still abort the request. Registering a listener on an
    // aborted signal never fires, which left the request hanging until its own deadline — the
    // exact class of bug this package exists to remove.
    const timeoutSignal = AbortSignal.timeout(Math.max(0, remainingMs))
    const signal = options.signal
      ? AbortSignal.any([options.signal, timeoutSignal])
      : timeoutSignal

    if (options.signal?.aborted) throw options.signal.reason ?? new Error('aborted')

    try {
      const token = await this.#o.token?.()
      const headers: Record<string, string> = {
        accept: 'application/json',
        ...this.#o.headers,
        ...options.headers,
      }
      if (token) headers['authorization'] = `Bearer ${token}`
      if (options.requestId) headers['x-request-id'] = options.requestId
      if (options.traceparent) headers['traceparent'] = options.traceparent
      if (options.idempotencyKey) headers['idempotency-key'] = options.idempotencyKey
      // Tells the peer how long it has. A peer that honours it can fail fast instead of
      // doing work whose answer will be thrown away.
      headers['x-deadline-ms'] = String(Math.max(0, Math.floor(remainingMs)))

      let body: string | undefined
      if (options.body !== undefined) {
        body = JSON.stringify(options.body)
        headers['content-type'] = 'application/json'
      }

      const res = await this.#fetch(url, {
        method,
        headers,
        ...(body !== undefined ? { body } : {}),
        signal,
        redirect: 'manual',
      })

      const text = await res.text()
      if (!res.ok) {
        throw new HttpError({
          status: res.status,
          body: text.slice(0, 2_000),
          url,
          method,
          requestId: res.headers.get('x-request-id') ?? undefined,
        })
      }

      if (options.accept === 'text') return { value: text as T, status: res.status }
      if (text.length === 0) return { value: undefined as T, status: res.status }
      try {
        return { value: JSON.parse(text) as T, status: res.status }
      } catch {
        throw new HttpError({
          status: res.status,
          body: `expected JSON, got ${text.slice(0, 200)}`,
          url,
          method,
        })
      }
    } catch (err) {
      // Our deadline expiring is a timeout. The caller giving up is not — surfacing that as a
      // TimeoutError would blame the peer for the caller's own cancellation.
      if (timeoutSignal.aborted && !options.signal?.aborted) {
        throw new TimeoutError(url, remainingMs)
      }
      throw err
    }
  }

  #emit(event: ResultEvent): void {
    this.#o.onResult?.(event)
  }
}

function classify(err: unknown): ResultEvent['outcome'] {
  if (err instanceof TimeoutError) return 'timeout'
  if (err instanceof HttpError) return err.peerDecided ? 'peer_error' : 'server_error'
  return 'transport_error'
}

function joinUrl(base: string, path: string): string {
  if (/^https?:\/\//i.test(path)) return path
  return `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
}

/** Strips query and userinfo, so a URL in a log or an error message cannot leak a token. */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url)
    u.search = ''
    u.username = ''
    u.password = ''
    return u.toString()
  } catch {
    return url.split('?')[0] ?? url
  }
}

/**
 * The retry backoff. The timer stays REFERENCED, deliberately.
 *
 * An unref'd timer that somebody is `await`ing is a promise that may never settle: if nothing else
 * holds the event loop open while the backoff runs, Node drains the loop and the retry simply
 * never fires. In a long-lived service a listening socket hides this, which is why it survived
 * here — but not everywhere the loop can empty:
 *
 *   - **During drain.** The server is closed and the loop is held open only by in-flight work. A
 *     request awaiting a retry backoff at that moment is exactly the work the drain exists to
 *     wait for, and an unref'd timer lets the process leave without it.
 *   - **In a library.** `@cloudsforge/sdk` copied this function verbatim, and in someone else's
 *     short-lived process eleven of its tests hung on a retry that never fired.
 *
 * This is the third instance of the same mistake in this estate — the lifecycle probe timeout and
 * the drain delay were both unref'd for the same reason and both silently skipped. The rule that
 * came out of it: `unref()` belongs on a timer nobody is waiting for (a poll tick, a force-exit
 * bomb), never on one whose expiry is the thing a promise resolves on.
 *
 * The cost of referencing is bounded by construction: the timer lives at most `ms`, and only while
 * a request is between attempts.
 */
function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}
