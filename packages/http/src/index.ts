/**
 * Outbound HTTP for service-to-service calls.
 *
 * What this replaces, and why each part is here:
 *
 * - **Nimbus's two admin proxies call bare `fetch`** (`routes/vault.ts`, `routes/pay.ts`).
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
 *    is how a user gets charged twice. A POST is retried only when it carries an idempotency key.
 *
 *    **THE KEY DOES NOT MAKE THE RETRY SAFE. THE RECEIVING ENDPOINT DOES.** This sentence used to
 *    read "which is what makes the retry safe", and ten caller files across the estate quote that
 *    claim back as their justification for supplying a key. It is unsound by construction: line
 *    ~221 infers retry-safety from the CALLER's intent, and the caller's intent is not evidence
 *    about the server's capability. A keyed POST to an endpoint that ignores the key is retried up
 *    to three times and takes effect up to three times — and a lost response on a call that
 *    actually SUCCEEDED is the ordinary case, not an exotic one.
 *
 *    Found when `custody`'s `POST /v1/addresses` turned out to read no key at all while `wallet`,
 *    `mint` and `foresight` were all sending one: the mechanism believed to make the call safe was
 *    the mechanism manufacturing the duplicate.
 *
 *    **So supplying a key is an assertion the caller owes evidence for**, and the evidence is a
 *    named constraint in the receiving service's schema, not a `src/idempotency.ts` in its tree. A
 *    filename proves nothing — custody's fix lives in `keys.ts` behind partial unique indexes and
 *    there is no such file; and a service that has one may still have routes it does not cover.
 *    The estate was audited endpoint by endpoint and every current target does honour its key:
 *
 *      ledger    POST /entries, /reservations, /reservations/:id/release
 *                  idempotency_keys.key (pk) + journal_entries_idempotency_key_uniq, claim and
 *                  work in ONE transaction
 *      custody   POST /v1/addresses          custody_keys_idempotency_uniq (migration 6) + 23505
 *      market    POST /v1/listings           listings_idempotency_uniq (migration 12) + 23505
 *      community POST /v1/communities        idempotency_keys.key (pk), tx threaded
 *      indexer   POST /v1/watch/…            naturally idempotent: upsert on the pk
 *      worlds    POST /v1/titles/:id/achievements/unlock
 *                  naturally idempotent: on conflict do nothing on the pk, and the outbox emit is
 *                  skipped on the duplicate
 *
 *    **This behaviour was deliberately NOT changed.** Refusing to retry keyed POSTs would be the
 *    sound rule in the abstract, but it would strip retries from calls whose loss has documented
 *    consequences ("a lost response would strand an order that has already paid") to fix nothing
 *    that is currently broken — and every alternative that looks sounder, such as a
 *    `retryKeyedPosts` flag, only moves the same unverifiable assertion further from its evidence.
 *    A server cannot advertise support before the request that would carry the advertisement. The
 *    obligation therefore sits with the caller, and it is written down here rather than enforced,
 *    because the thing that must be true is true in another repository.
 *
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

/**
 * The breaker is open, so this call was refused here rather than attempted.
 *
 * **IT CARRIES WHAT OPENED IT.** Until it did, this error was an absence: `circuit open for
 * indexer, retry in 8412ms` and nothing else. Every caller that has to say WHY a peer was not
 * observed therefore had exactly one thing it could say — `ledger`'s `reasonFor` maps a bare
 * `CircuitOpenError` to `unreachable`, and it is right to, because "the breaker is open" is all it
 * was ever handed. On the testnet estate on 2026-08-10 that turned a dead service credential into
 * hours of an operator being told the indexer was down; see `PREFLIGHT_FAILURES` below for the
 * measured timeline and for the pre-flight seam that now keeps a credential fault away from the
 * breaker entirely.
 *
 * With the pre-flight seam in place, `openedBy` should never be `token_unavailable`: a fault that
 * never reached the wire does not count against the peer. That is precisely why it is worth
 * reporting rather than assuming — **a failure that should be impossible needs a name an operator
 * can select on**, or its first occurrence is indistinguishable from the ordinary case it is
 * hiding inside. `openedBy: 'transport_error'` is a peer that really is unreachable and the
 * remedy "check it is up" is the right one; anything else means the remedy is somewhere else.
 *
 * `cause` is the standard ES2022 option, so `messageOf`/logger redaction and `--stack-trace-limit`
 * treat it the way they treat every other chained error, and a caller that wants to re-diagnose can
 * do `err.cause instanceof ServiceTokenUnavailableError` without this package knowing that type.
 *
 * The third parameter is optional so that constructing one positionally — which the estate's
 * tests do — keeps working unchanged.
 */
export class CircuitOpenError extends Error {
  readonly upstream: string
  readonly retryAfterMs: number
  /** The outcome of the failure that opened the breaker, or `null` if it was opened without one. */
  readonly openedBy: ResultEvent['outcome'] | null
  constructor(
    upstream: string,
    retryAfterMs: number,
    opened?: { readonly by: ResultEvent['outcome']; readonly cause?: unknown },
  ) {
    const after = opened ? ` after ${opened.by}` : ''
    const because =
      opened?.cause instanceof Error && opened.cause.message ? ` — last failure: ${opened.cause.message}` : ''
    super(`circuit open for ${upstream}${after}, retry in ${retryAfterMs}ms${because}`, {
      ...(opened && 'cause' in opened ? { cause: opened.cause } : {}),
    })
    this.name = 'CircuitOpenError'
    this.upstream = upstream
    this.retryAfterMs = retryAfterMs
    this.openedBy = opened?.by ?? null
  }
}

/**
 * Errors raised by the `token` supplier, before a request was ever sent.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A FAULT IN THE THING THAT AUTHENTICATES US IS NOT EVIDENCE ABOUT THE PEER**, and until this
 * existed the two were one error and one circuit.
 *
 * `#attempt` resolves `token()` inside the same try that wraps `fetch`, so a rejection from it
 * arrived at `request`'s catch indistinguishable from a socket hang-up: `classify` returned
 * `transport_error`, and `transport_error` calls `#circuit.failed()`. Five of those in a row open
 * the breaker — against a peer that has not been dialled once.
 *
 * Measured on the CloudsForge testnet estate, 2026-08-10. Every service credential was re-minted at
 * 12:03:44Z and again at 12:05:59Z; the containers were recreated seconds later still holding the
 * revoked generation, so `identity` answered every exchange `401 the service credential presented
 * is not valid`. `ledger`'s chain-backing sweep then recorded, from ONE unchanged cause:
 *
 *     12:11:59Z  token rejected  → failure 1
 *     12:12:00Z  token rejected  → failure 2   run recorded unobserved_reason = 'no_credential'  ✓
 *     12:12:03Z  token rejected  → failure 3
 *     12:12:04Z  token rejected  → failure 4   run recorded unobserved_reason = 'no_credential'  ✓
 *     12:12:07Z  token rejected  → failure 5   → CIRCUIT OPENS
 *     12:12:08Z  circuit open    → CircuitOpenError
 *                                  run recorded unobserved_reason = 'unreachable'               ✗
 *
 * and every run after that — 12:12:11Z, 12:19:21Z, 12:27:17Z — reported `unreachable` too, because
 * each 10s half-open probe fails on the token again and re-opens the breaker. `unreachable` is the
 * ledger's word for "no HTTP answer from the indexer at all", and the operator remedy printed
 * beside the resulting withdrawal freeze reads *"check it is up and that INDEXER_URL resolves from
 * this container"*. `indexer` was up and healthy throughout and was never asked anything. The
 * STEADY STATE of a bad credential was a freeze accusing the wrong service.
 *
 * That is the same misattribution `ServiceTokenUnavailableError` was created to end — "a 401 says
 * 'your credential is bad' when the truth is 'identity is down'" (`@cloudsforge/auth`) —
 * reinstated one layer down, where it also erases the first five honest rows behind it.
 *
 * So a pre-flight failure is marked, and `request` gives it the treatment a fault that never
 * reached the peer has earned: it does not touch the breaker, it is reported as
 * `token_unavailable` rather than as a transport error, and it reaches the caller **unchanged** —
 * which is what lets a caller that knows the supplier's error type keep diagnosing it. Nothing
 * here inspects, wraps or renames the error, so this file still depends on no auth package.
 *
 * **Not retried, either.** `ServiceTokenProvider` puts a one-second floor under its own exchange
 * attempts, and this client's backoff is 100–200ms, so the two further attempts a default GET
 * would spend are three identical rejections inside the provider's own backoff window. Failing at
 * once returns the diagnosis a whole deadline sooner.
 *
 * A `WeakSet` rather than a property on the error: the value belongs to the supplier, may be
 * frozen, and is about to be handed to a caller that must see exactly what was thrown.
 *
 * ── THE OTHER SEAM, WHICH THIS SET CANNOT REACH ───────────────────────────────────────────────
 *
 * The `token` supplier is not the only place a credential fault is raised. `ServiceTokenProvider`
 * is wired in twice — as `token` AND as `fetch`, because `authorizedFetch` re-mints and replays
 * once on a 401 — and that re-mint happens **inside the call this file makes to `fetch`**. A
 * rejection from it therefore arrives at the same catch a socket hang-up arrives at, with the same
 * consequence the hoist above removed for the supplier: `transport_error`, `#circuit.failed()`,
 * five of them and the breaker is open against a peer that answered every one of the five.
 *
 * micro-org#351 recorded it as a follow-up wanting "a dependency `@cloudsforge/http` does not
 * currently take". It does not have to take one. `PREFLIGHT` below is a **registry symbol**
 * (`Symbol.for`), so the two packages agree on one key through the runtime's own global symbol
 * table without either importing the other, and the direction of dependency between them stays
 * exactly as it is — none. `@cloudsforge/auth` sets it on `ServiceTokenUnavailableError`, which is
 * by construction the error meaning "we could not authenticate", never "the peer failed".
 *
 * A string key would have done the same job and is what makes this cheap to get wrong: `err.name
 * === 'ServiceTokenUnavailableError'` couples this file to a class name in a package it is
 * deliberately independent of, and matches any unrelated error that happens to be spelled the
 * same. A registered symbol is a name that cannot be collided with by accident.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const PREFLIGHT_FAILURES = new WeakSet<object>()

/**
 * The cross-package mark. An error carrying `[PREFLIGHT] === true` is one whose owner declares it
 * was raised before anything left this process, so it is not evidence about the peer.
 *
 * Set it on an error your own `fetch` or `token` implementation raises; nothing else reads it and
 * nothing here writes it onto an error it did not create.
 */
export const PREFLIGHT: unique symbol = Symbol.for('cloudsforge.http.preflight')

/** Marks `err` as raised before the request left this process, and returns it unchanged. */
function markPreflight(err: unknown): unknown {
  if (typeof err === 'object' && err !== null) PREFLIGHT_FAILURES.add(err)
  return err
}

function isPreflight(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false
  if (PREFLIGHT_FAILURES.has(err)) return true
  return (err as Record<symbol, unknown>)[PREFLIGHT] === true
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
  /**
   * `token_unavailable` is the one value that describes a call that **did not happen**: `status` is
   * null and `durationMs` is what the supplier spent, not what a peer did. It is separate from
   * `transport_error` because a dashboard that counted the two together would show an upstream
   * failing while it was serving every other caller — see `PREFLIGHT_FAILURES`.
   */
  readonly outcome:
    | 'ok'
    | 'peer_error'
    | 'server_error'
    | 'timeout'
    | 'transport_error'
    | 'circuit_open'
    | 'token_unavailable'
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
  /**
   * What opened it, kept so `CircuitOpenError` can say so. Refreshed on every failure that opens
   * or re-opens: after the reset window a half-open probe fails and re-opens, and the fault an
   * operator needs is the most recent one, not the one from twenty minutes ago.
   */
  #opened: { by: ResultEvent['outcome']; cause: unknown } | null = null
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

  /** The failure that opened it, for `CircuitOpenError`. `null` while the breaker is closed. */
  get opened(): { readonly by: ResultEvent['outcome']; readonly cause: unknown } | null {
    return this.#opened
  }

  succeeded(): void {
    this.#failures = 0
    this.#state = 'closed'
    this.#opened = null
  }

  /**
   * Only faults that mean "the peer is unwell" trip the breaker. A 404 or a 400 is the peer
   * answering correctly, and counting those would open the circuit on a caller's own bad input.
   *
   * Takes the fault rather than counting anonymously: an open breaker that cannot name what opened
   * it is the defect micro-org#351 is about, one layer down from where it was first found.
   */
  failed(by: ResultEvent['outcome'], cause: unknown): void {
    this.#failures += 1
    if (this.#failures >= this.#threshold) {
      this.#state = 'open'
      this.#openedAt = this.#now()
      this.#opened = { by, cause }
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
      const opened = this.#circuit.opened
      throw new CircuitOpenError(
        this.#o.name,
        this.#circuit.retryAfterMs,
        opened ? { by: opened.by, cause: opened.cause } : undefined,
      )
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
        // Nothing was sent, so there is nothing here that is evidence about the upstream: the
        // breaker is not touched, no retry is spent, and the error reaches the caller exactly as
        // the supplier threw it. See `PREFLIGHT_FAILURES` for the estate incident this is written
        // from. This catches BOTH seams a credential fault can be raised at — the `token` supplier
        // marked by `markPreflight` above, and a re-mint inside a `fetch` implementation, which
        // marks itself with `PREFLIGHT` because it is a package this one does not depend on.
        if (isPreflight(err)) {
          this.#emit({
            upstream: this.#o.name,
            method,
            path,
            status: null,
            durationMs: this.#now() - attemptStarted,
            attempt,
            outcome: 'token_unavailable',
          })
          throw err
        }
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
        if (outcome !== 'peer_error') this.#circuit.failed(outcome, err)

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
    // **RESOLVED BEFORE THE DEADLINE PLUMBING, AND IN ITS OWN CATCH.** It used to sit beside the
    // header merge below, inside the try that wraps `fetch`, which is what made a credential fault
    // and a socket fault the same error to everything above — see `PREFLIGHT_FAILURES`. Hoisting it
    // costs nothing: the supplier never receives `signal` and never did, so no deadline was ever
    // enforced on it here, and `ServiceTokenProvider` bounds its own exchange. What it buys is that
    // a rejection cannot be reinterpreted by the `timeoutSignal.aborted` branch below and lose its
    // mark on the way out.
    let token: string | undefined
    try {
      token = await this.#o.token?.()
    } catch (err) {
      throw markPreflight(err)
    }

    // `AbortSignal.any` rather than a manual listener, because a caller signal that is *already*
    // aborted when the attempt begins must still abort the request. Registering a listener on an
    // aborted signal never fires, which left the request hanging until its own deadline — the
    // exact class of bug this package exists to remove.
    //
    // A REFERENCED TIMER, NOT `AbortSignal.timeout`. This is the fourth instance in this estate of
    // the same mistake, and the first one in the deadline itself. `AbortSignal.timeout` uses an
    // UNREF'D timer: it does not hold the event loop open, so if nothing else does, Node drains
    // the loop and the deadline never fires — leaving the promise this method returns unsettled
    // for ever. `defaultSleep` at the foot of this file spells the rule out: `unref()` belongs on
    // a timer nobody is waiting for, never on one whose expiry is the thing a promise resolves on.
    // A deadline is exactly the second kind.
    //
    // It survived because a long-lived service always has a listening socket holding the loop. It
    // does not survive a short-lived process — `@cloudsforge/sdk` hit that already — and it does
    // not survive a drain, where the loop is held open only by the in-flight work this deadline
    // is the ceiling on. It surfaced in this package's own suite as
    // "Promise resolution is still pending but the event loop has already resolved".
    //
    // Holding the loop open costs nothing bounded badly: the timer lives at most `remainingMs`,
    // only while a request is in flight, and `clearTimeout` in the `finally` below releases it the
    // instant the attempt settles. A process that cannot exit while it is mid-request is a process
    // behaving correctly.
    const deadline = new AbortController()
    const timer = setTimeout(() => deadline.abort(), Math.max(0, remainingMs))
    const timeoutSignal = deadline.signal
    const signal = options.signal
      ? AbortSignal.any([options.signal, timeoutSignal])
      : timeoutSignal

    if (options.signal?.aborted) {
      clearTimeout(timer)
      throw options.signal.reason ?? new Error('aborted')
    }

    try {
      // PRECEDENCE, LOWEST FIRST: the accept default, the client's static `headers`, the client's
      // token, then the caller's per-request `headers`. The token sits BETWEEN the two bags rather
      // than after both, and that is the whole point: a static `headers` bag is a default the token
      // should beat, but a per-request header is an instruction for this one call.
      //
      // It used to sit after both, so `if (token) headers['authorization'] = …` silently replaced a
      // credential the caller had deliberately supplied — while the spread order above claimed the
      // opposite. `settlement`'s treasury provision route forwards an OPERATOR's bearer token to
      // custody's admin mint, custody requires `role:admin`, a service token does not carry it, and
      // so that route could only ever return 500. It never worked once (micro-org#251).
      //
      // `mergeHeaders` lower-cases as it goes. Header names are case-insensitive in HTTP but not in
      // a `Record<string, string>`: without it a caller's `Authorization` and the client's
      // `authorization` both survive to `fetch`, and which one wins becomes the `Headers`
      // constructor's business rather than ours.
      const headers: Record<string, string> = { accept: 'application/json' }
      mergeHeaders(headers, this.#o.headers)
      if (token) headers['authorization'] = `Bearer ${token}`
      mergeHeaders(headers, options.headers)
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
    } finally {
      // Releases the event loop the moment the attempt settles, whichever way it settled. Without
      // this, a fast call under a long deadline would keep the process alive for the rest of that
      // deadline — which is the opposite mistake, and just as real.
      clearTimeout(timer)
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

/**
 * Copies `from` onto `into`, lower-casing every name. A later source overwrites an earlier one
 * whatever case either wrote the name in — see the precedence note in `#attempt`.
 */
function mergeHeaders(into: Record<string, string>, from: Record<string, string> | undefined): void {
  if (!from) return
  for (const [name, value] of Object.entries(from)) into[name.toLowerCase()] = value
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
