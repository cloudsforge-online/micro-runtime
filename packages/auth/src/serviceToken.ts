/**
 * **The client half of the ten-minute cliff.**
 *
 * ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────
 *
 * Service tokens expire in 600 seconds (`identity/src/tokens.ts:28`). Every service in the estate
 * read its token once, from an environment variable, at boot:
 *
 *     const token = () => env.serviceToken      // wallet/src/index.ts:90, and eight more like it
 *
 * Nothing re-minted it, so the estate worked perfectly in every test and for the first ten minutes
 * of any real deployment, after which every service-to-service call began failing. No per-service
 * suite could see it, because each suite mints a fresh token as it starts and finishes well inside
 * ten minutes.
 *
 * `micro-identity` fixed the server half: a container now holds a long-lived, revocable
 * **credential** (`cfsc_…`) and exchanges it at `POST /service-tokens/exchange` for an ordinary
 * 600-second token. The exchange consumes nothing, so N replicas boot from one credential and a
 * restart days later still works. **The 600 seconds is deliberately unchanged** — rotation IS
 * expiry, and lengthening the TTL would leave the same defect arriving later and hurting more.
 *
 * This file is the other half: the thing that turns a credential into a token that is always live.
 * The author of wallet's seam wrote that the function exists "so a short-TTL token can be rotated
 * without a restart when identity starts minting them". Identity now does.
 *
 * ── WHY THERE IS NO TIMER, AND NO LEASE ───────────────────────────────────────────────────────
 *
 * Refresh is driven by **traffic, not by a clock**. Every call to `token()` asks "am I past the
 * refresh point?" and, if so, starts a background exchange while handing back the still-valid
 * token it already has. There is no `setInterval` (rule 8 forbids one doing domain work) and no
 * `setTimeout` either, which means:
 *
 *   * nothing to shut down, so a provider cannot hold the event loop open past a drain;
 *   * a service with no outbound traffic mints no tokens, because it needs none;
 *   * the refresh happens at the moment a token is about to be used, which is the only moment its
 *     freshness matters.
 *
 * It is also **not a leased job**, and this is the trap worth naming. A lease arbitrates a
 * contended shared resource. A token is per-process state: the replica that won the lease would
 * mint a token into its own memory that no other replica can see, leaving every other replica on
 * the cliff. `identity/src/serviceCredentials.ts` reached the same conclusion from the other side,
 * which is why the exchange is parallel-safe and consumes nothing.
 *
 * ── WHY 80%, AND WHY IT IS JITTERED ───────────────────────────────────────────────────────────
 *
 * Refreshing at 80% of `expiresIn` leaves the last 20% — two minutes of a ten-minute token — as
 * slack in which a failed exchange can be retried without a single request ever seeing an expired
 * credential. Refreshing at 99% would be correct only if identity never had a bad second.
 *
 * The 80% is jittered per process across [75%, 85%] because N replicas that boot together would
 * otherwise reach 80% together and exchange in the same instant, converting a rolling deploy into
 * a thundering herd against the one service every other service depends on. The jitter is drawn
 * ONCE PER TOKEN rather than once per provider, so replicas that happened to draw the same value
 * do not stay in lockstep for the life of the process.
 *
 * ── WHY THE 401 RETRY EXISTS ANYWAY ───────────────────────────────────────────────────────────
 *
 * The refresh point is computed from `expiresIn` and this process's own clock. A peer decides
 * expiry from `exp` and ITS clock. Those can disagree, a process can be paused between reading the
 * token and sending it, and a credential can be revoked mid-flight. So correctness must not rest
 * on the schedule: `authorizedFetch` catches a 401 from a peer, discards exactly the token that was
 * rejected, mints a replacement, and replays the request once. The schedule is the optimisation;
 * the 401 path is the guarantee.
 *
 * It re-mints **once**. A second 401 is answered by returning it, because a token that a peer
 * rejects twice is a scope or trust problem that minting a third token cannot fix, and a loop here
 * would turn one misconfiguration into a denial of service on identity.
 *
 * ── WHAT AN UNREACHABLE IDENTITY MEANS ────────────────────────────────────────────────────────
 *
 * The estate already has a considered answer for this on the inbound side, in `Verifier`: if the
 * JWKS endpoint is unreachable *we cannot decide*, so the answer is 503 and never 401 — an
 * unreachable verifier must not sign the estate out. The outbound side is the same reasoning
 * pointed the other way:
 *
 *   * A token we hold that is **still valid** is still good. An identity outage does not retract a
 *     token it already signed, so we keep using it and keep retrying in the background. Failing
 *     early here would take the estate down for a fault it is designed to ride out.
 *   * A token we hold that has **expired**, or no token at all, means we cannot authenticate. We
 *     throw `ServiceTokenUnavailableError`, which `statusFor` maps to **503** — the caller could
 *     not decide, exactly as with an unreachable verifier. We do NOT send the request unauthenticated
 *     and we do NOT send a stale token: either would produce a 401 from the peer, and a 401 says
 *     "your credential is bad" when the truth is "identity is down". That misattribution is what
 *     sends an operator to the wrong service at three in the morning.
 *
 * A failing exchange is not hammered. Concurrent callers share one in-flight exchange
 * (`#inFlight`), so a down identity sees at most one request per provider at a time, and
 * `failureBackoffMs` puts a floor under the interval between attempts so that a service under load
 * cannot turn its own outage into a retry storm.
 */

/**
 * The credential prefix identity issues. Mirrored here rather than imported, because
 * `@cloudsforge/auth` must not depend on the identity service — but a container that has been
 * handed a token where a credential belongs is a configuration error worth naming at boot rather
 * than discovering as a 401 ten minutes later.
 */
export const CREDENTIAL_PREFIX = 'cfsc_'

/**
 * We could not obtain a service token. **Answer 503, never 401.**
 *
 * The distinction is the same one `VerifierUnavailableError` draws inbound: a fault in the thing
 * that decides authentication is not evidence that the caller is unauthenticated.
 */
export class ServiceTokenUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'ServiceTokenUnavailableError'
  }
}

/** The shape `POST /service-tokens/exchange` answers with. */
export interface ExchangedToken {
  readonly token: string
  readonly service: string
  readonly scopes: readonly string[]
  /** Seconds. Identity clamps this to `SERVICE_TTL_SECONDS` and may only ever shorten it. */
  readonly expiresIn: number
}

export type ProviderEvent =
  | { readonly kind: 'minted'; readonly service: string; readonly expiresIn: number; readonly refreshInMs: number }
  | { readonly kind: 'exchange_failed'; readonly err: unknown; readonly hadUsableToken: boolean }
  | { readonly kind: 'reminted_after_401'; readonly url: string }
  | { readonly kind: 'replay_skipped'; readonly url: string; readonly reason: string }

export interface ServiceTokenProviderOptions {
  /** Identity's base URL, e.g. `http://identity:4000`. */
  readonly identityUrl: string
  /** The long-lived credential, from `<SERVICE>_IDENTITY_CREDENTIAL`. */
  readonly credential: string
  /**
   * Narrow the token to these scopes. Omitted asks for the service's whole allowlist, which is
   * what a long-running provider wants: at boot it cannot know which of its call sites will be
   * reached. Identity never widens either way.
   */
  readonly scopes?: readonly string[] | undefined
  /** Fraction of `expiresIn` at which refresh begins. Default 0.8. */
  readonly refreshAt?: number | undefined
  /** Half-width of the jitter band around `refreshAt`. Default 0.05, giving [0.75, 0.85]. */
  readonly refreshJitter?: number | undefined
  /** Wall-clock ceiling on one exchange. Default 5s. */
  readonly deadlineMs?: number | undefined
  /**
   * Never present a token within this margin of its expiry. Matches `Verifier`'s default clock
   * tolerance, so we do not hand a peer something its clock has already retired.
   */
  readonly skewMs?: number | undefined
  /** Floor on the interval between exchange attempts after a failure. Default 1s. */
  readonly failureBackoffMs?: number | undefined
  readonly fetch?: typeof globalThis.fetch | undefined
  readonly now?: (() => number) | undefined
  /** Deterministic jitter for tests. Returns 0..1. */
  readonly random?: (() => number) | undefined
  readonly onEvent?: ((event: ProviderEvent) => void) | undefined
}

interface Held {
  readonly token: string
  readonly service: string
  readonly expiresAtMs: number
  readonly refreshAtMs: number
}

export interface ProviderSnapshot {
  /**
   * Whether a call right now would be authenticated without waiting.
   *
   * Deliberately NOT "is a token present". An expired token is retained after it dies — it is the
   * most useful thing a diagnosing operator can be shown, because `expiresInSeconds` going steadily
   * negative says "identity has been unreachable for four minutes" where an absent token says
   * nothing. But a probe that read presence as health would report ready across exactly the outage
   * this file exists to survive, which is a check that cannot fail.
   */
  readonly hasUsableToken: boolean
  readonly service: string | null
  /** Seconds until the held token expires; negative once it has. `null` if none was ever minted. */
  readonly expiresInSeconds: number | null
  readonly refreshing: boolean
  readonly lastFailure: string | null
}

/**
 * Holds a credential, mints tokens from it, and keeps one live.
 *
 * Wire it into `@cloudsforge/http` with both hooks — the second is not optional decoration:
 *
 * ```ts
 * const identityTokens = new ServiceTokenProvider({
 *   identityUrl: env.identityUrl,
 *   credential: env.identityCredential,
 * })
 * const ledger = httpLedgerClient({
 *   baseUrl: env.ledgerUrl,
 *   token: identityTokens.token,          // per request, so refresh needs no restart
 *   fetch: identityTokens.authorizedFetch, // so a 401 re-mints and replays instead of failing
 * })
 * ```
 */
export class ServiceTokenProvider {
  readonly #identityUrl: string
  readonly #credential: string
  readonly #scopes: readonly string[] | undefined
  readonly #refreshAt: number
  readonly #refreshJitter: number
  readonly #deadlineMs: number
  readonly #skewMs: number
  readonly #failureBackoffMs: number
  readonly #fetch: typeof globalThis.fetch
  readonly #now: () => number
  readonly #random: () => number
  readonly #onEvent: ((event: ProviderEvent) => void) | undefined

  #held: Held | null = null
  #inFlight: Promise<Held> | null = null
  #lastFailure: { at: number; err: unknown } | null = null

  constructor(options: ServiceTokenProviderOptions) {
    if (!options.credential) {
      throw new Error('a service credential is required; see <SERVICE>_IDENTITY_CREDENTIAL')
    }
    // A container handed a JWT where a credential belongs would work for exactly ten minutes and
    // then fail in the way this whole file exists to prevent, so say so at construction instead.
    if (!options.credential.startsWith(CREDENTIAL_PREFIX)) {
      throw new Error(
        `a service credential begins '${CREDENTIAL_PREFIX}'; this looks like a token, which is the ` +
          'thing that expires in ten minutes and cannot renew itself',
      )
    }
    this.#identityUrl = options.identityUrl.replace(/\/+$/, '')
    this.#credential = options.credential
    this.#scopes = options.scopes
    this.#refreshAt = options.refreshAt ?? 0.8
    this.#refreshJitter = options.refreshJitter ?? 0.05
    this.#deadlineMs = options.deadlineMs ?? 5_000
    this.#skewMs = options.skewMs ?? 5_000
    this.#failureBackoffMs = options.failureBackoffMs ?? 1_000
    this.#fetch = options.fetch ?? globalThis.fetch
    this.#now = options.now ?? (() => Date.now())
    this.#random = options.random ?? Math.random
    this.#onEvent = options.onEvent

    if (this.#refreshAt - this.#refreshJitter <= 0 || this.#refreshAt + this.#refreshJitter >= 1) {
      throw new Error('refreshAt ± refreshJitter must stay strictly inside (0, 1)')
    }
  }

  /**
   * The live token. An arrow property rather than a method so it can be handed to `HttpClient`
   * unbound — `token: provider.token` — which is how every call site in the estate wants to read.
   *
   * Returns the held token when it is usable, starting a background refresh if it is past its
   * refresh point. Awaits an exchange only when there is nothing usable to return.
   */
  readonly token = async (): Promise<string> => {
    const held = this.#held
    if (held && this.#now() + this.#skewMs < held.expiresAtMs) {
      // Past 80%: refresh behind the request rather than in front of it. The caller pays nothing,
      // and the 20% slack is there precisely so this may fail a few times without being noticed.
      if (this.#now() >= held.refreshAtMs) this.#refreshInBackground()
      return held.token
    }
    // Nothing usable. This one blocks, and may fail closed — see the header.
    return (await this.#exchange()).token
  }

  /**
   * A `fetch` that re-mints and replays once on a 401.
   *
   * Pass it as `HttpClient`'s `fetch`. This is the layer where the 401 is visible and where the
   * `Authorization` header was set, so hooking it needs no change at any call site — and, unlike a
   * wrapper around each client method, it cannot be forgotten at one of them.
   */
  readonly authorizedFetch: typeof globalThis.fetch = async (input, init) => {
    const response = await this.#fetch(input, init)
    if (response.status !== 401) return response

    const url = urlOf(input)
    const headers = new Headers(init?.headers)
    const presented = bearerOf(headers.get('authorization'))
    // Not our bearer that was refused: an unauthenticated call, or one carrying a user's token
    // being forwarded. Minting a service token would not help and would hide the real fault.
    //
    // Deliberately imports nothing from `./index.ts`, so the dependency between the two files runs
    // in one direction only. `statusFor` there needs this file's error type; a cycle back would
    // work under ESM and be a trap for whoever next moves a declaration across the boundary.
    if (!presented || presented !== this.#held?.token) {
      this.#onEvent?.({ kind: 'replay_skipped', url, reason: 'the 401 was not for the held token' })
      return response
    }
    // A body that is not a string cannot be replayed — a stream is already drained. `HttpClient`
    // always serialises to a string, so this is a guard against a future caller rather than a
    // live case, and it fails honestly rather than replaying an empty body.
    if (init?.body != null && typeof init.body !== 'string') {
      this.#onEvent?.({ kind: 'replay_skipped', url, reason: 'the request body is not replayable' })
      return response
    }

    // Discard exactly the token that was rejected. Keyed on the token itself, so ten concurrent
    // 401s cause ONE re-mint: the first swaps `#held`, and the other nine find their presented
    // token is no longer the held one and simply replay with the new one.
    this.#discard(presented)
    const fresh = await this.token()
    if (fresh === presented) return response

    await response.body?.cancel().catch(() => {})
    headers.set('authorization', `Bearer ${fresh}`)
    this.#onEvent?.({ kind: 'reminted_after_401', url })
    // Once. A second 401 is returned as-is: see the header.
    return this.#fetch(input, { ...init, headers })
  }

  /** For a readiness probe or a gauge. Never returns the token itself. */
  snapshot(): ProviderSnapshot {
    const held = this.#held
    return {
      hasUsableToken: held !== null && this.#now() + this.#skewMs < held.expiresAtMs,
      service: held?.service ?? null,
      expiresInSeconds: held ? Math.round((held.expiresAtMs - this.#now()) / 1000) : null,
      refreshing: this.#inFlight !== null,
      lastFailure: this.#lastFailure ? messageOf(this.#lastFailure.err) : null,
    }
  }

  #discard(token: string): void {
    if (this.#held?.token === token) this.#held = null
  }

  #refreshInBackground(): void {
    if (this.#inFlight) return
    // `void` plus a catch: a background refresh that rejects must not become an unhandled
    // rejection and take the process down for a fault the next request will retry anyway.
    void this.#exchange().catch(() => {})
  }

  /**
   * One exchange, shared by every concurrent caller.
   *
   * The single-flight is not an optimisation. Without it, a replica whose token has just expired
   * under load exchanges once per in-flight request — a self-inflicted stampede against identity
   * at exactly the moment identity is least able to absorb one.
   */
  #exchange(): Promise<Held> {
    const existing = this.#inFlight
    if (existing) return existing

    const failure = this.#lastFailure
    if (failure && this.#now() - failure.at < this.#failureBackoffMs) {
      return Promise.reject(
        new ServiceTokenUnavailableError(
          `identity was unreachable ${this.#now() - failure.at}ms ago; not retrying yet`,
          { cause: failure.err },
        ),
      )
    }

    const attempt = this.#post()
      .then((issued) => {
        const held = this.#hold(issued)
        this.#held = held
        this.#lastFailure = null
        this.#onEvent?.({
          kind: 'minted',
          service: issued.service,
          expiresIn: issued.expiresIn,
          refreshInMs: held.refreshAtMs - this.#now(),
        })
        return held
      })
      .catch((err: unknown) => {
        this.#lastFailure = { at: this.#now(), err }
        const usable = this.#held !== null && this.#now() + this.#skewMs < this.#held.expiresAtMs
        this.#onEvent?.({ kind: 'exchange_failed', err, hadUsableToken: usable })
        throw err instanceof ServiceTokenUnavailableError
          ? err
          : new ServiceTokenUnavailableError(
              `could not exchange the service credential: ${messageOf(err)}`,
              { cause: err },
            )
      })
      .finally(() => {
        this.#inFlight = null
      })

    this.#inFlight = attempt
    return attempt
  }

  #hold(issued: ExchangedToken): Held {
    const lifetimeMs = issued.expiresIn * 1000
    // Drawn per token, not per provider: two replicas that drew the same fraction once must not
    // stay in step for the life of the process.
    const fraction = this.#refreshAt + (this.#random() * 2 - 1) * this.#refreshJitter
    const issuedAt = this.#now()
    return {
      token: issued.token,
      service: issued.service,
      expiresAtMs: issuedAt + lifetimeMs,
      refreshAtMs: issuedAt + lifetimeMs * fraction,
    }
  }

  async #post(): Promise<ExchangedToken> {
    const signal = AbortSignal.timeout(this.#deadlineMs)
    const body: Record<string, unknown> = {}
    if (this.#scopes && this.#scopes.length > 0) body['scopes'] = this.#scopes

    const response = await this.#fetch(`${this.#identityUrl}/service-tokens/exchange`, {
      method: 'POST',
      headers: {
        // The credential goes in the Authorization header, which is what the exchange reads. It is
        // never a query parameter: `redactUrl` strips a query from a log, but a proxy access log
        // in front of identity would not.
        authorization: `Bearer ${this.#credential}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(body),
      signal,
      redirect: 'manual',
    })

    if (!response.ok) {
      const text = await response.text().catch(() => '')
      throw new ServiceTokenUnavailableError(
        `identity refused the credential exchange: ${response.status} ${text.slice(0, 300)}`,
      )
    }

    const payload: unknown = await response.json()
    return readExchange(payload)
  }
}

/**
 * Validate identity's answer before trusting it to schedule anything.
 *
 * `expiresIn` is required and is NOT defaulted. A default would be a lifetime this file invented,
 * and inventing a lifetime is how the original defect is reintroduced: guess longer than the truth
 * and every token expires in service, exactly as before. A response without it is a protocol
 * mismatch and must be loud.
 */
function readExchange(payload: unknown): ExchangedToken {
  if (typeof payload !== 'object' || payload === null) {
    throw new ServiceTokenUnavailableError('the credential exchange did not answer with an object')
  }
  const body = payload as Record<string, unknown>
  const token = body['token']
  const service = body['service']
  const expiresIn = body['expiresIn']
  const scopes = body['scopes']

  if (typeof token !== 'string' || token.length === 0) {
    throw new ServiceTokenUnavailableError('the credential exchange answered without a token')
  }
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new ServiceTokenUnavailableError(
      'the credential exchange answered without a usable expiresIn, so the refresh point is unknowable',
    )
  }
  return {
    token,
    service: typeof service === 'string' ? service : 'unknown',
    expiresIn,
    scopes: Array.isArray(scopes) ? scopes.filter((s): s is string => typeof s === 'string') : [],
  }
}

/**
 * A readiness probe for the credential, shaped for `@cloudsforge/lifecycle` without importing it.
 *
 * The return type is `Probe` structurally — `{ name, kind, check }` — so this package stays
 * dependency-free and `lifecycle.addProbe(serviceTokenProbe(provider))` still type-checks. Six
 * services need exactly this check; six hand-written copies is how `obs.ts` ended up byte-identical
 * in five repositories and divergent in a sixth.
 *
 * **It fails for one reason only: no credential is configured.** That is a deployment that is
 * wrong and will stay wrong until someone changes it, so taking the replica out of the balancer is
 * right and the operator gets a named check instead of a wall of 503s.
 *
 * An identity outage returns `warn`, never `fail`. `fail` on a hard probe would remove EVERY
 * replica of EVERY service from its balancer the moment identity had a bad minute — a cascade
 * triggered by the one service the estate can least afford to amplify a fault in. The tokens
 * already held keep working; the warn is what says so out loud.
 *
 * It deliberately does not dial identity. A probe that did would multiply the estate's readiness
 * traffic by its replica count into a single service, and would answer a question this process can
 * already answer from what it holds.
 */
export function serviceTokenProbe(
  provider: ServiceTokenProvider | null,
  options: { readonly name?: string } = {},
): {
  readonly name: string
  readonly kind: 'hard'
  check(): Promise<{ state: 'pass' | 'warn' | 'fail'; detail?: string }>
} {
  return {
    name: options.name ?? 'identity-credential',
    kind: 'hard',
    check: async () => {
      if (!provider) {
        return { state: 'fail', detail: 'no service credential is configured' }
      }
      const snapshot = provider.snapshot()
      if (snapshot.hasUsableToken) return { state: 'pass' }
      if (snapshot.lastFailure) {
        // The message, never the token and never the credential — `detail` is shown to operators.
        return { state: 'warn', detail: `no live service token: ${snapshot.lastFailure}` }
      }
      // Configured, and nothing has gone wrong: a provider mints on first use, so a service that
      // has not yet called a peer holding no token is a service that is behaving correctly.
      return { state: 'pass', detail: 'no token minted yet' }
    },
  }
}

function bearerOf(header: string | null): string | null {
  if (!header) return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  return match?.[1]?.trim() ?? null
}

/**
 * Spelled off `globalThis.fetch` rather than as `RequestInfo`: that name is not in scope under
 * `lib: ["ES2023"]` with no DOM lib, and Node's own undici typings do not export it globally.
 */
type FetchInput = Parameters<typeof globalThis.fetch>[0]

function urlOf(input: FetchInput): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
