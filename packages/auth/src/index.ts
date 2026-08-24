/**
 * One JWKS verifier, replacing five divergent per-service copies.
 *
 * `services/<name>/src/auth.ts` exists five times in the estate — 87 lines in pay, 93 in game, 78 in
 * forge-mint, 54 in crucible, 55 in custody — all verifying the same RS256 token against the same
 * JWKS with the same audience, and all slightly different. That divergence is not cosmetic: the
 * services disagree about **what an unverifiable token means**, which is the single most
 * important decision this file makes.
 *
 * **A token fault is 401. A verifier fault is 503.**
 *
 * If the signature is bad, the audience is wrong or the token has expired, the caller is
 * unauthenticated and the answer is 401. If the JWKS endpoint is unreachable, *we* cannot decide
 * — and answering 401 would sign every user in the estate out because the identity service is
 * having a bad minute. Crucible and the game already get this right; this package makes it the
 * only available behaviour.
 */

import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose'
import type { JWTPayload } from 'jose'
import { ServiceTokenUnavailableError } from './serviceToken.ts'

/**
 * The outbound half of the same problem: holding a credential and keeping a live service token.
 * See `serviceToken.ts` — a service token expires in ten minutes and nothing used to re-mint it.
 */
export {
  CREDENTIAL_PREFIX,
  ServiceTokenProvider,
  ServiceTokenUnavailableError,
  serviceTokenProbe,
  type ExchangedToken,
  type ProviderEvent,
  type ProviderSnapshot,
  type ServiceTokenProviderOptions,
} from './serviceToken.ts'

export const AUDIENCE = 'cloudsforge'

export type Role = 'player' | 'admin'

export interface UserClaims extends JWTPayload {
  readonly sub: string
  readonly handle: string
  readonly roles: readonly Role[]
}

export interface ServiceClaims extends JWTPayload {
  /** `service:<name>` — e.g. `service:trade`. */
  readonly sub: string
  readonly scopes: readonly string[]
}

export type Principal =
  | { readonly kind: 'user'; readonly userId: string; readonly handle: string; readonly roles: readonly Role[] }
  | { readonly kind: 'service'; readonly service: string; readonly scopes: readonly string[] }

/** The token is bad. Answer 401. */
export class TokenError extends Error {
  readonly code: string
  constructor(message: string, code: string) {
    super(message)
    this.name = 'TokenError'
    this.code = code
  }
}

/** We could not decide. Answer 503, never 401. */
export class VerifierUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VerifierUnavailableError'
  }
}

/** The caller is authenticated but not permitted. Answer 403. */
export class ForbiddenError extends Error {
  readonly required: string
  constructor(required: string) {
    super(`missing required authority: ${required}`)
    this.name = 'ForbiddenError'
    this.required = required
  }
}

/**
 * jose error codes that mean "this token is bad", as opposed to anything else, which means
 * "we could not check". Enumerated rather than inferred, because getting this backwards turns
 * an identity outage into a mass sign-out.
 */
const TOKEN_FAULTS = new Set([
  'ERR_JWT_EXPIRED',
  'ERR_JWT_CLAIM_VALIDATION_FAILED',
  'ERR_JWT_INVALID',
  'ERR_JWS_INVALID',
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  'ERR_JWKS_NO_MATCHING_KEY',
  'ERR_JWK_INVALID',
  'ERR_JOSE_ALG_NOT_ALLOWED',
])

export interface VerifierOptions {
  readonly jwksUrl: string
  readonly issuer: string
  readonly audience?: string
  /** Tolerance for clock skew between services. */
  readonly clockToleranceSec?: number
  /** Test seam. Production uses the remote JWKS with jose's own caching. */
  readonly keySet?: ReturnType<typeof createRemoteJWKSet>
  /**
   * The network this deployment IS — 'mainnet' or 'testnet' — and the reason it matters
   * (micro-org#459 stage 2). Both estates verifying against ONE identity means a token minted
   * for a testnet service would otherwise pass at a mainnet service: receivers gate on SCOPE,
   * not on network, so a testnet compromise could reach mainnet money writes. When this is set
   * and a token carries a `net` claim, they must match.
   *
   * A token WITHOUT the claim is accepted, deliberately: enforcement has to be deployable
   * before every token in flight carries the claim, and a hard requirement here would take both
   * estates down at the moment of upgrade. Once both identities mint the claim everywhere, the
   * tolerance can be revisited — as a decision, not a default.
   */
  readonly expectedNetwork?: string
  /**
   * Called once per token that verified while carrying NO `net` claim.
   *
   * The tolerance above is load-bearing and temporary, and those are hard to hold together: a
   * tolerance nobody measures is one nobody can ever close, because "are there still net-less
   * tokens in flight?" has no answer. This makes it a number. The consolidation closes the window
   * when it reaches zero, which is a fact rather than a date.
   */
  readonly onNetlessToken?: (event: { readonly network: string }) => void
}

/** Per-call overrides. `network` is the one that matters, and it is the whole consolidation. */
export interface VerifyOptions {
  /**
   * The network THIS REQUEST arrived on — from the `CF-Network` header the gateway stamped
   * (`@cloudsforge/http`'s `requestNetwork`).
   *
   * Supplied, it decides the gate and `expectedNetwork` is ignored. That precedence is the point:
   * after the merge one pod serves both networks, so the deployment has no network to be, and a
   * pod still carrying `AUTH_EXPECTED_NETWORK=mainnet` from before the merge must not refuse every
   * testnet request routed to it.
   */
  readonly network?: string
}

export class Verifier {
  readonly #keys: ReturnType<typeof createRemoteJWKSet>
  readonly #issuer: string
  readonly #audience: string
  readonly #clockTolerance: number
  readonly #expectedNetwork: string | null
  readonly #onNetless: ((event: { readonly network: string }) => void) | undefined

  constructor(options: VerifierOptions) {
    this.#keys = options.keySet ?? createRemoteJWKSet(new URL(options.jwksUrl))
    this.#issuer = options.issuer
    this.#audience = options.audience ?? AUDIENCE
    // ── THE ONE ENV READ THIS PACKAGE PERMITS ITSELF, AND WHY ─────────────────────────────────
    //
    // This package otherwise takes everything through options, and that discipline stands. The
    // exception is deliberate and estate-shaped (micro-org#459 stage 2): the network gate has to
    // arrive at ~25 services at once for the shared-identity migration to be safe, and an option
    // means 25 constructor sites edited in step across a release boundary — during which a missed
    // one is a service that silently accepts the other estate's tokens forever. One compose
    // anchor setting AUTH_EXPECTED_NETWORK arms every verifier in the estate in a single deploy,
    // and an explicit option still wins where a caller has an opinion.
    //
    // Safe to arm before any token carries the claim: absent claims are tolerated (see
    // expectedNetwork above), so the gate only ever bites on a token that NAMES the wrong estate.
    this.#expectedNetwork =
      options.expectedNetwork ??
      (typeof process !== 'undefined' ? (process.env['AUTH_EXPECTED_NETWORK'] ?? null) : null) ??
      null
    this.#clockTolerance = options.clockToleranceSec ?? 5
    this.#onNetless = options.onNetlessToken
  }

  async verify(token: string, options: VerifyOptions = {}): Promise<JWTPayload> {
    if (!token) throw new TokenError('no token presented', 'missing')
    try {
      const { payload } = await jwtVerify(token, this.#keys, {
        issuer: this.#issuer,
        audience: this.#audience,
        clockTolerance: this.#clockTolerance,
        algorithms: ['RS256'],
      })
      // ── THE NETWORK GATE ────────────────────────────────────────────────────────────────────
      //
      // AFTER the signature, always: a claim on an unverified token is attacker text.
      //
      // WHAT it compares against moved with the consolidation (micro-deploy
      // `docs/network-consolidation.md`). It used to be "what network is this deployment", which
      // one pod serving both networks cannot answer. It is now "what network did this REQUEST
      // arrive on", and the deployment constant is the fallback for the callers that have not been
      // taught the header yet — which, on the day this ships, is all of them. That fallback is why
      // this change is deployable alone and changes nothing until a caller opts in.
      const expected = options.network ?? this.#expectedNetwork
      if (expected !== null && expected !== undefined) {
        const net = (payload as { net?: unknown }).net
        if (typeof net === 'string') {
          if (net !== expected) {
            throw new TokenError(
              `token minted for network ${net}, this request is ${expected}`,
              'wrong_network',
            )
          }
        } else {
          // See VerifierOptions.onNetlessToken. Reported, never refused — yet.
          this.#onNetless?.({ network: expected })
        }
      }
      return payload
    } catch (err) {
      // The network gate above throws from INSIDE this try. Without this line its refusal would
      // fall through to VerifierUnavailableError below and answer 503 — "try again later" — for a
      // token that must be refused identically on every retry.
      if (err instanceof TokenError) throw err
      const code = (err as { code?: string }).code
      if (code && TOKEN_FAULTS.has(code)) {
        throw new TokenError(messageOf(err), code)
      }
      if (err instanceof joseErrors.JOSEError && TOKEN_FAULTS.has(err.code)) {
        throw new TokenError(err.message, err.code)
      }
      // Network failure, DNS, a 500 from the identity service, a timeout. We do not know whether
      // this token is good, so we must not claim it is bad.
      throw new VerifierUnavailableError(messageOf(err))
    }
  }

  /** Verify and narrow to a principal. Refuses a token that is neither shape. */
  async principal(token: string, options: VerifyOptions = {}): Promise<Principal> {
    // Forwarded, not dropped. `principal()` is the method most routes actually call; a version of
    // it that could not carry the request's network would be a hole straight through the gate,
    // and a silent one — the token would verify and the wrong-network refusal would never run.
    const payload = await this.verify(token, options)
    const sub = payload['sub']
    if (typeof sub !== 'string' || sub.length === 0) {
      throw new TokenError('token has no subject', 'no_subject')
    }

    if (sub.startsWith('service:')) {
      const scopes = payload['scopes']
      if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === 'string')) {
        throw new TokenError('service token has no scopes', 'no_scopes')
      }
      return { kind: 'service', service: sub.slice('service:'.length), scopes: scopes as string[] }
    }

    const handle = payload['handle']
    const roles = payload['roles']
    return {
      kind: 'user',
      userId: sub,
      handle: typeof handle === 'string' ? handle : '',
      roles: Array.isArray(roles) ? (roles.filter((r) => typeof r === 'string') as Role[]) : [],
    }
  }
}

/** Pull a bearer token out of an Authorization header. */
export function bearerFrom(header: string | undefined | null): string | null {
  if (!header) return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  return match?.[1]?.trim() ?? null
}

export function isAdmin(principal: Principal): boolean {
  return principal.kind === 'user' && principal.roles.includes('admin')
}

/**
 * Scope matching, with one level of wildcard: `ledger:*` grants `ledger:post`.
 *
 * Deliberately not a general glob. `*` alone is not a scope, because a credential that grants
 * everything is a credential nobody can reason about — which is precisely the property of the
 * shared `PAY_SERVICE_TOKEN` this replaces.
 */
export function hasScope(principal: Principal, required: string): boolean {
  if (principal.kind !== 'service') return false
  return principal.scopes.some((granted) => {
    if (granted === required) return true
    if (!granted.endsWith(':*')) return false
    const prefix = granted.slice(0, -1)
    return required.startsWith(prefix) && required.length > prefix.length
  })
}

export function requireScope(principal: Principal, required: string): void {
  if (!hasScope(principal, required)) throw new ForbiddenError(required)
}

export function requireAdmin(principal: Principal): void {
  if (!isAdmin(principal)) throw new ForbiddenError('role:admin')
}

/**
 * The user a request acts for.
 *
 * A user token acts for itself. A service token acts for whoever it names — which is the
 * `userId`-as-parameter pattern the estate already relies on, because a settlement running an
 * hour after the user left has no user token to forward. The difference from today is that the
 * caller is now identified and scoped, so the ledger can record *which* service moved the money.
 */
export function subjectUserId(principal: Principal, requestedUserId?: string): string {
  if (principal.kind === 'user') {
    if (requestedUserId && requestedUserId !== principal.userId) {
      throw new ForbiddenError('acting for another user')
    }
    return principal.userId
  }
  if (!requestedUserId) throw new TokenError('service call must name a user', 'no_subject_user')
  return requestedUserId
}

/**
 * Maps an auth failure onto the status code it must produce.
 *
 * `ServiceTokenUnavailableError` is 503 for the same reason `VerifierUnavailableError` is. Inbound,
 * an unreachable JWKS means we cannot decide whether the caller is authentic. Outbound, an
 * unreachable identity means we cannot authenticate ourselves to the peer this request needs. In
 * neither case has anyone presented a bad credential, and answering 401 to either would blame the
 * caller for an outage two services away.
 */
export function statusFor(err: unknown): 401 | 403 | 503 | null {
  if (err instanceof TokenError) return 401
  if (err instanceof ForbiddenError) return 403
  if (err instanceof VerifierUnavailableError) return 503
  if (err instanceof ServiceTokenUnavailableError) return 503
  return null
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
