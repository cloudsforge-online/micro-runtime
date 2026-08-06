/**
 * **The ten-minute cliff, from the client's side.**
 *
 * THE DEFECT THIS FILE EXISTS FOR. Service tokens expire in 600 seconds. Every service read its
 * token once from an environment variable at boot — `const token = () => env.serviceToken` — and
 * nothing re-minted it. The estate worked in every test and for the first ten minutes of every
 * deployment.
 *
 * WHY NO SUITE CAUGHT IT. Every per-service suite mints a fresh token as it starts and finishes
 * well inside ten minutes, so no token was ever asked to survive its own lifetime. **A test that
 * mints a token and immediately uses it proves nothing about this defect.** That is the exact shape
 * that let it through two reviews and twenty-one suites.
 *
 * So the shape below is the other one. `the ten-minute cliff` mints at T+0, moves a simulated clock
 * PAST 600 seconds, asserts the token the provider was holding is now REFUSED BY A REAL VERIFIER,
 * and only then asserts a call still succeeds. It then models the old seam — a provider that
 * returns a static string — and asserts that same call fails, so the test cannot pass for a reason
 * other than the fix.
 *
 * THE CLOCK IS SIMULATED, NOT WAITED ON. `mock.timers` moves `Date` only; jose decides expiry from
 * `Date.now()`, so an eleven-minute jump is indistinguishable to it from eleven real minutes and
 * the suite still runs in milliseconds. `setTimeout` is deliberately NOT mocked — the provider
 * awaits promises that real timers settle, and freezing those would hang the suite rather than
 * test it.
 */

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose'
import { AUDIENCE, Verifier, statusFor } from './index.ts'
import { ServiceTokenProvider, ServiceTokenUnavailableError, serviceTokenProbe } from './serviceToken.ts'

const ISSUER = 'https://identity.test'
const IDENTITY = 'http://identity:4000'
const PEER = 'http://ledger:4000/entries'
const SERVICE = 'wallet'

/** identity/src/tokens.ts. Not a knob — see the header of serviceToken.ts. */
const SERVICE_TTL_SECONDS = 600

/* ── the simulated clock ────────────────────────────────────────────────────────────────────── */

/**
 * A fixed epoch so every test starts from the same instant and jose's `iat` never lands in the
 * past relative to a previous test's mocked `now`.
 */
const T0 = Date.UTC(2026, 7, 3, 12, 0, 0)

/** Move the whole world — the provider's `now` and jose's expiry check — to `T0 + ms`. */
function clockAt(ms: number): void {
  mock.timers.reset()
  mock.timers.enable({ apis: ['Date'], now: new Date(T0 + ms) })
}

/** Every test that moves the clock must put it back, or the next test inherits the future. */
function releaseClock(): void {
  mock.timers.reset()
}

/**
 * Let a background refresh finish. `setImmediate` rather than `setTimeout`, because only `Date` is
 * mocked and a macrotask boundary is all that is needed — the refresh is a promise chain, not a
 * timer.
 */
function settle(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve))
}

/* ── a real identity, and a real peer ───────────────────────────────────────────────────────── */

interface Estate {
  /** `fetch` for the provider: answers the exchange, and proxies everything else to the peer. */
  readonly fetch: typeof globalThis.fetch
  /** How many times the credential has actually been exchanged. */
  exchanges: number
  /** How many requests the peer has seen, and what it decided. */
  peerCalls: Array<{ token: string | null; status: number }>
  /** Set to make identity unreachable. */
  identityDown: boolean
  /** Set to make the peer refuse whatever it is given, however valid. */
  peerRefusesEverything: boolean
  readonly verifier: Verifier
  readonly signToken: (ttlSeconds: number) => Promise<string>
}

async function estate(options: { ttlSeconds?: number } = {}): Promise<Estate> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
  void jwk
  // A local key set standing in for the remote JWKS: jose's remote set is a function of the
  // protected header, so a local resolver has the same shape.
  const keySet = (async () => publicKey) as never
  const verifier = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })

  const ttl = options.ttlSeconds ?? SERVICE_TTL_SECONDS

  /**
   * Signed against the CURRENT simulated instant, exactly as identity would. `iat` and `exp` come
   * from `Date.now()` inside jose, so a token minted after the clock has moved is genuinely a
   * later token — not the same one relabelled.
   *
   * The `jti` is not decoration. RS256 is PKCS#1 v1.5, which is deterministic: two tokens signed
   * from an identical payload at an identical (simulated) instant are the SAME STRING, and the
   * provider's "did the token actually change?" guard would then correctly decline to replay.
   * identity mints a uuidv7 jti per token, so the counter here restores the property the real
   * service has rather than papering over one this test invented.
   */
  let jti = 0
  const signToken = (ttlSeconds: number): Promise<string> =>
    new SignJWT({ typ: 'service', scopes: ['ledger:post', 'ledger:read'], jti: `t-${++jti}` })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject(`service:${SERVICE}`)
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
      .sign(privateKey)

  const self: Estate = {
    exchanges: 0,
    peerCalls: [],
    identityDown: false,
    peerRefusesEverything: false,
    verifier,
    signToken,
    fetch: (async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url

      if (url.startsWith(IDENTITY)) {
        if (self.identityDown) throw new TypeError('fetch failed: ECONNREFUSED')
        const auth = new Headers(init?.headers).get('authorization')
        if (auth !== `Bearer ${CREDENTIAL}`) {
          return new Response('{"error":"unauthenticated"}', { status: 401 })
        }
        self.exchanges += 1
        // identity/src/server.ts — the fields the provider reads.
        return new Response(
          JSON.stringify({
            token: await signToken(ttl),
            service: SERVICE,
            scopes: ['ledger:post', 'ledger:read'],
            expiresIn: ttl,
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        )
      }

      // The peer. It does what every service in the estate does with an inbound bearer: hands it
      // to a real `Verifier` and answers 401 on a token fault. Nothing here knows about expiry
      // directly — jose decides, from the same simulated clock.
      //
      // The cap turns the one regression that would otherwise HANG — replaying through
      // `authorizedFetch` instead of the bare fetch, so every 401 re-mints and replays for ever —
      // into an assertion failure. A guard whose failure mode is a six-hour CI timeout is a guard
      // nobody will read the output of.
      if (self.peerCalls.length > 32) throw new Error('the 401 replay is looping')
      const presented = new Headers(init?.headers).get('authorization')?.replace(/^Bearer /, '') ?? null
      if (self.peerRefusesEverything || presented === null) {
        self.peerCalls.push({ token: presented, status: 401 })
        return new Response('{"error":"unauthenticated"}', { status: 401 })
      }
      try {
        await verifier.principal(presented)
        self.peerCalls.push({ token: presented, status: 200 })
        return new Response('{"ok":true}', { status: 200 })
      } catch {
        self.peerCalls.push({ token: presented, status: 401 })
        return new Response('{"error":"unauthenticated"}', { status: 401 })
      }
    }) as typeof globalThis.fetch,
  }
  return self
}

const CREDENTIAL = 'cfsc_a-long-lived-credential-that-does-not-expire'

/**
 * What `HttpClient` does on every request, in six lines: ask the token supplier, set the header,
 * go through the provider's fetch. Mirrors `@cloudsforge/http` `#attempt` — `headers['authorization']
 * = \`Bearer ${token}\`` then `this.#fetch(url, {...})`. `@cloudsforge/auth` may not depend on
 * `@cloudsforge/http`, so the wiring is reproduced rather than imported; `micro-wallet`'s suite
 * exercises the same provider through the real `HttpClient` against a real `Verifier`.
 */
async function callPeer(
  token: () => Promise<string>,
  doFetch: typeof globalThis.fetch,
  body?: string,
): Promise<number> {
  const bearer = await token()
  const res = await doFetch(PEER, {
    method: 'POST',
    headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
    ...(body !== undefined ? { body } : { body: '{}' }),
  })
  return res.status
}

function providerFor(
  world: Estate,
  overrides: Partial<ConstructorParameters<typeof ServiceTokenProvider>[0]> = {},
): ServiceTokenProvider {
  return new ServiceTokenProvider({
    identityUrl: IDENTITY,
    credential: CREDENTIAL,
    fetch: world.fetch,
    // Deterministic: the jitter band is asserted separately, and a random refresh point would make
    // every other test in this file flaky at the edges.
    random: () => 0.5,
    failureBackoffMs: 0,
    ...overrides,
  })
}

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * THE REGRESSION TEST FOR THE CLIFF.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test('a service still authenticates AFTER the token it booted with has expired — the ten-minute cliff', async (t) => {
  const world = await estate()
  t.after(releaseClock)

  clockAt(0)
  const provider = providerFor(world)

  // T+0. This is the token a container would have been handed at boot, and the moment at which
  // every existing suite in the estate stops looking.
  const atBoot = await provider.token()
  assert.equal(await callPeer(async () => atBoot, world.fetch), 200, 'the boot token works at T+0')

  // T+11min — past the 600s TTL, and the moment the estate used to fall over.
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)

  // FIRST: the cliff itself, reproduced against a real verifier — and this IS the old seam,
  // modelled exactly. `const token = () => env.serviceToken` is a supplier that returns the same
  // string for ever, wired to an ordinary `fetch`. If this ever stops being 401 the TTL has been
  // lengthened, which is the wrong fix and must fail here rather than pass quietly.
  assert.equal(
    await callPeer(async () => atBoot, world.fetch),
    401,
    'the token held at boot MUST be dead by now',
  )

  // SECOND: the fix, in the supplier alone. Plain `fetch`, no 401 replay, nothing to fall back on
  // — so a 200 here can only mean the provider went and got a live token by itself. This is the
  // assertion the old seam fails, and it fails it for the reason the estate fell over.
  assert.equal(
    await callPeer(provider.token, world.fetch),
    200,
    'a service must still authenticate past the first expiry',
  )

  // THIRD: the same again through the whole wiring a service actually uses.
  assert.equal(await callPeer(provider.token, provider.authorizedFetch), 200)

  const afterTheCliff = await provider.token()
  assert.notEqual(afterTheCliff, atBoot, 'a genuinely new token, not the old one')
  assert.equal((await world.verifier.principal(afterTheCliff)).kind, 'service')
})

test('the held token is refreshed BEFORE it expires, so no request ever sees the gap', async (t) => {
  const world = await estate()
  t.after(releaseClock)

  clockAt(0)
  const provider = providerFor(world)
  const atBoot = await provider.token()
  assert.equal(world.exchanges, 1)

  // 70% of the way through. Still inside the [75%, 85%] band, so nothing has happened yet.
  clockAt(SERVICE_TTL_SECONDS * 1000 * 0.7)
  assert.equal(await provider.token(), atBoot, 'not yet due')
  assert.equal(world.exchanges, 1, 'and nothing was exchanged')

  // 80%. The refresh runs BEHIND the request: this call still returns the old — and still valid —
  // token, and pays nothing for the mint.
  clockAt(SERVICE_TTL_SECONDS * 1000 * 0.8)
  assert.equal(await provider.token(), atBoot, 'the caller is not made to wait for the refresh')

  // Let the background exchange settle.
  await new Promise((resolve) => setTimeout(resolve, 5))
  assert.equal(world.exchanges, 2, 'and it happened anyway')
  const refreshed = await provider.token()
  assert.notEqual(refreshed, atBoot)
  // The whole point of 80%: two minutes of slack in which this could have failed and been retried.
  assert.equal(await callPeer(async () => atBoot, world.fetch), 200, 'the old token is still live')
})

test('N replicas waking together do not exchange together — the refresh point is jittered', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  /** Does a replica that booted at T+0 with this draw refresh when asked at `second`? */
  const refreshesAt = async (draw: number, second: number): Promise<boolean> => {
    clockAt(0)
    const provider = providerFor(world, { random: () => draw })
    await provider.token()
    clockAt(second * 1000)
    const before = world.exchanges
    await provider.token()
    await settle()
    return world.exchanges > before
  }

  /**
   * Bisection rather than a walk. The predicate is monotone in time — once a replica is past its
   * refresh point it stays past it — so ten probes find the second exactly, where stepping through
   * six hundred of them took twelve seconds of wall clock for the same answer.
   */
  const firstRefreshSecond = async (draw: number): Promise<number> => {
    let low = 1
    let high = SERVICE_TTL_SECONDS
    assert.equal(await refreshesAt(draw, high), true, `draw ${draw} never refreshes at all`)
    while (low < high) {
      const mid = Math.floor((low + high) / 2)
      if (await refreshesAt(draw, mid)) high = mid
      else low = mid + 1
    }
    return low
  }

  // A deterministic spread standing in for twenty replicas' `Math.random`.
  const refreshPoints: number[] = []
  for (let replica = 0; replica < 20; replica++) {
    refreshPoints.push(await firstRefreshSecond(replica / 20))
  }

  const low = Math.min(...refreshPoints)
  const high = Math.max(...refreshPoints)
  // Inside the band, and strictly before expiry — the slack is the point.
  assert.ok(low >= SERVICE_TTL_SECONDS * 0.75, `earliest refresh ${low}s is below the 75% floor`)
  assert.ok(high <= SERVICE_TTL_SECONDS * 0.85 + 1, `latest refresh ${high}s is above the 85% ceiling`)
  assert.ok(high < SERVICE_TTL_SECONDS, 'a refresh point at or past expiry is not a refresh point')
  // And genuinely spread: this is the assertion that fails if the jitter is ever removed.
  assert.ok(new Set(refreshPoints).size >= 10, `only ${new Set(refreshPoints).size} distinct refresh points`)
  assert.ok(high - low >= 30, `the herd is only spread over ${high - low}s`)
})

test('concurrent callers share one exchange — a cold provider under load does not stampede identity', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  const tokens = await Promise.all(Array.from({ length: 25 }, () => provider.token()))
  assert.equal(world.exchanges, 1, '25 concurrent callers must cause exactly one exchange')
  assert.equal(new Set(tokens).size, 1, 'and they must all get the same token')
})

/* ── the 401 path: correctness that does not depend on clock agreement ───────────────────────── */

test('a 401 re-mints once and replays, so a clock disagreement is not a failed request', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  const stale = await provider.token()

  // The peer's clock is ahead of ours: it has already retired a token our schedule still trusts.
  // Nothing in the provider's timing model can see this, which is why the 401 path exists.
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)
  world.peerCalls.length = 0

  const status = await callPeer(async () => stale, provider.authorizedFetch)
  assert.equal(status, 200, 'the replay must succeed')
  assert.equal(world.peerCalls.length, 2, 'exactly one replay, not a loop')
  assert.equal(world.peerCalls[0]?.status, 401)
  assert.equal(world.peerCalls[1]?.status, 200)
  assert.notEqual(world.peerCalls[1]?.token, stale, 'replayed with a NEW token, not the refused one')
  assert.equal(world.exchanges, 2)
})

test('a peer that refuses everything is not re-minted at for ever', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  world.peerRefusesEverything = true
  world.peerCalls.length = 0

  const status = await callPeer(provider.token, provider.authorizedFetch)
  assert.equal(status, 401, 'the second 401 is returned, not chased')
  assert.equal(world.peerCalls.length, 2, 'one original and one replay — and then it stops')
  // A token a peer refuses twice is a scope or trust problem. Minting a third would turn one
  // misconfiguration into a denial of service on identity.
  assert.ok(world.exchanges <= 2, `${world.exchanges} exchanges for one refused request`)
})

test('ten concurrent 401s cause ONE re-mint, not ten', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  const held = await provider.token()
  const before = world.exchanges

  // A live token that the peer refuses, ten times at once. Without the "was this the token I am
  // holding?" check in `authorizedFetch`, each of the ten would discard and re-mint in turn.
  world.peerRefusesEverything = true
  const statuses = await Promise.all(
    Array.from({ length: 10 }, () => callPeer(async () => held, provider.authorizedFetch)),
  )
  assert.deepEqual(new Set(statuses), new Set([401]))
  assert.equal(world.exchanges - before, 1, 'ten simultaneous 401s must not mint ten tokens')
})

test('a 401 that was not for our token is left alone', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  await provider.token()
  const before = world.exchanges

  // A forwarded user token, say. Re-minting a service token would not help and would hide the
  // real fault.
  const res = await provider.authorizedFetch(PEER, {
    method: 'POST',
    headers: { authorization: 'Bearer a-token-that-is-not-ours' },
    body: '{}',
  })
  assert.equal(res.status, 401)
  assert.equal(world.exchanges, before, 'nothing was re-minted')
})

/* ── an unreachable identity ─────────────────────────────────────────────────────────────────── */

test('an unreachable identity does NOT retract a token we already hold', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  const held = await provider.token()

  world.identityDown = true
  clockAt(SERVICE_TTL_SECONDS * 1000 * 0.8)

  // Past the refresh point, so a background exchange is attempted and fails. The caller must not
  // notice: an identity outage does not invalidate a token identity already signed, and failing
  // here would take the estate down for the fault it is designed to ride out.
  assert.equal(await provider.token(), held, 'the still-valid token is still served')
  await new Promise((resolve) => setTimeout(resolve, 5))
  assert.equal(await provider.token(), held)
  assert.equal(await callPeer(provider.token, world.fetch), 200)
  assert.equal(provider.snapshot().lastFailure !== null, true, 'and the failure is visible')
})

test('an unreachable identity with no usable token fails CLOSED — 503, never 401 and never stale', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world)
  const held = await provider.token()

  world.identityDown = true
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)

  const err = await provider.token().then(
    () => null,
    (e: unknown) => e,
  )
  assert.ok(err instanceof ServiceTokenUnavailableError, `expected the unavailable error, got ${String(err)}`)
  // The whole reason this error exists rather than a bare throw: the estate already answers 503
  // when a verifier is unreachable, because an unreachable verifier must not sign anyone out. An
  // unreachable identity must not make a healthy peer look like it rejected us.
  assert.equal(statusFor(err), 503)

  // And it must not fall back. Sending the expired token, or sending nothing, would each produce a
  // 401 from the peer — which says "your credential is bad" when the truth is "identity is down".
  assert.equal(
    provider.snapshot().hasUsableToken,
    false,
    'the expired token must not be reported as usable',
  )
  assert.equal((err as Error).message.includes(held), false, 'and the token must not reach the message')
  // The dead token is still remembered, and how dead it is, is exactly what an operator needs.
  assert.ok((provider.snapshot().expiresInSeconds ?? 0) < 0)
})

test('a failing identity is not hammered — one attempt in flight, and a floor between attempts', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = providerFor(world, { failureBackoffMs: 30_000 })
  world.identityDown = true

  // Fifty concurrent cold callers.
  const results = await Promise.allSettled(Array.from({ length: 50 }, () => provider.token()))
  assert.equal(results.every((r) => r.status === 'rejected'), true)

  // The dial count is what matters: a service under load must not convert its own outage into a
  // retry storm against the service every other service depends on.
  let dials = 0
  const counting = providerFor(world, {
    failureBackoffMs: 30_000,
    fetch: (async (input, init) => {
      if (String(input).startsWith(IDENTITY)) dials += 1
      return world.fetch(input as never, init as never)
    }) as typeof globalThis.fetch,
  })
  await Promise.allSettled(Array.from({ length: 50 }, () => counting.token()))
  assert.equal(dials, 1, `50 callers caused ${dials} dials at a dead identity`)

  // Still inside the backoff a moment later: the failure is remembered, not re-attempted.
  clockAt(1_000)
  await counting.token().catch(() => {})
  assert.equal(dials, 1, 'the backoff floor was not honoured')

  // Past it, it tries again — a floor, not a circuit that stays open.
  clockAt(31_000)
  world.identityDown = false
  assert.equal(typeof (await counting.token()), 'string')
  assert.equal(dials, 2)
})

/* ── configuration mistakes, caught at the point they are made ───────────────────────────────── */

test('a token where a credential belongs is refused at construction', async () => {
  // This is the pre-fix environment variable. Accepting it would produce a provider that works for
  // exactly ten minutes and then fails in the way this file exists to prevent.
  assert.throws(
    () =>
      new ServiceTokenProvider({
        identityUrl: IDENTITY,
        credential: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjdiNjY1YzczMWNjYWE3OWMifQ.eyJ0eXAi',
      }),
    /begins 'cfsc_'/,
  )
  assert.throws(
    () => new ServiceTokenProvider({ identityUrl: IDENTITY, credential: '' }),
    /IDENTITY_CREDENTIAL/,
  )
})

test('an exchange with no expiresIn is refused rather than given an invented lifetime', async (t) => {
  t.after(releaseClock)
  clockAt(0)
  const provider = new ServiceTokenProvider({
    identityUrl: IDENTITY,
    credential: CREDENTIAL,
    failureBackoffMs: 0,
    fetch: (async () =>
      new Response(JSON.stringify({ token: 'a.b.c', service: SERVICE }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      })) as typeof globalThis.fetch,
  })
  // Guessing a lifetime is how the original defect comes back: guess longer than the truth and
  // every token expires in service, exactly as before.
  await assert.rejects(() => provider.token(), /expiresIn/)
})

test('identity refusing the credential is surfaced, not retried into silence', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const provider = new ServiceTokenProvider({
    identityUrl: IDENTITY,
    credential: 'cfsc_a-revoked-or-unknown-credential',
    fetch: world.fetch,
    failureBackoffMs: 0,
  })
  await assert.rejects(() => provider.token(), ServiceTokenUnavailableError)
  assert.match(provider.snapshot().lastFailure ?? '', /401/)
})

test('a narrower scope set is asked for when the caller knows better', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  let sentBody: string | null = null
  const provider = providerFor(world, {
    scopes: ['ledger:read'],
    fetch: (async (input, init) => {
      if (String(input).endsWith('/service-tokens/exchange')) sentBody = String(init?.body ?? '')
      return world.fetch(input as never, init as never)
    }) as typeof globalThis.fetch,
  })
  await provider.token()
  assert.equal(sentBody, JSON.stringify({ scopes: ['ledger:read'] }))

  // Omitted means the service's whole allowlist — a long-running provider cannot know at boot
  // which of its call sites will be reached.
  let defaultBody: string | null = null
  const wide = providerFor(world, {
    fetch: (async (input, init) => {
      if (String(input).endsWith('/service-tokens/exchange')) defaultBody = String(init?.body ?? '')
      return world.fetch(input as never, init as never)
    }) as typeof globalThis.fetch,
  })
  await wide.token()
  assert.equal(defaultBody, '{}')
})

/* ── the readiness probe ─────────────────────────────────────────────────────────────────────── */

test('the probe fails for a missing credential and only WARNS for an identity outage', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  // A deployment nobody gave a credential to. Deterministic, will not fix itself, so the replica
  // must not take traffic.
  assert.deepEqual(await serviceTokenProbe(null).check(), {
    state: 'fail',
    detail: 'no service credential is configured',
  })

  // Configured but idle: the provider mints on first use, so holding nothing is correct.
  const provider = providerFor(world)
  assert.equal((await serviceTokenProbe(provider).check()).state, 'pass')

  await provider.token()
  assert.equal((await serviceTokenProbe(provider).check()).state, 'pass')

  // Identity is down and the token has expired. This is the case where a `fail` would remove every
  // replica of every service from its balancer at once — a cascade out of one service's bad
  // minute. It warns instead, and says why.
  world.identityDown = true
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)
  await provider.token().catch(() => {})
  const outage = await serviceTokenProbe(provider).check()
  assert.equal(outage.state, 'warn', 'an identity outage must not be a hard readiness failure')
  assert.match(outage.detail ?? '', /no live service token/)
  assert.equal(outage.detail?.includes('cfsc_'), false, 'the credential must not reach an operator-visible detail')
})

test('the credential is sent in the Authorization header and never in the URL', async (t) => {
  const world = await estate()
  t.after(releaseClock)
  clockAt(0)

  const seen: Array<{ url: string; auth: string | null }> = []
  const provider = providerFor(world, {
    fetch: (async (input, init) => {
      seen.push({ url: String(input), auth: new Headers(init?.headers).get('authorization') })
      return world.fetch(input as never, init as never)
    }) as typeof globalThis.fetch,
  })
  await provider.token()

  const exchange = seen.find((s) => s.url.includes('/service-tokens/exchange'))
  assert.ok(exchange)
  assert.equal(exchange.auth, `Bearer ${CREDENTIAL}`)
  // `redactUrl` strips a query from a log line; a proxy access log in front of identity would not.
  assert.equal(exchange.url.includes(CREDENTIAL), false, 'the credential reached the URL')
})
