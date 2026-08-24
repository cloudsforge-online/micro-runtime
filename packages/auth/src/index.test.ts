import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose'
import {
  AUDIENCE,
  ForbiddenError,
  TokenError,
  Verifier,
  VerifierUnavailableError,
  bearerFrom,
  hasScope,
  isAdmin,
  requireAdmin,
  requireScope,
  statusFor,
  subjectUserId,
  type Principal,
} from './index.ts'

const ISSUER = 'https://nimbus.test'

async function fixtures() {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }

  // A local key set standing in for the remote JWKS. jose's remote set is a function of the
  // protected header, so a local resolver has the same shape.
  const keySet = (async () => publicKey) as never

  const sign = (payload: Record<string, unknown>, opts: { exp?: string; aud?: string; iss?: string } = {}) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuedAt()
      .setIssuer(opts.iss ?? ISSUER)
      .setAudience(opts.aud ?? AUDIENCE)
      .setExpirationTime(opts.exp ?? '15m')
      .sign(privateKey)

  const verifier = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })
  const mainnetVerifier = new Verifier({
    jwksUrl: 'http://unused',
    issuer: ISSUER,
    keySet,
    expectedNetwork: 'mainnet',
  })
  return { sign, verifier, mainnetVerifier, jwk, keySet }
}

test('AUTH_EXPECTED_NETWORK arms the gate without an option, and an explicit option wins', async () => {
  // The one env read the package permits itself — the constructor documents why: the
  // shared-identity migration arms ~25 services with one compose anchor instead of 25 edited
  // constructor sites across a release boundary. Proven here so the fallback can never silently
  // stop working.
  const { sign, keySet } = await fixtures()
  const previous = process.env['AUTH_EXPECTED_NETWORK']
  process.env['AUTH_EXPECTED_NETWORK'] = 'mainnet'
  try {
    const armedByEnv = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })
    const foreign = await sign({ typ: 'service', sub: 'service:pool', scopes: [], net: 'testnet' })
    await assert.rejects(armedByEnv.verify(foreign), (err: unknown) => {
      assert.ok(err instanceof TokenError)
      assert.equal((err as TokenError & { code: string }).code, 'wrong_network')
      return true
    })
    // An explicit option beats the env: a verifier told testnet accepts the testnet token even
    // while the env says mainnet.
    const explicit = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet, expectedNetwork: 'testnet' })
    assert.equal((await explicit.verify(foreign)).sub, 'service:pool')
  } finally {
    if (previous === undefined) delete process.env['AUTH_EXPECTED_NETWORK']
    else process.env['AUTH_EXPECTED_NETWORK'] = previous
  }
})

test('a token minted for the other network is refused — 401, not 503 (micro-org#459)', async () => {
  // Both estates verifying against one identity means scope alone no longer separates them: a
  // testnet service token with ledger:post would pass a mainnet ledger's scope gate. The `net`
  // claim is the separation, and the refusal must be a TOKEN fault — deterministic on every
  // retry — not the "try again later" a 503 promises.
  const { sign, mainnetVerifier } = await fixtures()
  const token = await sign({ typ: 'service', sub: 'service:pool', scopes: ['ledger:post'], net: 'testnet' })
  await assert.rejects(mainnetVerifier.verify(token), (err: unknown) => {
    assert.ok(err instanceof TokenError, `expected TokenError, got ${String(err)}`)
    assert.equal((err as TokenError & { code: string }).code, 'wrong_network')
    return true
  })
})

test('a token WITHOUT the net claim still verifies under an expecting deployment', async () => {
  // Deliberate rollout tolerance: enforcement must be deployable before every token in flight
  // carries the claim, or the upgrade moment takes both estates down. The tolerance is recorded
  // as a decision at VerifierOptions.expectedNetwork.
  const { sign, mainnetVerifier } = await fixtures()
  const token = await sign({ typ: 'service', sub: 'service:pool', scopes: ['ledger:post'] })
  const payload = await mainnetVerifier.verify(token)
  assert.equal(payload.sub, 'service:pool')
})

test('a matching net claim verifies, and a verifier with no expectation ignores the claim', async () => {
  const { sign, verifier, mainnetVerifier } = await fixtures()
  const matching = await sign({ typ: 'user', sub: 'u-9', handle: 'sam', roles: [], net: 'mainnet' })
  assert.equal((await mainnetVerifier.verify(matching)).sub, 'u-9')
  const foreign = await sign({ typ: 'user', sub: 'u-9', handle: 'sam', roles: [], net: 'testnet' })
  // No expectedNetwork: the claim is inert, which is every service before the env lands.
  assert.equal((await verifier.verify(foreign)).sub, 'u-9')
})

test('a valid user token verifies and yields a user principal', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'u-1', handle: 'ash', roles: ['player'] })
  const p = await verifier.principal(token)
  assert.equal(p.kind, 'user')
  assert.equal(p.kind === 'user' && p.userId, 'u-1')
  assert.equal(p.kind === 'user' && p.handle, 'ash')
})

test('an expired token is a token fault — 401, not 503', async () => {
  const { sign, verifier } = await fixtures()
  // Comfortably past the 5s clock tolerance, which exists so services with a little drift do
  // not reject each other's freshly minted tokens.
  const token = await sign({ sub: 'u-1' }, { exp: '-1h' })
  await assert.rejects(() => verifier.verify(token), TokenError)
  await verifier.verify(token).catch((e) => assert.equal(statusFor(e), 401))
})

test('a token one second past expiry is still accepted inside the clock tolerance', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'u-1' }, { exp: '-1s' })
  await verifier.verify(token)
})

test('a wrong audience is refused — one audience for the whole estate', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'u-1' }, { aud: 'someone-else' })
  await assert.rejects(() => verifier.verify(token), TokenError)
})

test('a wrong issuer is refused', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'u-1' }, { iss: 'https://evil.test' })
  await assert.rejects(() => verifier.verify(token), TokenError)
})

test('a token signed by a different key is refused', async () => {
  const { verifier } = await fixtures()
  const other = await generateKeyPair('RS256', { extractable: true })
  const token = await new SignJWT({ sub: 'u-1' })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime('15m')
    .sign(other.privateKey)
  await assert.rejects(() => verifier.verify(token), TokenError)
})

test('THE RULE: an unreachable JWKS is 503, never 401', async () => {
  // Answering 401 here would sign every user in the estate out because the identity service is
  // having a bad minute. Five services currently disagree about this.
  //
  // The token must be well formed, or jose fails parsing before it ever asks for a key — which
  // is genuinely a token fault, and would make this test pass for the wrong reason.
  const { sign } = await fixtures()
  const token = await sign({ sub: 'u-1', handle: 'ash', roles: ['player'] })

  const keySet = (async () => {
    throw new Error('getaddrinfo EAI_AGAIN nimbus')
  }) as never
  const verifier = new Verifier({ jwksUrl: 'http://down', issuer: ISSUER, keySet })

  const err = await verifier.verify(token).catch((e) => e)
  assert.ok(err instanceof VerifierUnavailableError, `got ${err?.constructor?.name}: ${err?.message}`)
  assert.equal(statusFor(err), 503)
})

test('a malformed token is a token fault even while the JWKS is down', async () => {
  const keySet = (async () => {
    throw new Error('getaddrinfo EAI_AGAIN nimbus')
  }) as never
  const verifier = new Verifier({ jwksUrl: 'http://down', issuer: ISSUER, keySet })
  await assert.rejects(() => verifier.verify('not-a-jwt'), TokenError)
})

test('an empty token is refused without reaching the key set', async () => {
  const { verifier } = await fixtures()
  await assert.rejects(() => verifier.verify(''), TokenError)
})

test('a service token yields a service principal with scopes', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'service:trade', scopes: ['ledger:post', 'wallet:read'] })
  const p = await verifier.principal(token)
  assert.equal(p.kind, 'service')
  assert.equal(p.kind === 'service' && p.service, 'trade')
})

test('a service token without scopes is refused', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ sub: 'service:trade' })
  await assert.rejects(() => verifier.principal(token), TokenError)
})

test('a token with no subject is refused', async () => {
  const { sign, verifier } = await fixtures()
  const token = await sign({ handle: 'ash' })
  await assert.rejects(() => verifier.principal(token), TokenError)
})

const svc = (scopes: string[]): Principal => ({ kind: 'service', service: 'trade', scopes })
const usr = (roles: ('player' | 'admin')[]): Principal => ({
  kind: 'user',
  userId: 'u-1',
  handle: 'ash',
  roles,
})

test('scopes match exactly, and one wildcard level', () => {
  assert.equal(hasScope(svc(['ledger:post']), 'ledger:post'), true)
  assert.equal(hasScope(svc(['ledger:post']), 'ledger:read'), false)
  assert.equal(hasScope(svc(['ledger:*']), 'ledger:post'), true)
  assert.equal(hasScope(svc(['ledger:*']), 'wallet:read'), false)
})

test('a bare wildcard grants nothing — an omnipotent credential is the thing being replaced', () => {
  assert.equal(hasScope(svc(['*']), 'ledger:post'), false)
  assert.equal(hasScope(svc([':*']), 'ledger:post'), false)
})

test('a user principal never satisfies a service scope', () => {
  assert.equal(hasScope(usr(['admin']), 'ledger:post'), false)
  assert.throws(() => requireScope(usr(['admin']), 'ledger:post'), ForbiddenError)
})

test('requireAdmin distinguishes role from scope', () => {
  assert.equal(isAdmin(usr(['admin'])), true)
  assert.equal(isAdmin(usr(['player'])), false)
  assert.equal(isAdmin(svc(['ledger:*'])), false, 'a service is not an administrator')
  assert.throws(() => requireAdmin(usr(['player'])), ForbiddenError)
  assert.equal(statusFor(new ForbiddenError('x')), 403)
})

test('a user may only act for itself', () => {
  assert.equal(subjectUserId(usr(['player'])), 'u-1')
  assert.equal(subjectUserId(usr(['player']), 'u-1'), 'u-1')
  assert.throws(() => subjectUserId(usr(['player']), 'u-2'), ForbiddenError)
})

test('a service acts for the user it names, and must name one', () => {
  assert.equal(subjectUserId(svc(['ledger:post']), 'u-9'), 'u-9')
  assert.throws(() => subjectUserId(svc(['ledger:post'])), TokenError)
})

test('bearerFrom parses only a well-formed header', () => {
  assert.equal(bearerFrom('Bearer abc'), 'abc')
  assert.equal(bearerFrom('bearer   abc  '), 'abc')
  assert.equal(bearerFrom('Basic abc'), null)
  assert.equal(bearerFrom(undefined), null)
  assert.equal(bearerFrom(''), null)
})

test('statusFor returns null for an unrelated error, so it is not swallowed', () => {
  assert.equal(statusFor(new Error('database down')), null)
})

/* ── THE GATE MOVES FROM THE DEPLOYMENT TO THE REQUEST ────────────────────────────────────────────
 *
 * `expectedNetwork` asks "what network is this process?" — a question that stops having an answer
 * the moment one pod serves both (micro-deploy `docs/network-consolidation.md`). These tests pin
 * the replacement: `verify(token, { network })` compares the token's `net` against the network the
 * REQUEST arrived on, and the deployment constant survives only as the fallback for services that
 * really are single-network.
 */

test('a per-request network decides the gate, and one verifier serves both', async () => {
  // The consolidation in one test. ONE verifier — the merged pod has only one — refuses the
  // testnet token on a mainnet-routed request and accepts it on a testnet-routed one. Under the
  // old boot-time gate this was two processes.
  const { sign, keySet } = await fixtures()
  const merged = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })
  const testnetToken = await sign({ typ: 'service', sub: 'service:pool', scopes: ['ledger:post'], net: 'testnet' })

  await assert.rejects(merged.verify(testnetToken, { network: 'mainnet' }), (err: unknown) => {
    assert.ok(err instanceof TokenError)
    assert.equal((err as TokenError & { code: string }).code, 'wrong_network')
    return true
  })
  assert.equal((await merged.verify(testnetToken, { network: 'testnet' })).sub, 'service:pool')
})

test('the request network beats the deployment constant, which is only a fallback now', async () => {
  // A merged pod may still carry AUTH_EXPECTED_NETWORK from before the merge. The request must
  // win, or the merge silently refuses every testnet request at a pod whose old env says mainnet.
  const { sign, keySet } = await fixtures()
  const stillSaysMainnet = new Verifier({
    jwksUrl: 'http://unused',
    issuer: ISSUER,
    keySet,
    expectedNetwork: 'mainnet',
  })
  const testnetToken = await sign({ typ: 'user', sub: 'u-9', handle: 'sam', roles: [], net: 'testnet' })
  assert.equal((await stillSaysMainnet.verify(testnetToken, { network: 'testnet' })).sub, 'u-9')
})

test('with no per-request network the deployment constant still gates, unchanged', async () => {
  // Every caller that has not been taught the header yet — which is all of them on the day this
  // ships — keeps exactly today's behaviour. That is what makes this deployable on its own.
  const { sign, mainnetVerifier } = await fixtures()
  const foreign = await sign({ typ: 'service', sub: 'service:pool', scopes: [], net: 'testnet' })
  await assert.rejects(mainnetVerifier.verify(foreign), (err: unknown) => {
    assert.equal((err as TokenError & { code: string }).code, 'wrong_network')
    return true
  })
})

test('a net-less token is tolerated on a request-gated verify, and COUNTED', async () => {
  /*
   * The tolerance has to survive the move — tokens minted before the claim existed are still in
   * flight, and refusing them takes the estate down at the upgrade moment. But a tolerance nobody
   * measures is a tolerance nobody can ever close, so the verifier reports each one. The plan
   * closes the window on that number reaching zero, not on a date.
   */
  const { sign, keySet } = await fixtures()
  const seen: Array<{ network: string }> = []
  const merged = new Verifier({
    jwksUrl: 'http://unused',
    issuer: ISSUER,
    keySet,
    onNetlessToken: (e) => seen.push(e),
  })
  const netless = await sign({ typ: 'service', sub: 'service:pool', scopes: ['ledger:post'] })
  assert.equal((await merged.verify(netless, { network: 'testnet' })).sub, 'service:pool')
  assert.deepEqual(seen, [{ network: 'testnet' }])

  // A token that DOES carry the claim is not counted — the number has to mean "tokens that predate
  // the claim", not "tokens verified".
  const claimed = await sign({ typ: 'service', sub: 'service:pool', scopes: [], net: 'testnet' })
  await merged.verify(claimed, { network: 'testnet' })
  assert.equal(seen.length, 1)
})

test('principal() forwards the request network, so the gate is not bypassed by the common path', async () => {
  // `principal()` is what most routes call. If it could not carry the network, every route using
  // it would verify a foreign token successfully — the gate would exist and never run.
  const { sign, keySet } = await fixtures()
  const merged = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })
  const testnetToken = await sign({ typ: 'user', sub: 'u-9', handle: 'sam', roles: [], net: 'testnet' })
  await assert.rejects(merged.principal(testnetToken, { network: 'mainnet' }), (err: unknown) => {
    assert.equal((err as TokenError & { code: string }).code, 'wrong_network')
    return true
  })
  const ok = await merged.principal(testnetToken, { network: 'testnet' })
  assert.equal(ok.kind === 'user' ? ok.userId : null, 'u-9')
})
