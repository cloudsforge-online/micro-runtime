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
  return { sign, verifier, jwk }
}

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
