import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import {
  MIN_ENTROPY_BASE64,
  MIN_ENTROPY_HEX,
  MIN_SECRET_BYTES,
  SecretError,
  assertGeneratedSecret,
  assertGeneratedSecretList,
  assertOpaqueSecret,
  assertServiceCredential,
  parseSecretList,
  entropyPerChar,
} from './index.ts'

/**
 * The values that were actually deployed, actually in CI, or actually in a `.env.test` in this
 * estate — not invented ones. Each is a real string this guard has to refuse, and the comment says
 * where it was found, so a future edit that relaxes a floor fails against evidence rather than
 * against taste.
 */
const REAL_DEFECT_VALUES: readonly (readonly [string, string])[] = [
  // micro-org #142: 54 lines of a PUBLIC compose file. 40 chars, so the old 24-char floor passed.
  ['estate-only-outbox-secret-00000000000000', 'the estate placeholder, from the public compose file'],
  // 23 CI workflows' `smoke-env`, all seven aliases.
  ['ci-only-not-a-real-secret-000000000000', 'the CI placeholder'],
  ['ci-only-not-a-real-secret-32-chars-long-0000', 'the longer CI placeholder'],
  ['ci-only-not-a-real-secret-at-least-32-chars-0000', 'the longest CI placeholder'],
  // Per-service `.env.test` files and `testsupport.ts`.
  ['test-outbox-signing-secret-0123456789', 'identity/src/testsupport.ts'],
  ['dev-outbox-signing-secret', 'the deny-lists every service carried'],
  // Degenerate but well-formed: right alphabet, right length, no entropy. Nothing but the floor
  // catches these.
  ['0000000000000000000000000000000000000000000000000000000000000000', '64 zeros'],
  ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'deadbeef eight times'],
  ['ababababababababababababababababababababababababababababababababab', 'two characters, alternating'],
  // Long enough in characters, short in key material. The old floor counted keystrokes.
  ['K2sN4vQ8xR1wB6tY9zL3mF7hC5jD0pA4', 'ledger/.env.test — 32 chars but only 24 bytes'],
]

test('refuses every placeholder this estate actually deployed', () => {
  for (const [value, provenance] of REAL_DEFECT_VALUES) {
    assert.throws(
      () => assertGeneratedSecret('OUTBOX_SIGNING_SECRET', value),
      SecretError,
      `should have refused ${provenance}`,
    )
  }
})

test('no message contains the value, or any run of it', () => {
  // The reason the guard exists is that the value was readable. A refusal that echoes it moves the
  // secret from the compose file to the log collector, which is not an improvement.
  for (const [value] of REAL_DEFECT_VALUES) {
    let message = ''
    try {
      assertGeneratedSecret('OUTBOX_SIGNING_SECRET', value)
      assert.fail('expected a refusal')
    } catch (err) {
      message = (err as Error).message
    }
    assert.ok(!message.includes(value), 'message contained the whole value')
    // Also refuse any 8-character window of it, which is enough to be worth an attacker's time.
    for (let i = 0; i + 8 <= value.length; i += 1) {
      assert.ok(!message.includes(value.slice(i, i + 8)), `message leaked a window at ${i}`)
    }
  }
})

test('every message names the variable and the command that fixes it', () => {
  // A refusal an operator cannot act on is an outage rather than a control.
  for (const [value] of [...REAL_DEFECT_VALUES, ['', 'empty'] as const]) {
    try {
      assertGeneratedSecret('NOTIFY_INGEST_SIGNING_SECRET', value)
      assert.fail('expected a refusal')
    } catch (err) {
      const message = (err as Error).message
      assert.match(message, /NOTIFY_INGEST_SIGNING_SECRET/)
      assert.match(message, /openssl rand -base64 48/)
    }
  }
})

test('accepts what openssl actually generates, over enough samples to mean something', () => {
  // The floors are only worth having if they never fire on correct input: a guard that rejects a
  // genuine secret once a month is a guard somebody deletes. 20,000 samples of each shape.
  for (let i = 0; i < 20_000; i += 1) {
    assertGeneratedSecret('OUTBOX_SIGNING_SECRET', randomBytes(48).toString('base64'))
    assertGeneratedSecret('OUTBOX_SIGNING_SECRET', randomBytes(32).toString('base64'))
    assertGeneratedSecret('OUTBOX_SIGNING_SECRET', randomBytes(32).toString('hex'))
  }
})

test('accepts the shape the estate is actually running', () => {
  // Measured on 2026-08-05 from the running containers, both networks: 64 characters, base64, 48
  // bytes, 5.27 bits per character. Asserted as a shape rather than a value so this test can live
  // in a public repository.
  const live = randomBytes(48).toString('base64')
  assert.equal(live.length, 64)
  assert.ok(entropyPerChar(live) > 5.0)
  assertGeneratedSecret('OUTBOX_SIGNING_SECRET', live)
})

test('the byte floor counts key material, not keystrokes', () => {
  // 43 base64 characters is 32 bytes; 42 is 31 and must fail however random it looks.
  const thirtyOne = randomBytes(31).toString('base64').replace(/=+$/, '')
  assert.throws(() => assertGeneratedSecret('X', thirtyOne), /31 bytes of key material/)
  assertGeneratedSecret('X', randomBytes(MIN_SECRET_BYTES).toString('base64'))
})

test('the alphabet check is what catches a typed value', () => {
  // Every placeholder the estate wrote contained a hyphen or an underscore. Neither alphabet does.
  const generated = randomBytes(48).toString('base64')
  assert.throws(() => assertGeneratedSecret('X', `${generated}-x`), /not base64 or hex/)

  // THIS ASSERTION USED TO BE `generated.replace('+', '_')`, AND IT FAILED 36% OF RUNS.
  //
  // `String.prototype.replace` with a string pattern replaces the FIRST match only — and a 64-char
  // base64 string contains no `+` at all 36.1% of the time (measured, 20,000 samples). On those
  // runs the replace was a no-op, the value stayed valid base64, and the guard correctly did not
  // throw, so the TEST failed. The guard was never wrong; the test was.
  //
  // That matters more than a flake usually would. This is the suite that defends the secret guard
  // for the whole estate, and a suite that is red one run in three is a suite whose red is read as
  // noise and re-run. Substituting into a FIXED position removes the randomness from the assertion
  // while leaving the value itself random.
  assert.throws(() => assertGeneratedSecret('X', `_${generated.slice(1)}`), /not base64 or hex/)
  assert.throws(() => assertGeneratedSecret('X', `${generated.slice(0, -1)}-`), /not base64 or hex/)
})

test('markers are matched with punctuation and case stripped', () => {
  // One rule for `estate-only`, `ESTATE_ONLY` and `estateonly`.
  for (const spelling of ['estate-only', 'ESTATE_ONLY', 'EsTaTe.OnLy']) {
    const value = `${spelling}${randomBytes(48).toString('base64')}`
    assert.throws(() => assertGeneratedSecret('X', value), /reads as a placeholder/)
  }
})

test('a marker written in the base64 alphabet is refused — the case the marker list is for', () => {
  // No punctuation, so the alphabet check passes it; long enough that the byte and entropy floors
  // pass it too. Only the marker catches it.
  const value = `estateonlyOutboxSecret${randomBytes(32).toString('base64').replace(/[+/=]/g, 'A')}`
  assert.match(value, /^[A-Za-z0-9+/]+={0,2}$/)
  assert.throws(() => assertGeneratedSecret('X', value), /reads as a placeholder/)
})

test('a base64-ENCODED placeholder passes, and that is a known and measured limit', () => {
  // Documented in the header under "what this does not catch". Asserted here so the limit is a
  // recorded fact rather than something rediscovered during an incident: base64 destroys the
  // substring the marker check matches on, and what comes out clears every remaining floor.
  const wrapped = Buffer.from('estate-only-outbox-secret-00000000000000').toString('base64')
  assert.match(wrapped, /^[A-Za-z0-9+/]+={0,2}$/)
  assert.equal(Buffer.from(wrapped, 'base64').length, 40)
  assert.ok(entropyPerChar(wrapped) > MIN_ENTROPY_BASE64)
  assert.doesNotThrow(() => assertGeneratedSecret('X', wrapped))
})

test('entropy floors sit below the measured minima for real generators', () => {
  assert.ok(MIN_ENTROPY_BASE64 < 4.292, 'base64 floor must sit under the measured rand -base64 32 minimum')
  assert.ok(MIN_ENTROPY_HEX < 3.375, 'hex floor must sit under the measured rand -hex 32 minimum')
})

test('every entry of a rotation list is checked, and an empty list is refused', () => {
  const a = randomBytes(48).toString('base64')
  const b = randomBytes(48).toString('base64')
  assertGeneratedSecretList('OUTBOX_ACCEPT_SECRETS', [a, b])
  assert.throws(() => assertGeneratedSecretList('OUTBOX_ACCEPT_SECRETS', []), /at least one secret/)
  // The OUTGOING key in an overlap window is the one that leaked. It does not get a pass.
  assert.throws(
    () => assertGeneratedSecretList('OUTBOX_ACCEPT_SECRETS', [a, 'estate-only-outbox-secret-00000000000000']),
    /OUTBOX_ACCEPT_SECRETS\[1\]/,
  )
})

test('there is no off switch', () => {
  // The hatches somebody would add under time pressure. `assertGeneratedSecret` takes two
  // arguments and reads no environment, and this test is what keeps it that way.
  assert.equal(assertGeneratedSecret.length, 2)

  const placeholder = 'estate-only-outbox-secret-00000000000000'
  for (const value of ['development', 'test', 'ci', 'local', 'production', undefined]) {
    const before = process.env['NODE_ENV']
    if (value === undefined) delete process.env['NODE_ENV']
    else process.env['NODE_ENV'] = value
    try {
      assert.throws(() => assertGeneratedSecret('OUTBOX_SIGNING_SECRET', placeholder), SecretError)
    } finally {
      if (before === undefined) delete process.env['NODE_ENV']
      else process.env['NODE_ENV'] = before
    }
  }

  // And no escape hatch is read anywhere in the CODE. Comments are stripped first: the header
  // discusses `NODE_ENV` at length in order to say the guard does not have one, and a test that
  // failed on the discussion would push the reasoning out of the file.
  const code = readFileSync(new URL('./index.ts', import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '')
  assert.ok(!/process\.env/.test(code), 'the guard must not read the environment at all')
  for (const hatch of [/NODE_ENV/, /ALLOW_WEAK/, /SKIP_SECRET/, /INSECURE_OK/, /\bif\s*\(\s*ci\b/i]) {
    assert.ok(!hatch.test(code), `code mentions ${String(hatch)}`)
  }
})

test('entropyPerChar is the textbook definition', () => {
  assert.equal(entropyPerChar(''), 0)
  assert.equal(entropyPerChar('aaaa'), 0)
  assert.equal(entropyPerChar('ab'), 1)
  assert.equal(entropyPerChar('abcd'), 2)
})

/**
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 * SERVICE CREDENTIALS — the class `assertGeneratedSecret` would have killed
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * The two shapes MEASURED on the running estates on 2026-08-05. Both are 43-character base64url
 * bodies; the testnet one contains a hyphen and the mainnet one does not.
 *
 * The hyphenated fixture is the point of this constant. Every instinct in review says a secret has
 * no hyphens — every placeholder this estate ever wrote had one — and a guard written on that
 * instinct passes mainnet and kills testnet at boot. With this fixture pinned, that guard fails CI
 * instead. It is deliberately NOT a randomly generated value: a random base64url body contains a
 * hyphen only about nine times in ten, and a test that catches the regression nine runs out of ten
 * is a test that lets it through on the run that matters.
 */
const MAINNET_CREDENTIAL = 'cfsc_' + 'qN8xKvR2mT7bY4wL9pF3hJ6dS1gZ5cA0eU8iO2nQ7rV'
const TESTNET_CREDENTIAL = 'cfsc_' + 'qN8xKvR2mT7bY4wL9pF3hJ6dS1gZ5cA0eU8iO2n-7rV'

test('a service credential is accepted on BOTH estates, hyphen and all', () => {
  assert.doesNotThrow(() => assertServiceCredential('LEDGER_IDENTITY_CREDENTIAL', MAINNET_CREDENTIAL))

  // THE REGRESSION THIS FILE EXISTS FOR. A "no hyphens" rule passes the line above and fails here.
  assert.ok(TESTNET_CREDENTIAL.includes('-'), 'the testnet fixture must actually contain a hyphen')
  assert.doesNotThrow(() => assertServiceCredential('LEDGER_IDENTITY_CREDENTIAL', TESTNET_CREDENTIAL))
})

test('the generated-secret guard would refuse every credential the estate has ever minted', () => {
  // Not a curiosity — this is why `assertServiceCredential` exists rather than one shared rule.
  // If this ever stops throwing, the two guards have converged and one of them is now wrong.
  for (const credential of [MAINNET_CREDENTIAL, TESTNET_CREDENTIAL]) {
    assert.throws(() => assertGeneratedSecret('LEDGER_IDENTITY_CREDENTIAL', credential), SecretError)
  }
})

test('a credential guard refuses a JWT by name — micro-org #197 and #222', () => {
  // Shape only. The real ones measured live were 669-805 bytes and all expired 26 hours before
  // this was written, on containers reporting healthy.
  const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlOmxlZGdlciIsImV4cCI6MX0.c2ln'
  assert.throws(
    () => assertServiceCredential('ADMIN_API_SERVICE_TOKEN', jwt),
    (err: unknown) => err instanceof SecretError && /TOKEN, not a credential/.test(err.message),
  )
})

test('a credential guard refuses placeholders, prefixless values and short bodies', () => {
  for (const [value, why] of REAL_DEFECT_VALUES) {
    assert.throws(() => assertServiceCredential('LEDGER_IDENTITY_CREDENTIAL', value), SecretError, why)
  }
  // Right prefix, body too short to carry 32 bytes: 32 base64url chars is 24 bytes.
  assert.throws(() => assertServiceCredential('X', 'cfsc_' + 'a'.repeat(32)), SecretError)
  // Right prefix, right length, no entropy — the degenerate case a length check cannot see.
  assert.throws(() => assertServiceCredential('X', 'cfsc_' + 'a'.repeat(43)), SecretError)
  assert.throws(() => assertServiceCredential('X', ''), SecretError)
})

/**
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 * OPAQUE THIRD-PARTY SECRETS — and the four #142 placeholders still live when this was written
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * Read out of `deploy/compose/docker-compose.estate.yml` on 2026-08-05 and confirmed with
 * `printenv` inside the running containers on BOTH estates. Three of the four are hardcoded
 * literals in the compose file rather than variable defaults, so no deploy could ever have
 * overridden them. This is micro-org #142 — the defect that started all of this — still live.
 */
const LIVE_PLACEHOLDER_TOKENS: readonly (readonly [string, string])[] = [
  ['BEACON_TOKEN', 'estate-only-beacon-breakglass-000000000'],
  ['FAUCET_TOKEN', 'estate-only-faucet-operator-token-00000'],
  ['LANTERN_TOKEN', 'estate-only-lantern-token-000000000000'],
  ['ANALYTICS_TOKEN', 'estate-placeholder-token-0000000000000000'],
]

test('the opaque guard refuses all four placeholders that were live on both estates', () => {
  for (const [name, value] of LIVE_PLACEHOLDER_TOKENS) {
    assert.throws(
      () => assertOpaqueSecret(name, value),
      (err: unknown) => err instanceof SecretError && !err.message.includes(value),
      `${name} must be refused, and the message must not carry the value`,
    )
  }
})

test('the opaque guard accepts a vendor secret whose alphabet the estate does not control', () => {
  // The whole reason this is not `assertGeneratedSecret`. An SMTP provider is entitled to issue a
  // password with punctuation in it, and refusing a working credential is how a guard gets deleted.
  // NONE of these may imitate a real provider's key format. An earlier draft used an
  // `sk_live_…` fixture and GitHub push protection correctly blocked the push as a Stripe live
  // key — a fake credential shaped like a real provider's is a fake credential that gets reported,
  // rotated and chased. It was doubly wrong here: this estate is crypto-native and has no Stripe.
  for (const vendor of [
    'S3cure!Smtp#Pass_2026$xyzQ',     // notify's SMTP password shape
    'rpc-user:9f3Kd0!vLmZ2qWxE7tBn', // a chain node's RPC password
    'vendor.key.7Yq!2Lm@4Xd~9Rb^3Tz', // a vendor API key, punctuation and all
  ]) {
    assert.doesNotThrow(() => assertOpaqueSecret('THIRD_PARTY_SECRET', vendor))
    // ...and each of these WOULD have been refused by the generated-key rule. That is the bug this
    // class prevents: a correct value refused at boot on both estates.
    assert.throws(() => assertGeneratedSecret('THIRD_PARTY_SECRET', vendor), SecretError)
  }
})

test('the opaque guard still refuses empty, short, degenerate and JWT values', () => {
  assert.throws(() => assertOpaqueSecret('X', ''), SecretError)
  assert.throws(() => assertOpaqueSecret('X', 'short!'), SecretError)
  assert.throws(() => assertOpaqueSecret('X', '0'.repeat(40)), SecretError)
  assert.throws(
    () => assertOpaqueSecret('X', 'eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.c2ln'),
    (err: unknown) => err instanceof SecretError && /#222/.test(err.message),
  )
})

/**
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 * ROTATION LISTS
 * ═══════════════════════════════════════════════════════════════════════════════════════════════
 */

test('parseSecretList splits, trims, freezes and refuses a duplicate', () => {
  const a = randomBytes(48).toString('base64')
  const b = randomBytes(48).toString('base64')

  const parsed = parseSecretList('OUTBOX_ACCEPT_SECRETS', ` ${a} , ${b} `)
  assert.deepEqual([...parsed], [a, b])
  assert.ok(Object.isFrozen(parsed))

  // A duplicate makes "which key verified this" ambiguous, which is the answer that tells an
  // operator a rotation has finished and the outgoing key may be dropped.
  assert.throws(() => parseSecretList('OUTBOX_ACCEPT_SECRETS', `${a},${a}`), SecretError)

  // Absence and an all-whitespace value are both an EMPTY list, not a list with one bad entry.
  assert.throws(() => parseSecretList('OUTBOX_ACCEPT_SECRETS', ''), SecretError)
  assert.throws(() => parseSecretList('OUTBOX_ACCEPT_SECRETS', ' , , '), SecretError)
})

test('a rotation list applies the full rule to the OUTGOING key too', () => {
  // "Just for the drain" is exactly how a placeholder survives the rotation meant to remove it.
  const good = randomBytes(48).toString('base64')
  assert.throws(
    () => parseSecretList('OUTBOX_ACCEPT_SECRETS', `${good},estate-only-outbox-secret-00000000000000`),
    (err: unknown) => err instanceof SecretError && /\[1\]/.test(err.message),
    'the message must name the INDEX, and must not carry the entry',
  )
})
