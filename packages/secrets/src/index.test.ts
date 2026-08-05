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
  assert.throws(() => assertGeneratedSecret('X', generated.replace('+', '_')), /not base64 or hex/)
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
