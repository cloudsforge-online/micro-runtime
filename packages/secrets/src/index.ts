/**
 * Is this value a GENERATED secret, or is it something a person typed?
 *
 * ── Why this package exists ────────────────────────────────────────────────────────────────────
 *
 * `OUTBOX_SIGNING_SECRET` is one HMAC key shared by 25 services under 7 different variable names,
 * and it is the only thing standing between an unauthenticated POST and a handler that credits a
 * deposit. It sat in a PUBLIC compose file as the literal `estate-only-outbox-secret-…` on 54
 * lines (micro-org #142), and every guard in the estate passed it.
 *
 * They passed it because each service carries its own private `requiredSecret`, and all of them
 * check the same two things: membership of a fixed deny-list of exact strings, and a length floor
 * of 24 characters. The estate placeholder was 40 characters and on nobody's list, so no check
 * could have failed — which is worse than having no check, because the absence of an alarm was
 * read as the absence of a problem.
 *
 * A deny-list of exact strings cannot work. The next placeholder somebody writes is, by
 * definition, not on it. So this package asserts the SHAPE of a generated value instead, and the
 * shape is what a placeholder cannot have.
 *
 * ── The four checks, and why each one is here ──────────────────────────────────────────────────
 *
 *   1. **The alphabet is base64 or hex, and nothing else.** This is the check that catches every
 *      placeholder this estate has actually written — `estate-only-outbox-secret-…`,
 *      `ci-only-not-a-real-secret-…`, `dev-outbox-signing-secret`, `change-me` — because a human
 *      writing a memorable value reaches for a hyphen or an underscore and neither alphabet
 *      contains one. It costs an operator nothing: `openssl rand -base64 48` is what the runbook
 *      already tells them to run.
 *   2. **It decodes to at least 32 BYTES.** The old floor counted keystrokes. The unit that
 *      matters for an HMAC key is entropy, and 32 characters of prose is not 32 bytes of key.
 *   3. **Its Shannon entropy per character clears a floor**, which is what rejects a value that is
 *      long, well-formed and degenerate — 64 zeros, `deadbeef` eight times, a base64'd placeholder
 *      that happens to repeat. The floors are MEASURED, not guessed: over 200,000 samples the
 *      minimum was 4.292 for `rand -base64 32`, 4.605 for `rand -base64 48` and 3.375 for
 *      `rand -hex 32`. The floors below sit under those with margin, so the chance of refusing a
 *      genuinely generated secret is negligible — which matters, because a guard that occasionally
 *      rejects correct input is a guard somebody removes.
 *   4. **A normalised placeholder MARKER anywhere in the value is refused.** Punctuation and case
 *      are stripped first, so `estate-only`, `ESTATE_ONLY` and `estateonly` are one rule. This is
 *      redundant with (1) for every value seen so far, and it is kept for the value that clears
 *      the alphabet check because it was WRITTEN in that alphabet — `estateonlyOutboxSecret0000…`
 *      has no punctuation to catch it on, and (2) and (3) would pass it at enough length.
 *
 * The floors, the marker list and the ordering are ported from `micro-custody`'s
 * `assertMasterSecret` (`custody/src/env.ts:196-238`), which is the only place in the estate that
 * got this right. Custody's copy predates this package and still holds its own; folding it in is
 * micro-org #143.
 *
 * ── WHAT THIS DOES NOT CATCH, STATED PLAINLY ───────────────────────────────────────────────────
 *
 * A placeholder that has been base64-ENCODED passes. `estate-only-outbox-secret-00000000000000`
 * run through base64 is 56 characters of the base64 alphabet, decodes to 40 bytes, and measures
 * 4.489 bits per character — above the 4.0 floor. MEASURED, not assumed; `index.test.ts` asserts
 * it, so nobody rediscovers it in an incident. Custody's header claims the marker check "still
 * fires the day somebody base64s a placeholder" and that claim is wrong, because base64 destroys
 * the substring the marker matches on.
 *
 * That is accepted rather than fixed. The defect this guard exists to stop is a placeholder TYPED
 * into a compose file by somebody in a hurry, and nobody in a hurry base64s anything. A guard that
 * tried to detect deliberate circumvention would need to decode every candidate under every
 * encoding and re-check, and would then start refusing genuine secrets that happen to decode to
 * printable text — trading a real false-negative nobody has hit for a false-positive that ends
 * with the guard deleted.
 *
 * ── THERE IS NO OFF SWITCH, AND THAT IS THE POINT ──────────────────────────────────────────────
 *
 * No `NODE_ENV` exemption, no `CF_ALLOW_WEAK_SECRET`, no CI branch, no argument that weakens the
 * rule for a caller that says it is only testing. An escape hatch is a comment with a longer name
 * — it would be reached for in exactly the hurry that produced the defect, and every production
 * incident this guard exists to prevent begins with somebody in a hurry. A developer or a CI job
 * that needs a secret runs one command. `index.test.ts` asserts the absence of the hatches
 * somebody would otherwise add.
 *
 * ── THIS GUARD PROVES SHAPE, NOT SECRECY ───────────────────────────────────────────────────────
 *
 * A high-entropy value published in a public repository still passes, and nothing here can know
 * that. Secrecy is the deploy's job and is bought by the value living only in a gitignored file —
 * see `deploy/compose/docker-compose.estate.yml`'s `x-outbox-secret-file` anchor. What this buys
 * is that the value in that file cannot be a placeholder without the service refusing to boot.
 *
 * ── NO MESSAGE BELOW CONTAINS THE VALUE ────────────────────────────────────────────────────────
 *
 * Callers write `err.message` verbatim to stderr and the log collector ships it, so an echoed
 * secret would move from one public place to another. Lengths and measurements only. And every
 * message names the variable AND the command that fixes it, because a refusal an operator cannot
 * act on is an outage rather than a control.
 */

/** Standard base64, padding optional. `-` and `_` are absent on purpose: see check (1) above. */
const BASE64_ONLY = /^[A-Za-z0-9+/]+={0,2}$/
const HEX_ONLY = /^[0-9a-fA-F]+$/

/** Bytes, not characters. `openssl rand -base64 32` and `openssl rand -hex 32` both clear it. */
export const MIN_SECRET_BYTES = 32

/**
 * Shannon entropy floors, per character, per alphabet — because the ceilings differ: 6 bits for
 * base64 and 4 for hex, so one number cannot serve both. See the measured minima in the header.
 */
export const MIN_ENTROPY_BASE64 = 4.0
export const MIN_ENTROPY_HEX = 2.8

/**
 * The exact strings the estate's 25 private `requiredSecret` copies each refused. Kept as a
 * first check purely so the message can say "known placeholder" rather than "not base64" — every
 * one of them is caught by the alphabet check a few lines later anyway. Nothing should ever be
 * ADDED here; adding to a deny-list is the habit this package replaces.
 */
const PLACEHOLDERS = new Set([
  'change-me',
  'change_me',
  'changeme',
  'dev-master-secret',
  'dev-outbox-signing-secret',
  'dev-secret',
  'pepper',
  'placeholder',
  'replace-me',
  'replace-with-a-real-secret',
  'secret',
  'test-master-secret',
  'token',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

/**
 * Placeholder markers, PUNCTUATION AND CASE STRIPPED before matching.
 *
 * Every entry is six characters or more. That is not stylistic: the test is a substring test over
 * a value that may legitimately be random, and a four-letter marker would match a genuine secret
 * about once in seventeen thousand — a boot failure nobody could explain. At six the odds are
 * below one in ten million per marker, and a spurious refusal is one regeneration away in any case.
 *
 * `cionly` is the one entry custody's list does not have. It is here because the value 23 CI
 * workflows used to set was `ci-only-not-a-real-secret-…`, and a marker that names the case this
 * package was written to refuse should say so rather than rely on `notareal` catching it.
 */
const SECRET_MARKERS = [
  'estateonly',
  'testonly',
  'localonly',
  'cionly',
  'changeme',
  'placeholder',
  'notareal',
  'notarealsecret',
  'donotuse',
  'insecure',
  'example',
  'replaceme',
  'temporary',
  'password',
  'mastersecret',
  'sufficientlength',
]

/**
 * Raised when a value is not shaped like a generated secret.
 *
 * A distinct class so a caller can tell configuration from every other failure — and so a caller
 * that re-wraps it into its own `EnvError` can do so without matching on message text. Callers
 * that do not re-wrap lose nothing: their `fatalConfig` handlers read `err.message` off `unknown`.
 */
export class SecretError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SecretError'
  }
}

function normalise(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}

/** Shannon entropy of the value's own character distribution, in bits per character. */
export function entropyPerChar(value: string): number {
  if (value.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) {
    const p = n / value.length
    bits -= p * Math.log2(p)
  }
  return bits
}

/**
 * The one gate every generated secret in the estate passes through.
 *
 * `name` is the variable as the deploy spells it, and it is the whole value of the message: an
 * operator reading the container's last line has to know which of the seven aliases to regenerate.
 *
 * @throws {SecretError} with a message that never contains `value`.
 */
export function assertGeneratedSecret(name: string, value: string): void {
  const fix = 'generate one with: openssl rand -base64 48'

  if (value.length === 0) {
    throw new SecretError(`${name} is empty — ${fix}`)
  }

  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new SecretError(`${name} is set to a known placeholder — ${fix}`)
  }

  const flat = normalise(value)
  for (const marker of SECRET_MARKERS) {
    if (flat.includes(marker)) {
      throw new SecretError(`${name} reads as a placeholder (it contains '${marker}') — ${fix}`)
    }
  }

  const hex = HEX_ONLY.test(value)
  const base64 = !hex && BASE64_ONLY.test(value)
  if (!hex && !base64) {
    // Naming the alphabets rather than the offending character keeps the value out of the message.
    throw new SecretError(
      `${name} is not base64 or hex — a signing key is generated, not typed, and a typed one is ` +
        `readable by whoever reads the file it was typed into. ${fix}`,
    )
  }

  const bytes = hex ? Math.floor(value.length / 2) : Buffer.from(value, 'base64').length
  if (bytes < MIN_SECRET_BYTES) {
    throw new SecretError(
      `${name} carries ${bytes} bytes of key material and at least ${MIN_SECRET_BYTES} are ` +
        `required — length in CHARACTERS is not the unit that matters. ${fix}`,
    )
  }

  const floor = hex ? MIN_ENTROPY_HEX : MIN_ENTROPY_BASE64
  const measured = entropyPerChar(value)
  if (measured < floor) {
    throw new SecretError(
      `${name} is long enough but its entropy is ${measured.toFixed(2)} bits per character, below ` +
        `the ${floor} floor for ${hex ? 'hex' : 'base64'} — a repeated pattern is not a key. ${fix}`,
    )
  }
}

/**
 * Every entry of a rotation list, checked exactly as a single secret is.
 *
 * The list variables (`OUTBOX_ACCEPT_SECRETS`, `ACTIVITY_INGEST_SECRETS`, and the four other
 * ingest aliases) exist so a rotation has an overlap window: receivers hold both the outgoing and
 * incoming key while producers cut over. A list is not a place where the rule relaxes — the
 * OUTGOING key is the one an attacker already has if it leaked, and "just for the drain" is
 * exactly how a placeholder survives a rotation that was supposed to remove it.
 *
 * The index is named in the message and the entry is not. An operator with the file open can count
 * commas; a log collector must not be handed the value.
 *
 * @throws {SecretError} if the list is empty or any entry fails.
 */
export function assertGeneratedSecretList(name: string, values: readonly string[]): void {
  if (values.length === 0) {
    throw new SecretError(`${name} must name at least one secret — generate one with: openssl rand -base64 48`)
  }
  values.forEach((value, index) => {
    assertGeneratedSecret(`${name}[${index}]`, value)
  })
}
