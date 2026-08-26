/**
 * EIP-55, the only typo protection a 20-byte EVM address has.
 *
 * Kept beside `keccak.ts` rather than in a service, because it is the checksum every service
 * validates a withdrawal destination against and they must all compute it the same way. Five
 * services carried a byte-identical copy of this function until 2026-08-26 — `faucet`,
 * `foresight`, `mint`, `settlement` and `wallet` — inside five differently-shaped files
 * (`address.ts`, `evm.ts`, `addresses.ts`), which is why the duplication was easy to miss: the
 * FILES all differ, and only the function is the same.
 *
 * ## WHAT IS DELIBERATELY NOT HERE
 *
 * `wallet/src/addresses.ts` is 657 lines and this package takes eleven of them. The rest —
 * `canonicaliseAddress`, `bitcoinFamilyParams`, the chain registry, the asset mapping — is
 * genuinely per-service knowledge about which chains that service supports, and hoisting it
 * would make every service depend on every chain's rules. What belongs in a shared package is
 * the part where disagreeing is the defect, not the part where differing is the design.
 *
 * `hearth-wallet-core` has its own, longer implementation and keeps it: it is a client-side
 * package published to browsers and extensions rather than an estate service, and it should not
 * take a server-side dependency to check a checksum.
 */
import { keccak256 } from './keccak.ts'

/**
 * EIP-55 checksum encoding.
 *
 * The hex digits of the lower-cased address are upper-cased where the corresponding nibble of
 * `keccak256(lowercase address without 0x)` is 8 or above. That is the entire specification, and it
 * is the only typo protection a 20-byte EVM address has.
 */
export function toChecksumAddress(address: string): string {
  const lower = address.toLowerCase().replace(/^0x/, '')
  const hash = Buffer.from(keccak256(Buffer.from(lower, 'ascii'))).toString('hex')
  let out = '0x'
  for (let i = 0; i < lower.length; i++) {
    const character = lower[i]!
    // Digits have no case, so only letters are touched.
    out += Number.parseInt(hash[i]!, 16) >= 8 ? character.toUpperCase() : character
  }
  return out
}
