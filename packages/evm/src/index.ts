/**
 * The EVM primitives shared by every service that turns bytes into an address or a payment id.
 *
 * Deliberately small. This package is not "everything EVM" — `evm.ts`, `chains.ts` and the
 * contract bytecode stay in the services that deploy and broadcast, because those differ per
 * product in ways that matter (gas floors, kill switches, allowlists). What lives here is the
 * part where differing at all is the defect: the permutation underneath addresses, transaction
 * ids and signature recovery.
 *
 * See `keccak.ts` for the measurement that justified extracting it.
 */
export { keccak256, keccak256Hex, sha3_256 } from './keccak.ts'
export { toChecksumAddress } from './addresses.ts'
