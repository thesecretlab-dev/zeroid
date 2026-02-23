/**
 * ZeroID Server — Poseidon Hash Utilities
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Wraps circomlibjs Poseidon for credential hashing.
 */

// @ts-expect-error — circomlibjs lacks proper type declarations
import { buildPoseidon } from 'circomlibjs';

let poseidonInstance: any = null;

/** Lazily initialize the Poseidon hasher */
async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Compute Poseidon hash of arbitrary inputs.
 * Returns the hash as a bigint.
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs.map((i) => poseidon.F.e(i)));
  return poseidon.F.toObject(hash);
}

/**
 * Hash a credential: Poseidon(age, country, secret).
 * This matches the circuit's credential hash computation.
 *
 * @param age - User's age as integer
 * @param country - ISO 3166-1 numeric country code
 * @param secret - User's secret commitment (bigint)
 * @returns Credential hash as bigint
 */
export async function hashCredential(
  age: number,
  country: number,
  secret: bigint,
): Promise<bigint> {
  return poseidonHash([BigInt(age), BigInt(country), secret]);
}
