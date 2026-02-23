/**
 * ZeroID Server — Proof Verification
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Verifies Groth16 proofs using snarkjs.
 */

// @ts-expect-error — snarkjs ESM types
import * as snarkjs from 'snarkjs';
import fs from 'node:fs';

/**
 * Verify a Groth16 proof against a verification key.
 *
 * @param proof - The Groth16 proof object (pi_a, pi_b, pi_c)
 * @param publicSignals - Array of public signal strings
 * @param vkeyPath - Path to the verification_key.json file
 * @returns True if the proof is valid
 */
export async function verifyProof(
  proof: Record<string, unknown>,
  publicSignals: string[],
  vkeyPath: string,
): Promise<boolean> {
  if (!fs.existsSync(vkeyPath)) {
    throw new Error(`Verification key not found: ${vkeyPath}`);
  }

  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
  return snarkjs.groth16.verify(vkey, publicSignals, proof) as Promise<boolean>;
}

/**
 * Verify a proof using an in-memory verification key object.
 */
export async function verifyProofWithKey(
  proof: Record<string, unknown>,
  publicSignals: string[],
  vkey: Record<string, unknown>,
): Promise<boolean> {
  return snarkjs.groth16.verify(vkey, publicSignals, proof) as Promise<boolean>;
}
