/**
 * ZeroID SDK — Browser-Side Proof Generator
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Generates Groth16 proofs in the browser using snarkjs WASM.
 * Private inputs never leave the user's device.
 */

// @ts-expect-error — snarkjs has no proper ESM types
import * as snarkjs from 'snarkjs';
import type { Proof } from './types.js';

/** Private inputs for proof generation */
export interface ProverInputs {
  /** User's age (private) */
  userAge: number;
  /** User's country code — ISO 3166-1 numeric (private) */
  userCountry: number;
  /** User's secret commitment (private) */
  userSecret: string;
  /** EdDSA signature R8 point from credential (private) */
  issuerSignatureR8: [string, string];
  /** EdDSA signature scalar S from credential (private) */
  issuerSignatureS: string;
  /** Issuer public key (public) */
  issuerPubKey: [string, string];
  /** Required age threshold (public) */
  requiredAge: number;
  /** Restricted country code (public) */
  restrictedCountryCode: number;
  /** Application ID for sybil nullifier (public) */
  appId: string;
}

/** Result of proof generation */
export interface ProverResult {
  proof: Proof;
  publicSignals: string[];
}

/** Configuration for the prover */
export interface ProverConfig {
  /** URL or path to the circuit WASM file */
  wasmUrl: string;
  /** URL or path to the final zkey file */
  zkeyUrl: string;
}

/**
 * Generate a Groth16 proof in the browser.
 *
 * @param config - URLs for WASM and zkey files
 * @param inputs - Private and public inputs for the circuit
 * @returns The proof and public signals
 *
 * @example
 * ```ts
 * const { proof, publicSignals } = await generateProof(
 *   {
 *     wasmUrl: '/circuits/kyc_verifier.wasm',
 *     zkeyUrl: '/circuits/kyc_verifier_final.zkey',
 *   },
 *   {
 *     userAge: 25,
 *     userCountry: 840,
 *     userSecret: '123456789...',
 *     issuerSignatureR8: ['0x...', '0x...'],
 *     issuerSignatureS: '0x...',
 *     issuerPubKey: ['0x...', '0x...'],
 *     requiredAge: 18,
 *     restrictedCountryCode: 408,
 *     appId: '1',
 *   },
 * );
 * ```
 */
export async function generateProof(
  config: ProverConfig,
  inputs: ProverInputs,
): Promise<ProverResult> {
  // Build the circuit input object matching the circom signal names
  const circuitInputs = {
    // Public inputs
    issuerPubKey: inputs.issuerPubKey,
    requiredAge: inputs.requiredAge,
    restrictedCountryCode: inputs.restrictedCountryCode,
    appId: inputs.appId,
    // Private inputs
    userAge: inputs.userAge,
    userCountry: inputs.userCountry,
    userSecret: inputs.userSecret,
    issuerSignatureR8: inputs.issuerSignatureR8,
    issuerSignatureS: inputs.issuerSignatureS,
  };

  // Load WASM and zkey, then compute the full Groth16 proof
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    config.wasmUrl,
    config.zkeyUrl,
  );

  return {
    proof: proof as Proof,
    publicSignals: publicSignals as string[],
  };
}

/**
 * Verify a Groth16 proof locally (useful for testing).
 * In production, verification happens on-chain or server-side.
 */
export async function verifyProofLocally(
  verificationKeyUrl: string,
  proof: Proof,
  publicSignals: string[],
): Promise<boolean> {
  const vkeyResponse = await fetch(verificationKeyUrl);
  const vkey = await vkeyResponse.json();
  return snarkjs.groth16.verify(vkey, publicSignals, proof) as Promise<boolean>;
}
