/**
 * @zeroid/sdk — Zero-Knowledge KYC SDK
 * © thesecretlab | "Verify the human. Drop the liability."
 */

export { ZeroID } from './client.js';
export { generateProof, verifyProofLocally } from './prover.js';
export { createPasskey, getPasskeyAssertion } from './passkey.js';
export type {
  ProverInputs,
  ProverResult,
  ProverConfig,
} from './prover.js';
export type {
  ZeroIdConfig,
  ProofRequirement,
  ProofRequirementType,
  VerificationRequest,
  Credential,
  Proof,
  PublicSignals,
  VerificationResult,
  VerificationStatus,
  VerificationStatusResponse,
  VerificationLevel,
  KycData,
  PasskeyOptions,
  PasskeyCredential,
} from './types.js';
