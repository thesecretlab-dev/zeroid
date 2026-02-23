/**
 * ZeroID SDK — Type Definitions
 * © thesecretlab | "Verify the human. Drop the liability."
 */

/** SDK configuration */
export interface ZeroIdConfig {
  /** API key for authentication */
  apiKey: string;
  /** Base URL for the ZeroID API (default: https://api.zeroid.io) */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
}

/** Types of proof requirements */
export type ProofRequirementType =
  | 'age_gte'
  | 'country_not'
  | 'sanctions_clear'
  | 'sybil_unique';

/** A single proof requirement */
export interface ProofRequirement {
  type: ProofRequirementType;
  /** Requirement value — age threshold, country code, or app ID */
  value: number;
}

/** Request to start a verification */
export interface VerificationRequest {
  /** Unique user identifier */
  userId: string;
  /** List of proof requirements to satisfy */
  requirements: ProofRequirement[];
}

/**
 * Verification level — progressive disclosure model.
 * Users start at level 0 and unlock higher levels only when an app requires it.
 *
 * | Level | What's Proven                                      | Use Case                     |
 * |-------|-----------------------------------------------------|------------------------------|
 * | 0     | Unique human (sybil-resistant)                      | Social media, voting         |
 * | 1     | Age ≥ threshold                                     | Gaming, content              |
 * | 2     | Age + Country                                       | Financial lite               |
 * | 3     | Full KYC (age + country + sanctions + liveness)      | Banking, exchanges           |
 * | 4     | Accredited investor                                 | Securities, private sales    |
 */
export type VerificationLevel = 0 | 1 | 2 | 3 | 4;

/** Signed credential issued by ZeroID after KYC.
 *
 * PRIVACY: This credential is stored ONLY on the user's device (secure enclave).
 * It contains a Poseidon hash of the user's attributes — NOT the attributes themselves.
 * The raw data was processed transiently and wiped after credential issuance.
 * No plaintext PII is stored on any server.
 */
export interface Credential {
  /** Unique credential identifier */
  id: string;
  /** Poseidon hash of (age, country, secret) — this is NOT the raw data */
  credentialHash: string;
  /** EdDSA signature R8 point [x, y] */
  signatureR8: [string, string];
  /** EdDSA signature scalar S */
  signatureS: string;
  /** Issuer public key [x, y] */
  issuerPubKey: [string, string];
  /** ERC-4337 smart account address this credential is bound to (if applicable) */
  boundAddress?: string;
  /** Verification level achieved */
  level: VerificationLevel;
  /** Unix timestamp of issuance */
  issuedAt: number;
  /** Expiration timestamp */
  expiresAt: number;
}

/** Groth16 proof */
export interface Proof {
  /** Proof point A [x, y] */
  pi_a: [string, string, string];
  /** Proof point B [[x0, x1], [y0, y1], [1, 0]] */
  pi_b: [[string, string], [string, string], [string, string]];
  /** Proof point C [x, y] */
  pi_c: [string, string, string];
  /** Protocol identifier */
  protocol: 'groth16';
  /** Curve identifier */
  curve: 'bn128';
}

/** Public signals output from proof generation */
export interface PublicSignals {
  /** Issuer public key components */
  issuerPubKey: [string, string];
  /** Required age threshold */
  requiredAge: string;
  /** Restricted country code */
  restrictedCountryCode: string;
  /** Application ID */
  appId: string;
  /** Sybil nullifier */
  nullifier: string;
  /** Credential hash */
  credentialHash: string;
}

/** Result of a proof verification */
export interface VerificationResult {
  /** Whether the proof is valid */
  valid: boolean;
  /** The nullifier from the proof (for dedup tracking) */
  nullifier: string;
  /** Error message if verification failed */
  error?: string;
}

/** Status of an ongoing verification process */
export type VerificationStatus =
  | 'pending'
  | 'kyc_processing'
  | 'credential_issued'
  | 'proof_generating'
  | 'proof_ready'
  | 'verified'
  | 'failed';

/** Verification status response */
export interface VerificationStatusResponse {
  /** Verification ID */
  id: string;
  /** Current status */
  status: VerificationStatus;
  /** Credential (available after KYC passes) */
  credential?: Credential;
  /** Proof (available after generation) */
  proof?: Proof;
  /** Public signals */
  publicSignals?: string[];
  /** Error message if failed */
  error?: string;
}

/** KYC data submitted for credential issuance.
 *
 * PRIVACY: This data is processed transiently on the server.
 * It is hashed (Poseidon), signed (EdDSA), encrypted to escrow (AES-256-GCM),
 * then WIPED from memory. The server never persists plaintext PII.
 */
export interface KycData {
  /** User's date of birth (ISO 8601) */
  dateOfBirth: string;
  /** ISO 3166-1 numeric country code */
  countryCode: number;
  /** Document type used for verification */
  documentType: 'passport' | 'drivers_license' | 'national_id';
  /** Document number (encrypted, never stored in plaintext) */
  documentNumber: string;
  /** Full legal name */
  fullName: string;
  /** ERC-4337 smart account address to bind the credential to */
  boundAddress?: string;
  /** Requested verification level */
  level?: VerificationLevel;
}

/**
 * WebAuthn passkey registration options.
 * The passkey becomes the owner of the user's ERC-4337 smart account,
 * while the ZeroID credential becomes the identity proof.
 */
export interface PasskeyOptions {
  /** Relying party name (displayed to user) */
  rpName: string;
  /** Relying party ID (domain) */
  rpId: string;
  /** User display name */
  userName: string;
  /** Challenge from the server (base64url) */
  challenge: string;
  /** Timeout in milliseconds */
  timeout?: number;
}

/** Result of passkey registration */
export interface PasskeyCredential {
  /** Credential ID (base64url) */
  credentialId: string;
  /** Public key (COSE, base64url) */
  publicKey: string;
  /** Attestation object (base64url) */
  attestation: string;
  /** Algorithm used (typically -7 for ES256) */
  algorithm: number;
}
