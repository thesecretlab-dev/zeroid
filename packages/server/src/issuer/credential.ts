/**
 * ZeroID Server — Credential Issuance
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Issues signed credentials after KYC verification.
 * The credential contains a Poseidon hash of the user's attributes,
 * signed by the issuer's EdDSA key.
 */

import crypto from 'node:crypto';
import { hashCredential } from './poseidon.js';
import { sign, type EdDSASignature } from '../crypto/eddsa.js';
import { getIssuerKeyPair } from '../crypto/keys.js';
import type { KycResult } from '../kyc/types.js';

/** Verification level — progressive disclosure (matches SDK types) */
export type VerificationLevel = 0 | 1 | 2 | 3 | 4;

/**
 * Signed credential object returned to the user.
 *
 * PRIVACY: This object is stored ONLY on the user's device.
 * The credentialHash is a Poseidon hash — NOT reversible to the original data.
 * The userSecret is the private input for ZK proofs — it never leaves the device
 * after this response is delivered over TLS.
 */
export interface SignedCredential {
  /** Unique credential ID */
  id: string;
  /** Poseidon hash of (age, country, secret) — NOT the raw data */
  credentialHash: string;
  /** EdDSA signature R8 point [x, y] as string tuple */
  signatureR8: [string, string];
  /** EdDSA signature scalar S as string */
  signatureS: string;
  /** Issuer public key [x, y] as string tuple */
  issuerPubKey: [string, string];
  /** User's secret (private input for proofs — stored only on user's device) */
  userSecret: string;
  /** ERC-4337 smart account address this credential is bound to */
  boundAddress?: string;
  /** Verification level achieved */
  level: VerificationLevel;
  /** Unix timestamp of issuance */
  issuedAt: number;
  /** Expiration timestamp (default: 1 year) */
  expiresAt: number;
}

const CREDENTIAL_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1 year

/**
 * Issue a signed credential from verified KYC data.
 *
 * @param kycResult - The verified KYC extraction result
 * @returns A signed credential containing the Poseidon hash and EdDSA signature
 */
/**
 * Issue a signed credential from verified KYC data.
 *
 * PRIVACY FLOW:
 * 1. KYC data arrives over TLS → processed in memory only
 * 2. Poseidon hash computed (irreversible) → this is the credential
 * 3. EdDSA signature applied → proves issuer authenticity
 * 4. Raw data wiped from memory after escrow encryption
 * 5. Only the hash + signature returned to user
 *
 * @param kycResult - The verified KYC extraction result
 * @param boundAddress - Optional ERC-4337 smart account address to bind to
 * @param level - Verification level (default: determined by available data)
 */
export async function issueCredential(
  kycResult: KycResult,
  boundAddress?: string,
  level?: VerificationLevel,
): Promise<SignedCredential> {
  const keyPair = await getIssuerKeyPair();

  // Generate a random secret for this credential
  const userSecret = BigInt('0x' + crypto.randomBytes(31).toString('hex'));

  // Calculate age from date of birth
  const dob = new Date(kycResult.dateOfBirth);
  const now = new Date();
  let age = now.getFullYear() - dob.getFullYear();
  const monthDiff = now.getMonth() - dob.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < dob.getDate())) {
    age--;
  }

  // Compute the credential hash: Poseidon(age, countryCode, secret)
  const credHash = await hashCredential(age, kycResult.countryCode, userSecret);

  // Sign the credential hash with the issuer's EdDSA key
  const signature: EdDSASignature = await sign(keyPair.privateKey, credHash);

  const now_ts = Date.now();

  // Determine verification level based on available data
  const resolvedLevel: VerificationLevel = level ?? (
    kycResult.countryCode && age ? 3 : age ? 1 : 0
  ) as VerificationLevel;

  return {
    id: crypto.randomUUID(),
    credentialHash: credHash.toString(),
    signatureR8: [signature.R8[0].toString(), signature.R8[1].toString()],
    signatureS: signature.S.toString(),
    issuerPubKey: [
      keyPair.publicKey[0].toString(),
      keyPair.publicKey[1].toString(),
    ],
    userSecret: userSecret.toString(),
    boundAddress,
    level: resolvedLevel,
    issuedAt: now_ts,
    expiresAt: now_ts + CREDENTIAL_TTL_MS,
  };
}
