/**
 * ZeroID SDK — WebAuthn Passkey Integration
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * ARCHITECTURE:
 * - Passkey (secp256r1 in secure enclave) → owns the ERC-4337 smart account
 * - ZeroID credential (EdDSA Poseidon)    → proves identity via ZK
 * - Together: invisible wallet + private identity, no seed phrases
 *
 * The passkey is stored in iCloud Keychain / Google Password Manager.
 * Recovery = recovering your phone. No seed phrases. No browser extensions.
 */

import type { PasskeyOptions, PasskeyCredential } from './types.js';

/**
 * Create a new WebAuthn passkey.
 * This passkey becomes the owner of the user's ERC-4337 smart account.
 *
 * @param options - Passkey registration options from the server
 * @returns The passkey credential (public key for smart account ownership)
 */
export async function createPasskey(
  options: PasskeyOptions,
): Promise<PasskeyCredential> {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  const challengeBuffer = base64urlToBuffer(options.challenge);

  const createOptions: CredentialCreationOptions = {
    publicKey: {
      rp: {
        name: options.rpName,
        id: options.rpId,
      },
      user: {
        id: new TextEncoder().encode(options.userName),
        name: options.userName,
        displayName: options.userName,
      },
      challenge: challengeBuffer,
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256 (secp256r1) — ERC-4337 compatible
        { alg: -257, type: 'public-key' },  // RS256 fallback
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform', // Device biometrics (Face ID / fingerprint)
        residentKey: 'required',             // Discoverable credential
        userVerification: 'required',        // Must verify (biometric or PIN)
      },
      timeout: options.timeout ?? 60_000,
      attestation: 'none', // Privacy: don't leak authenticator info
    },
  };

  const credential = (await navigator.credentials.create(
    createOptions,
  )) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Passkey creation was cancelled');
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    credentialId: bufferToBase64url(credential.rawId),
    publicKey: bufferToBase64url(response.getPublicKey()!),
    attestation: bufferToBase64url(response.attestationObject),
    algorithm: -7, // ES256
  };
}

/**
 * Get a passkey assertion (for signing transactions / proving ownership).
 *
 * @param challenge - Server challenge (base64url)
 * @param credentialId - Optional: specific credential to use
 * @returns The signed assertion
 */
export async function getPasskeyAssertion(
  challenge: string,
  credentialId?: string,
): Promise<{
  credentialId: string;
  signature: string;
  authenticatorData: string;
  clientDataJSON: string;
}> {
  const requestOptions: CredentialRequestOptions = {
    publicKey: {
      challenge: base64urlToBuffer(challenge),
      allowCredentials: credentialId
        ? [{ id: base64urlToBuffer(credentialId), type: 'public-key' }]
        : [],
      userVerification: 'required',
      timeout: 60_000,
    },
  };

  const assertion = (await navigator.credentials.get(
    requestOptions,
  )) as PublicKeyCredential;

  if (!assertion) {
    throw new Error('Passkey assertion was cancelled');
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  return {
    credentialId: bufferToBase64url(assertion.rawId),
    signature: bufferToBase64url(response.signature),
    authenticatorData: bufferToBase64url(response.authenticatorData),
    clientDataJSON: bufferToBase64url(response.clientDataJSON),
  };
}

// --- Helpers ---

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
