/**
 * ZeroID Server — Key Management
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Manages issuer EdDSA keypairs and regulator encryption keys.
 * Keys are loaded from environment or generated fresh for development.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { generateKeyPair, type EdDSAKeyPair } from './eddsa.js';
import { generateKey as generateAesKey } from './aes.js';

const KEYS_DIR = process.env.ZEROID_KEYS_DIR ?? './.keys';

/** Cached issuer keypair */
let issuerKeyPair: EdDSAKeyPair | null = null;

/** Cached regulator public keys */
let regulatorKeys: Map<string, string> = new Map();

/**
 * Ensure the keys directory exists.
 */
function ensureKeysDir(): void {
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }
}

/**
 * Load or generate the issuer EdDSA keypair.
 * In production, the private key should be loaded from a secure vault (e.g., AWS KMS).
 */
export async function getIssuerKeyPair(): Promise<EdDSAKeyPair> {
  if (issuerKeyPair) return issuerKeyPair;

  ensureKeysDir();
  const keyPath = path.join(KEYS_DIR, 'issuer.json');

  // Try loading from file
  if (fs.existsSync(keyPath)) {
    const data = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    issuerKeyPair = {
      privateKey: data.privateKey,
      publicKey: [BigInt(data.publicKey[0]), BigInt(data.publicKey[1])],
    };
    return issuerKeyPair;
  }

  // Try loading from environment
  if (process.env.ZEROID_ISSUER_PRIVATE_KEY) {
    const kp = await generateKeyPair();
    // Re-derive from the env private key
    issuerKeyPair = {
      ...kp,
      privateKey: process.env.ZEROID_ISSUER_PRIVATE_KEY,
    };
    return issuerKeyPair;
  }

  // Generate new keypair (development only)
  console.warn('⚠️  Generating new issuer keypair — NOT for production use');
  issuerKeyPair = await generateKeyPair();

  // Persist for development consistency
  fs.writeFileSync(
    keyPath,
    JSON.stringify(
      {
        privateKey: issuerKeyPair.privateKey,
        publicKey: [
          issuerKeyPair.publicKey[0].toString(),
          issuerKeyPair.publicKey[1].toString(),
        ],
      },
      null,
      2,
    ),
  );

  return issuerKeyPair;
}

/**
 * Load regulator public keys for escrow encryption.
 * Each regulator has an AES key used to encrypt PII escrow blobs.
 */
export function getRegulatorKey(regulatorId: string): string {
  const cached = regulatorKeys.get(regulatorId);
  if (cached) return cached;

  // Try environment variable
  const envKey = process.env[`ZEROID_REGULATOR_KEY_${regulatorId.toUpperCase()}`];
  if (envKey) {
    regulatorKeys.set(regulatorId, envKey);
    return envKey;
  }

  // Try file
  ensureKeysDir();
  const keyPath = path.join(KEYS_DIR, `regulator_${regulatorId}.key`);
  if (fs.existsSync(keyPath)) {
    const key = fs.readFileSync(keyPath, 'utf-8').trim();
    regulatorKeys.set(regulatorId, key);
    return key;
  }

  // Generate for development
  console.warn(`⚠️  Generating regulator key for "${regulatorId}" — NOT for production`);
  const key = generateAesKey();
  fs.writeFileSync(keyPath, key);
  regulatorKeys.set(regulatorId, key);
  return key;
}

/**
 * Derive a deterministic sub-key from a master key using HKDF.
 */
export function deriveKey(
  masterKey: string | Buffer,
  info: string,
  length: number = 32,
): Buffer {
  const keyBuf = typeof masterKey === 'string' ? Buffer.from(masterKey, 'hex') : masterKey;
  return crypto.hkdfSync('sha256', keyBuf, Buffer.alloc(0), info, length) as unknown as Buffer;
}
