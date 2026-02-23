/**
 * ZeroID Server — AES-256-GCM Encryption
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Used for encrypting raw PII to escrow storage.
 * Only regulators with the correct key can decrypt.
 */

import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV for GCM
const TAG_LENGTH = 16; // 128-bit auth tag
const KEY_LENGTH = 32; // 256-bit key

/** Encrypted payload structure */
export interface EncryptedPayload {
  /** Initialization vector (hex) */
  iv: string;
  /** Ciphertext (hex) */
  ciphertext: string;
  /** Authentication tag (hex) */
  tag: string;
  /** Algorithm identifier */
  algorithm: 'aes-256-gcm';
}

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param plaintext - Data to encrypt (string or buffer)
 * @param key - 256-bit encryption key (32-byte hex string or Buffer)
 * @returns Encrypted payload with IV, ciphertext, and auth tag
 */
export function encrypt(
  plaintext: string | Buffer,
  key: string | Buffer,
): EncryptedPayload {
  const keyBuf = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
  if (keyBuf.length !== KEY_LENGTH) {
    throw new Error(`AES key must be ${KEY_LENGTH} bytes, got ${keyBuf.length}`);
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, keyBuf, iv, {
    authTagLength: TAG_LENGTH,
  });

  const plaintextBuf =
    typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf-8') : plaintext;

  const encrypted = Buffer.concat([
    cipher.update(plaintextBuf),
    cipher.final(),
  ]);

  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    algorithm: ALGORITHM,
  };
}

/**
 * Decrypt an AES-256-GCM encrypted payload.
 *
 * @param payload - The encrypted payload
 * @param key - 256-bit decryption key (32-byte hex string or Buffer)
 * @returns Decrypted plaintext as UTF-8 string
 */
export function decrypt(
  payload: EncryptedPayload,
  key: string | Buffer,
): string {
  const keyBuf = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
  if (keyBuf.length !== KEY_LENGTH) {
    throw new Error(`AES key must be ${KEY_LENGTH} bytes, got ${keyBuf.length}`);
  }

  const iv = Buffer.from(payload.iv, 'hex');
  const ciphertext = Buffer.from(payload.ciphertext, 'hex');
  const tag = Buffer.from(payload.tag, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, keyBuf, iv, {
    authTagLength: TAG_LENGTH,
  });
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf-8');
}

/**
 * Generate a random AES-256 key.
 * @returns 32-byte key as hex string
 */
export function generateKey(): string {
  return crypto.randomBytes(KEY_LENGTH).toString('hex');
}
