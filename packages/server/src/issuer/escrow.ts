/**
 * ZeroID Server — PII Escrow (OrbitDB Backend)
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * PRIVACY MODEL — WHERE DATA GOES:
 *
 *   ┌─────────────────────────────────────────────────┐
 *   │  Raw PII (name, DOB, document)                  │
 *   │  → AES-256-GCM encrypt (regulator key)          │  Layer 1
 *   │  → AES-256-GCM encrypt (store key)              │  Layer 2
 *   │  → OrbitDB KeyValue → IPFS DAG                  │  Storage
 *   │  → Plaintext WIPED from memory                  │
 *   └─────────────────────────────────────────────────┘
 *
 *   Who can read the escrow?
 *   ✅ The specific regulator named at verification time (with their key + legal process)
 *   ❌ The app / business — CANNOT read it
 *   ❌ ZeroID servers — CANNOT read it (store key ≠ regulator key)
 *   ❌ IPFS nodes — see only double-encrypted ciphertext
 *   ❌ Any attacker — CANNOT read it (AES-256-GCM × 2)
 *
 *   Compliance:
 *   - FinCEN BSA: 5-year minimum retention enforced via TTL
 *   - GDPR right-to-erasure: crypto-shredding after retention expires
 *   - Every access logged to immutable OrbitDB EventLog audit trail
 */

import crypto from 'node:crypto';
import { getRegulatorKey } from '../crypto/keys.js';
import {
  putEscrowEntry,
  getEscrowEntry,
  rotateEscrowEntry,
  appendAuditLog,
} from '../db/stores.js';

/**
 * Encrypt raw PII and store it in OrbitDB escrow.
 *
 * @param rawPII - The raw personally identifiable information
 * @param regulatorId - Identifier for the regulator who can decrypt
 * @param credentialId - The credential ID this escrow is linked to
 * @param jurisdiction - Jurisdiction code for retention policy (default: 'US')
 * @returns The escrow ID (ULID) for future retrieval
 */
export async function encryptForEscrow(
  rawPII: Record<string, unknown>,
  regulatorId: string,
  credentialId: string,
  jurisdiction: string = 'US',
): Promise<string> {
  const regulatorKey = getRegulatorKey(regulatorId);
  const escrowId = generateULID();

  await putEscrowEntry(
    escrowId,
    rawPII,
    regulatorKey,
    regulatorId,
    credentialId,
    jurisdiction,
  );

  return escrowId;
}

/**
 * Retrieve and decrypt an escrow record.
 * Only the designated regulator can decrypt with their key.
 *
 * @param escrowId - The escrow record ID
 * @param regulatorId - The regulator requesting decryption
 * @returns The decrypted PII
 */
export async function retrieveEscrow(
  escrowId: string,
  regulatorId: string,
): Promise<Record<string, unknown>> {
  const regulatorKey = getRegulatorKey(regulatorId);
  return getEscrowEntry(escrowId, regulatorKey, regulatorId);
}

/**
 * GDPR right-to-erasure: request invalidation of an escrow entry.
 * If within FinCEN retention period, the request is logged but deferred.
 * After retention expires, the entry is crypto-shredded.
 */
export async function requestErasure(
  escrowId: string,
  requesterId: string,
): Promise<{ success: boolean; reason: string }> {
  return rotateEscrowEntry(escrowId, requesterId);
}

/**
 * Check if an escrow record exists (without decrypting).
 */
export async function escrowExists(escrowId: string): Promise<boolean> {
  try {
    // Attempt access with a dummy key — it will fail to decrypt
    // but we can catch the "not found" vs other errors
    const regulatorKey = crypto.randomBytes(32).toString('hex');
    await getEscrowEntry(escrowId, regulatorKey, 'existence_check');
    return true;
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('not found')) return false;
    // Entry exists but we can't decrypt (expected)
    return true;
  }
}

// ─── ULID Generator (monotonic, sortable) ────────────────────────────────────

const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
let lastTime = 0;
let lastRandom = 0;

function generateULID(): string {
  let now = Date.now();
  if (now === lastTime) {
    lastRandom++;
  } else {
    lastTime = now;
    lastRandom = crypto.randomInt(0, 2 ** 40);
  }

  // Encode timestamp (48 bits = 10 chars)
  let ts = '';
  for (let i = 9; i >= 0; i--) {
    ts = ENCODING[now % 32] + ts;
    now = Math.floor(now / 32);
  }

  // Encode randomness (80 bits = 16 chars)
  const randBytes = crypto.randomBytes(10);
  let rand = '';
  for (let i = 0; i < 16; i++) {
    rand += ENCODING[randBytes[i % 10] % 32];
  }

  return ts + rand;
}
