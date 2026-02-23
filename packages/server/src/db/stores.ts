/**
 * ZeroID Server — OrbitDB Stores with Encryption Wrappers
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * STORES:
 *   1. escrowStore      (KeyValue)  — Encrypted PII escrow blobs
 *   2. credentialStore   (Documents) — Issued credentials (encrypted)
 *   3. nullifierStore    (KeyValue)  — Sybil nullifier registry
 *   4. proofCacheStore   (KeyValue)  — Verified proof result cache
 *   5. auditLogStore     (Events)    — Immutable access audit trail
 *
 * SECURITY:
 *   - ALL values are AES-256-GCM encrypted BEFORE being written to OrbitDB
 *   - OrbitDB syncs ciphertext over IPFS — no plaintext ever hits the DAG
 *   - Each store has its own encryption key (derived from master via HKDF)
 *   - libp2p noise for transport, authorized-peer-only replication
 *
 * COMPLIANCE:
 *   - GDPR right-to-erasure: rotateEscrowEntry() invalidates an entry
 *   - FinCEN 5-year retention: TTL enforced per jurisdiction config
 *   - Every escrow access logged to immutable audit EventLog
 */

import type { OrbitDB } from '@orbitdb/core';
import crypto from 'node:crypto';
import { encrypt, decrypt, type EncryptedPayload } from '../crypto/aes.js';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EscrowEntry {
  /** Encrypted blob (AES-256-GCM ciphertext + iv + tag) */
  encryptedBlob: EncryptedPayload;
  /** ID of the regulator key used for blob encryption */
  regulatorKeyId: string;
  /** Credential ID this escrow is linked to */
  credentialId: string;
  /** Creation timestamp (ms) */
  createdAt: number;
  /** Expiration timestamp (ms) — per-jurisdiction retention policy */
  expiresAt: number;
  /** Whether this entry has been invalidated (GDPR erasure) */
  invalidated: boolean;
  /** SHA-256 integrity hash of plaintext before encryption */
  integrityHash: string;
}

export interface CredentialEntry {
  _id: string;
  /** Encrypted credential data */
  data: string;
  nonce: string;
  /** Bound wallet address (plaintext for indexing) */
  boundAddress?: string;
  /** Bound smart account address (plaintext for indexing) */
  smartAccountAddress?: string;
  /** Verification level */
  level: number;
  /** Creation timestamp */
  createdAt: number;
}

export interface NullifierEntry {
  /** Whether this nullifier has been used */
  used: boolean;
  /** Credential ID it maps to */
  credentialId: string;
  /** App ID that consumed it */
  appId: string;
  /** Timestamp of first use */
  usedAt: number;
}

export interface ProofCacheEntry {
  /** Whether the proof was valid */
  valid: boolean;
  /** When it was verified */
  verifiedAt: number;
  /** The nullifier from the proof */
  nullifier: string;
}

export interface AuditLogEntry {
  /** What happened */
  action: 'escrow_create' | 'escrow_access' | 'escrow_rotate' | 'escrow_purge'
    | 'credential_issue' | 'credential_bind' | 'proof_verify' | 'nullifier_register';
  /** Target resource ID */
  resourceId: string;
  /** Who performed the action (API key hash, regulator ID, etc.) */
  actor: string;
  /** Timestamp */
  timestamp: number;
  /** Additional metadata (never contains PII) */
  metadata?: Record<string, string>;
}

// ─── Store Instances ─────────────────────────────────────────────────────────

export interface ZeroIdStores {
  escrow: any;       // KeyValue store
  credentials: any;  // Documents store
  nullifiers: any;   // KeyValue store
  proofCache: any;   // KeyValue store
  auditLog: any;     // Events store
}

let storesInstance: ZeroIdStores | null = null;

/** Store-level encryption keys (derived from master key via HKDF) */
let storeKeys: Map<string, Buffer> = new Map();

/**
 * Derive per-store encryption keys from a master key using HKDF.
 * Each store gets a unique key so compromising one doesn't compromise others.
 */
export function deriveStoreKeys(masterKeyHex: string): void {
  const masterKey = Buffer.from(masterKeyHex, 'hex');
  const stores = ['escrow', 'credentials', 'nullifiers', 'proofCache', 'auditLog'];

  for (const store of stores) {
    const derived = Buffer.from(
      crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), `zeroid-store-${store}`, 32),
    );
    storeKeys.set(store, derived);
  }

  console.log(`[ZeroID/Stores] Derived ${stores.length} store encryption keys`);
}

function getStoreKey(storeName: string): Buffer {
  const key = storeKeys.get(storeName);
  if (!key) throw new Error(`Store key not derived for "${storeName}" — call deriveStoreKeys() first`);
  return key;
}

// ─── Store Initialization ────────────────────────────────────────────────────

/**
 * Open all ZeroID OrbitDB stores.
 */
export async function openStores(orbitdb: OrbitDB): Promise<ZeroIdStores> {
  console.log('[ZeroID/Stores] Opening OrbitDB stores...');

  const escrow = await orbitdb.open('zeroid/escrow', { type: 'keyvalue' });
  const credentials = await orbitdb.open('zeroid/credentials', { type: 'documents' });
  const nullifiers = await orbitdb.open('zeroid/nullifiers', { type: 'keyvalue' });
  const proofCache = await orbitdb.open('zeroid/proof-cache', { type: 'keyvalue' });
  const auditLog = await orbitdb.open('zeroid/audit-log', { type: 'events' });

  storesInstance = { escrow, credentials, nullifiers, proofCache, auditLog };
  console.log('[ZeroID/Stores] All stores opened.');
  return storesInstance;
}

/** Get the current stores instance. */
export function getStores(): ZeroIdStores {
  if (!storesInstance) throw new Error('[ZeroID] Stores not opened — call openStores() first');
  return storesInstance;
}

/** Close all stores gracefully. */
export async function closeStores(): Promise<void> {
  if (!storesInstance) return;
  await Promise.all([
    storesInstance.escrow.close(),
    storesInstance.credentials.close(),
    storesInstance.nullifiers.close(),
    storesInstance.proofCache.close(),
    storesInstance.auditLog.close(),
  ]);
  storesInstance = null;
  console.log('[ZeroID/Stores] All stores closed.');
}

// ─── Encrypted KV Helpers ────────────────────────────────────────────────────

/**
 * Encrypt a value and store it in a KeyValue store.
 * The value is AES-256-GCM encrypted with the store-specific key
 * BEFORE being written to OrbitDB → IPFS. No plaintext touches the DAG.
 */
async function encryptedKVPut(
  store: any,
  storeName: string,
  key: string,
  value: Record<string, unknown>,
): Promise<void> {
  const storeKey = getStoreKey(storeName);
  const plaintext = JSON.stringify(value);
  const payload = encrypt(plaintext, storeKey);
  await store.put(key, {
    enc: payload.ciphertext,
    iv: payload.iv,
    tag: payload.tag,
    alg: payload.algorithm,
  });
}

/**
 * Fetch and decrypt a value from a KeyValue store.
 */
function decryptKVGet(
  entry: { enc: string; iv: string; tag: string; alg: string } | null,
  storeName: string,
): Record<string, unknown> | null {
  if (!entry?.enc) return null;
  const storeKey = getStoreKey(storeName);
  const payload: EncryptedPayload = {
    ciphertext: entry.enc,
    iv: entry.iv,
    tag: entry.tag,
    algorithm: 'aes-256-gcm',
  };
  const plaintext = decrypt(payload, storeKey);
  return JSON.parse(plaintext);
}

/**
 * Encrypt and store a document in a Documents store.
 * Sensitive fields encrypted; index fields (boundAddress, level) left in plaintext.
 */
async function encryptedDocPut(
  store: any,
  doc: Record<string, unknown>,
  sensitiveFields: string[],
): Promise<string> {
  const storeKey = getStoreKey('credentials');
  const sensitive: Record<string, unknown> = {};
  const metadata: Record<string, unknown> = { _id: doc._id };

  for (const [k, v] of Object.entries(doc)) {
    if (k === '_id') continue;
    if (sensitiveFields.includes(k)) {
      sensitive[k] = v;
    } else {
      metadata[k] = v;
    }
  }

  const payload = encrypt(JSON.stringify(sensitive), storeKey);
  return store.put({
    ...metadata,
    data: payload.ciphertext,
    iv: payload.iv,
    tag: payload.tag,
  });
}

// ─── Escrow Operations ──────────────────────────────────────────────────────

/** Jurisdiction-specific retention policies (in years) */
const RETENTION_POLICIES: Record<string, number> = {
  US: 5,      // FinCEN BSA: 5-year minimum
  EU: 5,      // AMLD: 5 years after business relationship ends
  UK: 5,      // MLR 2017: 5 years
  DEFAULT: 5, // Conservative default
};

function getRetentionMs(jurisdiction: string): number {
  const years = RETENTION_POLICIES[jurisdiction] ?? RETENTION_POLICIES.DEFAULT;
  return years * 365.25 * 24 * 60 * 60 * 1000;
}

/**
 * Store encrypted PII in the escrow OrbitDB store.
 *
 * DATA FLOW:
 *   Raw PII → AES-256-GCM encrypt (regulator key) → encrypted blob
 *   Encrypted blob → AES-256-GCM encrypt (store key) → OrbitDB → IPFS
 *   ⇒ Double encryption: regulator layer + store layer
 *   ⇒ No plaintext ever touches IPFS
 *
 * @param escrowId - ULID key for this entry
 * @param rawPII - The raw KYC data (will be encrypted and then WIPED)
 * @param regulatorKey - AES-256 key for the designated regulator
 * @param regulatorKeyId - Identifier for the regulator key
 * @param credentialId - Linked credential ID
 * @param jurisdiction - Jurisdiction code for retention policy (default: 'US')
 */
export async function putEscrowEntry(
  escrowId: string,
  rawPII: Record<string, unknown>,
  regulatorKey: string,
  regulatorKeyId: string,
  credentialId: string,
  jurisdiction: string = 'US',
): Promise<void> {
  const stores = getStores();

  // Compute integrity hash BEFORE encryption
  const plaintext = JSON.stringify(rawPII);
  const integrityHash = crypto.createHash('sha256').update(plaintext).digest('hex');

  // Layer 1: Encrypt with the regulator's key (only they can decrypt)
  const encryptedBlob = encrypt(plaintext, regulatorKey);

  const entry: EscrowEntry = {
    encryptedBlob,
    regulatorKeyId,
    credentialId,
    createdAt: Date.now(),
    expiresAt: Date.now() + getRetentionMs(jurisdiction),
    invalidated: false,
    integrityHash,
  };

  // Layer 2: Encrypt the entire entry with the store key before writing to OrbitDB
  await encryptedKVPut(stores.escrow, 'escrow', escrowId, entry as unknown as Record<string, unknown>);

  // Audit: log the escrow creation (NO PII in the log)
  await appendAuditLog({
    action: 'escrow_create',
    resourceId: escrowId,
    actor: 'system',
    timestamp: Date.now(),
    metadata: { regulatorKeyId, jurisdiction, credentialId },
  });
}

/**
 * Retrieve and decrypt an escrow entry.
 * ONLY the designated regulator can decrypt the inner blob.
 *
 * @param escrowId - The escrow entry key
 * @param regulatorKey - The regulator's AES-256 key
 * @param actorId - Who is accessing (for audit trail)
 */
export async function getEscrowEntry(
  escrowId: string,
  regulatorKey: string,
  actorId: string,
): Promise<Record<string, unknown>> {
  const stores = getStores();
  const raw = await stores.escrow.get(escrowId);
  const entry = decryptKVGet(raw, 'escrow') as unknown as EscrowEntry | null;

  if (!entry) throw new Error(`Escrow entry not found: ${escrowId}`);
  if (entry.invalidated) throw new Error(`Escrow entry has been invalidated (GDPR erasure): ${escrowId}`);
  if (Date.now() > entry.expiresAt) throw new Error(`Escrow entry has expired: ${escrowId}`);

  // Audit: log the access attempt
  await appendAuditLog({
    action: 'escrow_access',
    resourceId: escrowId,
    actor: actorId,
    timestamp: Date.now(),
    metadata: { regulatorKeyId: entry.regulatorKeyId },
  });

  // Decrypt the inner blob with the regulator's key
  const plaintext = decrypt(entry.encryptedBlob, regulatorKey);

  // Verify integrity
  const hash = crypto.createHash('sha256').update(plaintext).digest('hex');
  if (hash !== entry.integrityHash) {
    throw new Error('Escrow integrity check failed — data may be corrupted');
  }

  return JSON.parse(plaintext);
}

/**
 * GDPR right-to-erasure: Invalidate an escrow entry.
 * The encrypted blob is overwritten with random data (crypto-shredding).
 * The entry metadata is preserved for the audit trail.
 *
 * NOTE: Due to FinCEN 5-year retention, erasure requests during the
 * retention period are LOGGED but NOT executed. After retention expires,
 * the entry is purged automatically.
 */
export async function rotateEscrowEntry(
  escrowId: string,
  actorId: string,
  forceErasure: boolean = false,
): Promise<{ success: boolean; reason: string }> {
  const stores = getStores();
  const raw = await stores.escrow.get(escrowId);
  const entry = decryptKVGet(raw, 'escrow') as unknown as EscrowEntry | null;

  if (!entry) return { success: false, reason: 'Entry not found' };

  // Check retention period (FinCEN: 5-year minimum)
  const retentionRemaining = entry.expiresAt - Date.now();
  if (retentionRemaining > 0 && !forceErasure) {
    await appendAuditLog({
      action: 'escrow_rotate',
      resourceId: escrowId,
      actor: actorId,
      timestamp: Date.now(),
      metadata: {
        result: 'deferred',
        reason: 'retention_period_active',
        expiresAt: new Date(entry.expiresAt).toISOString(),
      },
    });
    return {
      success: false,
      reason: `Retention period active until ${new Date(entry.expiresAt).toISOString()}. Erasure request logged and will execute after expiry.`,
    };
  }

  // Crypto-shred: replace the encrypted blob with random data
  const shredded: EscrowEntry = {
    ...entry,
    encryptedBlob: encrypt(
      crypto.randomBytes(256).toString('hex'),
      crypto.randomBytes(32).toString('hex'),
    ),
    invalidated: true,
    integrityHash: 'INVALIDATED',
  };

  await encryptedKVPut(stores.escrow, 'escrow', escrowId, shredded as unknown as Record<string, unknown>);

  await appendAuditLog({
    action: 'escrow_rotate',
    resourceId: escrowId,
    actor: actorId,
    timestamp: Date.now(),
    metadata: { result: 'completed' },
  });

  return { success: true, reason: 'Entry crypto-shredded and invalidated' };
}

/**
 * Purge expired escrow entries.
 * Run periodically (e.g., daily cron) to enforce retention policies.
 */
export async function purgeExpiredEscrow(): Promise<number> {
  const stores = getStores();
  const all = stores.escrow.all;
  let purged = 0;
  const now = Date.now();

  // OrbitDB KeyValue .all returns an iterator or object depending on version
  if (all && typeof all[Symbol.asyncIterator] === 'function') {
    for await (const [key, rawVal] of all) {
      const entry = decryptKVGet(rawVal, 'escrow') as unknown as EscrowEntry | null;
      if (entry && now > entry.expiresAt && !entry.invalidated) {
        await rotateEscrowEntry(key, 'system/purge', true);
        purged++;
      }
    }
  }

  if (purged > 0) {
    console.log(`[ZeroID/Stores] Purged ${purged} expired escrow entries`);
  }

  return purged;
}

// ─── Credential Operations ───────────────────────────────────────────────────

/**
 * Store an issued credential (encrypted).
 * Index fields (boundAddress, smartAccountAddress, level) are plaintext for querying.
 * Sensitive credential data (hashes, signatures) are encrypted.
 */
export async function putCredential(
  credentialId: string,
  credentialData: Record<string, unknown>,
  boundAddress?: string,
  smartAccountAddress?: string,
  level: number = 0,
): Promise<void> {
  const stores = getStores();

  await encryptedDocPut(
    stores.credentials,
    {
      _id: credentialId,
      // Plaintext index fields (non-sensitive)
      boundAddress,
      smartAccountAddress,
      level,
      createdAt: Date.now(),
      // Sensitive fields (will be encrypted)
      credentialHash: credentialData.credentialHash,
      signatureR8: credentialData.signatureR8,
      signatureS: credentialData.signatureS,
      issuerPubKey: credentialData.issuerPubKey,
      userSecret: credentialData.userSecret,
    },
    ['credentialHash', 'signatureR8', 'signatureS', 'issuerPubKey', 'userSecret'],
  );

  await appendAuditLog({
    action: 'credential_issue',
    resourceId: credentialId,
    actor: 'system',
    timestamp: Date.now(),
    metadata: { level: String(level), boundAddress: boundAddress ?? 'unbound' },
  });
}

/**
 * Bind a credential to a smart account address.
 */
export async function bindCredentialToAccount(
  credentialId: string,
  smartAccountAddress: string,
  actorId: string,
): Promise<void> {
  // For DocumentStore, we need to update the document.
  // OrbitDB documents are append-only — we put a new version with the same _id.
  const stores = getStores();
  const existing = await stores.credentials.get(credentialId);
  if (!existing) throw new Error(`Credential not found: ${credentialId}`);

  await stores.credentials.put({ ...existing, smartAccountAddress });

  await appendAuditLog({
    action: 'credential_bind',
    resourceId: credentialId,
    actor: actorId,
    timestamp: Date.now(),
    metadata: { smartAccountAddress },
  });
}

// ─── Nullifier Operations ────────────────────────────────────────────────────

/**
 * Register a nullifier (marks it as used).
 */
export async function registerNullifier(
  nullifier: string,
  credentialId: string,
  appId: string,
): Promise<void> {
  const stores = getStores();

  const entry: NullifierEntry = {
    used: true,
    credentialId,
    appId,
    usedAt: Date.now(),
  };

  await encryptedKVPut(stores.nullifiers, 'nullifiers', nullifier, entry as unknown as Record<string, unknown>);

  await appendAuditLog({
    action: 'nullifier_register',
    resourceId: nullifier,
    actor: 'system',
    timestamp: Date.now(),
    metadata: { appId },
  });
}

/**
 * Check if a nullifier has already been used.
 */
export async function isNullifierUsed(nullifier: string): Promise<boolean> {
  const stores = getStores();
  const raw = await stores.nullifiers.get(nullifier);
  if (!raw) return false;
  const entry = decryptKVGet(raw, 'nullifiers') as unknown as NullifierEntry | null;
  return entry?.used ?? false;
}

// ─── Proof Cache Operations ─────────────────────────────────────────────────

/**
 * Cache a proof verification result.
 */
export async function cacheProofResult(
  proofHash: string,
  valid: boolean,
  nullifier: string,
): Promise<void> {
  const stores = getStores();
  const entry: ProofCacheEntry = {
    valid,
    verifiedAt: Date.now(),
    nullifier,
  };
  await encryptedKVPut(stores.proofCache, 'proofCache', proofHash, entry as unknown as Record<string, unknown>);
}

/**
 * Get a cached proof verification result.
 */
export async function getCachedProofResult(
  proofHash: string,
): Promise<ProofCacheEntry | null> {
  const stores = getStores();
  const raw = await stores.proofCache.get(proofHash);
  return decryptKVGet(raw, 'proofCache') as unknown as ProofCacheEntry | null;
}

// ─── Audit Log ──────────────────────────────────────────────────────────────

/**
 * Append an entry to the immutable audit log.
 * EventLog is append-only — entries cannot be deleted or modified.
 * This provides a cryptographic audit trail for compliance.
 */
export async function appendAuditLog(entry: AuditLogEntry): Promise<void> {
  const stores = getStores();
  // Audit log entries are encrypted at rest too
  const storeKey = getStoreKey('auditLog');
  const payload = encrypt(JSON.stringify(entry), storeKey);
  await stores.auditLog.add({
    enc: payload.ciphertext,
    iv: payload.iv,
    tag: payload.tag,
  });
}

/**
 * Query audit log entries (decrypts them).
 * @param limit - Maximum entries to return
 */
export async function queryAuditLog(limit: number = 100): Promise<AuditLogEntry[]> {
  const stores = getStores();
  const storeKey = getStoreKey('auditLog');
  const entries: AuditLogEntry[] = [];

  const all = stores.auditLog.all;
  let count = 0;

  if (all && typeof all[Symbol.asyncIterator] === 'function') {
    for await (const record of all) {
      if (count >= limit) break;
      try {
        const val = record.value ?? record;
        if (val?.enc) {
          const payload: EncryptedPayload = {
            ciphertext: val.enc,
            iv: val.iv,
            tag: val.tag,
            algorithm: 'aes-256-gcm',
          };
          const plaintext = decrypt(payload, storeKey);
          entries.push(JSON.parse(plaintext));
        }
      } catch {
        // Skip corrupted entries
      }
      count++;
    }
  }

  return entries;
}
