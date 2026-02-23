/**
 * ZeroID Server — Verification Result Cache
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Dual-layer cache:
 *   1. In-memory LRU for hot lookups (fast, volatile)
 *   2. OrbitDB KeyValue for persistent cache (encrypted at rest on IPFS)
 *
 * Keyed by SHA-256 hash of the proof + public signals.
 */

import crypto from 'node:crypto';
import {
  cacheProofResult,
  getCachedProofResult,
  type ProofCacheEntry,
} from '../db/stores.js';

// ─── In-Memory LRU (Layer 1: hot cache) ─────────────────────────────────────

interface MemoryCacheEntry {
  valid: boolean;
  nullifier: string;
  timestamp: number;
}

class LRUMemoryCache {
  private cache: Map<string, MemoryCacheEntry>;
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(maxSize: number = 10_000, ttlMs: number = 3_600_000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  get(key: string): MemoryCacheEntry | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return undefined;
    }
    // Move to end (LRU)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry;
  }

  set(key: string, valid: boolean, nullifier: string): void {
    if (this.cache.size >= this.maxSize) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, { valid, nullifier, timestamp: Date.now() });
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }
}

const memoryCache = new LRUMemoryCache();

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Generate a cache key from a proof and public signals.
 */
export function hashProof(
  proof: Record<string, unknown>,
  publicSignals: string[],
): string {
  const data = JSON.stringify({ proof, publicSignals });
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Look up a cached verification result.
 * Checks in-memory first, then OrbitDB.
 */
export async function getCached(
  proofHash: string,
): Promise<{ valid: boolean; nullifier: string; cached: true } | null> {
  // Layer 1: in-memory
  const mem = memoryCache.get(proofHash);
  if (mem) {
    return { valid: mem.valid, nullifier: mem.nullifier, cached: true };
  }

  // Layer 2: OrbitDB (persistent, encrypted)
  try {
    const entry = await getCachedProofResult(proofHash);
    if (entry) {
      // Promote to memory cache
      memoryCache.set(proofHash, entry.valid, entry.nullifier);
      return { valid: entry.valid, nullifier: entry.nullifier, cached: true };
    }
  } catch {
    // OrbitDB unavailable — degrade gracefully
  }

  return null;
}

/**
 * Store a verification result in both caches.
 */
export async function setCached(
  proofHash: string,
  valid: boolean,
  nullifier: string,
): Promise<void> {
  // Layer 1: in-memory
  memoryCache.set(proofHash, valid, nullifier);

  // Layer 2: OrbitDB (persistent)
  try {
    await cacheProofResult(proofHash, valid, nullifier);
  } catch {
    // OrbitDB unavailable — memory cache still works
  }
}

/** Re-export for backward compatibility */
export const VerificationCache = {
  hashProof,
};

export const verificationCache = {
  get: getCached,
  set: setCached,
};
