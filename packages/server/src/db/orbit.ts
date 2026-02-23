/**
 * ZeroID Server — OrbitDB + Helia Initialization
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * ARCHITECTURE:
 * - Helia (IPFS) provides content-addressed storage
 * - libp2p with noise protocol for encrypted transport
 * - OrbitDB provides CRDT-based replicated databases
 * - ALL data encrypted with AES-256-GCM BEFORE hitting IPFS
 * - No plaintext EVER touches the IPFS DAG
 * - Authorized-peer-only replication (same pattern as veil-gov-forum)
 */

import { createHelia } from 'helia';
import { createOrbitDB } from '@orbitdb/core';
import { noise } from '@chainsafe/libp2p-noise';
import { tcp } from '@libp2p/tcp';
import { mplex } from '@libp2p/mplex';
import { createLibp2p } from 'libp2p';
import { identify } from '@libp2p/identify';
import type { OrbitDB } from '@orbitdb/core';
import type { Libp2p } from 'libp2p';
import { multiaddr } from '@multiformats/multiaddr';

let orbitInstance: OrbitDB | null = null;
let heliaInstance: Awaited<ReturnType<typeof createHelia>> | null = null;

export interface OrbitSetup {
  orbitdb: OrbitDB;
  ipfs: Awaited<ReturnType<typeof createHelia>>;
}

// ─── Authorized Peer Replication ─────────────────────────────────────────────

const authorizedPeers = new Set<string>();

/** Authorize a peer for replication. */
export function authorizePeer(peerId: string): void {
  authorizedPeers.add(peerId);
  console.log(`[ZeroID/OrbitDB] Authorized peer: ${peerId}`);
}

/** Deauthorize a peer. */
export function deauthorizePeer(peerId: string): void {
  authorizedPeers.delete(peerId);
  console.log(`[ZeroID/OrbitDB] Deauthorized peer: ${peerId}`);
}

/** Check if a peer is authorized. Empty set = allow all (bootstrap mode). */
export function isPeerAuthorized(peerId: string): boolean {
  if (authorizedPeers.size === 0) return true;
  return authorizedPeers.has(peerId);
}

/**
 * Configure connection gating on the libp2p instance.
 * Rejects connections from unauthorized peers — no plaintext escrow data
 * should ever replicate to untrusted nodes.
 */
function configureConnectionGating(libp2p: Libp2p): void {
  libp2p.addEventListener('peer:connect', (evt) => {
    const remotePeer = evt.detail.toString();
    if (!isPeerAuthorized(remotePeer)) {
      console.warn(`[ZeroID/OrbitDB] Rejected unauthorized peer: ${remotePeer}`);
      try {
        const connections = libp2p.getConnections().filter(
          (c) => c.remotePeer.toString() === remotePeer,
        );
        for (const conn of connections) {
          conn.close().catch(() => {});
        }
      } catch {
        // Best effort
      }
    }
  });
}

// ─── Initialization ──────────────────────────────────────────────────────────

export interface OrbitDBOptions {
  /** Storage directory for OrbitDB data */
  directory?: string;
  /** libp2p TCP listen address */
  listenAddr?: string;
  /** Bootstrap peer multiaddrs */
  bootstrapAddrs?: string[];
  /** Authorized peer IDs for replication */
  authorizedPeerIds?: string[];
}

/**
 * Initialize Helia IPFS node + OrbitDB.
 *
 * SECURITY:
 * - libp2p noise protocol for transport encryption
 * - Authorized-peer-only replication
 * - All data is pre-encrypted before OrbitDB stores it
 */
export async function initOrbitDB(options?: OrbitDBOptions): Promise<OrbitSetup> {
  const directory = options?.directory ?? process.env.ZEROID_ORBITDB_DIR ?? './orbitdb/zeroid';
  const listenAddr = options?.listenAddr ?? process.env.ZEROID_IPFS_LISTEN ?? '/ip4/0.0.0.0/tcp/4002';

  // Register authorized peers
  if (options?.authorizedPeerIds) {
    for (const id of options.authorizedPeerIds) {
      authorizePeer(id);
    }
  }
  const envPeers = process.env.ZEROID_AUTHORIZED_PEERS;
  if (envPeers) {
    for (const id of envPeers.split(',').map((s) => s.trim())) {
      authorizePeer(id);
    }
  }

  // Create libp2p with noise encryption
  const libp2p = await createLibp2p({
    addresses: { listen: [listenAddr] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [mplex()],
    services: { identify: identify() },
  });

  // Configure peer authorization
  configureConnectionGating(libp2p);

  // Create Helia IPFS node
  const ipfs = await createHelia({ libp2p });
  heliaInstance = ipfs;

  // Create OrbitDB instance
  const orbitdb = await createOrbitDB({ ipfs, directory });
  orbitInstance = orbitdb;

  console.log(`[ZeroID/OrbitDB] Initialized — directory: ${directory}`);
  console.log(`[ZeroID/OrbitDB] Peer ID: ${ipfs.libp2p.peerId.toString()}`);
  console.log(`[ZeroID/OrbitDB] Listening: ${listenAddr}`);

  // Connect to bootstrap peers
  if (options?.bootstrapAddrs) {
    for (const addr of options.bootstrapAddrs) {
      try {
        await libp2p.dial(multiaddr(addr));
        console.log(`[ZeroID/OrbitDB] Connected to bootstrap: ${addr}`);
      } catch (err) {
        console.warn(`[ZeroID/OrbitDB] Bootstrap dial failed: ${addr} — ${(err as Error).message}`);
      }
    }
  }

  return { orbitdb, ipfs };
}

/** Get the OrbitDB instance (must call initOrbitDB first). */
export function getOrbitDB(): OrbitDB {
  if (!orbitInstance) throw new Error('[ZeroID] OrbitDB not initialized — call initOrbitDB() first');
  return orbitInstance;
}

/** Gracefully shut down OrbitDB + IPFS. */
export async function shutdownOrbitDB(setup: OrbitSetup): Promise<void> {
  console.log('[ZeroID/OrbitDB] Shutting down...');
  await setup.orbitdb.stop();
  await setup.ipfs.stop();
  orbitInstance = null;
  heliaInstance = null;
  console.log('[ZeroID/OrbitDB] Stopped.');
}
