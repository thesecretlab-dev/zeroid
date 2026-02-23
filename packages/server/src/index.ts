/**
 * ZeroID Server — Bootstrap
 * © thesecretlab | "Verify the human. Drop the liability."
 */

import 'dotenv/config';
import { createApp } from './api/server.js';
import { getSanctionsTree } from './sanctions/ofac.js';
import { getIssuerKeyPair } from './crypto/keys.js';
import { initOrbitDB, shutdownOrbitDB, type OrbitSetup } from './db/orbit.js';
import { openStores, deriveStoreKeys, closeStores } from './db/stores.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const HOST = process.env.HOST ?? '0.0.0.0';

let orbitSetup: OrbitSetup | null = null;

async function main(): Promise<void> {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║        🔐 ZeroID Server v0.1.0       ║');
  console.log('  ║   "Verify the human. Drop the liability."  ║');
  console.log('  ║        © thesecretlab                 ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  console.log('⚡ Initializing...');

  // 1. Initialize OrbitDB + IPFS
  orbitSetup = await initOrbitDB({
    directory: process.env.ZEROID_ORBITDB_DIR,
    listenAddr: process.env.ZEROID_IPFS_LISTEN,
    bootstrapAddrs: process.env.ZEROID_BOOTSTRAP_ADDRS?.split(',').map((s) => s.trim()),
    authorizedPeerIds: process.env.ZEROID_AUTHORIZED_PEERS?.split(',').map((s) => s.trim()),
  });

  // 2. Derive per-store encryption keys from master key
  const masterKey = process.env.ZEROID_STORE_MASTER_KEY;
  if (!masterKey) {
    console.warn('⚠️  ZEROID_STORE_MASTER_KEY not set — generating ephemeral key (NOT for production)');
    const { randomBytes } = await import('node:crypto');
    deriveStoreKeys(randomBytes(32).toString('hex'));
  } else {
    deriveStoreKeys(masterKey);
  }

  // 3. Open all OrbitDB stores
  await openStores(orbitSetup.orbitdb);

  // 4. Pre-warm crypto and data structures
  const [keyPair] = await Promise.all([
    getIssuerKeyPair(),
    getSanctionsTree(),
  ]);

  console.log(`🔑 Issuer public key: [${keyPair.publicKey[0].toString().slice(0, 16)}..., ${keyPair.publicKey[1].toString().slice(0, 16)}...]`);

  // 5. Start Express server
  const app = createApp();
  const server = app.listen(PORT, HOST, () => {
    console.log(`🚀 ZeroID server listening on http://${HOST}:${PORT}`);
    console.log(`   Health: http://${HOST}:${PORT}/health`);
    console.log('');
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`\n${signal} received — shutting down...`);
    server.close();
    await closeStores();
    if (orbitSetup) await shutdownOrbitDB(orbitSetup);
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('❌ Fatal startup error:', err);
  process.exit(1);
});
