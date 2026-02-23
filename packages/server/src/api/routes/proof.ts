/**
 * ZeroID Server — Proof Verification Route
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * POST /api/v1/proof/verify — Verify a ZK proof.
 */

import { Router } from 'express';
import path from 'node:path';
import { validateBody, proofVerifyRequestSchema } from '../middleware.js';
import { verifyProof } from '../../verifier/verify.js';
import { hashProof, getCached, setCached } from '../../verifier/cache.js';
import { registerNullifier, isNullifierUsed } from '../../db/stores.js';

const router = Router();

const VKEY_PATH = process.env.ZEROID_VKEY_PATH ??
  path.resolve('circuits/setup/verification_key.json');

/**
 * POST /api/v1/proof/verify
 * Verify a Groth16 ZK proof.
 *
 * Body: { proof: object, publicSignals: string[] }
 * Returns: { valid: boolean, nullifier: string }
 */
router.post(
  '/',
  validateBody(proofVerifyRequestSchema),
  async (req, res) => {
    try {
      const { proof, publicSignals } = (req as any).validated;

      // Check cache first (in-memory → OrbitDB)
      const proofHash = hashProof(proof, publicSignals);
      const cached = await getCached(proofHash);
      if (cached) {
        res.json(cached);
        return;
      }

      // Verify the proof
      const valid = await verifyProof(proof, publicSignals, VKEY_PATH);

      // Extract nullifier from public signals (index 5 in our circuit)
      const nullifier = publicSignals[5] ?? '0';

      // Check for nullifier replay
      if (valid) {
        const alreadyUsed = await isNullifierUsed(nullifier);
        if (alreadyUsed) {
          res.status(409).json({
            valid: false,
            nullifier,
            error: 'Nullifier already used — duplicate verification attempt',
          });
          return;
        }

        // Register nullifier in OrbitDB
        const appId = publicSignals[4] ?? '0';
        await registerNullifier(nullifier, 'unknown', appId);
      }

      // Cache the result (memory + OrbitDB)
      await setCached(proofHash, valid, nullifier);

      res.json({ valid, nullifier, cached: false });
    } catch (err) {
      console.error('Proof verification error:', err);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to verify proof',
      });
    }
  },
);

export default router;
