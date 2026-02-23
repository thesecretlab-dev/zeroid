/**
 * ZeroID Server — Proof Aggregation Route
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * POST /api/v1/proof/aggregate — Batch verify multiple proofs.
 */

import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { validateBody, aggregateRequestSchema } from '../middleware.js';
import { aggregateProofs } from '../../verifier/aggregate.js';

const router = Router();

const VKEY_PATH = process.env.ZEROID_VKEY_PATH ??
  path.resolve('circuits/setup/verification_key.json');

/**
 * POST /api/v1/proof/aggregate
 * Batch verify multiple Groth16 proofs in parallel.
 *
 * Body: { proofs: Array<{ proof: object, publicSignals: string[] }> }
 * Returns: { allValid, total, validCount, results }
 */
router.post(
  '/',
  validateBody(aggregateRequestSchema),
  async (req, res) => {
    try {
      const { proofs } = (req as any).validated;

      if (!fs.existsSync(VKEY_PATH)) {
        res.status(503).json({
          error: 'Service Unavailable',
          message: 'Verification key not found. Run trusted setup first.',
        });
        return;
      }

      const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf-8'));
      const result = await aggregateProofs(proofs, vkey);

      res.json(result);
    } catch (err) {
      console.error('Aggregate verification error:', err);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to aggregate proofs',
      });
    }
  },
);

export default router;
