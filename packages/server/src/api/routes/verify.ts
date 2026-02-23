/**
 * ZeroID Server — Verify Route
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * POST /api/v1/verify — Start a KYC verification flow.
 */

import { Router } from 'express';
import crypto from 'node:crypto';
import { validateBody, verifyRequestSchema } from '../middleware.js';

const router = Router();

/** In-memory verification store (use database in production) */
const verifications = new Map<
  string,
  {
    id: string;
    userId: string;
    requirements: Array<{ type: string; value: number }>;
    status: string;
    createdAt: number;
  }
>();

/** Exported for other routes to access */
export { verifications };

/**
 * POST /api/v1/verify
 * Start a new KYC verification for a user.
 *
 * Body: { userId: string, requirements: ProofRequirement[] }
 * Returns: { id: string, status: string }
 */
router.post(
  '/',
  validateBody(verifyRequestSchema),
  (req, res) => {
    const { userId, requirements } = (req as any).validated;

    const id = crypto.randomUUID();
    const verification = {
      id,
      userId,
      requirements,
      status: 'pending',
      createdAt: Date.now(),
    };

    verifications.set(id, verification);

    res.status(201).json({
      id,
      status: 'pending',
      message: 'Verification initiated. Submit KYC data to /api/v1/credential.',
    });
  },
);

/**
 * GET /api/v1/verify/:id
 * Get the status of a verification.
 */
router.get('/:id', (req, res) => {
  const verification = verifications.get(req.params.id);
  if (!verification) {
    res.status(404).json({ error: 'Not Found', message: 'Verification not found' });
    return;
  }

  res.json({
    id: verification.id,
    status: verification.status,
    userId: verification.userId,
    requirements: verification.requirements,
    createdAt: verification.createdAt,
  });
});

export default router;
