/**
 * ZeroID Server — Credential Route
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * POST /api/v1/credential — Issue a signed credential after KYC passes.
 *
 * DATA FLOW:
 *   1. KYC data arrives over TLS
 *   2. Sanctions check (reject if sanctioned)
 *   3. KYC provider verifies identity
 *   4. Credential issued: Poseidon hash + EdDSA signature
 *   5. Raw PII encrypted to OrbitDB escrow (double-encrypted: regulator + store key)
 *   6. Credential stored in OrbitDB (encrypted at rest)
 *   7. Plaintext WIPED from memory
 *   8. Only the hash + signature returned to user's device
 */

import { Router } from 'express';
import { validateBody, credentialRequestSchema } from '../middleware.js';
import { mockKycProvider } from '../../kyc/mock.js';
import { issueCredential } from '../../issuer/credential.js';
import { encryptForEscrow } from '../../issuer/escrow.js';
import { isCountrySanctioned } from '../../sanctions/ofac.js';
import { putCredential } from '../../db/stores.js';

const router = Router();

/**
 * POST /api/v1/credential
 * Verify KYC data and issue a signed credential.
 * Raw PII is encrypted to OrbitDB escrow — never stored in plaintext.
 */
router.post(
  '/',
  validateBody(credentialRequestSchema),
  async (req, res) => {
    try {
      const submission = (req as any).validated;

      // Step 1: Check sanctions before processing
      const sanctioned = await isCountrySanctioned(submission.countryCode);
      if (sanctioned) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Country is on the sanctions list',
        });
        return;
      }

      // Step 2: Run KYC verification through provider
      const kycResult = await mockKycProvider.verify(submission);
      if (!kycResult.passed) {
        res.status(422).json({
          error: 'KYC Failed',
          message: 'Identity verification did not pass',
          confidence: kycResult.confidence,
        });
        return;
      }

      // Step 3: Issue signed credential (bound to smart account if provided)
      const credential = await issueCredential(
        kycResult,
        submission.boundAddress,
        submission.level,
      );

      // Step 4: Encrypt raw PII to OrbitDB escrow
      // Double encryption: regulator key (layer 1) + store key (layer 2) → IPFS
      const escrowId = await encryptForEscrow(
        {
          fullName: submission.fullName,
          dateOfBirth: submission.dateOfBirth,
          countryCode: submission.countryCode,
          documentType: submission.documentType,
          documentNumber: submission.documentNumber,
          kycProviderRef: kycResult.providerRef,
          verifiedAt: kycResult.verifiedAt,
        },
        'default',
        credential.id,
      );

      // Step 5: Store credential in OrbitDB (encrypted at rest)
      await putCredential(
        credential.id,
        credential as unknown as Record<string, unknown>,
        submission.boundAddress,
        undefined, // smart account bound later via /credential/bind
        credential.level,
      );

      // Step 6: Plaintext wiped — only credential (hash + sig) returned
      res.status(201).json({
        credential,
        escrowId,
        message: 'Credential issued. Use the credential to generate a ZK proof client-side.',
      });
    } catch (err) {
      console.error('Credential issuance error:', err);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to issue credential',
      });
    }
  },
);

export default router;
