/**
 * ZeroID Server — Mock KYC Provider
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Returns fake extracted data for development and testing.
 * DO NOT use in production.
 */

import type { KycProvider, KycSubmission, KycResult } from './types.js';

/**
 * Mock KYC provider that simulates identity verification.
 * Always passes unless the name contains "REJECT".
 */
export const mockKycProvider: KycProvider = {
  name: 'mock',

  async verify(submission: KycSubmission): Promise<KycResult> {
    // Simulate processing delay (500-1500ms)
    await new Promise((r) => setTimeout(r, 500 + Math.random() * 1000));

    // Simulate rejection for testing
    const shouldReject = submission.fullName.toUpperCase().includes('REJECT');

    return {
      passed: !shouldReject,
      fullName: submission.fullName,
      dateOfBirth: submission.dateOfBirth,
      countryCode: submission.countryCode,
      documentType: submission.documentType,
      documentNumber: submission.documentNumber,
      confidence: shouldReject ? 0.15 : 0.95 + Math.random() * 0.05,
      providerRef: `mock_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      verifiedAt: Date.now(),
    };
  },
};
