/**
 * ZeroID Widget — React Hook
 * © thesecretlab | "Verify the human. Drop the liability."
 */

import { useState, useCallback, useRef } from 'react';
import {
  ZeroID,
  generateProof,
  type ZeroIdConfig,
  type ProofRequirement,
  type Proof,
  type ProverConfig,
  type Credential,
} from '@zeroid/sdk';

export type ZeroIdStatus =
  | 'idle'
  | 'initializing'
  | 'kyc_pending'
  | 'generating_proof'
  | 'complete'
  | 'error';

export interface UseZeroIdConfig extends ZeroIdConfig {
  /** Prover configuration (WASM + zkey URLs) */
  prover?: ProverConfig;
}

export interface UseZeroIdReturn {
  /** Start the verification flow */
  startVerification: (
    userId: string,
    requirements: ProofRequirement[],
  ) => Promise<void>;
  /** The generated proof (available when status === 'complete') */
  proof: Proof | null;
  /** Public signals from the proof */
  publicSignals: string[] | null;
  /** Current status of the verification flow */
  status: ZeroIdStatus;
  /** Error message if status === 'error' */
  error: string | null;
  /** Reset the hook state */
  reset: () => void;
}

const DEFAULT_PROVER_CONFIG: ProverConfig = {
  wasmUrl: '/circuits/kyc_verifier.wasm',
  zkeyUrl: '/circuits/kyc_verifier_final.zkey',
};

/**
 * React hook for ZeroID verification.
 *
 * @example
 * ```tsx
 * const { startVerification, proof, status, error } = useZeroId({
 *   apiKey: 'zid_live_...',
 * });
 *
 * const handleVerify = () => {
 *   startVerification('user-123', [{ type: 'age_gte', value: 18 }]);
 * };
 * ```
 */
export function useZeroId(config: UseZeroIdConfig): UseZeroIdReturn {
  const [status, setStatus] = useState<ZeroIdStatus>('idle');
  const [proof, setProof] = useState<Proof | null>(null);
  const [publicSignals, setPublicSignals] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const clientRef = useRef<ZeroID | null>(null);

  // Lazily initialize the client
  const getClient = useCallback(() => {
    if (!clientRef.current) {
      clientRef.current = new ZeroID(config);
    }
    return clientRef.current;
  }, [config]);

  const reset = useCallback(() => {
    setStatus('idle');
    setProof(null);
    setPublicSignals(null);
    setError(null);
  }, []);

  const startVerification = useCallback(
    async (userId: string, requirements: ProofRequirement[]) => {
      try {
        reset();
        setStatus('initializing');

        const client = getClient();

        // Step 1: Request verification (server-side KYC)
        setStatus('kyc_pending');
        const { id: verificationId } = await client.requestVerification(
          userId,
          requirements,
        );

        // Step 2: Poll for credential issuance
        let credential: Credential | undefined;
        const maxAttempts = 60;
        for (let i = 0; i < maxAttempts; i++) {
          const statusResp = await client.getProofStatus(verificationId);

          if (statusResp.status === 'failed') {
            throw new Error(statusResp.error ?? 'Verification failed');
          }

          if (statusResp.credential) {
            credential = statusResp.credential;
            break;
          }

          // Wait 2 seconds between polls
          await new Promise((r) => setTimeout(r, 2000));
        }

        if (!credential) {
          throw new Error('Verification timed out waiting for credential');
        }

        // Step 3: Generate proof client-side
        setStatus('generating_proof');
        const proverConfig = config.prover ?? DEFAULT_PROVER_CONFIG;

        const result = await generateProof(proverConfig, {
          userAge: 0, // These come from the credential flow — placeholder for hook API
          userCountry: 0,
          userSecret: '0',
          issuerSignatureR8: credential.signatureR8,
          issuerSignatureS: credential.signatureS,
          issuerPubKey: credential.issuerPubKey,
          requiredAge: requirements.find((r) => r.type === 'age_gte')?.value ?? 18,
          restrictedCountryCode:
            requirements.find((r) => r.type === 'country_not')?.value ?? 0,
          appId: '1',
        });

        setProof(result.proof);
        setPublicSignals(result.publicSignals);
        setStatus('complete');
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        setError(message);
        setStatus('error');
      }
    },
    [config, getClient, reset],
  );

  return {
    startVerification,
    proof,
    publicSignals,
    status,
    error,
    reset,
  };
}
