/**
 * ZeroID Server — Proof Aggregation
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Batch-verifies multiple Groth16 proofs in parallel.
 * Future: recursive proof aggregation via SNARK composition.
 */

import { verifyProofWithKey } from './verify.js';

/** A single proof to aggregate */
export interface AggregateProofEntry {
  proof: Record<string, unknown>;
  publicSignals: string[];
}

/** Result of an individual proof within a batch */
export interface AggregateResultEntry {
  index: number;
  valid: boolean;
  error?: string;
}

/** Result of batch verification */
export interface AggregateResult {
  /** True if ALL proofs are valid */
  allValid: boolean;
  /** Total number of proofs */
  total: number;
  /** Number of valid proofs */
  validCount: number;
  /** Individual results */
  results: AggregateResultEntry[];
}

/**
 * Batch-verify multiple Groth16 proofs in parallel.
 *
 * @param proofs - Array of proof + publicSignals pairs
 * @param vkey - Verification key object (shared across all proofs)
 * @returns Aggregate verification result
 */
export async function aggregateProofs(
  proofs: AggregateProofEntry[],
  vkey: Record<string, unknown>,
): Promise<AggregateResult> {
  if (proofs.length === 0) {
    return { allValid: true, total: 0, validCount: 0, results: [] };
  }

  // Verify all proofs in parallel
  const results = await Promise.allSettled(
    proofs.map(async (entry, index): Promise<AggregateResultEntry> => {
      try {
        const valid = await verifyProofWithKey(
          entry.proof,
          entry.publicSignals,
          vkey,
        );
        return { index, valid };
      } catch (err) {
        return {
          index,
          valid: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        };
      }
    }),
  );

  const entries: AggregateResultEntry[] = results.map((r) =>
    r.status === 'fulfilled'
      ? r.value
      : { index: 0, valid: false, error: 'Verification threw unexpectedly' },
  );

  const validCount = entries.filter((e) => e.valid).length;

  return {
    allValid: validCount === proofs.length,
    total: proofs.length,
    validCount,
    results: entries,
  };
}
