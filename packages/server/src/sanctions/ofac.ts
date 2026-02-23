/**
 * ZeroID Server — OFAC Sanctions List
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Builds a Poseidon Merkle tree from the OFAC sanctions list.
 * Currently uses mock data — in production, fetch from OFAC SDN list.
 */

import { PoseidonMerkleTree } from './merkle.js';

/** Merkle tree depth (supports up to 2^10 = 1024 entries) */
const TREE_DEPTH = 10;

/**
 * Mock OFAC sanctioned country codes (ISO 3166-1 numeric).
 * In production, this would be fetched from the OFAC SDN list
 * and include entity-level sanctions, not just countries.
 */
const SANCTIONED_COUNTRY_CODES: number[] = [
  408, // North Korea (DPRK)
  364, // Iran
  760, // Syria
  192, // Cuba
  728, // South Sudan
  // Add more as needed from OFAC SDN list
];

/** Singleton tree instance */
let sanctionsTree: PoseidonMerkleTree | null = null;

/**
 * Build (or return cached) the sanctions Merkle tree.
 */
export async function getSanctionsTree(): Promise<PoseidonMerkleTree> {
  if (sanctionsTree) return sanctionsTree;

  const leaves = SANCTIONED_COUNTRY_CODES.map((code) => BigInt(code));
  sanctionsTree = new PoseidonMerkleTree(TREE_DEPTH, leaves);
  await sanctionsTree.build();

  console.log(`📋 Sanctions Merkle tree built: ${leaves.length} entries, root: ${sanctionsTree.root}`);

  return sanctionsTree;
}

/**
 * Check if a country code is in the sanctions list.
 */
export async function isCountrySanctioned(countryCode: number): Promise<boolean> {
  const tree = await getSanctionsTree();
  return tree.indexOf(BigInt(countryCode)) !== -1;
}

/**
 * Get the sanctioned country codes list.
 */
export function getSanctionedCountries(): number[] {
  return [...SANCTIONED_COUNTRY_CODES];
}

/**
 * Refresh the sanctions tree (e.g., after updating the list).
 */
export async function refreshSanctionsTree(): Promise<void> {
  sanctionsTree = null;
  await getSanctionsTree();
}
