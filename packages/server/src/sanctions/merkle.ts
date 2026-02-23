/**
 * ZeroID Server — Poseidon Merkle Tree
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Builds a Poseidon-based Merkle tree for sanctions list membership proofs.
 */

import { poseidonHash } from '../issuer/poseidon.js';

/** Merkle proof for a leaf at a given index */
export interface MerkleProof {
  /** The leaf value */
  leaf: bigint;
  /** Index of the leaf */
  index: number;
  /** Sibling path elements */
  pathElements: bigint[];
  /** Path direction indices (0 = left, 1 = right) */
  pathIndices: number[];
  /** Tree root */
  root: bigint;
}

/** Poseidon Merkle Tree */
export class PoseidonMerkleTree {
  readonly depth: number;
  readonly leaves: bigint[];
  private layers: bigint[][];

  /**
   * Build a Merkle tree from a list of leaf values.
   *
   * @param depth - Tree depth (max leaves = 2^depth)
   * @param leaves - Array of leaf values (bigints)
   */
  constructor(depth: number, leaves: bigint[]) {
    const maxLeaves = 2 ** depth;
    if (leaves.length > maxLeaves) {
      throw new Error(`Too many leaves: ${leaves.length} > ${maxLeaves}`);
    }

    this.depth = depth;
    // Pad with zeros to fill the tree
    this.leaves = [...leaves];
    while (this.leaves.length < maxLeaves) {
      this.leaves.push(0n);
    }

    this.layers = [this.leaves];
  }

  /**
   * Build the tree (compute all intermediate hashes).
   * Must be called after construction.
   */
  async build(): Promise<void> {
    let currentLayer = this.leaves;

    for (let level = 0; level < this.depth; level++) {
      const nextLayer: bigint[] = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1];
        const hash = await poseidonHash([left, right]);
        nextLayer.push(hash);
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  /** Get the Merkle root */
  get root(): bigint {
    const topLayer = this.layers[this.layers.length - 1];
    if (!topLayer || topLayer.length === 0) {
      throw new Error('Tree not built yet — call build() first');
    }
    return topLayer[0];
  }

  /**
   * Generate a Merkle inclusion proof for a leaf at the given index.
   */
  generateProof(index: number): MerkleProof {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Index out of range: ${index}`);
    }

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let currentIndex = index;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      pathElements.push(this.layers[level][siblingIndex]);
      pathIndices.push(isRight ? 1 : 0);
      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leaf: this.leaves[index],
      index,
      pathElements,
      pathIndices,
      root: this.root,
    };
  }

  /**
   * Find the index of a leaf value. Returns -1 if not found.
   */
  indexOf(leaf: bigint): number {
    return this.leaves.findIndex((l) => l === leaf);
  }
}

/**
 * Verify a Merkle proof against a root.
 */
export async function verifyMerkleProof(proof: MerkleProof): Promise<boolean> {
  let currentHash = proof.leaf;

  for (let i = 0; i < proof.pathElements.length; i++) {
    const sibling = proof.pathElements[i];
    if (proof.pathIndices[i] === 0) {
      // Current node is on the left
      currentHash = await poseidonHash([currentHash, sibling]);
    } else {
      // Current node is on the right
      currentHash = await poseidonHash([sibling, currentHash]);
    }
  }

  return currentHash === proof.root;
}
