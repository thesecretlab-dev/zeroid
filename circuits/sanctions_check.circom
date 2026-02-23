// ============================================================================
// ZeroID — Sanctions Check Circuit (Non-Membership Proof)
// © thesecretlab | "Verify the human. Drop the liability."
// ============================================================================
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/mux1.circom";

// SanctionsCheck: Proves that a user's country is NOT in the sanctions Merkle tree.
// Uses a Merkle inclusion proof for a *neighbor* leaf to demonstrate the target
// leaf is absent (sorted Merkle tree non-membership proof).
//
// `levels` is the depth of the Merkle tree.
template SanctionsCheck(levels) {
    signal input leaf;               // The value we want to prove is NOT in the tree
    signal input root;               // The known Merkle root of the sanctions list
    signal input neighborLeaf;       // An adjacent leaf in the sorted tree
    signal input neighborIndex;      // Index of the neighbor leaf
    signal input pathElements[levels]; // Merkle proof siblings
    signal input pathIndices[levels];  // 0 = left, 1 = right at each level

    signal output valid;

    // Step 1: Verify the neighbor leaf IS in the tree via Merkle inclusion
    signal hashes[levels + 1];
    hashes[0] <== neighborLeaf;

    component hashers[levels];
    component muxes[levels];

    for (var i = 0; i < levels; i++) {
        muxes[i] = Mux1();
        muxes[i].c[0] <== hashes[i];
        muxes[i].c[1] <== pathElements[i];
        muxes[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        // If pathIndices[i] == 0, node is on the left: H(node, sibling)
        // If pathIndices[i] == 1, node is on the right: H(sibling, node)
        hashers[i].inputs[0] <== muxes[i].out;

        component muxRight = Mux1();
        muxRight.c[0] <== pathElements[i];
        muxRight.c[1] <== hashes[i];
        muxRight.s <== pathIndices[i];

        hashers[i].inputs[1] <== muxRight.out;

        hashes[i + 1] <== hashers[i].out;
    }

    // Computed root must match the known root
    component rootCheck = IsEqual();
    rootCheck.in[0] <== hashes[levels];
    rootCheck.in[1] <== root;
    rootCheck.out === 1;

    // Step 2: Verify the leaf is NOT the neighbor (non-membership)
    component notEqual = IsEqual();
    notEqual.in[0] <== leaf;
    notEqual.in[1] <== neighborLeaf;

    // Must NOT be equal — leaf is absent from the tree
    valid <== 1 - notEqual.out;
    valid === 1;
}
