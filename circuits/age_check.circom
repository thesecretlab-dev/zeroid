// ============================================================================
// ZeroID — Age Check Circuit
// © thesecretlab | "Verify the human. Drop the liability."
// ============================================================================
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/comparators.circom";

// AgeCheck: Proves that `userAge` >= `requiredAge` without revealing exact age.
// Parameter `bits` defines the bit-width for comparison (e.g., 8 for ages 0-255).
template AgeCheck(bits) {
    signal input userAge;
    signal input requiredAge;
    signal output valid;

    // LessThan(n) outputs 1 if in[0] < in[1], else 0.
    // We want userAge >= requiredAge, i.e., NOT (userAge < requiredAge).
    component lt = LessThan(bits);
    lt.in[0] <== userAge;
    lt.in[1] <== requiredAge;

    // lt.out == 0 means userAge >= requiredAge
    valid <== 1 - lt.out;

    // Constrain: the check MUST pass
    valid === 1;
}
