// ============================================================================
// ZeroID — Sybil Nullifier Circuit
// © thesecretlab | "Verify the human. Drop the liability."
// ============================================================================
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";

// SybilNullifier: Generates a deterministic nullifier from (userSecret, appId).
// The nullifier is unique per user per application, preventing duplicate
// registrations (Sybil attacks) without revealing the user's identity.
//
// nullifier = Poseidon(userSecret, appId)
//
// PRIVACY: One credential works across ALL apps without linkability.
// Each app gets a DIFFERENT nullifier (because appId differs), so App A
// cannot correlate a user with App B. The userSecret never leaves the device.
//
// - userSecret: private identity commitment known only to the user
// - appId: public application identifier
// - nullifier: public output, checked on-chain for uniqueness
template SybilNullifier() {
    signal input userSecret;  // Private: user's secret identity key
    signal input appId;       // Public: application identifier
    signal output nullifier;  // Public: unique per (user, app) pair

    component hasher = Poseidon(2);
    hasher.inputs[0] <== userSecret;
    hasher.inputs[1] <== appId;

    nullifier <== hasher.out;
}
