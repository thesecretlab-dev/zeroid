// ============================================================================
// ZeroID — Main KYC Verifier Circuit
// © thesecretlab | "Verify the human. Drop the liability."
//
// Composes all sub-circuits into a single proof:
//   1. EdDSA Poseidon signature verification (credential authenticity)
//   2. Age check (age >= required threshold)
//   3. Country check (country != restricted)
//   4. Sybil nullifier generation (unique per app)
// ============================================================================
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/eddsaposeidon.circom";
include "age_check.circom";
include "country_check.circom";
include "sybil_nullifier.circom";

// PRIVACY MODEL:
//   - Public inputs are visible to the verifier (app / smart contract)
//   - Private inputs NEVER leave the user's device — they are consumed
//     by the WASM prover in-browser and produce only the proof
//   - The nullifier is unique per (user, app) — one credential works
//     across apps without cross-app linkability
//   - Apps request ONLY the proofs they need (progressive disclosure)
//
// MODULARITY: Each sub-circuit is independent. An app requiring only
// age verification triggers only AgeCheck. The full circuit composes
// all checks, but each can be toggled by the proof requirements.
template KYCVerifier() {
    // === Public Inputs (visible to verifier) ===
    signal input issuerPubKey[2];         // EdDSA public key of the credential issuer
    signal input requiredAge;             // Minimum age threshold
    signal input restrictedCountryCode;   // Country code that is disallowed
    signal input appId;                   // Application ID for sybil nullifier (per-app)

    // === Private Inputs (NEVER leave the user's device) ===
    signal input userAge;                 // User's actual age — kept private
    signal input userCountry;             // User's country code — kept private
    signal input userSecret;              // User's secret commitment — kept private
    signal input issuerSignatureR8[2];    // EdDSA signature R8 — kept private
    signal input issuerSignatureS;        // EdDSA signature scalar — kept private

    // === Public Outputs ===
    signal output nullifier;              // Sybil nullifier for on-chain dedup
    signal output credentialHash;         // Hash of the credential (for reference)

    // ----- Step 1: Compute credential hash -----
    // The credential is a Poseidon hash of (userAge, userCountry, userSecret)
    component credHasher = Poseidon(3);
    credHasher.inputs[0] <== userAge;
    credHasher.inputs[1] <== userCountry;
    credHasher.inputs[2] <== userSecret;
    credentialHash <== credHasher.out;

    // ----- Step 2: Verify EdDSA Poseidon signature on the credential hash -----
    // The issuer signed the credential hash with their private key.
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== issuerPubKey[0];
    sigVerifier.Ay <== issuerPubKey[1];
    sigVerifier.R8x <== issuerSignatureR8[0];
    sigVerifier.R8y <== issuerSignatureR8[1];
    sigVerifier.S <== issuerSignatureS;
    sigVerifier.M <== credentialHash;

    // ----- Step 3: Age check -----
    // Prove userAge >= requiredAge (8-bit comparison, supports ages 0-255)
    component ageCheck = AgeCheck(8);
    ageCheck.userAge <== userAge;
    ageCheck.requiredAge <== requiredAge;

    // ----- Step 4: Country check -----
    // Prove userCountry != restrictedCountryCode
    component countryCheck = CountryNotEqual();
    countryCheck.userCountry <== userCountry;
    countryCheck.restrictedCountryCode <== restrictedCountryCode;

    // ----- Step 5: Sybil nullifier -----
    // Generate a unique nullifier = Poseidon(userSecret, appId)
    component sybil = SybilNullifier();
    sybil.userSecret <== userSecret;
    sybil.appId <== appId;
    nullifier <== sybil.nullifier;
}

component main {public [issuerPubKey, requiredAge, restrictedCountryCode, appId]} = KYCVerifier();
