// ============================================================================
// ZeroID — Country Check Circuit
// © thesecretlab | "Verify the human. Drop the liability."
// ============================================================================
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/comparators.circom";

// CountryNotEqual: Proves that `userCountry` != `restrictedCountryCode`.
// Country codes are represented as integers (e.g., ISO 3166-1 numeric).
template CountryNotEqual() {
    signal input userCountry;
    signal input restrictedCountryCode;
    signal output valid;

    component eq = IsEqual();
    eq.in[0] <== userCountry;
    eq.in[1] <== restrictedCountryCode;

    // eq.out == 1 if equal, 0 if not equal
    // We require they are NOT equal
    valid <== 1 - eq.out;

    // Constrain: must not be the restricted country
    valid === 1;
}
