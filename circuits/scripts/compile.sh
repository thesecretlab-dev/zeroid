#!/usr/bin/env bash
# ============================================================================
# ZeroID — Circuit Compilation Script
# © thesecretlab | "Verify the human. Drop the liability."
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUIT_DIR/build"

echo "🔐 ZeroID Circuit Compiler"
echo "=========================="

# Create build directory
mkdir -p "$BUILD_DIR"

# Check for circom
if ! command -v circom &> /dev/null; then
    echo "❌ circom not found. Install from https://docs.circom.io/getting-started/installation/"
    exit 1
fi

echo "📦 Compiling kyc_verifier.circom..."
circom "$CIRCUIT_DIR/kyc_verifier.circom" \
    --r1cs \
    --wasm \
    --sym \
    --output "$BUILD_DIR" \
    -l "$CIRCUIT_DIR/node_modules"

echo ""
echo "✅ Compilation complete!"
echo "   R1CS:  $BUILD_DIR/kyc_verifier.r1cs"
echo "   WASM:  $BUILD_DIR/kyc_verifier_js/kyc_verifier.wasm"
echo "   SYM:   $BUILD_DIR/kyc_verifier.sym"
echo ""

# Print circuit info
if command -v snarkjs &> /dev/null; then
    echo "📊 Circuit info:"
    snarkjs r1cs info "$BUILD_DIR/kyc_verifier.r1cs"
fi
