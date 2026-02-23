#!/usr/bin/env bash
# ============================================================================
# ZeroID — Trusted Setup Script (Powers of Tau + Circuit-Specific Setup)
# © thesecretlab | "Verify the human. Drop the liability."
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUIT_DIR/build"
SETUP_DIR="$CIRCUIT_DIR/setup"

echo "🔐 ZeroID Trusted Setup"
echo "========================"

# Check prerequisites
if ! command -v snarkjs &> /dev/null; then
    echo "❌ snarkjs not found. Install: npm install -g snarkjs"
    exit 1
fi

if [ ! -f "$BUILD_DIR/kyc_verifier.r1cs" ]; then
    echo "❌ R1CS file not found. Run compile.sh first."
    exit 1
fi

mkdir -p "$SETUP_DIR"

# --- Phase 1: Powers of Tau (universal) ---
echo ""
echo "⚡ Phase 1: Powers of Tau ceremony..."

PTAU_POWER=14  # 2^14 = 16384 constraints (adjust if circuit is larger)
PTAU_FILE="$SETUP_DIR/pot${PTAU_POWER}_final.ptau"

if [ ! -f "$PTAU_FILE" ]; then
    echo "  → Starting new ceremony (2^${PTAU_POWER})..."
    snarkjs powersoftau new bn128 "$PTAU_POWER" "$SETUP_DIR/pot${PTAU_POWER}_0000.ptau" -v

    echo "  → Contributing entropy..."
    snarkjs powersoftau contribute \
        "$SETUP_DIR/pot${PTAU_POWER}_0000.ptau" \
        "$SETUP_DIR/pot${PTAU_POWER}_0001.ptau" \
        --name="ZeroID Phase 1 Contribution" \
        --entropy="$(head -c 64 /dev/urandom | xxd -p -c 128)" -v

    echo "  → Applying beacon..."
    snarkjs powersoftau beacon \
        "$SETUP_DIR/pot${PTAU_POWER}_0001.ptau" \
        "$SETUP_DIR/pot${PTAU_POWER}_beacon.ptau" \
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" 10 -v

    echo "  → Preparing phase 2..."
    snarkjs powersoftau prepare phase2 \
        "$SETUP_DIR/pot${PTAU_POWER}_beacon.ptau" \
        "$PTAU_FILE" -v

    # Clean up intermediate files
    rm -f "$SETUP_DIR/pot${PTAU_POWER}_0000.ptau" \
          "$SETUP_DIR/pot${PTAU_POWER}_0001.ptau" \
          "$SETUP_DIR/pot${PTAU_POWER}_beacon.ptau"

    echo "  ✅ Phase 1 complete: $PTAU_FILE"
else
    echo "  ✅ Using existing PTAU: $PTAU_FILE"
fi

# --- Phase 2: Circuit-Specific Setup ---
echo ""
echo "⚡ Phase 2: Circuit-specific setup..."

ZKEY_FILE="$SETUP_DIR/kyc_verifier_final.zkey"
VKEY_FILE="$SETUP_DIR/verification_key.json"

echo "  → Generating initial zkey..."
snarkjs groth16 setup \
    "$BUILD_DIR/kyc_verifier.r1cs" \
    "$PTAU_FILE" \
    "$SETUP_DIR/kyc_verifier_0000.zkey" -v

echo "  → Contributing to phase 2..."
snarkjs zkey contribute \
    "$SETUP_DIR/kyc_verifier_0000.zkey" \
    "$SETUP_DIR/kyc_verifier_0001.zkey" \
    --name="ZeroID Phase 2 Contribution" \
    --entropy="$(head -c 64 /dev/urandom | xxd -p -c 128)" -v

echo "  → Applying final beacon..."
snarkjs zkey beacon \
    "$SETUP_DIR/kyc_verifier_0001.zkey" \
    "$ZKEY_FILE" \
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" 10 -v

# Clean up intermediate zkeys
rm -f "$SETUP_DIR/kyc_verifier_0000.zkey" \
      "$SETUP_DIR/kyc_verifier_0001.zkey"

echo "  → Exporting verification key..."
snarkjs zkey export verificationkey "$ZKEY_FILE" "$VKEY_FILE"

echo ""
echo "✅ Setup complete!"
echo "   ZKEY: $ZKEY_FILE"
echo "   VKEY: $VKEY_FILE"
echo ""

# Optionally export Solidity verifier
echo "📝 Exporting Solidity verifier..."
snarkjs zkey export solidityverifier "$ZKEY_FILE" "$CIRCUIT_DIR/../contracts/Groth16Verifier.sol"
echo "   Solidity verifier: contracts/Groth16Verifier.sol"
