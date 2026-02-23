# ZeroID — Zero-Knowledge Identity Infrastructure

**"Verify the human. Drop the liability."**

TSL product: Privacy-preserving KYC layer using ZK-SNARKs.
Enterprises verify age, citizenship, liveness — store ZERO PII.

## Stack
- **ZK Framework:** Circom 2.1 + SnarkJS (WASM provers, Solidity verifiers)
- **Curve:** BN254 (Groth16)
- **Backend:** Node.js + TypeScript + Express
- **Frontend Widget:** React + Vite + WebAssembly
- **Encryption:** AES-256-GCM (escrow), EdDSA Poseidon (credential signing)
- **Identity:** WebAuthn Passkeys, DID:PKH
- **Escrow:** Encrypted blob storage (regulator-accessible only)
- **Auth:** API key based (B2B customers)

## Security Model
1. Raw PII processed in transient enclave — never persisted in plaintext
2. Credential issued as signed Poseidon hash — user holds private inputs
3. ZK proof generated client-side (browser WASM) — private inputs never leave device
4. Encrypted PII escrow for regulatory compliance — multi-sig regulator keys
5. Proof verification via native ZK compute or on-chain Solidity verifier

## Directory Structure
```
zeroid/
├── circuits/
│   ├── kyc_verifier.circom       — Main KYC circuit
│   ├── age_check.circom          — Age >= threshold
│   ├── country_check.circom      — Country != restricted
│   ├── sanctions_check.circom    — Merkle proof not-in-list
│   ├── sybil_nullifier.circom    — Unique identity nullifier
│   └── scripts/
│       ├── compile.sh            — Compile circuits
│       └── setup.sh              — Trusted setup (powers of tau)
├── contracts/
│   └── ZeroIdVerifier.sol        — Auto-generated Groth16 verifier
├── packages/
│   ├── sdk/                      — @zeroid/sdk (npm package)
│   │   ├── src/
│   │   │   ├── client.ts         — ZeroID API client
│   │   │   ├── prover.ts         — Browser WASM proof generation
│   │   │   ├── types.ts          — TypeScript types
│   │   │   └── index.ts
│   │   └── package.json
│   ├── widget/                   — @zeroid/widget (React drop-in)
│   │   ├── src/
│   │   │   ├── ZeroIdModal.tsx   — KYC capture modal
│   │   │   ├── ProofStatus.tsx   — Proof generation UI
│   │   │   ├── useZeroId.ts      — React hook
│   │   │   └── index.ts
│   │   └── package.json
│   └── server/                   — ZeroID backend
│       ├── src/
│       │   ├── issuer/
│       │   │   ├── credential.ts — Issue signed credentials
│       │   │   ├── escrow.ts     — Encrypt + store PII for regulators
│       │   │   └── poseidon.ts   — Poseidon hash utilities
│       │   ├── verifier/
│       │   │   ├── verify.ts     — Proof verification (snarkjs)
│       │   │   ├── aggregate.ts  — Recursive proof aggregation
│       │   │   └── cache.ts      — Verification result cache
│       │   ├── kyc/
│       │   │   ├── mock.ts       — Mock KYC provider (dev)
│       │   │   ├── onfido.ts     — Onfido integration (prod)
│       │   │   └── types.ts
│       │   ├── sanctions/
│       │   │   ├── ofac.ts       — OFAC list Merkle tree
│       │   │   └── merkle.ts     — Merkle tree utilities
│       │   ├── api/
│       │   │   ├── server.ts     — Express server
│       │   │   ├── middleware.ts  — API key auth, rate limiting
│       │   │   └── routes/
│       │   │       ├── verify.ts     — POST /verify (start KYC)
│       │   │       ├── credential.ts — POST /credential (issue)
│       │   │       ├── proof.ts      — POST /proof/verify
│       │   │       └── aggregate.ts  — POST /proof/aggregate
│       │   ├── crypto/
│       │   │   ├── eddsa.ts      — EdDSA signing (Poseidon)
│       │   │   ├── aes.ts        — AES-256-GCM escrow encryption
│       │   │   └── keys.ts       — Key management
│       │   └── index.ts
│       ├── package.json
│       └── tsconfig.json
├── package.json                  — Workspace root
└── turbo.json
```
