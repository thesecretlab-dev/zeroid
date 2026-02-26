# ZER0ID

**Privacy-preserving identity for the sovereign web.**

ZER0ID proves who you are without revealing what you are. ZK-SNARK circuits generate cryptographic proofs of identity attributes â€” age, jurisdiction, sanctions compliance, sybil resistance â€” without exposing underlying data.

Built for [VEIL](https://veil.markets) agents and humans alike.

## Architecture

```
zeroid/
â”œâ”€â”€ circuits/              Circom ZK circuits
â”‚   â”œâ”€â”€ kyc_verifier.circom        Master KYC verification circuit
â”‚   â”œâ”€â”€ age_check.circom           Age threshold proof
â”‚   â”œâ”€â”€ country_check.circom       Jurisdiction membership proof
â”‚   â”œâ”€â”€ sanctions_check.circom     OFAC sanctions exclusion proof
â”‚   â””â”€â”€ sybil_nullifier.circom     Unique-human nullifier
â”‚
â”œâ”€â”€ contracts/
â”‚   â””â”€â”€ ZeroIdVerifier.sol         On-chain Groth16 verifier
â”‚
â”œâ”€â”€ packages/
â”‚   â”œâ”€â”€ sdk/               Client SDK (TypeScript)
â”‚   â”‚   â”œâ”€â”€ client.ts              API client
â”‚   â”‚   â”œâ”€â”€ prover.ts              Browser-side proof generation
â”‚   â”‚   â”œâ”€â”€ passkey.ts             WebAuthn passkey integration
â”‚   â”‚   â””â”€â”€ types.ts               Shared types
â”‚   â”‚
â”‚   â”œâ”€â”€ server/            Issuer & Verifier (Node.js)
â”‚   â”‚   â”œâ”€â”€ api/                   REST endpoints (credential, proof, verify, aggregate)
â”‚   â”‚   â”œâ”€â”€ crypto/                AES-256, EdDSA, key management
â”‚   â”‚   â”œâ”€â”€ issuer/                Credential issuance, escrow, Poseidon hashing
â”‚   â”‚   â”œâ”€â”€ kyc/                   KYC provider adapters
â”‚   â”‚   â”œâ”€â”€ sanctions/             OFAC Merkle tree, sanctions screening
â”‚   â”‚   â”œâ”€â”€ verifier/              Proof verification, caching, aggregation
â”‚   â”‚   â””â”€â”€ db/                    OrbitDB persistence
â”‚   â”‚
â”‚   â””â”€â”€ widget/            React Components
â”‚       â”œâ”€â”€ ZeroIdModal.tsx         Drop-in verification modal
â”‚       â”œâ”€â”€ ProofStatus.tsx         Proof state display
â”‚       â””â”€â”€ useZeroId.ts           React hook
â”‚
â””â”€â”€ turbo.json             Monorepo pipeline
```

## Trust Levels

| Level | Name | What It Proves |
|-------|------|---------------|
| **L0** | Anonymous | Nothing â€” default state |
| **L1** | Pseudonymous | Unique human (sybil nullifier) |
| **L2** | Verified | Age + jurisdiction + sanctions clear |
| **L3** | Attested | L2 + third-party attestation |
| **L4** | Sovereign | L3 + on-chain identity bond |

## Quick Start

```bash
# Install dependencies
npm install

# Build all packages
npx turbo build

# Run the server
cd packages/server && npm start

# Compile circuits (requires circom + snarkjs)
cd circuits/scripts && ./compile.sh && ./setup.sh
```

## Integration

```typescript
import { ZeroIdClient } from '@zeroid/sdk';

const client = new ZeroIdClient({ endpoint: 'https://api.zeroid.dev' });

// Generate a proof of age â‰¥ 18 without revealing DOB
const proof = await client.prove('age_check', {
  threshold: 18,
  credential: userCredential,
});

// Verify on-chain or off-chain
const valid = await client.verify(proof);
```

### React Widget

```tsx
import { ZeroIdModal } from '@zeroid/widget';

<ZeroIdModal
  checks={['age_check', 'sanctions_check']}
  onVerified={(proof) => handleProof(proof)}
/>
```

## How It Works

1. **Credential Issuance** â€” User completes KYC with a provider. ZER0ID issues a signed credential containing hashed attributes (never raw data).
2. **Proof Generation** â€” Client-side Circom circuits generate a Groth16 proof that specific attributes satisfy constraints (e.g., age â‰¥ 18) without revealing the attributes themselves.
3. **Verification** â€” Proofs are verified on-chain via `ZeroIdVerifier.sol` or off-chain via the server API. The verifier learns only the boolean result.
4. **Nullifiers** â€” Sybil nullifiers ensure one-proof-per-human without linking proofs to identities.

## Stack

`Circom` Â· `Groth16` Â· `snarkjs` Â· `Solidity` Â· `TypeScript` Â· `React` Â· `OrbitDB` Â· `WebAuthn`

## Links

- **Product Page**: [thesecretlab.app/kyc](https://thesecretlab.app/kyc)
- **VEIL Ecosystem**: [veil.markets](https://veil.markets)
- **Parent Org**: [thesecretlab](https://github.com/thesecretlab-dev)

---

*Prove who you are without revealing what you are.*
