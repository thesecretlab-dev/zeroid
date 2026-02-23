# ZeroID — Product Philosophy

## The Promise to Users

**"Your identity. Your device. Nobody else."**

When you verify with ZeroID, here's what happens — and more importantly, what DOESN'T happen:

### What Happens
1. You scan your ID with your phone camera
2. Your phone reads the text (age, country) — locally, on YOUR chip
3. Your phone generates a mathematical proof: "I am over 18" or "I am not on a sanctions list"
4. That proof — a string of numbers, not your face, not your name — gets sent to the app
5. The app sees: ✅ verified. That's it.

### What Does NOT Happen
- ❌ Your photo is NOT uploaded to any server
- ❌ Your name is NOT stored in any database
- ❌ Your ID number is NOT transmitted over the internet
- ❌ The company you're signing up for NEVER sees your document
- ❌ ZeroID itself does NOT keep your data
- ❌ No government, no hacker, no employee can pull your file — because there IS no file

### Where Does the Data Go?
Nowhere. It stays on your phone for 30 seconds while the math runs, then it's wiped.

The ONLY thing that survives is a **Verifiable Credential** — a cryptographic token stored in your phone's secure enclave (same place your Face ID lives). It says "ZeroID confirmed this person is real and meets the requirements" — signed by us, held by you.

If a regulator legally compels disclosure (subpoena, court order), there IS an encrypted backup — but it requires the regulator's own cryptographic key to unlock. The company can't read it. We can't read it. Only the specific government authority named at verification time can, and only with legal process.

---

## UX: The Most Painless KYC Ever Built

### The Bar: Apple Pay
The entire flow should feel like Apple Pay. Glance. Tap. Done.

### The Flow (3 taps, <15 seconds)

```
[App says "Verify your identity"]
         ↓
    TAP 1: "Verify with ZeroID"
         ↓
    [Camera opens — hold ID in frame]
    [Auto-capture — no button press needed]
    [1-2 second processing spinner]
         ↓
    TAP 2: Face scan (reuses Face ID / fingerprint)
         ↓
    [Proof generates — 200ms in background]
         ↓
    ✅ "You're verified" 
    [Auto-dismiss — user is back in the app]
```

### No:
- No account creation
- No email entry
- No password
- No "upload a photo of your ID" (the camera IS the scanner)
- No "take a selfie holding your ID"
- No waiting 24-48 hours for manual review
- No app download
- No crypto wallet popup
- No seed phrases
- No "connect wallet" buttons
- No blockchain terminology anywhere in the UI

### Yes:
- Auto-capture (ML detects document edges, snaps automatically)
- Instant verification (proof generation is <500ms)
- One credential, infinite apps (verify once, prove everywhere)
- Works in browser (WebAssembly) — no native app required
- Passkey-based (stored in iCloud Keychain / Google Password Manager)
- Progressive trust (start anonymous, reveal more only if needed)

---

## Account Abstraction Integration

ZeroID is designed to be the identity layer for VEIL's account abstraction ecosystem.

### The Problem with Wallets Today
1. User creates a wallet → gets a seed phrase → loses it → funds gone
2. KYC requires uploading passport to a centralized server → data breach → identity stolen
3. dApps can't comply with regulations without becoming centralized custodians

### ZeroID + Account Abstraction = Invisible Onchain Identity

```
┌─────────────────────────────────────────────────────┐
│                    USER SEES                         │
│                                                      │
│   "Sign up"  →  Face scan  →  "Welcome!"            │
│                                                      │
├─────────────────────────────────────────────────────┤
│                  WHAT HAPPENS                        │
│                                                      │
│  1. Passkey created (WebAuthn)                       │
│  2. Smart account deployed (ERC-4337)                │
│  3. ZeroID credential issued (ZK)                    │
│  4. Credential bound to smart account                │
│  5. Gas sponsored by app (paymaster)                 │
│                                                      │
│  User has:                                           │
│  - A wallet (they don't know it's a wallet)          │
│  - A verified identity (they don't know it's ZK)     │
│  - Gas paid for (they don't know what gas is)        │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### How It Works Together

**Passkeys = Private Keys (but human)**
- WebAuthn creates a secp256r1 keypair in the device's secure enclave
- The public key becomes the owner of an ERC-4337 smart account
- No seed phrase. Recovery via iCloud/Google backup. Same as recovering your phone.

**ZeroID Credential = Onchain Identity (but private)**
- The ZK credential is bound to the smart account's address
- The smart account can prove "my owner is KYC'd" without revealing who they are
- Nullifier prevents one person from creating multiple accounts

**Smart Account = Wallet (but invisible)**  
- ERC-4337 smart contract wallet owned by the passkey
- Paymaster sponsors gas — user never sees ETH/AVAX
- Batched transactions — "approve + swap" in one click
- Social recovery via guardian passkeys (family, friends)

### The Stack

```
User's Phone
├── Passkey (Secure Enclave)
│   └── Controls → Smart Account (ERC-4337)
│                   ├── Owned by: Passkey pubkey
│                   ├── Identity: ZeroID nullifier
│                   ├── Recovery: Guardian passkeys
│                   └── Gas: Paymaster (app sponsors)
│
├── ZeroID Credential (Secure Enclave)
│   └── Proves → "I am verified" (ZK proof)
│                 ├── Age ≥ threshold ✅
│                 ├── Not sanctioned ✅
│                 ├── Unique human ✅
│                 └── Raw data: NOWHERE
│
└── App (Browser/PWA)
    └── Uses → SDK (@zeroid/sdk)
              ├── Proof generation (WASM)
              ├── Transaction signing (Passkey)
              └── Session management (JWT)
```

### Compliance Model

```
         Normal Operations              Regulatory Audit
         ─────────────────              ────────────────
App sees: nullifier + proof   →   App provides: escrow_id
                                  Regulator uses: their private key
                                  Regulator sees: original ID data
                                  
Nobody else can decrypt it. Ever.
```

### Progressive Disclosure

Not every app needs full KYC. ZeroID supports levels:

| Level | What's Proven | Use Case |
|-------|---------------|----------|
| 0 | Unique human (sybil-resistant) | Social media, voting |
| 1 | Age ≥ 18 | Gaming, content |
| 2 | Age + Country | Financial lite |
| 3 | Full KYC (age + country + sanctions + liveness) | Banking, exchanges |
| 4 | Accredited investor | Securities, private sales |

Users start at Level 0 (one face scan) and progressively unlock higher levels only when an app requires it. Each level reuses the existing credential — no re-scanning.

---

## Why This Wins

**For Users:** "I scanned my face once. Now every app knows I'm real, and none of them know who I am."

**For Businesses:** "We're fully compliant. We verified every user. We store zero PII. Our breach liability is zero."

**For Regulators:** "The data exists. It's encrypted for us specifically. We can access it with legal process. The system is more compliant than traditional KYC because the audit trail is cryptographic."

**For VEIL Ecosystem:** "Every user gets an invisible wallet, a private identity, and sponsored gas. Web3 that feels like Web2. Privacy that's actually real."
