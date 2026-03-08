# ZKP Credential Wallet — ISEAHackathon

A **Zero-Knowledge Proof credential system** built in Rust with a JavaScript bridge, enabling privacy-preserving verification of identity attributes (age, nationality) without revealing any underlying personal data.

---

## 🔍 Project Overview

This project implements a zkSNARK-based credential wallet using:

- **Nova / SuperNova** — Incremental Verifiable Computation (IVC) with a two-curve cycle (`E1`/`E2`) for recursive proving
- **BN254 elliptic curve** — for PS signature scheme and NIZK proofs
- **Spartan / CompressedSNARK** — for proof compression
- **PS Signatures** — for credential issuance and rerandomisation
- **Neon (Node.js native bindings)** — for JavaScript interop via a native `.node` module

A user can prove predicates about their credentials (e.g. *"I am over 18"* or *"I am from country X"*) to a verifier **without revealing** their actual date of birth or nationality.
---

## 🗂 Project Structure
```
.
├── src/
│   ├── main.rs                  # Entry point
│   ├── wallet_core.rs           # Core ZKP proving logic (prove_credential)
│   ├── machine.rs               # PublicParams setup & credential machine runner
│   ├── credential_machine.rs    # SuperNova step circuit definitions
│   ├── bn254_ps.rs              # PS signature scheme on BN254
│   ├── ps_rand.rs               # PsRand circuit (signature rerandomisation)
│   ├── ps_dob.rs                # PsDob circuit (age predicate)
│   └── ps_nat.rs                # PsNat circuit (nationality predicate)
├── js/
│   ├── wallet.js                # JS wallet interface
│   ├── issuer.js                # JS credential issuer
│   ├── wallet_bridge.js         # Native bridge for wallet
│   ├── demo_bridge.js           # Demo bridge
│   └── demo.js                  # End-to-end demo
├── native/
│   └── index.node               # Compiled Rust native module
├── Cargo.toml
└── package.json
```

---


### Prerequisites

- [Rust](https://rustup.rs/) (stable, 1.75+)
- [Node.js](https://nodejs.org/) (v18+)
- [npm](https://www.npmjs.com/)

### 1. Clone the repository
```bash
git clone https://github.com/zephyr7723/ISEAHackathon.git
cd ISEAHackathon
```

### 2. Build the Rust library
```bash
cargo build --release
```

### 3. Install Node.js dependencies
```bash
npm install
```

---

## 🚀 How to Run

### Run the end-to-end demo
```bash
node js/demo.js
```

This will:
1. Issue a PS-signed credential (age + nationality)
2. Generate a ZK proof of the requested predicates
3. Verify the proof — without revealing personal data

### Run via CLI
```bash
Terminal A:
node cli.js verifier listen --port 8080

Terminal B
node cli.js prove --verifier 127.0.0.1:8080
```



---

## 🔐 How It Works

1. **Issuance** — An issuer signs a credential (date of birth, nationality) using a PS signature on BN254.
2. **Request** — A user specifies which predicates to prove (age range, nationality).
3. **Proving** — `prove_credential()` builds a SuperNova IVC proof across 3 circuits:
   - `PsRand` — rerandomises the PS signature
   - `PsDob` — proves age is within a range
   - `PsNat` — proves nationality matches
4. **Compression** — The recursive proof is compressed using Spartan (CompressedSNARK).
5. **Verification** — The verifier checks the compressed proof against public parameters, learning only what was claimed.

### Key Design Decision
`PublicParams` (`pp`) are generated **once** in `machine.rs` and passed into `prove_credential()` — avoiding expensive recomputation on every proof generation.

---

## 🧪 Tech Stack

| Component | Technology |
|-----------|-----------|
| ZK Proving | Nova / SuperNova (Arecibo) |
| Curve | BN254 (Arkworks) |
| Signatures | PS Signature Scheme |
| Compression | Spartan (CompressedSNARK) |
| Language | Rust |
| JS Bridge | Neon (Node.js native bindings) |

---

## 👥 Team

Bimit Mandal\
Protyasha Kundu\
Rupayan Mandal\
Shreyas Gangopadhyay
