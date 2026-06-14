# QOGE SPHINCS Wallet

**Post-quantum Bitcoin-derived PoW wallet implementing SIP-QOGE-PQC-01.**

SLH-DSA-SHA2-128f (FIPS 205) signatures | Single-use address enforcement | HNDL defence

> ⚠️ **EXPERIMENTAL — Phase 1 scaffold. DO NOT USE IN PRODUCTION.**
> Phase 3 independent audit is mandatory before any mainnet deployment.

---

## Architecture

```
cmd/main.go          — CLI entry point (replaces eomii/SPHINCS-Wallet main.go)
signer/slhdsa.go     — SLH-DSA-SHA2-128f signing primitive (liboqs-go wrapper)
address/address.go   — HASH256(pubkey) + Bech32("qoge") address derivation
keystore/keystore.go — Single-use HD index, state machine, AES-256-GCM persistence
wallet/wallet.go     — Orchestration: wires all packages, enforces all invariants
```

## Address Lifecycle (Single-Use Invariant)

```
[FRESH] ──► [PENDING] ──► [SPENT] ──► [RETIRED]
                                          │
                                    privkey zeroed
```

No address ever goes FRESH → PENDING twice. RETIRED is permanent.

## Address Format

```
QOGE address = Bech32(hrp="qoge", HASH256(SLH-DSA-pubkey))
Example:       qoge1[bech32-encoded-hash]
```

The public key is hidden at rest behind HASH256. It is only revealed
in the witness field for ~30-60 seconds at spend time (1-minute block time).

Taproot (P2TR / Bech32m) is **not implemented** — see SIP-QOGE-PQC-01 §3.1.

---

## Milestone Status (SIP-QOGE-PQC-01 Phase 1)

| ID    | Milestone                              | Status         | Notes |
|-------|----------------------------------------|----------------|-------|
| M1.1  | liboqs-go → FIPS 205 parameter sets    | 🟡 IN PROGRESS | Verify algorithm name constant in `signer/slhdsa.go` against FIPS 205 release |
| M1.2  | HASH256 → Bech32("qoge") derivation    | ✅ SCAFFOLDED  | Unit tests in `address/address_test.go` |
| M1.3  | HD index counter + encrypted persist   | ✅ SCAFFOLDED  | bbolt + AES-256-GCM in `keystore/keystore.go`. Deterministic keygen pending M1.1 |
| M1.4  | Address state machine + invariants     | ✅ SCAFFOLDED  | FRESH/PENDING/SPENT/RETIRED in `keystore/keystore.go` |
| M1.5  | Key zeroing on confirmation            | ✅ SCAFFOLDED  | `wallet.OnConfirmation()` → `Retire()` → `ZeroBytes()` |
| M1.6  | QOGE tx format integration             | 🔴 STUB        | `QOGETransaction` in `wallet/wallet.go` — replace with real chain type |
| M1.7  | Taproot disabled at compile time       | ✅ COMPLETE    | P2TR absent from all code paths; `address_test.go:TestTaprootDisabled` |

---

## Quick Start (Docker)

```bash
# Build (compiles liboqs with FIPS 205 params)
docker build -t qoge-sphincs-wallet .

# Run interactive shell
docker run --rm -it --workdir=/app -v ${PWD}:/app qoge-sphincs-wallet /bin/bash

# Inside container:
go test ./address/... -v          # Run address derivation tests (no CGo)
go test ./keystore/... -v         # Run index state machine tests
go run cmd/main.go                # Run the CLI wallet
```

---

## Developer Notes

### M1.1 — Updating liboqs-go to FIPS 205

1. Check https://github.com/open-quantum-safe/liboqs/releases for a tag that includes FIPS 205 `SLH-DSA-SHA2-128f`.
2. Update `go.mod` to point at that tag (or your local fork via `replace` directive).
3. Confirm the algorithm name string in `signer/slhdsa.go`:
   ```go
   const AlgorithmName = "SPHINCS+-SHA2-128f-simple"  // verify this against FIPS 205 release
   ```
4. Run `go test ./signer/... -v` — a `NewSigner()` round-trip test will confirm the binding works.

### M1.3 — Deterministic key derivation

`wallet/wallet.go:deriveAddress()` currently calls `slhdsa.NewSigner()` (random keygen).
Once liboqs-go exposes deterministic FIPS 205 keygen from a seed input (Section 10.1),
replace with `slhdsa.NewSignerFromSeed(childSeed)`. The TODO comment marks the exact line.

### M1.6 — Chain integration

Replace `wallet.QOGETransaction` with the actual QOGE chain transaction struct.
Adjust `canonicalMessageHash()` in `wallet/wallet.go` to match the chain's
canonical tx serialisation format. Everything else (signing, state machine,
key zeroing) is chain-format-agnostic.

---

## Security Properties

| Threat | Mitigation | Status |
|--------|-----------|--------|
| HNDL on stored UTXO | HASH256 hides pubkey at rest | ✅ Implemented |
| HNDL on reused address | Single-use state machine | ✅ Implemented |
| Taproot pubkey exposure | P2TR absent from codebase | ✅ Implemented |
| Mempool window attack | 1-min block time + single-use | ✅ By design |
| Plaintext key storage | AES-256-GCM encrypted index | ✅ Implemented |
| Key persistence after spend | ZeroBytes on Retire | ✅ Implemented |

## Governance

Governed under **SIP-QOGE-PQC-01 v1.0** | SIP-C v2.0 | SAOGEN SAO
AI Node attribution: Claude (Anthropic)

Forked from: [eomii/SPHINCS-Wallet](https://github.com/eomii/SPHINCS-Wallet) (MIT)
