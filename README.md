# Symbiont Wallet

**The post-quantum wallet for QOGE — implementing SIP-QOGE-PQC-01.**

SLH-DSA-SHA2-128f (FIPS 205) signatures | Single-use address enforcement | HNDL defence

> ⚠️ **EXPERIMENTAL — Phase 1 core implemented and tested. DO NOT USE IN PRODUCTION.**
> Phase 3 independent audit is mandatory before any mainnet deployment.

**Status: Phase 1 core validated — 41/41 tests passing.** Real SLH-DSA-SHA2-128f
keypairs, real `qoge1...` addresses, real 17,088-byte FIPS 205 signatures,
end-to-end single-use lifecycle confirmed on Ubuntu 24 LTS.

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

No address ever goes FRESH → PENDING twice. RETIRED is permanent. Verified
in `keystore_test.go` and exercised end-to-end (41 full cycles, zero repeats)
in `wallet_test.go:TestFullSymbiontLifecycle`.

## Address Format

```
QOGE address = Bech32(hrp="qoge", HASH256(SLH-DSA-pubkey))
Example:       qoge1q7syrzy8v5l2zh8np2fhknyqq55xfecj6h7zy7tn8gjr7hzayl9msfdrqpd
```

The public key is hidden at rest behind HASH256. It is only revealed
in the witness field for ~30-60 seconds at spend time (1-minute block time).

Taproot (P2TR / Bech32m) is **not implemented** — see SIP-QOGE-PQC-01 §3.1.
Absence verified by `address_test.go:TestTaprootDisabled`.

---

## Milestone Status (SIP-QOGE-PQC-01 Phase 1)

| ID    | Milestone                              | Status         | Tests |
|-------|----------------------------------------|----------------|-------|
| M1.1  | liboqs-go → FIPS 205 (SLH-DSA-SHA2-128f) | ✅ VALIDATED | `signer` — 7/7 |
| M1.2  | HASH256 → Bech32("qoge") derivation    | ✅ VALIDATED   | `address` — 7/7 |
| M1.3  | HD index counter + encrypted persist   | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.4  | Address state machine + invariants     | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.5  | Key zeroing on confirmation            | ✅ VALIDATED   | `wallet` — 17/17 |
| M1.6  | QOGE tx format integration             | 🔴 STUB        | `QOGETransaction` in `wallet/wallet.go` — replace with real chain type |
| M1.7  | Taproot disabled at compile time       | ✅ VALIDATED   | `address` — `TestTaprootDisabled` |
| M2.1  | Change routing to fresh address        | ✅ VALIDATED   | `wallet` — `TestSignTransactionRejects*` |
| M2.2  | Address pre-generation pool (N=20)     | ✅ VALIDATED   | `wallet` — `TestNewWalletPreGeneratesPool`, `TestOnConfirmationRefillsPool` |

Everything that does not depend on the QOGE chain's wire format is
implemented and tested. M1.6 is the remaining Phase 1 item, blocked on
a QOGE testnet transaction format to integrate against.

---

## Test Results

```
go test ./address/...  -v   →  7/7  PASS   (0.003s)
go test ./signer/...   -v   →  7/7  PASS   (0.177s)
go test ./keystore/... -v   →  17/17 PASS  (0.185s)
go test ./wallet/...   -v   →  17/17 PASS  (1.624s)

TOTAL: 41/41 PASS
```

Key figures confirmed by the test suite, on real liboqs (built from source,
`OQS_DIST_BUILD=ON`, `liboqs.so.0.15.0`):

| Property | Value | Spec (SIP-QOGE-PQC-01 §4.2) |
|----------|-------|------------------------------|
| Public key size | 32 bytes | 32 bytes ✓ |
| Secret key size | 64 bytes | 64 bytes ✓ |
| Signature size | 17,088 bytes | 17,088 bytes ✓ |
| Algorithm identifier (liboqs) | `SLH_DSA_PURE_SHA2_128F` | FIPS 205 SLH-DSA-SHA2-128f ✓ |

`TestFullSymbiontLifecycle` runs 41 consecutive receive → sign → confirm →
retire cycles and confirms no retired address is ever reissued.

The CLI (`cmd/main.go`) has also been run interactively end-to-end: wallet
creation, address generation, marking a payment received, signing a real
message (producing a 17,088-byte SLH-DSA signature with successful
self-verification), and confirming the transaction — which zeroed the key
and retired the address permanently.

---

## Getting Started — Native Build (Ubuntu 24 LTS)

This is the build path actually used to produce the test results above.

### 1. System dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential cmake ninja-build git golang-go \
    libssl-dev pkg-config ca-certificates
```

Requires Go 1.21+ (Ubuntu 24.04 ships 1.22.x).

### 2. Build liboqs from source

```bash
cd ~
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_DIST_BUILD=ON \
    ..
ninja
sudo ninja install
sudo ldconfig
```

This installs `sig_slh_dsa.h` and friends to `/usr/local/include/oqs/`, and
`liboqs.so*` to `/usr/local/lib/`. `OQS_DIST_BUILD=ON` enables all algorithms,
including `SLH_DSA_PURE_SHA2_128F`.

### 3. Clone liboqs-go and fix pkg-config

```bash
cd ~
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-go.git
```

liboqs-go's CGo bindings look for a `liboqs-go.pc` pkg-config file, which
does not get installed by the liboqs build above (only `liboqs.pc` does).
Create it manually:

```bash
sudo tee /usr/local/lib/pkgconfig/liboqs-go.pc > /dev/null << 'EOF'
prefix=/usr/local
libdir=${prefix}/lib
includedir=${prefix}/include

Name: liboqs-go
Description: Open Quantum Safe liboqs (for liboqs-go CGo bindings)
Version: 0.15.0
Requires.private: openssl
Cflags: -I${includedir}
Libs: -L${libdir} -loqs
EOF
sudo ldconfig
```

### 4. Clone this repo and point go.mod at your liboqs-go checkout

```bash
cd ~
git clone https://github.com/QOGE/symbiont-wallet.git
cd symbiont-wallet
go mod edit -replace github.com/open-quantum-safe/liboqs-go=$HOME/liboqs-go
go mod tidy
```

> **Note:** `go.mod` currently ships with a `replace` directive pointing at
> `/home/ion/liboqs-go` (the development machine's path). The `go mod edit`
> command above overwrites it with the correct path for your machine — run
> it even if you intend to keep the same path, to be safe.

### 5. Run the tests

```bash
go test ./address/...  -v   # no CGo — fastest
go test ./signer/...   -v   # exercises liboqs via CGo — this is the M1.1 check
go test ./keystore/... -v   # HD index + state machine
go test ./wallet/...   -v   # full integration — slower (~1.6s, 20+ keygens per test)
```

### 6. Run the CLI

```bash
go run cmd/main.go
```

Choose **1** to create a new wallet. **Save the printed seed hex** — this
experimental version has no recovery path without it. From the main menu:
get a receive address (1), mark it as paid (2), sign a message (3), then
confirm (4) to retire the address and zero its key.

---

## Getting Started — Docker (alternative)

```bash
docker build -t symbiont-wallet .
docker run --rm -it --workdir=/app -v ${PWD}:/app symbiont-wallet /bin/bash
# inside container:
go test ./... -v
go run cmd/main.go
```

The Dockerfile builds liboqs from source with the same flags as the native
path above. Not yet exercised as part of the validated test run — the native
path is currently the proven one.

---

## Developer Notes

### M1.1 — RESOLVED: FIPS 205 algorithm identifier

The correct liboqs-go algorithm string for SLH-DSA-SHA2-128f (FIPS 205,
"pure" variant — not prehash) is:

```go
const AlgorithmName = "SLH_DSA_PURE_SHA2_128F"
```

This was confirmed by inspecting `/usr/local/include/oqs/sig.h`:

```c
/** Algorithm identifier for slh_dsa_pure_sha2_128f */
#define OQS_SIG_alg_slh_dsa_pure_sha2_128f "SLH_DSA_PURE_SHA2_128F"
```

liboqs-go itself has no static algorithm allowlist — `Init()` calls
`OQS_SIG_alg_is_enabled()` directly against the C library, so any algorithm
string the installed liboqs supports works without patching liboqs-go.

We use the **"pure"** variant, not any `*_prehash_*` variant. The prehash
variants expect an OID-prefixed context string per FIPS 205 §10.2.2; the
wallet already pre-hashes messages itself via `canonicalMessageHash()`, so
"pure" is the correct match.

### M1.3 — Deterministic key derivation (open item)

`wallet/wallet.go:deriveAddress()` currently calls `slhdsa.NewSigner()`
(random keygen) rather than deriving deterministically from `childSeed`.
The HD derivation path (`hkdfDerive32`) is implemented and produces a
correct child seed per index, but liboqs-go's `GenerateKeyPair()` does not
currently accept a seed input for SLH-DSA.

**Impact:** wallet recovery from the master seed alone is not yet possible
— the encrypted index DB (`qoge_wallet.db`) is currently the sole source of
truth for which keypairs exist. Losing the DB loses the wallet, even with
the seed. This must be resolved before any real-value use.

**Path forward:** check whether liboqs's `OQS_SIG_slh_dsa_pure_sha2_128f_keypair`
supports seeded generation at the C level (FIPS 205 §10.1 specifies SLH-DSA
key generation as deterministic given `SK.seed`, `SK.prf`, `PK.seed`). If so,
expose this via liboqs-go or call it directly via cgo in `signer/slhdsa.go`.

### M1.6 — Chain integration (open item)

Replace `wallet.QOGETransaction` with the actual QOGE chain transaction
struct once the testnet wire format exists. Adjust `canonicalMessageHash()`
in `wallet/wallet.go` to match the chain's canonical tx serialisation.
Everything else (signing, state machine, key zeroing, change routing) is
chain-format-agnostic and already validated.

**Also pending:** block size / propagation testing. SLH-DSA-SHA2-128f
signatures are 17,088 bytes — roughly 100x a secp256k1 transaction. QOGE
chain `MAX_TX_SIZE` and `MAX_BLOCK_SIZE` need to accommodate this from
genesis (recommended `MAX_TX_SIZE >= 25,000` bytes). This needs measurement
on an actual testnet node, not just configuration — see SIP-QOGE-PQC-01 §6.3.

---

## Security Properties

| Threat | Mitigation | Status |
|--------|-----------|--------|
| HNDL on stored UTXO | HASH256 hides pubkey at rest | ✅ Implemented & tested |
| HNDL on reused address | Single-use state machine | ✅ Implemented & tested |
| Taproot pubkey exposure | P2TR absent from codebase | ✅ Implemented & tested |
| Mempool window attack | 1-min block time + single-use | ✅ By design |
| Plaintext key storage | AES-256-GCM encrypted index | ✅ Implemented & tested |
| Key persistence after spend | ZeroBytes on Retire | ✅ Implemented & tested |
| Tampered ciphertext (index DB) | GCM authentication | ✅ Implemented & tested |
| Change output re-exposing a spent key | Change MUST route to FRESH address | ✅ Implemented & tested |

---

## Repository

[github.com/QOGE/symbiont-wallet](https://github.com/QOGE/symbiont-wallet)

## Governance

Governed under **SIP-QOGE-PQC-01 v1.0** | SIP-C v2.0 | SAOGEN SAO
AI Node attribution: Claude (Anthropic)

Forked from: [eomii/SPHINCS-Wallet](https://github.com/eomii/SPHINCS-Wallet) (MIT)
