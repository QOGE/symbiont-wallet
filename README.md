# Symbiont Wallet

**The post-quantum wallet for QOGE — implementing SIP-QOGE-PQC-01 and
SIP-QOGE-PQC-02 (Phase A).**

SLH-DSA-SHA2-128f (FIPS 205) signatures | P2QPK single-use addresses (witness v2 / Bech32m) | HNDL defence

> ⚠️ **EXPERIMENTAL — wallet-side core implemented and tested. Consensus-side
> Phase E (regtest validation) complete — tampered-sig rejected, real SLH-DSA
> spend accepted and confirmed on-chain. Phase F (public testnet) is next.
> DO NOT USE IN PRODUCTION. Phase 3 independent audit is mandatory before any
> mainnet deployment.**

**Status: 47/47 tests passing.** Real SLH-DSA-SHA2-128f keypairs, real
`bq1z...` P2QPK addresses (witness version 2, Bech32m/BIP350), real
17,088-byte FIPS 205 signatures, end-to-end single-use lifecycle confirmed
on Ubuntu 24 LTS.

---

## Architecture

```
cmd/main.go          — CLI entry point (replaces eomii/SPHINCS-Wallet main.go)
signer/slhdsa.go     — SLH-DSA-SHA2-128f signing primitive (liboqs-go wrapper)
address/address.go   — HASH256(pubkey) + Bech32m("bq", witver=2) P2QPK address derivation
address/bech32m.go   — Vendored BIP173 (Bech32) + BIP350 (Bech32m) codec
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

## Address Format — P2QPK (Pay to Quantum Public Key)

```
QOGE address = Bech32m(hrp="bq", witver=2, HASH256(SLH-DSA-pubkey))
Example:        bq1z9vedkmpvpf3rt7cnjl5zyh4gtc8sum5v0vfx6qqkej77pen8z50qglwrd3
```

The public key is hidden at rest behind HASH256. It is only revealed
in the witness field for ~30-60 seconds at spend time (1-minute block time).

**Witness version 2, not 0.** A 32-byte witness-v0 program is defined by
BIP141 as P2WSH (`SHA256(script)`) — an unrelated commitment. Witness
version 2 ("P2QPK") is currently undefined by Bitcoin/Qogecoin consensus
(anyone-can-spend, per BIP141's soft-fork reservation for v2-16) and is the
subject of SIP-QOGE-PQC-02's proposed soft fork, which gives it SLH-DSA
meaning. See SIP-QOGE-PQC-02 for the full consensus design.

**Taproot (witver=1) is structurally rejected.** Per BIP350, witness
version 0 uses Bech32 and versions 1-16 use Bech32m, with the checksum
constant bound to the version — `address.go`'s `decode()` enforces this
binding and explicitly rejects `witver==1` (Taproot) via
`ErrTaprootDetected`. This is not a string-pattern heuristic; it's a
structural check on the decoded witness-version byte. See SIP-QOGE-PQC-02
§4 for why Taproot is rejected (key-path spending exposes a classical
secp256k1 point at rest, defeating any script-path PQC check).

---

## Milestone Status

### SIP-QOGE-PQC-01 (Phase 1 — wallet core)

| ID    | Milestone                              | Status         | Tests |
|-------|----------------------------------------|----------------|-------|
| M1.1  | liboqs-go → FIPS 205 (SLH-DSA-SHA2-128f) | ✅ VALIDATED | `signer` — 7/7 |
| M1.2  | HASH256 → address derivation           | ✅ VALIDATED   | `address` — 13/13 (was 7/7; +6 from SIP-02 Phase A) |
| M1.3  | HD index counter + encrypted persist   | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.4  | Address state machine + invariants     | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.5  | Key zeroing on confirmation            | ✅ VALIDATED   | `wallet` — 17/17 |
| M1.6  | QOGE tx format integration             | 🔴 STUB        | Address format (Phase A) done; consensus (Phase B+) is SIP-QOGE-PQC-02 |
| M1.7  | Taproot disabled                       | ✅ VALIDATED   | `address` — `TestTaprootRejected` (structural, not heuristic) |
| M2.1  | Change routing to fresh address        | ✅ VALIDATED   | `wallet` — `TestSignTransactionRejects*` |
| M2.2  | Address pre-generation pool (N=20)     | ✅ VALIDATED   | `wallet` — pool tests |

### SIP-QOGE-PQC-02 (Consensus Integration — Candidate)

| Phase | Description | Status |
|-------|-------------|--------|
| A | Symbiont Wallet address format: witver 0→2, Bech32→Bech32m | ✅ **COMPLETE** — this commit |
| B | liboqs integration into Qogecoin Core build | ✅ **COMPLETE** — liboqs linked via `PKG_CHECK_MODULES([LIBOQS], [liboqs])` (Option B, host pkg-config, dev/Phase D-E only); committed locally in `qogecoin/qogecoin` as `8550582`, not pushed (fork+PR step deferred per §9) |
| C | Sighash sub-spec (SIP-QOGE-PQC-02a) — source investigation and test vector | ✅ **COMPLETE** — all SIP-02a open items resolved; P2QPKSighash `8a17f83e...` computed, cross-validated, and **independently recomputed** by GPT-5.5 Thinking (PASS, 20 June 2026); five Phase D safeguards folded into spec as SIP-02a §7; see [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md) |
| D | Consensus implementation (`VerifyWitnessProgram` P2QPK branch) | ✅ **COMPLETE** (local) — `SignatureHashP2QPK` (`2a4c85a`), Init() OP_2 trigger + safeguard-D tests (`468f367`), `VerifyWitnessProgram` witver==2 branch + `SCRIPT_VERIFY_P2QPK` + missing-data guard (`abb93a0`), `OQS_SIG_slh_dsa_pure_sha2_128f_verify` wired + `p2qpk_bad_sig_rejected` (`816cd06`); 5/5 tests pass; not pushed (fork+PR deferred per §9) |
| E | Regtest functional testing | ✅ **COMPLETE** — regtest validation complete — tampered-sig rejected, real SLH-DSA spend accepted and confirmed (`56a2aed` in [QOGE/qogecoin](https://github.com/QOGE/qogecoin)) |
| F | Public testnet | ⏳ Pending |

**Important:** addresses produced by this wallet (witver=2) are, on the
*current, unmodified* Qogecoin network, anyone-can-spend (BIP141 v2-16
reservation). They become SLH-DSA-protected only after the SIP-QOGE-PQC-02
soft fork activates. **Do not send funds of value to these addresses before
that activation.** See SIP-QOGE-PQC-02 §5.5.

---

## Test Results

```
go test ./address/...  -v   →  13/13 PASS  (0.003s)
go test ./signer/...   -v   →   7/7  PASS  (0.177s)
go test ./keystore/... -v   →  17/17 PASS  (0.177s)
go test ./wallet/...   -v   →  17/17 PASS  (1.690s)

TOTAL: 47/47 PASS
```

Key figures confirmed by the test suite, on real liboqs (built from source,
`OQS_DIST_BUILD=ON`, `liboqs.so.0.15.0`):

| Property | Value | Spec |
|----------|-------|------|
| Public key size | 32 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Secret key size | 64 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Signature size | 17,088 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Algorithm identifier (liboqs) | `SLH_DSA_PURE_SHA2_128F` | — |
| Address HRP | `bq` | Confirmed against qogecoin/qogecoin release notes |
| Address witness version | 2 (P2QPK) | SIP-QOGE-PQC-02 §5.1 |
| Address encoding | Bech32m (BIP350) | Required for witver≥1 |

The new address-package tests (`TestBIP173CanonicalChecksumVector`,
`TestBIP350CanonicalChecksumVector`, `TestEncodeMatchesCanonicalVectors`,
`TestCrossConstantRejected`) check the vendored Bech32/Bech32m checksum
implementation (`bech32m.go`) against the canonical first test vectors from
BIP173 (`a12uel5l`) and BIP350 (`a1lqfn3a`) — external ground truth,
independent of this project's address-specific logic.

`TestFullSymbiontLifecycle` runs 41 consecutive receive → sign → confirm →
retire cycles and confirms no retired address is ever reissued.

---

## Getting Started — Native Build (Ubuntu 24 LTS)

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

> **Note:** `go.mod` ships with a `replace` directive pointing at a specific
> development machine's path. The `go mod edit` command above overwrites it
> for your machine — run it even if you intend to keep the same path.

### 5. Run the tests

```bash
go test ./address/...  -v   # no CGo — fastest; includes BIP173/BIP350 vectors
go test ./signer/...   -v   # exercises liboqs via CGo — this is the M1.1 check
go test ./keystore/... -v   # HD index + state machine
go test ./wallet/...   -v   # full integration — slower (~1.7s, 20+ keygens per test)
```

### 6. Run the CLI

```bash
go run cmd/main.go
```

Choose **1** to create a new wallet. **Save the printed seed hex** — this
experimental version has no recovery path without it (see M1.3 note below).
From the main menu: get a receive address (1), mark it as paid (2), sign a
message (3), then confirm (4) to retire the address and zero its key.

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

```go
const AlgorithmName = "SLH_DSA_PURE_SHA2_128F"
```

Confirmed via `/usr/local/include/oqs/sig.h`:
`#define OQS_SIG_alg_slh_dsa_pure_sha2_128f "SLH_DSA_PURE_SHA2_128F"`.

We use the **"pure"** variant, not `*_prehash_*` — the wallet already
pre-hashes messages itself via `canonicalMessageHash()`.

### SIP-QOGE-PQC-02 Phase A — RESOLVED: address format

`address.go` now derives P2QPK addresses: `Bech32m("bq", witver=2,
HASH256(pubkey))`. The project's existing `btcutil v1.0.2` dependency
implements BIP173 (Bech32) only — no Bech32m/BIP350 support — so a small,
self-contained BIP173+BIP350 codec is vendored in `bech32m.go`, reusing only
`bech32.ConvertBits` (5-bit/8-bit regrouping, unaffected by BIP350) from the
existing dependency.

### M1.3 — Deterministic key derivation (open item)

`wallet/wallet.go:deriveAddress()` currently calls `slhdsa.NewSigner()`
(random keygen) rather than deriving deterministically from `childSeed`.

**Impact:** wallet recovery from the master seed alone is not yet possible
— the encrypted index DB (`qoge_wallet.db`) is currently the sole source of
truth for which keypairs exist. Losing the DB loses the wallet, even with
the seed. This must be resolved before any real-value use.

**Path forward:** check whether liboqs's
`OQS_SIG_slh_dsa_pure_sha2_128f_keypair` supports seeded generation at the C
level (FIPS 205 §10.1 specifies SLH-DSA key generation as deterministic
given `SK.seed`, `SK.prf`, `PK.seed`).

### M1.6 / SIP-QOGE-PQC-02 Phase B+ — Consensus integration

Phase A (this commit) made addresses structurally correct for the P2QPK
design. Consensus-side work is in `qogecoin/qogecoin`, not in this repo.
See [`docs/sips/SIP-QOGE-PQC-02.md`](docs/sips/SIP%20QOGE%20PQC%2002%20P2QPK.md)
and [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md)
for full normative detail.

- **Phase B ✅ COMPLETE:** `PKG_CHECK_MODULES([LIBOQS], [liboqs])` added to
  `configure.ac`; `LIBOQS_CFLAGS`/`LIBOQS_LIBS` wired into
  `libqogecoin_consensus_a_CPPFLAGS` and `qogecoin_bin_ldadd`. Option B
  (host pkg-config, `/usr/local`); Option A (`depends/packages/liboqs.mk`)
  required for Phase F cross-compiled builds.
- **Phase C ✅ COMPLETE:** `m_bip341_taproot_ready` confirmed witver==1-specific;
  `Init()` extension identified (1-line `OP_1→OP_1||OP_2`); `HASHER_P2QPKSIGHASH`
  location confirmed (`interpreter.cpp:1464`); P2QPKSighash test vector
  `8a17f83e...` computed and cross-validated. See `docs/sips/SIP-QOGE-PQC-02a.md`.
- **Phase D ✅ COMPLETE** (local-only commits, fork+PR deferred per §9):
  - Step 1 (`2a4c85a`): `SignatureHashP2QPK` + test vector `8a17f83e...` in C++
  - Step 2 (`468f367`): `Init()` OP_2 trigger + safeguard-D tests (unforced precompute path)
  - Step 3 (`abb93a0`): `VerifyWitnessProgram` witver==2 branch — exact-length checks (§7-A),
    HASH256 commitment, `SCRIPT_VERIFY_P2QPK` gate, missing-data guard
  - Step 4 (`816cd06`): `OQS_SIG_slh_dsa_pure_sha2_128f_verify` wired (pure mode, §7-B);
    `extern "C"` required (sig_slh_dsa.h lacks own guard); compile-time `#error` if SLH-DSA
    variant absent; `p2qpk_bad_sig_rejected` test confirms stub is gone; 5/5 tests pass
- **Phase E ✅ COMPLETE** (`56a2aed` in [QOGE/qogecoin](https://github.com/QOGE/qogecoin)):
  `DEPLOYMENT_P2QPK` added to `DeploymentPos` enum, `deploymentinfo.cpp`, and
  `CRegTestParams.vDeployments` (`ALWAYS_ACTIVE`); `DeploymentActiveAt(DEPLOYMENT_P2QPK)`
  gates `SCRIPT_VERIFY_P2QPK` in `GetBlockScriptFlags`. Validated on regtest:
  tampered-sig spend rejected (`SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` from
  `OQS_SIG_slh_dsa_pure_sha2_128f_verify`); real SLH-DSA spend accepted and
  confirmed on-chain.
- Phase F: public testnet — bech32_hrp decision, Option A liboqs build
  (`depends/packages/liboqs.mk`), BIP9 governance for mainnet activation

Once a P2QPK-aware testnet exists, `wallet.QOGETransaction` (currently a
stub) gets replaced with the real transaction type, and
`SignTransaction`/`canonicalMessageHash` need to compute the
SIP-QOGE-PQC-02a `P2QPKSighash` for actual on-chain signing (the existing
`canonicalMessageHash` remains valid only for the CLI's generic
message-signing demo, a separate non-consensus use case).

---

## Security Properties

| Threat | Mitigation | Status |
|--------|-----------|--------|
| HNDL on stored UTXO | HASH256 hides pubkey at rest | ✅ Implemented & tested |
| HNDL on reused address | Single-use state machine | ✅ Implemented & tested |
| HNDL via Taproot key-path | Taproot (witver=1) structurally rejected | ✅ Implemented & tested |
| Mempool window attack | 1-min block time + single-use | ✅ By design |
| Plaintext key storage | AES-256-GCM encrypted index | ✅ Implemented & tested |
| Key persistence after spend | ZeroBytes on Retire | ✅ Implemented & tested |
| Tampered ciphertext (index DB) | GCM authentication | ✅ Implemented & tested |
| Change output re-exposing a spent key | Change MUST route to FRESH address | ✅ Implemented & tested |
| Cross-version checksum confusion | BIP350 witver↔constant binding enforced | ✅ Implemented & tested |
| Pre-activation fund loss | P2QPK addresses are anyone-can-spend until SIP-QOGE-PQC-02 activates | ⚠️ Do not fund pre-activation |

---

## Repository

[github.com/QOGE/symbiont-wallet](https://github.com/QOGE/symbiont-wallet)

## Documentation

- [`docs/sips/SIP-QOGE-PQC-02.md`](docs/sips/SIP%20QOGE%20PQC%2002%20P2QPK.md) — condensed normative reference for SIP-02 (P2QPK consensus design), for use during Phase C/D implementation work
- [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md) — condensed normative reference for SIP-02a (P2QPK sighash spec), including Phase C source findings and the `P2QPKSighash` test vector
- [`CLAUDE.md`](CLAUDE.md) — guidance for Claude Code sessions working in this repository (build prerequisites, architecture, open items)

## Governance

Governed under:
- **SIP-QOGE-PQC-01 v1.0** — wallet-side SLH-DSA implementation (this repo, Phase 1)
- **SIP-QOGE-PQC-02 v1.0** — consensus integration design (P2QPK), Candidate
- **SIP-QOGE-PQC-02a v1.0** — P2QPK sighash specification, Candidate

SIP-C v2.0 | SAOGEN SAO | AI Node attribution: Claude (Anthropic)

Forked from: [eomii/SPHINCS-Wallet](https://github.com/eomii/SPHINCS-Wallet) (MIT)
