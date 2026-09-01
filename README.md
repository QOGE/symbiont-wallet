# Symbiont Wallet

**The post-quantum wallet for QOGE — implementing SIP-QOGE-PQC-01 and
the ratified SIP-2.0-AMD-012 P2QPK mainnet activation.**

SLH-DSA-SHA2-128f (FIPS 205) signatures | P2QPK single-use addresses (witness v2 / Bech32m) | HNDL defence

> ✅ **P2QPK is active on Qogecoin mainnet from height 2,459,520.** P2QPK outputs are enforced by Qogecoin consensus and may be used for real mainnet funds. Back up the wallet seed before receiving funds and keep it private; losing it can make funds permanently unrecoverable.

**Status: 155/155 tests passing.** Real SLH-DSA-SHA2-128f keypairs, real `bq1z...` / `bqt1z...` P2QPK addresses (witness version 2, Bech32m/BIP350), real 17,088-byte FIPS 205 signatures, and an end-to-end single-use lifecycle validated on Ubuntu 24 LTS. SIP-2.0-AMD-012 was signed by SAOGEN-SAO on 31 July 2026 and ratified in Qogecoin commit `69c5ebe72`. P2QPK subsequently activated on the real mainnet at height 2,459,520; the production network uses the mainnet P2P port `42069` (the former `167.86.81.222:42070` endpoint was the completed public-testnet phase, not mainnet).

---

## Architecture

```
cmd/main.go          — CLI entry point (replaces eomii/SPHINCS-Wallet main.go)
cmd/gui/main.go      — Primary Fyne GUI: wallet, addresses, send, and network workflows
signer/slhdsa.go     — SLH-DSA-SHA2-128f signing primitive (liboqs-go wrapper)
address/address.go   — P2QPK derivation plus validated destination decoding/script construction
address/bech32m.go   — Vendored BIP173 (Bech32) + BIP350 (Bech32m) codec
keystore/keystore.go — Single-use HD index, state machine, AES-256-GCM persistence
wallet/wallet.go     — Orchestration: wires all packages, enforces all invariants
internal/rpcclient/  — Qogecoin JSON-RPC balance, mempool, and broadcast operations
internal/txbuilder/  — Consensus transaction construction and serialization
```

## Address Lifecycle (Single-Use Invariant)

```
[FRESH] ──► [FUNDED] ──► [SPEND_PENDING] ──► [SPENT] ──► [RETIRED]
                                                               │
                                                         privkey zeroed
```

`FUNDED` is detected automatically from a positive `scantxoutset` balance
whose shallowest UTXO has at least `FundingMinConfirmations` (default 20).
Successful signing atomically moves the source to `SPEND_PENDING`, records its
transaction ID, and reserves the FRESH change address. Refresh detects the
confirmed spend and moves the source to `SPENT`; confirmed change matures into
`FUNDED` and its reservation is cleared. `RETIRED` is a permanent, manual key
purge. The invariants are covered across the keystore and wallet test suites.

**Database compatibility:** this lifecycle intentionally has no migration.
Pre-five-state databases are rejected. Delete `qoge_wallet.db` and create a
fresh wallet with a new seed; do not attempt to reuse or map old records.

## Address Format — P2QPK (Pay to Quantum Public Key)

```
QOGE address = Bech32m(hrp="bq", witver=2, HASH256(SLH-DSA-pubkey))
Example:        bq1z9vedkmpvpf3rt7cnjl5zyh4gtc8sum5v0vfx6qqkej77pen8z50qglwrd3
```

Testnet addresses use HRP `"bqt"` and produce `bqt1z...` addresses.
Set `address.DefaultNetwork = address.Testnet` before wallet initialisation
to generate testnet addresses. Default is `address.Mainnet` (`bq`).

The public key is hidden at rest behind HASH256. It is revealed in the witness field at spend time. The wallet automatically flags the address as SPENT once the spending transaction reaches confirmations ≥ 1, preventing reuse — this does NOT destroy the private key. Key destruction is a SEPARATE, optional, manual, irreversible operation (`wallet.PurgeSpentKey`), gated at confirmations ≥ 101 (`KeyDestructionMinConfirmations`), and is never called automatically by the wallet. The exposure window does not enable quantum key recovery — SLH-DSA's security does not depend on any problem Shor's algorithm can solve. The single-use model exists to prevent accidental address reuse, which is the actual threat to SLH-DSA's security properties; key destruction (when and if invoked) provides an additional, separate forward-secrecy property against local database compromise.

**Witness version 2, not 0.** A 32-byte witness-v0 program is defined by
BIP141 as P2WSH (`SHA256(script)`) — an unrelated commitment. Qogecoin's
ratified SIP-2.0-AMD-012 soft fork assigns witness version 2 to P2QPK and
enforces its SLH-DSA validation rules on mainnet from height 2,459,520. See
SIP-QOGE-PQC-02 for the full consensus design.

**Wallet-owned receive addresses are always P2QPK.** The P2QPK-specific decoder
structurally rejects witness version 1, so a Taproot address cannot be confused
with a wallet-owned quantum address. The separate external-destination decoder
does support P2TR outputs deliberately, alongside the other standard Qogecoin
address types.

---

## Milestone Status

### SIP-QOGE-PQC-01 (Phase 1 — wallet core)

| ID    | Milestone                              | Status         | Tests |
|-------|----------------------------------------|----------------|-------|
| M1.1  | liboqs-go → FIPS 205 (SLH-DSA-SHA2-128f) | ✅ VALIDATED | `signer` — 11/11 |
| M1.2  | HASH256 → address derivation           | ✅ VALIDATED   | `address` — 20/20 |
| M1.3  | HD index counter + encrypted persist   | ✅ VALIDATED   | `keystore` — 19/19 |
| M1.4  | Address state machine + invariants     | ✅ VALIDATED   | `keystore` — 19/19 |
| M1.5  | Key purge after confirmed spend        | ✅ VALIDATED   | `wallet` — 48/48 |
| M1.6  | QOGE tx format integration             | ✅ ACTIVE      | Real P2QPK signing, serialization, mempool validation, and mainnet broadcast |
| M1.7  | Taproot disabled                       | ✅ VALIDATED   | `address` — `TestTaprootRejected` (structural, not heuristic) |
| M2.1  | Change routing to fresh address        | ✅ VALIDATED   | `wallet` — `TestSignTransactionRejects*` |
| M2.2  | Address pre-generation pool (N=20)     | ✅ VALIDATED   | `wallet` — pool tests |

### SIP-QOGE-PQC-02 / SIP-2.0-AMD-012 (Consensus Integration — Ratified and Active)

| Phase | Description | Status |
|-------|-------------|--------|
| A | Symbiont Wallet address format: witver 0→2, Bech32→Bech32m | ✅ **COMPLETE** — deployed and active |
| B | liboqs integration into Qogecoin Core build | ✅ **COMPLETE** — liboqs integrated into the Qogecoin Core build and deployed on mainnet |
| C | Sighash sub-spec (SIP-QOGE-PQC-02a) — source investigation and test vector | ✅ **COMPLETE** — all SIP-02a open items resolved; P2QPKSighash `8a17f83e...` computed, cross-validated, and **independently recomputed** by GPT-5.5 Thinking (PASS, 20 June 2026); five Phase D safeguards folded into spec as SIP-02a §7; see [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md) |
| D | Consensus implementation (`VerifyWitnessProgram` P2QPK branch) | ✅ **COMPLETE** — `SignatureHashP2QPK`, the witness-v2 verification branch, deployment gate, liboqs verification, and negative tests are in Qogecoin Core |
| E | Regtest functional testing | ✅ **COMPLETE** — regtest validation complete — tampered-sig rejected, real SLH-DSA spend accepted and confirmed (`56a2aed` in [QOGE/qogecoin](https://github.com/QOGE/qogecoin)) |
| F | Public testnet | ✅ **COMPLETE** — Public testnet live at `167.86.81.222:42070`; `p2qpk: active: true` confirmed; P2QPK tx `357d4d0c...` confirmed in block 104; two-node peer network validated end-to-end. |
| G | Mainnet activation | ✅ **ACTIVE** — the BIP9 cycle was validated in simulation, SIP-2.0-AMD-012 was signed and ratified, and the real daemon reports P2QPK active from mainnet height 2,459,520 |

### Pre-Mainnet Audit Series (Audits 1–5)

| Audit | Scope | Status |
|---|---|---|
| 1 | Sighash construction | ✅ COMPLETE — 3 models, sound |
| 2 | Witness verification | ✅ COMPLETE — real bug found and fixed |
| 3 | liboqs integration | ✅ COMPLETE — 6 passes, no blocker |
| 4 | Single-use lifecycle | ✅ COMPLETE — redesigned, PASS, ready for mainnet |
| 5 | Wallet lifecycle (unstructured) | ✅ COMPLETE — 1 false positive ruled out, 2 real fixes |

Full triage artifacts in `docs/sips/`. See `CLAUDE.md` for complete detail per audit.

**Mainnet status:** P2QPK consensus validation is active from height 2,459,520.
Outputs sent to this wallet's witness-v2 addresses are protected by the
ratified SLH-DSA rules. Nodes and miners must run a P2QPK-capable Qogecoin
release; see SIP-QOGE-PQC-02 §5.5 for the consensus design.

---

## Test Results

```
go test ./address/...  -v              →  20/20 PASS
go test ./signer/...   -v              →  11/11 PASS
go test ./keystore/... -v              →  19/19 PASS
go test ./wallet/...   -v              →  48/48 PASS
go test ./internal/rpcclient/... -v →  22/22 PASS
go test ./internal/txbuilder/... -v →  21/21 PASS
go test ./cmd/gui/...  -v              →  14/14 PASS
TOTAL: 155/155 PASS
```

The suite covers deterministic SLH-DSA derivation, the five-state lifecycle,
concurrent signing exclusion, real P2QPK transaction construction, RPC result
handling, destination decoding and script generation, and GUI safety gates.

Key figures confirmed by the test suite, on real liboqs (built from source,
`OQS_DIST_BUILD=ON`, `liboqs.so.0.15.0`):

| Property | Value | Spec |
|----------|-------|------|
| Public key size | 32 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Secret key size | 64 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Signature size | 17,088 bytes | FIPS 205 SLH-DSA-SHA2-128f |
| Algorithm identifier (liboqs) | `SLH_DSA_PURE_SHA2_128F` | — |
| Address HRP | `bq` (mainnet/regtest) / `bqt` (testnet) | Confirmed against qogecoin/qogecoin release notes |
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

### 6. Run the GUI (primary interface)

```bash
go run ./cmd/gui
```

The GUI has four tabs:

- **Wallet** — generate a cryptographically random 32-byte seed or enter an
  existing 64-character hex seed; generated seeds are shown in a read-only
  backup field and must be explicitly acknowledged before creation. Open and
  Create are separate authenticated actions.
- **My Addresses** — refresh and inspect the complete five-state lifecycle
  (`FRESH`, `FUNDED`, `SPEND_PENDING`, `SPENT`, `RETIRED`), hide spent and
  retired entries by default without excluding them from wallet scanning, and
  generate/copy new P2QPK receive addresses.
- **Send** — select a `FUNDED` source, choose a wallet-owned or explicitly
  external destination, Preview, Sign, Test in Mempool, and deliberately
  Broadcast. Broadcast is authorized only for the exact signed transaction
  accepted by `testmempoolaccept` and requires a second confirmation showing
  the destination, decoded type, and amount.
- **Network** — automatically try a local Qogecoin node using RPC cookie auth
  from `~/.qogecoin/.cookie`, or connect manually to a local or remote node
  with host, port, username, and password. Connection status remains visible
  in the global footer on every tab.

External destinations are strictly checksum- and network-validated. Supported
output types are P2QPK (wallet-owned or external), P2PKH, P2SH, P2WPKH, P2WSH,
and P2TR. The complete workflow has been exercised with real mainnet
transactions, including a confirmed send to an external, non-P2QPK Qogecoin
Core Qt wallet.

> ⚠️ **Seed backup:** the seed is the only recovery secret for a newly created
> wallet. Save it securely before receiving funds. Anyone with the seed can
> spend the wallet, and losing it can make the wallet permanently unrecoverable.

### 7. Run the CLI (alternative)

```bash
go run ./cmd
```

The CLI exposes the same explicit Open Existing/Create New split and core
wallet lifecycle operations. The GUI is the primary interface for the complete
receive, transaction preview, signing, mempool-test, and broadcast workflow.

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

### M1.3 — Deterministic key derivation — RESOLVED

`wallet/wallet.go:deriveAddress()` now calls `slhdsa.NewSignerFromSeed(childSeed)`
where `childSeed` is 48 bytes derived via `HKDF-SHA256(masterSeed, nil, "qoge-key-{index}")`.

**Implementation:** `oqs.RandomBytesCustomAlgorithm` installs a one-shot process-global
callback delivering the 48-byte child seed; `oqs.RandomBytesSwitchAlgorithm("system")`
restores normal randomness in a deferred call. A package-level `rngMu sync.Mutex` is
held for the full install-generate-restore sequence and is also held during `Sign` (which
draws 16 bytes for `addrnd`) and random `NewSigner` calls — preventing concurrent RNG
corruption. KAT vector pinned: seed `[0x01..0x30]` →
`2122232425262728292a2b2c2d2e2f30a3356a1283ac92dcae6a36960ace2600`.

### M1.6 / SIP-QOGE-PQC-02 — Consensus integration — RESOLVED

Consensus-side work lives in [QOGE/qogecoin](https://github.com/QOGE/qogecoin).
The completed implementation includes liboqs integration, the P2QPK sighash,
witness-v2 verification, deployment gating, regtest and public-testnet
validation, and the production build/configuration work. The BIP9 activation
cycle was validated before deployment; SIP-2.0-AMD-012 was then signed by
SAOGEN-SAO on 31 July 2026 and ratified in commit `69c5ebe72`. P2QPK is active
on real Qogecoin mainnet from height 2,459,520.

The wallet now constructs and serializes real Qogecoin transactions, signs
P2QPK inputs using the consensus sighash, validates transactions with
`testmempoolaccept`, and broadcasts with `sendrawtransaction`. See
[`docs/sips/SIP-QOGE-PQC-02.md`](docs/sips/SIP%20QOGE%20PQC%2002%20P2QPK.md)
and [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md)
for the design and sighash specification.

### Fyne GUI — PRIMARY INTERFACE

`cmd/gui/main.go` implements the complete four-tab interface documented
above: safe wallet creation/opening and seed backup, automatic lifecycle and
balance observation, internal and external payments, preview, real P2QPK
signing, mempool validation, deliberate broadcast, and local or remote RPC
connection. This replaces the original receive-only GUI stub; address-list and
send support are no longer deferred.

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
| P2QPK consensus enforcement | SIP-2.0-AMD-012 active on mainnet from height 2,459,520 | ✅ Active |

---

## Repository

[github.com/QOGE/symbiont-wallet](https://github.com/QOGE/symbiont-wallet)

## Documentation

- [`docs/sips/SIP-QOGE-PQC-02.md`](docs/sips/SIP%20QOGE%20PQC%2002%20P2QPK.md) — consensus design reference for SIP-02 (P2QPK)
- [`docs/sips/SIP-QOGE-PQC-02a.md`](docs/sips/SIP%20QOGE%20PQC%2002a%20P2QPK.md) — consensus sighash reference for SIP-02a (P2QPK), including the `P2QPKSighash` test vector
- [`CLAUDE.md`](CLAUDE.md) — guidance for Claude Code sessions working in this repository (build prerequisites, architecture, open items)
- [`contrib/qogecoin-production.conf.example`](https://github.com/QOGE/qogecoin/blob/stable/contrib/qogecoin-production.conf.example) (QOGE/qogecoin) — reference production node config; documents `changetype=bech32`, fee fallback, and wallet-persistence lessons learned during this project

## Governance

Governed under:
- **SIP-QOGE-PQC-01 v1.0** — wallet-side SLH-DSA implementation (this repo, Phase 1)
- **SIP-QOGE-PQC-02 v1.0** — P2QPK consensus integration design, incorporated into the ratified mainnet amendment
- **SIP-QOGE-PQC-02a v1.0** — P2QPK sighash specification, incorporated into the ratified mainnet amendment

SIP-C v2.0 | SAOGEN SAO | AI Node attribution: Claude (Anthropic)

Forked from: [eomii/SPHINCS-Wallet](https://github.com/eomii/SPHINCS-Wallet) (MIT)

**Note on SIP/governance documentation:** This repository references SIP
(SAOGEN Improvement Proposal) documents and SIP-C v2.0 governance
throughout its commit history and `docs/sips/` directory. These are
internal SAOGEN organizational artifacts — records of design decisions,
technical rationale, audit findings, and attribution — not a separate
license or legal encumbrance. They impose no terms, conditions, or
compliance requirements on anyone using, forking, modifying, or
redistributing this code. All code in this repository, including the
P2QPK implementation, remains unambiguously MIT-licensed in full.
