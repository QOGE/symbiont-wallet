# Symbiont Wallet

**The post-quantum wallet for QOGE — implementing SIP-QOGE-PQC-01 and
SIP-QOGE-PQC-02 (Phase A).**

SLH-DSA-SHA2-128f (FIPS 205) signatures | P2QPK single-use addresses (witness v2 / Bech32m) | HNDL defence

> ⚠️ **EXPERIMENTAL — wallet-side core implemented and tested. Consensus-side complete through Phase G; mainnet activation parameters set (`nStartTime` 2026-08-09, `nTimeout` 2026-11-07). DO NOT USE IN PRODUCTION. DO NOT SEND FUNDS to P2QPK addresses on mainnet before soft fork activation.**

**Status: 73/73 tests passing.** Real SLH-DSA-SHA2-128f keypairs, real `bq1z...` / `bqt1z...` P2QPK addresses (witness version 2, Bech32m/BIP350), real 17,088-byte FIPS 205 signatures, end-to-end single-use lifecycle confirmed on Ubuntu 24 LTS. Public testnet live at `167.86.81.222:42070`. BIP9 activation cycle validated end-to-end (Phase G). **Mainnet activation parameters set** (`7912fa1c1`, 2026-07-26): `bit=3`, `nStartTime=1786284720` (2026-08-09 14:12 UTC), `nTimeout=1794060720` (2026-11-07 14:12 UTC). What remains: formal SIP ratification.

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

Testnet addresses use HRP `"bqt"` and produce `bqt1z...` addresses.
Set `address.DefaultNetwork = address.Testnet` before wallet initialisation
to generate testnet addresses. Default is `address.Mainnet` (`bq`).

The public key is hidden at rest behind HASH256. It is revealed in the witness field at spend time. The wallet automatically flags the address as SPENT once the spending transaction reaches confirmations ≥ 1, preventing reuse — this does NOT destroy the private key. Key destruction is a SEPARATE, optional, manual, irreversible operation (`wallet.PurgeSpentKey`), gated at confirmations ≥ 101 (`KeyDestructionMinConfirmations`), and is never called automatically by the wallet. The exposure window does not enable quantum key recovery — SLH-DSA's security does not depend on any problem Shor's algorithm can solve. The single-use model exists to prevent accidental address reuse, which is the actual threat to SLH-DSA's security properties; key destruction (when and if invoked) provides an additional, separate forward-secrecy property against local database compromise.

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
| M1.1  | liboqs-go → FIPS 205 (SLH-DSA-SHA2-128f) | ✅ VALIDATED | `signer` — 11/11 |
| M1.2  | HASH256 → address derivation           | ✅ VALIDATED   | `address` — 17/17 (was 13/13; +4 network tests) |
| M1.3  | HD index counter + encrypted persist   | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.4  | Address state machine + invariants     | ✅ VALIDATED   | `keystore` — 17/17 |
| M1.5  | Key zeroing on confirmation            | ✅ VALIDATED   | `wallet` — 28/28 |
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
| F | Public testnet | ✅ **COMPLETE** — Public testnet live at `167.86.81.222:42070`; `p2qpk: active: true` confirmed; P2QPK tx `357d4d0c...` confirmed in block 104; two-node peer network validated end-to-end. |
| G | Real-parameter mainnet activation simulation | ✅ **COMPLETE** — Full BIP9 cycle validated on an isolated, air-gapped two-node simulation (simulation used testnet-scale `nMinerConfirmationWindow=2016`/`nRuleChangeActivationThreshold=1512`; actual `CMainParams` values are 8064/6048). Phase transitions at exactly the predicted heights: `DEFINED→STARTED` at 2016, `STARTED→LOCKED_IN` at 4032, `LOCKED_IN→ACTIVE` at 6048. Post-`ACTIVE`: real P2QPK spend confirmed on both nodes; tampered spend correctly rejected by `SCRIPT_VERIFY_P2QPK`. All technical unknowns resolved. **Mainnet activation parameters set (`7912fa1c1`, 2026-07-26):** `bit=3`, `nStartTime=1786284720` (2026-08-09 14:12 UTC), `nTimeout=1794060720` (2026-11-07 14:12 UTC), `nMinerConfirmationWindow=8064` (5.6 days/window), `nRuleChangeActivationThreshold=6048` (75%) — last two unchanged. Timeline: `nStartTime`→STARTED 0–~5.6 days; STARTED→ACTIVE with continuous signaling exactly 11.2 days (two windows); worst-case ~16.8 days; `nTimeout` provides ~74 days margin. Independently reviewed by Codex and Grok Build — zero discrepancies. What remains: formal SIP ratification. |

### Pre-Mainnet Audit Series (Audits 1–5)

| Audit | Scope | Status |
|---|---|---|
| 1 | Sighash construction | ✅ COMPLETE — 3 models, sound |
| 2 | Witness verification | ✅ COMPLETE — real bug found and fixed |
| 3 | liboqs integration | ✅ COMPLETE — 6 passes, no blocker |
| 4 | Single-use lifecycle | ✅ COMPLETE — redesigned, PASS, ready for mainnet |
| 5 | Wallet lifecycle (unstructured) | ✅ COMPLETE — 1 false positive ruled out, 2 real fixes |

Full triage artifacts in `docs/sips/`. See `CLAUDE.md` for complete detail per audit.

**Important:** addresses produced by this wallet (witver=2) are, on the
*current, unmodified* Qogecoin network, anyone-can-spend (BIP141 v2-16
reservation). They become SLH-DSA-protected only after the SIP-QOGE-PQC-02
soft fork activates. **Do not send funds of value to these addresses before
that activation.** See SIP-QOGE-PQC-02 §5.5.

---

## Test Results

```
go test ./address/...  -v   →  17/17 PASS
go test ./signer/...   -v   →  11/11 PASS
go test ./keystore/... -v   →  17/17 PASS
go test ./wallet/...   -v   →  28/28 PASS
TOTAL: 73/73 PASS
```

Signer package gained 4 tests for M1.3 deterministic keygen (`TestNewSignerFromSeedDeterministic`, `TestNewSignerFromSeedKnownAnswer`, `TestNewSignerFromSeedConcurrent`, `TestNewSignerFromSeedVsSignRace`). Wallet package tests grew from 20 to 28 across Audit 4/5 fixes and M1.3 integration (`TestDeriveAddressDeterministic`, `TestSignP2QPKInput*`, `TestPurgeSpentKey*`, `TestListPurgeEligibleAddressesFiltersCorrectly`, and others).

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

### 6. Run the CLI

```bash
go run cmd/main.go
```

Choose **1** to create a new wallet.

> ⚠️ **Backup — new wallets (post-M1.3):** Save the seed hex. Key generation
> is now deterministic from the seed — the database file is a performance
> cache and can be rebuilt from the seed. The seed alone is sufficient for
> recovery of all addresses generated after this fix.
>
> ⚠️ **Backup — existing wallets (pre-M1.3, created before this commit):**
> Save BOTH the seed hex AND a copy of your `qoge_wallet.db` file. Keys
> generated before this fix used random keygen and cannot be re-derived from
> the seed alone. Loss of the DB file means permanent loss of those keys.

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

**Forward-looking only:** addresses generated before this commit used random keygen.
Those keys cannot be re-derived from the seed alone — the DB file remains the sole
source of truth for pre-fix addresses. Post-fix addresses are fully seed-recoverable.

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
- **Phase F ✅ COMPLETE:** `bqt` HRP support added (`83bbc73`); public testnet
  node live at `167.86.81.222:42070`; P2QPK tx `357d4d0c...` confirmed in
  block 104 on public testnet.
- **Phase G ✅ COMPLETE:** Full BIP9 activation cycle validated end-to-end on
  an isolated, air-gapped two-node local simulation (simulation used
  testnet-scale 2016/1512 windows; actual `CMainParams` is 8064/6048).
  Phase heights confirmed at 2016 / 4032 / 6048. Post-`ACTIVE`: real P2QPK
  spend confirmed; tampered spend correctly rejected by `SCRIPT_VERIFY_P2QPK`.
  All technical unknowns resolved.
- **Mainnet activation parameters set ✅** (`7912fa1c1`, QOGE/qogecoin,
  2026-07-26): `bit=3`, `nStartTime=1786284720` (2026-08-09 14:12 UTC),
  `nTimeout=1794060720` (2026-11-07 14:12 UTC). `nMinerConfirmationWindow=8064`
  (5.6 days/window at 1-min blocks) and `nRuleChangeActivationThreshold=6048`
  (75%) are long-standing values, unchanged. Timeline: `nStartTime`→STARTED
  0–~5.6 days; STARTED→ACTIVE with continuous signaling exactly 11.2 days
  (two 8064-block windows); worst-case ~16.8 days; `nTimeout` provides ~74 days
  margin. 5/5 `script_p2qpk_tests` pass. Independently reviewed by Codex and
  Grok Build — zero discrepancies on any parameter value. What remains: formal
  SIP ratification (SAOGEN governance).
- **Reference production node config ✅** (`37adfd719`, QOGE/qogecoin,
  [`contrib/qogecoin-production.conf.example`](https://github.com/QOGE/qogecoin/blob/stable/contrib/qogecoin-production.conf.example)):
  Captures every operational lesson learned during development and testnet
  operation so a fresh mainnet node deployment starts correct. Documented
  lessons: (1) `changetype=bech32` — forces change outputs to SegWit v0
  (P2WPKH) rather than Taproot; Taproot change exposes the raw public key
  on-chain at funding time, which is exactly wrong for a PQC project whose
  purpose is minimising at-rest key exposure; (2) `fallbackfee`/`paytxfee`/
  `mintxfee` — fee estimation fails silently on low-activity chains without
  these, halting all payment processing; (3) `wallet=` persistence — a wallet
  loaded once via `loadwallet` RPC is not reloaded on restart, causing silent
  `-18` errors after every daemon restart.
- **Build fixes ✅** (`dbea00cc7`, QOGE/qogecoin): (1) `configure.ac` — liboqs
  Option A prefix detection used `$prefix` (always empty/NONE in the depends
  workflow) instead of `$depends_prefix` (set by `config.site.in` when
  `CONFIG_SITE` is used); corrected to check `depends_prefix` first, falling
  back to `$prefix`/`$ac_default_prefix` for non-depends builds. Cosmetic fix
  only — `config.site.in`'s own `PKG_CONFIG_PATH` redirection masked the bug
  in practice, but this removes reliance on that implicit behavior. (2)
  `depends/packages/boost.mk` — primary source `boostorg.jfrog.io` is
  permanently dead (JFrog discontinued free Boost hosting); synced to
  `archives.boost.io` (matching upstream `bitcoin/bitcoin@ffbc173ca1`'s own
  fix) and added a QOGE-hosted GitHub release as a Boost-specific fallback
  tier via `$(package)_fetch_cmds`; sha256 hash unchanged. Empirically tested
  (forced tier-1 failure, confirmed clean fallback). Independently reviewed by
  Codex and Grok Build — zero findings.

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
- [`contrib/qogecoin-production.conf.example`](https://github.com/QOGE/qogecoin/blob/stable/contrib/qogecoin-production.conf.example) (QOGE/qogecoin) — reference production node config; documents `changetype=bech32`, fee fallback, and wallet-persistence lessons learned during this project

## Governance

Governed under:
- **SIP-QOGE-PQC-01 v1.0** — wallet-side SLH-DSA implementation (this repo, Phase 1)
- **SIP-QOGE-PQC-02 v1.0** — consensus integration design (P2QPK), Candidate
- **SIP-QOGE-PQC-02a v1.0** — P2QPK sighash specification, Candidate

SIP-C v2.0 | SAOGEN SAO | AI Node attribution: Claude (Anthropic)

Forked from: [eomii/SPHINCS-Wallet](https://github.com/eomii/SPHINCS-Wallet) (MIT)
