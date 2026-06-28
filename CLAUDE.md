# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Symbiont Wallet is a post-quantum wallet for the QOGE blockchain, implementing SIP-QOGE-PQC-01 and SIP-QOGE-PQC-02 (Phase A). It uses SLH-DSA-SHA2-128f (FIPS 205) via liboqs, enforces single-use addresses, and produces P2QPK addresses (`bq1z...`, witness version 2, Bech32m/BIP350).

**Status:** Wallet-side complete (48/48 tests). Consensus-side (SIP-QOGE-PQC-02) Phase E complete — `DEPLOYMENT_P2QPK` activated in regtest, full liboqs SLH-DSA verification confirmed (56a2aed). Phase F (public testnet) in progress — testnet deployment wired (89812b7c), `bqt` HRP set. Addresses are anyone-can-spend on mainnet until the soft fork activates via governance.

## Build Prerequisites

This project requires CGo and a native liboqs installation. Without it, nothing in `signer/` compiles.

**Required:** Build and install liboqs from source (see README §2), then clone liboqs-go (see README §3). Then update the `replace` directive in `go.mod` to point at your local liboqs-go checkout:

```bash
go mod edit -replace github.com/open-quantum-safe/liboqs-go=$HOME/liboqs-go
go mod tidy
```

The `replace` directive in `go.mod` is machine-specific and must be set before any build or test.

## Commands

```bash
# Run all tests
go test ./...

# Run tests by package (in order of speed)
go test ./address/...  -v   # pure Go, ~0.003s — includes BIP173/BIP350 vectors
go test ./signer/...   -v   # CGo (liboqs), ~0.177s
go test ./keystore/... -v   # ~0.177s
go test ./wallet/...   -v   # integration, ~1.7s (20+ SLH-DSA keygens per test)

# Run a single test
go test ./wallet/... -v -run TestFullSymbiontLifecycle

# Run the CLI
go run cmd/main.go

# Docker (alternative — not the validated native path)
docker build -t symbiont-wallet .
docker run --rm -it --workdir=/app -v ${PWD}:/app symbiont-wallet /bin/bash
```

## Architecture

```
cmd/main.go          — Interactive CLI. All wallet ops go through wallet.Wallet.
signer/slhdsa.go     — CGo wrapper: NewSigner(), ImportSigner(), Sign(), Verify(), Clean().
address/address.go   — FromPublicKey(): HASH256(pubkey) → Bech32m("bq", witver=2).
address/bech32m.go   — Vendored BIP173+BIP350 codec (btcutil only has BIP173/Bech32).
keystore/keystore.go — bbolt DB + AES-256-GCM encryption + address state machine.
wallet/wallet.go     — Orchestration: wires signer + address + keystore, enforces invariants.
```

### Data flow

`wallet.New()` → `keystore.Open()` → `keystore.PreGenerate(20)` → per address: `wallet.deriveAddress()` → `slhdsa.NewSigner()` + `address.FromPublicKey()` + `keystore.EncryptSeed()` → stored in bbolt as `AddressRecord`.

### Address lifecycle (enforced by keystore)

```
FRESH → PENDING → SPENT → RETIRED (EncSeedBlob zeroed, permanent)
```

`keystore.transition()` is the sole state machine executor. Any skip or reversal returns a sentinel error (`ErrAddressAlreadyUsed`, etc.). `wallet.OnConfirmation()` runs MarkSpent + Retire + pool refill atomically.

### Encryption

The AES-256-GCM key is derived from the master seed via HKDF-SHA256 with info `"qoge-keyindex-aes256-gcm"`. Each encrypted blob is `nonce (12 bytes) || ciphertext`. The master seed and enc key are zeroed in `keystore.Close()`.

### Address encoding

`btcutil v1.0.2` is in go.mod for `bech32.ConvertBits` (5↔8 bit regrouping) only — it has no Bech32m support. The vendored `bech32m.go` supplies the BIP350 codec. `address.decode()` enforces the BIP350 checksum-constant/witver binding and explicitly rejects `witver==1` (Taproot) via `ErrTaprootDetected`.

## Key Open Items (do not close without addressing)

- **M1.3 — non-deterministic keygen:** `wallet.deriveAddress()` calls `slhdsa.NewSigner()` (random), ignoring `childSeed`. Losing `qoge_wallet.db` loses the wallet even with the seed. The TODO is to pass `childSeed` to liboqs once it exposes FIPS 205 §10.1 seeded keygen.
- **`KeyDestructionMinConfirmations = 101` gates `OnConfirmation()`:** Key destruction requires `confirmations >= 101` (coinbase maturity depth). `OnConfirmation(addr, confirmations int)` is a no-op until that threshold is met. The application layer integrating Symbiont Wallet is responsible for tracking confirmation depth before calling `OnConfirmation()`. This is an operational safeguard against accidental address reuse, not a consensus rule. Applications MAY increase via `SetKeyDestructionMinConfirmations()` but SHOULD NOT decrease below 101 in production.
- **M1.6 — `SignP2QPKInput` implemented; `QOGETransaction`/`SignTransaction` still a stub:** `wallet.go` now has `SignP2QPKInput` (449300d) which computes the correct P2QPKSighash per SIP-02a §3 and signs it with SLH-DSA. `SignTransaction` retains the placeholder `QOGETransaction` struct — real chain-layer integration (SIP-QOGE-PQC-02 Phases B–F) happens in `qogecoin/qogecoin`, not here.
- **`go.mod` replace directive** must be updated per machine (see above).
- **`qogecoin/qogecoin` fork:** The P2QPK consensus implementation lives at **https://github.com/QOGE/qogecoin** (`stable` and `main` branches, currently in sync). Local checkout at `~/qogecoin` on this machine. Push new commits with `git push qoge-fork stable:stable && git push qoge-fork stable:main`. Do not push to `origin` (upstream `qogecoin/qogecoin`) — fork+PR per SIP-QOGE-PQC-02 §9.
- **SIP-QOGE-PQC-02 Phase B — liboqs in Qogecoin Core:** Option B (system pkg-config) is the dev/Phase D-E path. **Option A — `depends/packages/liboqs.mk` — is now written (liboqs 0.15.0, `BUILD_SHARED_LIBS=OFF`, `OQS_DIST_BUILD=ON`; sha256 verified). `configure.ac` updated with Option A / Option B fallback logic: prefers `${prefix}/lib/liboqs.a` (static, `-lcrypto` transitive dep explicit) and falls back to `PKG_CHECK_MODULES` for the dev VM.** `depends/packages/packages.mk` updated to include `liboqs` in the base packages list. Full depends build (`make -C depends HOST=… liboqs` + `./configure`) not yet run in this session — do that before tagging Phase F complete.
- **SIP-QOGE-PQC-02 Phase E — COMPLETE (56a2aed):** All 6 regtest steps done. Node running, blocks mined (yescrypt PoWHash fix + DGW `fPowNoRetargeting` fix), P2QPK UTXO confirmed, spend mined with 17,088-byte SLH-DSA witness (449300d), sighash cross-validation test added (3689e00, 19/19 tests pass). Activation: `DEPLOYMENT_P2QPK` added to `DeploymentPos` enum + `deploymentinfo.cpp` + `CRegTestParams.vDeployments` (`ALWAYS_ACTIVE`); `DeploymentActiveAt(DEPLOYMENT_P2QPK)` gates `SCRIPT_VERIFY_P2QPK` in `GetBlockScriptFlags`. **Validation:** tampered-sig spend rejected (`SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` via `OQS_SIG_slh_dsa_pure_sha2_128f_verify`), real SLH-DSA spend accepted (txid `1d566789...`) and confirmed in block `f8bc31d9...`.
- **SIP-QOGE-PQC-02 Phase F — IN PROGRESS:** `DEPLOYMENT_P2QPK` added to `CTestNetParams` (`ALWAYS_ACTIVE`, bit 3, `89812b7c` in QOGE/qogecoin); `bech32_hrp = "bqt"`; `DeploymentInfo()` wired for all chains; `address.Network` + `bqt` HRP in Symbiont Wallet (`83bbc73`); `depends/packages/liboqs.mk` written (Option A, 0.15.0, static). **Pending:** full depends build verification (`make -C depends HOST=… liboqs` + `./configure`), `nRuleChangeActivationThreshold` fix on testnet, independent BIP9 parameter review, public testnet node launch.
- **Pre-mainnet checklist — `nRuleChangeActivationThreshold` vs `nMinerConfirmationWindow` on testnet:** `CTestNetParams` sets `nRuleChangeActivationThreshold = 8064` but `nMinerConfirmationWindow = 2016`. The threshold exceeds the window, making real BIP9 lock-in structurally impossible on testnet. Fix before any real BIP9 signaling test on testnet.
- **Pre-mainnet checklist — P2QPK mempool standardness:** `AreInputsStandard()` rejects `WITNESS_UNKNOWN` on mainnet (`fRequireStandard = true`). P2QPK spends are consensus-valid but will not relay through standard mempools without a policy exception in `IsStandard()` or equivalent. Must be addressed before mainnet activation.

## SLH-DSA Constants

| Property | Value |
|----------|-------|
| Algorithm ID (liboqs) | `SLH_DSA_PURE_SHA2_128F` |
| Public key | 32 bytes |
| Secret key | 64 bytes |
| Signature | 17,088 bytes |
| Address HRP | `bq` |
| Witness version | 2 (P2QPK) |
| DB file | `qoge_wallet.db` (bbolt) |
