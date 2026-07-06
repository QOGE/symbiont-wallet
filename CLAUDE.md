# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Symbiont Wallet is a post-quantum wallet for the QOGE blockchain, implementing SIP-QOGE-PQC-01 and SIP-QOGE-PQC-02 (Phase A). It uses SLH-DSA-SHA2-128f (FIPS 205) via liboqs, enforces single-use addresses, and produces P2QPK addresses (`bq1z...`, witness version 2, Bech32m/BIP350).

**Status:** Wallet-side complete (63/63 tests). Consensus-side (SIP-QOGE-PQC-02) Phase F complete — public testnet live at `167.86.81.222:42070`, P2QPK tx `357d4d0c...` confirmed in block 104. Addresses are anyone-can-spend on mainnet until the soft fork activates via governance.

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

`keystore.transition()` is the sole state machine executor. Any skip or reversal returns a sentinel error (`ErrAddressAlreadyUsed`, etc.). `wallet.OnConfirmation()` runs MarkSpent + Retire atomically (single bbolt transaction via `MarkSpentAndRetire`) then refills the pool in a separate operation — pool refill is not part of the atomic write.

### Encryption

The AES-256-GCM key is derived from the master seed via HKDF-SHA256 with info `"qoge-keyindex-aes256-gcm"`. Each encrypted blob is `nonce (12 bytes) || ciphertext`. The master seed and enc key are zeroed in `keystore.Close()`.

### Address encoding

`btcutil v1.0.2` is in go.mod for `bech32.ConvertBits` (5↔8 bit regrouping) only — it has no Bech32m support. The vendored `bech32m.go` supplies the BIP350 codec. `address.decode()` enforces the BIP350 checksum-constant/witver binding and explicitly rejects `witver==1` (Taproot) via `ErrTaprootDetected`.

## Key Open Items (do not close without addressing)

- **M1.3 — non-deterministic keygen:** `wallet.deriveAddress()` calls `slhdsa.NewSigner()` (random), ignoring `childSeed`. Losing `qoge_wallet.db` loses the wallet even with the seed. The TODO is to pass `childSeed` to liboqs once it exposes FIPS 205 §10.1 seeded keygen. **User-facing impact:** users MUST back up both the seed AND the database file. The seed alone is insufficient for recovery until M1.3 is resolved.
- **`KeyDestructionMinConfirmations = 101` gates `OnConfirmation()`:** Key destruction requires `confirmations >= 101` (coinbase maturity depth). `OnConfirmation(addr, confirmations int)` is a no-op until that threshold is met. The application layer integrating Symbiont Wallet is responsible for tracking confirmation depth before calling `OnConfirmation()`. This is an operational safeguard against accidental address reuse, not a consensus rule. Applications MAY increase via `SetKeyDestructionMinConfirmations()` but SHOULD NOT decrease below 101 in production.
- **M1.6 — `SignP2QPKInput` implemented; `QOGETransaction`/`SignTransaction` still a stub:** `wallet.go` now has `SignP2QPKInput` (449300d) which computes the correct P2QPKSighash per SIP-02a §3 and signs it with SLH-DSA. `SignTransaction` retains the placeholder `QOGETransaction` struct — real chain-layer integration (SIP-QOGE-PQC-02 Phases B–F) happens in `qogecoin/qogecoin`, not here.
- **`go.mod` replace directive** must be updated per machine (see above).
- **`qogecoin/qogecoin` fork:** The P2QPK consensus implementation lives at **https://github.com/QOGE/qogecoin** (`stable` and `main` branches, currently in sync). Local checkout at `~/qogecoin` on this machine. Push new commits with `git push qoge-fork stable:stable && git push qoge-fork stable:main`. Do not push to `origin` (upstream `qogecoin/qogecoin`) — fork+PR per SIP-QOGE-PQC-02 §9.
- **SIP-QOGE-PQC-02 Phase B — liboqs in Qogecoin Core:** Option B (system pkg-config) is the dev/Phase D-E path. **Option A — `depends/packages/liboqs.mk` — FULLY VERIFIED (`88c400c59`, `135c2fc0b` in QOGE/qogecoin): liboqs 0.15.0, `BUILD_SHARED_LIBS=OFF`, `BUILD_TESTING=OFF`, `OQS_DIST_BUILD=ON`; sha256 pinned; `CMAKE_SYSTEM_PROCESSOR=$(host_arch)` fix included. `configure.ac` prefers `${prefix}/lib/liboqs.a` (static, Option A) and falls back to `PKG_CHECK_MODULES` (Option B, dev VM). `$(LIBOQS_LIBS)` added to all LDADD targets in `src/Makefile.am`. Verified: `liboqs.a` (21 MB) installed to depends prefix; configure reports "Option A — static lib"; all 5 `script_p2qpk_tests` pass.**
- **SIP-QOGE-PQC-02 Phase E — COMPLETE (56a2aed):** All 6 regtest steps done. Node running, blocks mined (yescrypt PoWHash fix + DGW `fPowNoRetargeting` fix), P2QPK UTXO confirmed, spend mined with 17,088-byte SLH-DSA witness (449300d), sighash cross-validation test added (3689e00, 19/19 tests pass). Activation: `DEPLOYMENT_P2QPK` added to `DeploymentPos` enum + `deploymentinfo.cpp` + `CRegTestParams.vDeployments` (`ALWAYS_ACTIVE`); `DeploymentActiveAt(DEPLOYMENT_P2QPK)` gates `SCRIPT_VERIFY_P2QPK` in `GetBlockScriptFlags`. **Validation:** tampered-sig spend rejected (`SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` via `OQS_SIG_slh_dsa_pure_sha2_128f_verify`), real SLH-DSA spend accepted (txid `1d566789...`) and confirmed in block `f8bc31d9...`.
- **SIP-QOGE-PQC-02 Phase F — COMPLETE:** `DEPLOYMENT_P2QPK` added to `CTestNetParams` (`ALWAYS_ACTIVE`, bit 3, `89812b7c`); `bech32_hrp = "bqt"`; `DeploymentInfo()` wired for all chains; `address.Network` + `bqt` HRP in Symbiont Wallet (`83bbc73`); Option A liboqs depends build fully verified (`88c400c59`, `135c2fc0b`); `nRuleChangeActivationThreshold` fixed to 1512/2016 (`c00f6112d`); `BIP9Deployment` safe defaults + explicit `NEVER_ACTIVE` in `CMainParams`/`CSigNetParams` (`09638b35`); independent BIP9 parameter review (PASS); public testnet live at `167.86.81.222:42070`; P2QPK tx `357d4d0c...` confirmed in block 104 on public testnet.
- **Pre-mainnet checklist — P2QPK mempool standardness: COMPLETE (`3262636a0` in QOGE/qogecoin):** Policy exception implemented in `src/policy/policy.cpp` and `src/policy/policy.h` — P2QPK spends are now standard on mainnet.
- **Pre-mainnet Audit 1 (sighash construction) — COMPLETE:** Multi-model audit of `SignatureHashP2QPK` and SIP-QOGE-PQC-02a. Auditors: Claude Opus 4.8, ChatGPT 5.5, OpenAI Codex (independent, fresh context, 1–2 July 2026). Test vector `8a17f83e...` independently recomputed to exact match by all three. Core security properties (cross-input reuse, cross-transaction replay, domain separation, length-extension): unanimous PASS. One framing disagreement (Q1 malleability, Codex FAIL narrow): acknowledged, fund-safe, inherited from SegWit, not fixable, wallet-avoided, documented in SIP-02a §8. Code fixes applied: sighash gate guardrail (`061e88ea6`, QOGE/qogecoin) + stale "liboqs stub" comment corrected. Documentation fixes applied: explicit no-`spend_type` note in SIP-02a §3, SIGHASH_ALL-only framed as deliberate design decision in §5, Q1 malleability documented in SIP-02a §8. **No finding is a bottleneck for mainnet activation.** Triage artifact: `docs/sips/Audit_1_Sighash_Construction_Triage.md`.
- **Pre-mainnet Audit 2 (witness verification) — COMPLETE:** Multi-model audit of P2QPK mempool policy path. Auditors: Codex, Claude Opus 4.8, ChatGPT 5.5, Grok (independent, fresh context, 5 July 2026). Bug confirmed: `SCRIPT_VERIFY_P2QPK` absent from `constexpr STANDARD_SCRIPT_VERIFY_FLAGS`; `PolicyScriptChecks` (`src/validation.cpp`) used this static set, never enforcing SLH-DSA verification at the mempool policy layer. 3/4 auditors found the bug (Codex, Opus, ChatGPT); Grok PASS (examined `GetBlockScriptFlags`/`ConnectBlock` path, which is correct, without separately examining `STANDARD_SCRIPT_VERIFY_FLAGS`). Fix disagreement: Opus proposed adding `SCRIPT_VERIFY_P2QPK` to the `constexpr` (wrong — would enforce SLH-DSA before activation, breaking pre-activation anyone-can-spend per §3.4); ChatGPT proposed dynamic `DeploymentActiveAfter` gate (correct). Resolved by direct code inspection. Fix applied: `88888dc51` (QOGE/qogecoin) — same `DeploymentActiveAfter` pattern as `AreInputsStandard` (`3262636a0`). Third consequence discovered during verification (not by auditors): `testmempoolaccept` reported `allowed:true` for invalid-sig P2QPK tx — fixed by same commit (same function, same code path). All three consequences resolved: mempool acceptance of invalid sigs, "BUG! PLEASE REPORT THIS!" log spam, `test_accept` false positive. Triage artifact: `docs/sips/Audit_2_Witness_Verification_Triage.md`.
- **Audit 5 (wallet lifecycle, unstructured) — COMPLETE:** Codex CLI (0.142.5) given direct read-only filesystem access to `~/symbiont-wallet` for a self-directed security review (6 July 2026). Methodologically distinct from Audits 1–4, which use pre-written structured prompts run across multiple models for cross-comparison — Audit 5 is a single-auditor unstructured pass and is not directly comparable to the verdict-matrix format. Three findings surfaced: (1) Address reservation — FALSE POSITIVE: `NextReceiveAddress` intentionally returns the same address on repeated calls without consuming state (read-only peek semantics, tested and documented); (2) Retirement atomicity — CONFIRMED, FIXED (`b093d0f`): `OnConfirmation` called `MarkSpent` then `Retire` as two separate bbolt `Update` transactions; new `KeyIndex.MarkSpentAndRetire` performs both in one transaction, `CLAUDE.md` corrected, two new tests added (63/63 pass); (3) `SignP2QPKInput` cross-check gap — CONFIRMED, DEFERRED: no validation that `SpentUTXOs[InputIndex].scriptPubKey` matches `FromAddr` before signing; not urgent until M1.6 wires real transactions. Not a bottleneck for mainnet activation. Triage artifact: `docs/sips/Audit_5_Wallet_Lifecycle_ Triage_Summary.md`.

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
