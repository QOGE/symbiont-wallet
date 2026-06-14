# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Symbiont Wallet is a post-quantum wallet for the QOGE blockchain, implementing SIP-QOGE-PQC-01 and SIP-QOGE-PQC-02 (Phase A). It uses SLH-DSA-SHA2-128f (FIPS 205) via liboqs, enforces single-use addresses, and produces P2QPK addresses (`bq1z...`, witness version 2, Bech32m/BIP350).

**Status:** Wallet-side complete (47/47 tests). Consensus-side (the SIP-QOGE-PQC-02 soft fork on the QOGE node) is pending. Addresses are currently anyone-can-spend on-chain until the soft fork activates.

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
- **M1.6 — `QOGETransaction` is a stub:** `wallet.go`'s `SignTransaction` uses a placeholder struct. Real consensus integration (SIP-QOGE-PQC-02 Phases B–F) happens in `qogecoin/qogecoin`, not here.
- **`go.mod` replace directive** must be updated per machine (see above).

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
