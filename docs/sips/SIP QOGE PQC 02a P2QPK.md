# SIP-QOGE-PQC-02a — P2QPK Sighash Specification (Normative Reference)

> Condensed from SIP-QOGE-PQC-02a v1.0 (docx, SAOGEN governance) for use by
> Claude Code sessions working on Phase C/D. This file covers the
> **normative construction and open items only** — see the full docx for
> threat model, governance tables, and rationale prose.
>
> **Status: CANDIDATE.** Per SIP-QOGE-PQC-02 §9, cryptographic review of this
> specification is a hard gate before Phase D (any C++ implementation of the
> `VerifyWitnessProgram` P2QPK branch or the sighash function itself).
> **Phase C = working through the open items below against the real
> qogecoin/qogecoin source. Phase C is NOT "implement the sighash."**

## 1. SigVersion::WITNESS_V2_SLHDSA = 4

Confirmed enum (qogecoin: `src/script/interpreter.h:188-194`):

```cpp
enum class SigVersion
{
    BASE = 0,
    WITNESS_V0 = 1,
    TAPROOT = 2,
    TAPSCRIPT = 3,
    WITNESS_V2_SLHDSA = 4,  // <-- NEW, append only, no renumbering
};
```

## 2. Precompute reuse — zero new fields

`PrecomputedTransactionData` (qogecoin: `src/script/interpreter.h:168-170`
and the BIP341 `m_*_single_hash` fields) already contains everything this
sighash needs:

- `m_prevouts_single_hash`
- `m_spent_amounts_single_hash`
- `m_spent_scripts_single_hash`
- `m_sequences_single_hash`
- `m_outputs_single_hash`
- `m_bip341_taproot_ready` (readiness gate — **see Open Item 1**)
- `m_spent_outputs` / `m_spent_outputs_ready`

**Claim: SIP-QOGE-PQC-02a introduces ZERO new fields to
`PrecomputedTransactionData`.** This claim is falsifiable by Open Item 1.

## 3. Normative construction (SIGHASH_ALL only, v1)

```
P2QPKSighash =
    TaggedHash("P2QPKSighash";
        0x00                                  // epoch
     || 0x01                                  // hash_type = SIGHASH_ALL (fixed, v1)
     || tx.nVersion
     || tx.nLockTime
     || cache.m_prevouts_single_hash
     || cache.m_spent_amounts_single_hash
     || cache.m_spent_scripts_single_hash
     || cache.m_sequences_single_hash
     || cache.m_outputs_single_hash
     || in_pos                                // u32, this input's index
    )
```

This is a **strict subset** of BIP341's `SignatureHashSchnorr`
(`src/script/interpreter.cpp:1478-1538`). Every field is unconditional — no
`hash_type` branching, no `ANYONECANPAY` per-input path, no annex, no
`ext_flag`/`key_version`/`tapleaf_hash`/codeseparator position. All of those
are Tapscript-specific and P2QPK has no script tree (SIP-QOGE-PQC-02 §4.2).

**Tagged hash domain**: `HASHER_P2QPKSIGHASH = TaggedHashWriter("P2QPKSighash")`
— same BIP340 tagged-hash construction as `HASHER_TAPSIGHASH`
(`"TapSighash"`), different tag string. Guarantees no collision with any
existing sighash domain.

## 4. Proposed function signature

```cpp
template <class T>
bool SignatureHashP2QPK(
    uint256& hash_out,
    const T& tx_to,
    uint32_t in_pos,
    const PrecomputedTransactionData& cache,
    MissingDataBehavior mdb
);
```

Deliberately fewer parameters than `SignatureHashSchnorr`: no
`ScriptExecutionData& execdata` (no annex/tapleaf/codesep), no `hash_type`
(fixed SIGHASH_ALL), no `SigVersion` (this function IS the
`WITNESS_V2_SLHDSA` case — no dispatch needed).

## 5. Explicitly out of scope for v1

- `SIGHASH_ANYONECANPAY`, `SIGHASH_NONE`, `SIGHASH_SINGLE` — would
  reintroduce per-input/output branching this spec eliminates. If ever
  needed: new `SigVersion::WITNESS_V2_SLHDSA_EXT = 5` with its own sighash,
  not an extension of this one.
- Script-path / multi-leaf spending — P2QPK has no script tree by
  definition.
- Annex — P2QPK witness stack is fixed at exactly `[sig, pubkey]`
  (SIP-QOGE-PQC-02 §5.2).

## 6. Open Items — THIS IS PHASE C

### Open Item 1 — `m_bip341_taproot_ready` gating (HIGHEST PRIORITY)

**Question**: is `m_bip341_taproot_ready` (and the precompute that sets it)
keyed on "any witver>=1 spend" or specifically "witver==1 (Taproot)"?

**Why it matters**: Section 2's "zero new precompute" claim depends on this
precompute already running for witver==2 (P2QPK) spends. If it's
Taproot-specific (witver==1 only), the precompute *trigger* needs extending
to witver==2 — a small but real change, and the one thing that could
invalidate this spec's core simplification claim.

**How to check**: in `~/qogecoin`, find where `m_bip341_taproot_ready` is
set (likely in `PrecomputedTransactionData`'s constructor or an `Init`-style
method in `src/script/interpreter.cpp` or `.h`). Read the condition under
which it's computed. Report back: is it gated on `witversion == 1`,
`witversion >= 1`, "any segwit v1+ output in the tx", or something else?

**Rejection criterion** (SIP-QOGE-PQC-02a §8): if this cannot be extended to
witver==2 without a structural precompute change, this SIP needs revision.

### Open Item 2 — Test vectors

Produce a reference set of `(transaction, input index) -> expected
P2QPKSighash` tuples, derivable from Section 3 plus a BIP341 test-vector
transaction (same cache fields, different tag + reduced field set),
**independent of any SLH-DSA signing**. These are the deliverable a
cryptographic reviewer checks Section 3 against — before any C++ exists.

### Open Item 3 — `HASHER_P2QPKSIGHASH` precomputation

Locate where `HASHER_TAPSIGHASH` is defined (likely a static
`CHashWriter`/tagged-hash midstate constant). Replicate the pattern with tag
`"P2QPKSighash"`. Mechanical once located — this is "find the pattern and
copy it with a different string," not new design.

### Open Item 4 — Symbiont Wallet cross-check

`wallet/wallet.go`'s `canonicalMessageHash` (SIP-QOGE-PQC-01, used by the
CLI's "sign message" demo, option 3) is a **different hash** from
`P2QPKSighash` above. Once this spec is finalized, `SignTransaction`
(M1.6, currently a stub) must compute `P2QPKSighash` for actual on-chain
signing. `canonicalMessageHash` remains valid only for the CLI's generic
message-signing demo — a separate, non-consensus use case. Do not conflate
the two when M1.6 resumes.

---

**Phase C exit criteria**: Open Items 1 and 3 answered against real source
(grep + read, like Phase B.1's secp256k1/CMake investigation); Open Item 2
test vectors drafted. Only then does Phase D (C++ implementation of
`SignatureHashP2QPK` and the `VerifyWitnessProgram` witver==2 branch) begin.
