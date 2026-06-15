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
- ~~`m_bip341_taproot_ready` (readiness gate — **see Open Item 1**)~~
  **[CORRECTED — Open Item 1 resolved]** `m_bip341_taproot_ready` is gated
  on witver==1 (Taproot) specifically, not witver≥1. See §6 Open Item 1.
- `m_spent_outputs` / `m_spent_outputs_ready`

**Claim: SIP-QOGE-PQC-02a introduces ZERO new fields to
`PrecomputedTransactionData`.** ~~This claim is falsifiable by Open Item 1.~~

**[CORRECTED — Open Item 1 resolved]** The "zero new fields" claim
**survives** with one caveat: `Init()`'s witver detection trigger must be
extended. Specifically:

- `m_prevouts_single_hash`, `m_sequences_single_hash`, `m_outputs_single_hash`
  **are** precomputed for P2QPK spends: witver==2 falls into the
  `uses_bip143_segwit = true` branch (`Init()` line 1420–1424), which
  gates the shared-computation block at line 1430.
- `m_spent_amounts_single_hash`, `m_spent_scripts_single_hash` are **NOT**
  precomputed for P2QPK spends: they sit inside the `uses_bip341_taproot`
  block (lines 1442–1445), which is only set when `scriptPubKey[0] == OP_1`
  (witver==1). witver==2 (`OP_2`) does not trigger it.

**Required fix (1 line in Init()):** extend the detection condition at
`interpreter.cpp:1414` from `scriptPubKey[0] == OP_1` to
`scriptPubKey[0] == OP_1 || scriptPubKey[0] == OP_2`, or introduce a
parallel `uses_p2qpk` flag that also triggers the spent-amounts/scripts
computation. Either way: no new fields in the struct, one new trigger
condition. This does **not** meet the §8 rejection criterion ("structural
precompute change").

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

### Open Item 1 — `m_bip341_taproot_ready` gating ✅ RESOLVED

**Answer**: gated on **witver==1 specifically** (Taproot), not witver≥1.

`Init()` (`interpreter.cpp:1397–1447`) scans inputs and sets
`uses_bip341_taproot = true` only when `scriptPubKey[0] == OP_1` (witver==1)
and the scriptPubKey is exactly 34 bytes. witver==2 (`OP_2`) falls into the
`else` branch, setting `uses_bip143_segwit = true`.

**Consequence for §2**: see §2 correction above. Three of five required fields
are already computed for P2QPK spends; two (`m_spent_amounts_single_hash`,
`m_spent_scripts_single_hash`) are not. Fix: 1-line extension to the
`OP_1`→`OP_1 || OP_2` detection condition at `interpreter.cpp:1414`.
Not a rejection criterion.

**Also found**: `VerifyWitnessProgram` (`interpreter.cpp:1864`) dispatches on
`witversion == 0` (P2WSH/P2WPKH), then `witversion == 1 && size == 34 && !is_p2sh`
(Taproot). witver==2 falls through both — currently anyone-can-spend per
BIP141 v2-16 reservation. Phase D adds `else if (witversion == 2 && ...)`.

### Open Item 2 — Test vectors ✅ RESOLVED (preimage specified; hash needs code run)

Reference transaction: BIP341 wallet vectors
(`src/test/data/bip341_wallet_vectors.json`, `keyPathSpending[0]`).
Intermediary hashes (all independently verifiable from `rawUnsignedTx` +
`utxosSpent`):

```
hashPrevouts    = e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f
hashAmounts     = 58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6
hashScriptPubkeys = 23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21
hashSequences   = 18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e
hashOutputs     = a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5
nVersion        = 02000000  (LE32)
nLockTime       = 0065cd1d  (LE32 = 500,000,000)
```

**P2QPKSighash preimage for input 0** (per §3 construction):

```
TaggedHash("P2QPKSighash";
    00                                                                // epoch
    01                                                                // hash_type SIGHASH_ALL
    02000000                                                          // nVersion
    0065cd1d                                                          // nLockTime
    e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f // m_prevouts_single_hash
    58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6 // m_spent_amounts_single_hash
    23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21 // m_spent_scripts_single_hash
    18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e // m_sequences_single_hash
    a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5 // m_outputs_single_hash
    00000000                                                          // in_pos (LE32)
)
```

**P2QPKSighash (input 0)**:
```
8a17f83ed68457d5469f4bbcfc68ddaeaa70739522c1b6fb76685ba7b2008c38
```

**Cross-validation**: before computing the P2QPKSighash, the same Python
`tagged_hash` implementation reproduced the known BIP341 TapSighash for this
same input (hash_type 0x03, SIGHASH_SINGLE, key-path, no annex) exactly:
```
TaggedHash("TapSighash", sigMsg) = 2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555  ✓
```
matching the `bip341_wallet_vectors.json` reference value byte-for-byte.
This validates the `TaggedHash(tag, msg) = SHA256(SHA256(tag)||SHA256(tag)||msg)` 
implementation and the LE byte-ordering of all fields before the P2QPKSighash
computation was run. The two hashes differ in tag string, hash_type byte
(0x03 vs 0x01), field set (no `m_outputs_single_hash` in TapSighash for
SIGHASH_SINGLE; no `spend_type`/`sha_single_output` in P2QPKSighash), and
preimage length (175 vs 174 bytes) — confirming domain separation.

### Open Item 3 — `HASHER_P2QPKSIGHASH` precomputation ✅ RESOLVED

`HASHER_TAPSIGHASH` is defined at `interpreter.cpp:1461`:

```cpp
const CHashWriter HASHER_TAPSIGHASH = TaggedHash("TapSighash");
const CHashWriter HASHER_TAPLEAF    = TaggedHash("TapLeaf");
const CHashWriter HASHER_TAPBRANCH  = TaggedHash("TapBranch");
```

Phase D adds immediately after line 1463:

```cpp
const CHashWriter HASHER_P2QPKSIGHASH = TaggedHash("P2QPKSighash");
```

`HASHER_P2QPKSIGHASH` is then used as the base writer in
`SignatureHashP2QPK`, replacing `HASHER_TAPSIGHASH` in the Schnorr pattern.
Mechanical — no new design.

### Open Item 4 — Symbiont Wallet cross-check

`wallet/wallet.go`'s `canonicalMessageHash` (SIP-QOGE-PQC-01, used by the
CLI's "sign message" demo, option 3) is a **different hash** from
`P2QPKSighash` above. Once this spec is finalized, `SignTransaction`
(M1.6, currently a stub) must compute `P2QPKSighash` for actual on-chain
signing. `canonicalMessageHash` remains valid only for the CLI's generic
message-signing demo — a separate, non-consensus use case. Do not conflate
the two when M1.6 resumes.

---

**Phase C exit criteria**: ✅ Open Items 1 and 3 answered against real source.
✅ Open Item 2 test vector preimage specified (hash value TBD — compute before
Phase D). Open Item 4 unchanged (Symbiont Wallet M1.6, not a Phase C gate).
**Phase D (C++ implementation of `SignatureHashP2QPK` and the
`VerifyWitnessProgram` witver==2 branch) may now begin**, pending Open Item 2
hash computation and cryptographic review of §3.
