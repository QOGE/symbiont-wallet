# SIP-QOGE-PQC-02a — P2QPK Sighash Specification (Normative Reference)

> Condensed from SIP-QOGE-PQC-02a v1.0 (docx, SAOGEN governance) for use by
> Claude Code sessions working on Phase C/D. This file covers the
> **normative construction and open items only** — see the full docx for
> threat model, governance tables, and rationale prose.
>
> **Status: CANDIDATE — Phases C through F complete.** All normative
> safeguards (§7-A through §7-E) implemented and verified. Public testnet
> live at `167.86.81.222:42070`; P2QPK tx `357d4d0c...` confirmed in block
> 104. **Audit 1 (sighash construction) complete** — test vector
> `8a17f83e...` independently recomputed by 3 frontier models; no mainnet
> blocker found; see `Audit_1_Sighash_Construction_Triage.md`. Mainnet
> activation pending SAOGEN governance (BIP9 parameters).

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

**No `spend_type` byte.** BIP341 `SignatureHashSchnorr` includes a
`spend_type` byte encoding key-path vs script-path and annex presence.
P2QPK has neither — witness stack is always exactly `[sig, pubkey]`, there
is no script tree, and no annex. The `spend_type` byte is absent from the
preimage above. This was confirmed by three independent Audit 1 reviewers
who each recomputed the test vector to an exact match without it.

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

**`SIGHASH_ALL` is the only supported hash type. This is a deliberate
design decision**, not an oversight. Rationale:

1. **Single-use address model.** Each P2QPK address is used exactly once
   (FRESH → PENDING → SPENT → RETIRED). `SIGHASH_SINGLE` and
   `SIGHASH_NONE` exist to enable multi-party protocols where parties sign
   before the full transaction is assembled — a use case that is
   structurally incompatible with single-use, pre-generated address pools.
2. **Eliminates sighash-flag replay surfaces.** `SIGHASH_SINGLE`'s
   "Sighash Single bug" (unsigned outputs beyond `in_pos`) and
   `SIGHASH_NONE`'s signature-reuse across outputs are well-known attack
   surfaces. Hardcoding `SIGHASH_ALL` eliminates both.
3. **Confirmed secure by Audit 1** (Q3 cross-transaction replay: unanimous
   PASS across three models; Q5 canonicalization: unanimous PASS).

If additional hash types are ever needed: define a new
`SigVersion::WITNESS_V2_SLHDSA_EXT = 5` with its own sighash function —
not an extension of this one. Do not add `hash_type` branching here.

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

### Open Item 2 — Test vectors ✅ FULLY RESOLVED

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

**Independent recomputation**: the GPT-5.5 Thinking review (20 June 2026,
`docs/sips/QOGE_P2QPK_PQC_Independent_Review.md`) independently recomputed
this value from the raw preimage using `SHA256(SHA256(tag)||SHA256(tag)||preimage)`
with `tag = "P2QPKSighash"` and confirmed it matches exactly. Open Item 2 is
**fully resolved** — preimage specified and hash independently verified.

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

## 7. Phase D Normative Requirements (from independent review)

Source: GPT-5.5 Thinking independent review, 20 June 2026
(`docs/sips/QOGE_P2QPK_PQC_Independent_Review.md`, §Required Phase D Safeguards).
These are **blocking consensus rules**, not prose suggestions. Each must be
satisfied before the Phase D C++ implementation is considered complete.

### 7-A. Exact signature and public key length validation

Consensus MUST enforce exact lengths before invoking liboqs:

```
pubkey.size()    == 32       bytes   (SLHDSA_PK_LEN)
signature.size() == 17,088   bytes   (SLHDSA_SIG_LEN — exact, not ≤ max)
```

The `VerifyWitnessProgram` pseudocode in §3.3 of SIP-QOGE-PQC-02 currently
uses `sig.size() > SLHDSA_SIG_MAX_LEN` — this is **incorrect for consensus**
and must be changed to `sig.size() != SLHDSA_SIG_LEN` (exact equality).
No appended sighash byte is permitted. Rationale: exact validation keeps
consensus canonical and avoids relying on downstream library rejection for
malformed lengths.

### 7-B. Exact SLH-DSA mode must be normative

The implementation MUST specify:

```
Algorithm:        SLH-DSA-SHA2-128f
Mode:             pure SLH-DSA (not pre-hash)
Context string:   empty ("")
Message:          exactly the 32-byte P2QPKSighash output
Signature length: exactly 17,088 bytes
Public key:       exactly 32 bytes
```

**Reference**: RFC 9814 §3 distinguishes pure and pre-hash SLH-DSA and
specifies that the context string is included in the signed message. The
context must be empty; the message must be the 32-byte P2QPKSighash
exactly — not a re-hash of it or a prefixed encoding.

liboqs API path to use: `OQS_SIG_slh_dsa_pure_sha2_128f_verify` (or the
generic `OQS_SIG` struct with `OQS_SIG_alg_slh_dsa_pure_sha2_128f`). Using
a `*_prehash_*` variant is a consensus-breaking error.

### 7-C. liboqs must be pinned/reproducible for consensus builds

Phase B's Option B (host `pkg-config`, dynamic system liboqs) is explicitly
**dev/Phase D-E only**. It must NOT become the consensus build path.

**Required property for any consensus merge**: liboqs must be integrated via
Option A — `depends/packages/liboqs.mk`, CMake via `$(package)_cmake`,
following the `native_libmultiprocess.mk` template — providing a pinned,
version-locked, reproducible build. Different distro liboqs packages or
compile-time flags across node operators risk consensus divergence if library
behavior changes.

**Implication for roadmap**: Option A was previously scoped to Phase F+ (cross-
compiled release builds). The independent review's finding elevates it: Option A
should be completed before any consensus code is merged for relay/mining, not
just before cross-platform release. Review with SAOGEN before finalizing the
Phase D/E/F ordering.

**[RESOLVED — Phase F]** Option A (`depends/packages/liboqs.mk`) is fully
implemented and verified (`88c400c59`, `135c2fc0b` in QOGE/qogecoin).
Static build, `BUILD_TESTING=OFF`, `CMAKE_SYSTEM_PROCESSOR=$(host_arch)`
fix included. This is now the consensus build path. Option B (host
pkg-config) remains available as a dev-only fallback.

### 7-D. Precompute trigger must be tested

Extending `Init()` from `scriptPubKey[0] == OP_1` to
`scriptPubKey[0] == OP_1 || scriptPubKey[0] == OP_2` (or introducing a
`uses_p2qpk` flag) is necessary but not sufficient. Phase D/E MUST include
tests for:

1. Single P2QPK input — `m_spent_amounts_single_hash` and
   `m_spent_scripts_single_hash` correctly computed
2. Multiple P2QPK inputs — all per-input cache fields populated
3. Mixed legacy + P2QPK inputs in the same transaction
4. Mixed Taproot + P2QPK inputs (if Taproot exists in QOGE)
5. **Missing spent-output data must cause a hard failure** — not silently
   hash zeroes. This is the critical case: a missing-data path that produces
   an all-zero hash and a verifiable signature would be a consensus exploit.

`MissingDataBehavior::FAIL_WITH_ERROR` must be enforced in
`SignatureHashP2QPK` when `!cache.m_bip341_taproot_ready` (or the P2QPK
equivalent readiness gate) — analogous to the Schnorr path.

**[PARTIALLY RESOLVED — per audit 1, `061e88ea6`]** A maintenance guardrail
comment has been added directly above the `m_bip341_taproot_ready` gate in
`SignatureHashP2QPK` explaining why the gate must not be changed to
`m_bip143_segwit_ready`: a witver-2 spend also sets `m_bip143_segwit_ready`,
so swapping the gate would let the sighash proceed with default-zero
`m_spent_amounts_single_hash` / `m_spent_scripts_single_hash`, silently
bypassing input-amount and spent-script binding — the consensus exploit
described in item 5 above. The fail-closed behavior is preserved and now
documented in-code. Full resolution requires the test coverage in items 1–4
(regtest precompute trigger tests) which remain open.

### 7-E. Mempool relay and standardness testing is distinct from block validation

Phase E functional testing MUST explicitly verify:

```
1. Construct a standard P2QPK spend (17,088-byte signature witness item)
2. Submit it via sendrawtransaction on regtest with default mempool policy
3. Confirm it is accepted into the mempool and mined in a subsequent block
   without manual block injection (generateblock with explicit txids)
```

This is separate from block-validation testing (which only confirms the node
accepts a pre-built block containing a P2QPK spend). A P2QPK spend must relay
through default policy — `MAX_STANDARD_TX_WEIGHT = 400,000 wu` (verified in
SIP-QOGE-PQC-02 §4) accommodates a P2QPK input (~17,150 wu, ~4.3% of limit),
but `IsStandard()` / `AreInputsStandard()` and the witness item size checks in
`policy/policy.cpp` must be confirmed to not reject it at the policy layer.

**[RESOLVED — Phase F + `3262636a0`]** P2QPK mempool relay confirmed:
policy exception implemented in `AreInputsStandard()` and
`IsWitnessStandard()` (`src/policy/policy.cpp`, commit `3262636a0`).
P2QPK tx `357d4d0c...` relayed from dev VM to public testnet VPS
(`167.86.81.222:42070`) and confirmed in block 104. Relay through
standard mainnet mempools confirmed working.

---

**Phase C exit criteria**: ✅ All met.

- ✅ Open Item 1: `m_bip341_taproot_ready` gating confirmed witver==1-specific; 1-line Init() fix identified
- ✅ Open Item 2: P2QPKSighash preimage fully specified; hash `8a17f83e...` computed and independently recomputed by GPT-5.5 Thinking review (20 June 2026) — see `docs/sips/QOGE_P2QPK_PQC_Independent_Review.md`
- ✅ Open Item 3: `HASHER_P2QPKSIGHASH` placement confirmed (`interpreter.cpp:1464`)
- Open Item 4: Symbiont Wallet M1.6 — not a Phase C gate, unchanged

**Phase D gate cleared**: independent cryptographic review PASS (with required safeguards).
Safeguards A-E have been folded into the spec as normative requirements in §7 (above).
Phase D implementation complete (`56a2aed`). Phase E regtest validation complete.
Phase F public testnet complete. **Audit 1 (sighash construction) complete** — no
mainnet blocker; see `Audit_1_Sighash_Construction_Triage.md`. Mainnet activation
pending SAOGEN governance (BIP9 parameters) and private mainnet simulation.

## 8. Security notes (from Audit 1)

### Mixed-input transaction malleability (Audit 1 Q1)

A transaction mixing a P2QPK input with a **malleable legacy input** (non-SegWit
scriptSig) inherits legacy scriptSig malleability. An attacker who controls the
legacy input can mutate its scriptSig, changing the txid while the P2QPK signature
on the other input remains valid.

**This does not risk funds.** The attacker cannot redirect outputs, swap P2QPK
prevouts, or alter amounts. It is txid malleability only — the transaction still
performs exactly what was signed.

**This is a pre-existing property of all SegWit-derived chains** (including
Bitcoin). It is inherited from the legacy input, not introduced by P2QPK. A P2QPK
output's own scriptSig is forced empty by the `!is_p2sh` guard; witness malleation
does not change the txid. Committing to all scriptSigs would make signatures
circular (impossible to construct).

**Standard mitigation**: avoid mixing malleable legacy inputs where stable txids
are required (e.g., pre-signed HTLC chains). The Symbiont Wallet does not
construct mixed P2QPK/legacy-malleable transactions — the scenario does not arise
for the wallet's own outputs.

**Verdict matrix from Audit 1:** Opus 4.8 PASS, ChatGPT 5.5 PASS, Codex FAIL
(narrow — scoped to whole-transaction behavior including mixed legacy inputs).
All three agree funds are safe. Framing disagreement triaged and documented in
`Audit_1_Sighash_Construction_Triage.md`. Not a bottleneck for mainnet activation.
