# Audit 1 (Sighash Construction) — Multi-Model Triage Summary

**Component:** `SignatureHashP2QPK` (`src/script/interpreter.cpp`) and its
normative spec SIP-QOGE-PQC-02a.

**Auditors (independent, fresh conversations, no shared context):**
- Claude Opus 4.8 (Anthropic) — 2 July 2026
- ChatGPT 5.5 (OpenAI) — 2 July 2026
- OpenAI Codex — 1 July 2026 (run before same-day comment fixes landed)

**Methodology note:** all three auditors independently recomputed the test
vector in Python from the raw BIP341 wallet-vector transaction. This
document preserves each auditor's verdict verbatim and records the
project's triage disposition separately. Auditor verdicts are NOT edited.

---

## Headline result

The sighash test vector `8a17f83ed68457d5469f4bbcfc68ddaeaa70739522c1b6fb76685ba7b2008c38`
was **independently recomputed to an exact match by all three models**, from
three separate Python implementations. The construction's core security
properties (cross-input reuse, cross-transaction replay, domain separation,
length-extension resistance) were assessed PASS by all three.

**No finding in Audit 1 is a bottleneck for mainnet activation.**

---

## Verdict matrix (auditor verdicts preserved verbatim)

| Question | Opus 4.8 | ChatGPT 5.5 | Codex |
|----------|----------|-------------|-------|
| Q1 — Transaction malleability | PASS | PASS | **FAIL (narrow)** |
| Q2 — Cross-input signature reuse | PASS | PASS | PASS |
| Q3 — Cross-transaction replay | PASS | PASS | PASS |
| Q4 — Sighash domain separation | PASS | PASS | PASS |
| Q5 — Length-extension / canonicalization | PASS | PASS | PASS |
| Q6 — Test-vector consistency (recomputed) | PASS | PASS | PASS |

Five of six questions: unanimous PASS across three independent frontier
models. One question (Q1) has a framing disagreement, triaged below.

---

## Triage dispositions

### Q1 — Transaction malleability

**Codex verdict: FAIL (narrow). Opus & ChatGPT verdict: PASS.**

**Triage disposition: ACKNOWLEDGED — NOT A BOTTLENECK FOR MAINNET ACTIVATION.**

Codex correctly identified that a transaction which **mixes a P2QPK input
with a separately-malleable legacy input** inherits legacy scriptSig
malleability — an attacker controlling the legacy input could mutate its
scriptSig, changing the transaction's txid while the P2QPK signature on the
other input remains valid.

The framing disagreement is legitimate and resolves as follows:

- **This is a pre-existing property of ALL SegWit-derived chains**, including
  Bitcoin itself. It is inherited from the legacy input, not introduced by
  P2QPK. Opus and ChatGPT scoped Q1 to *P2QPK-specific* behavior (where the
  answer is correctly PASS — a P2QPK output's scriptSig is forced empty by
  the `!is_p2sh` guard, and witness malleation does not change the txid).
  Codex scoped Q1 to *whole-transaction* behavior including mixed legacy
  inputs (where inherited malleability exists).
- **It does not risk funds.** All three audits agree the attacker cannot
  redirect outputs, swap P2QPK prevouts, or alter amounts. It is txid
  malleability only — the transaction still performs exactly what was signed.
- **It is not fixable and not P2QPK's to fix.** Codex itself notes that
  committing to all scriptSigs would make signatures circular (impossible).
  The standard mitigation for any SegWit chain is to avoid mixing malleable
  legacy inputs where stable txids are required.
- **The Symbiont Wallet does not construct mixed P2QPK/legacy-malleable
  transactions.** The scenario does not arise for the wallet's own outputs.

**Resolution:** documented in SIP-QOGE-PQC-02a security section. No code
change. Not a bottleneck for mainnet activation.

---

### §7.1 — Sighash gate maintenance hazard (Opus + ChatGPT, both flagged)

**Triage disposition: RESOLVED.**

Both Opus and ChatGPT independently identified that the sighash's binding of
input amounts and spent scripts depends on the readiness gate staying on
`m_bip341_taproot_ready` (NOT `m_bip143_segwit_ready`). Swapping the gate
during future maintenance would silently bypass amount/spent-script binding.

A maintenance guardrail comment was added at the gate
(`5f1e7c1`, `QOGE/qogecoin` `stable`) warning against this specific change.
The behavior currently fails closed (safe). Resolved.

---

### §7.2 — Stale "liboqs stub" comment (Opus flagged)

**Triage disposition: RESOLVED.**

Comment at `interpreter.cpp` falsely described the SLH-DSA verifier as a
stub. Corrected to reflect the real, working verification path
(`5f1e7c1`). Resolved.

---

### Spec prose: `spend_type` byte mismatch (all three flagged)

**Triage disposition: DOCUMENTATION FIX PENDING.**

The prompt/prose referenced a BIP341-style `spend_type` byte. The actual
normative construction and the code do NOT include it (the preimage is
`00 || 01 || nVersion || nLockTime || hashPrevouts || hashAmounts ||
hashScriptPubKeys || hashSequences || hashOutputs || in_pos`). All three
auditors confirmed the code and test vector match the no-`spend_type`
construction. The SIP prose summary should be cleaned up to remove any
`spend_type` reference so prose, code, and vector are mutually consistent.

**Resolution:** spec text update pending (batched with other post-audit
documentation). No code change — the code is already correct.

---

### Spec note: SIGHASH_ALL-only (ChatGPT emphasized)

**Triage disposition: DOCUMENTATION FIX PENDING.**

P2QPK hardcodes `SIGHASH_ALL` — no `SINGLE`/`NONE`/`ANYONECANPAY` support.
This is an intentional and arguably correct choice for a single-use address
model (it also eliminates the classic sighash-flag replay surfaces, which
contributed to the Q3 PASS). Should be documented explicitly in the spec as
a deliberate design decision so future implementers do not assume other
sighash types are supported.

**Resolution:** spec text update pending. No code change.

---

## Summary

- **Sighash arithmetic:** confirmed correct by three independent Python
  recomputations. Highest-confidence verification the AI-audit process can
  produce.
- **Core security properties:** unanimous PASS across three models.
- **One framing disagreement (Q1):** inherited SegWit malleability,
  fund-safe, unfixable, wallet-avoided. Not a bottleneck for mainnet.
- **Code fixes applied:** §7.1 guardrail comment, §7.2 stale comment
  (`5f1e7c1`).
- **Documentation fixes pending (no code change):** remove `spend_type`
  prose, document SIGHASH_ALL-only decision, document Q1 malleability
  scoping.

**Audit 1 overall: no bottleneck for mainnet activation.**

---

*Multi-model triage artifact for SIP-QOGE-PQC-02a. Auditor verdicts
preserved verbatim; project dispositions recorded separately. Prepared as
part of the pre-mainnet review process for the P2QPK soft fork.*
