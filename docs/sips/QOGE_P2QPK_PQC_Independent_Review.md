# Independent AI Review of QOGE P2QPK PQC Integration

**Phase:** Phase C / Pre-Phase D Design Review  
**Review date:** 20 June 2026  
**Reviewer:** OpenAI ChatGPT, GPT-5.5 Thinking  
**Input reviewed:** `qoge-pqc-sip-review-pack.md`, containing condensed SIP-QOGE-PQC-02 and SIP-QOGE-PQC-02a normative references.

> **Reviewer boundary:** This is an independent AI technical review of the supplied SIP material. It is useful as a pre-audit design review, but it is not a substitute for a human Bitcoin/PQC cryptography audit before any mainnet activation.

## Executive Verdict

**Status: PASS for Phase C design review, with required Phase D safeguards.**

I did not find a fatal flaw in the proposed P2QPK sighash construction. The rejection of Taproot/Tapscript as the PQC carrier is correct under the stated CRQC threat model. However, mainnet activation should remain blocked until exact SLH-DSA mode, signature length validation, liboqs reproducibility, precompute gating, and mempool standardness are tested and documented.

```text
Phase C: acceptable after documentation cleanup
Phase D: allowed to begin
Mainnet activation: not yet
Human cryptographer / Bitcoin consensus review: still recommended before deployment
```

## Independent Test Vector Reproduction

The P2QPKSighash test vector in SIP-QOGE-PQC-02a was independently recomputed from the supplied preimage. The result matches exactly:

```text
preimage length: 174 bytes
TaggedHash("P2QPKSighash", preimage):
8a17f83ed68457d5469f4bbcfc68ddaeaa70739522c1b6fb76685ba7b2008c38
```

Reproduction method:

```text
SHA256(SHA256(tag) || SHA256(tag) || preimage)
tag = "P2QPKSighash"
```

## Findings Overview

| Area | Severity | Finding | Status |
|---|---:|---|---|
| Taproot/Tapscript carrier | Critical design | Rejected design is correctly rejected; Taproot key-path remains secp256k1-exposed. | No objection |
| P2QPK sighash | Critical design | Commits to version, locktime, prevouts, amounts, scriptPubKeys, sequences, outputs, and input index. | No fatal flaw found |
| Taproot-only fields | Medium | Annex, ext_flag, key_version, tapleaf_hash, and codesep fields are not needed for fixed-stack P2QPK. | Accept |
| Signature length | High | Consensus should require exact 17,088-byte SLH-DSA-SHA2-128f signatures, not merely <= max length. | Fix before Phase D merge |
| SLH-DSA mode | High | Pure/pre-hash mode, context, message length, and exact liboqs API path must be normative. | Fix before Phase D merge |
| liboqs linkage | High | Dynamic system liboqs is suitable for development, not final consensus builds. | Reproducible/pinned build required |
| Precompute cache | High | OP_2/P2QPK must trigger spent amount and spent scriptPubKey hashes. | Implementation test required |
| Mempool policy | Medium | Large 17,088-byte witness item must be accepted by default policy, not only by block validation. | Regtest relay test required |

## Detailed Review

### 1. Taproot/Tapscript Rejection

**Conclusion: correct.** The SIP's reason for rejecting Taproot/Tapscript as the PQC migration carrier is valid. Taproot is a SegWit v1 output type based on Schnorr signatures, Merkle branches, and a Taproot output key. A Taproot output can be spent through key path or script path; if a CRQC can recover the private scalar for the Taproot output key, it can bypass a PQC script leaf entirely. Reference: [R3].

**Design consequence:** Tapscript may still be appropriate for non-PQC features such as covenants or asset logic, but it is not suitable as the carrier for a PQC migration whose goal is to remove exposed secp256k1 public-key risk from the output itself.

### 2. P2QPK Sighash Structure

**Conclusion: structurally safe in this review.** The proposed SIGHASH_ALL-only construction commits to the transaction version, locktime, all prevouts, all spent amounts, all spent scriptPubKeys, all sequences, all outputs, and the input index. This addresses the main lessons of SegWit v0/BIP143 and Taproot/BIP341 without inheriting their branch complexity. References: [R2], [R3].

```text
P2QPKSighash = TaggedHash("P2QPKSighash";
    0x00                                  // epoch
 || 0x01                                  // SIGHASH_ALL, fixed v1
 || tx.nVersion
 || tx.nLockTime
 || cache.m_prevouts_single_hash
 || cache.m_spent_amounts_single_hash
 || cache.m_spent_scripts_single_hash
 || cache.m_sequences_single_hash
 || cache.m_outputs_single_hash
 || in_pos
)
```

**No BIP143/BIP341-style malleability hole was found** because no signature branch allows outputs, amounts, prevouts, or the input being signed to float outside the signed message. The absence of ANYONECANPAY, NONE, and SINGLE also reduces malleability and replay surface.

### 3. Taproot-Only Field Removal

**Conclusion: safe for v1.** P2QPK has no script tree, no annex, no Tapscript extension flag, no TapLeaf, and no code-separator semantics. Therefore, removing spend_type, annex hash, ext_flag, key_version, tapleaf_hash, and code-separator position is reasonable for this fixed witness-stack construction. References: [R3], [R4].

```text
P2QPK witness stack:
[signature, pubkey]
```

## Required Phase D Safeguards

### A. Enforce Exact Signature Length

**Issue:** The pseudocode checks only `sig.size() > SLHDSA_SIG_MAX_LEN`. For consensus, this should be exact-length validation before invoking liboqs.

```text
Required consensus rule:
pubkey.size()    MUST equal 32 bytes
signature.size() MUST equal 17,088 bytes
No appended sighash byte is permitted
```

**Reason:** SLH-DSA-SHA2-128f has a 32-byte public key and a 17,088-byte signature in the referenced OQS algorithm table. Exact validation keeps consensus canonical and avoids relying on downstream library rejection for malformed lengths. Reference: [R8].

### B. Specify the Exact SLH-DSA Mode

**Issue:** The SIP should make the exact signing mode normative, not implicit.

```text
Algorithm: SLH-DSA-SHA2-128f
Mode: pure SLH-DSA over the 32-byte P2QPKSighash
Context: empty context string
Message length: exactly 32 bytes
Signature length: exactly 17,088 bytes
Public key length: exactly 32 bytes
```

**Reason:** SLH-DSA has pure and pre-hash modes and supports a context string. RFC 9814 states that SLH-DSA signature operations include a context string, with empty string as the default in that profile, and distinguishes pure versus pre-hash mode. Consensus must be explicit. Reference: [R5].

### C. Pin or Vendor liboqs for Consensus

**Issue:** Development linkage through pkg-config is acceptable for Phase B/Phase D experimentation, but dynamic system liboqs must not become an unpinned consensus dependency.

**Required property:** Final consensus builds should use a pinned, reproducible, version-locked liboqs path or a vendored implementation with deterministic build settings and release-test coverage. References: [R6], [R7].

**Risk:** Different node operators using different liboqs versions, compile-time options, or distro packages could cause consensus divergence if behavior changes or an algorithm is unavailable.

### D. Implement and Test the Precompute Trigger

**Issue:** The SIP correctly notes that witver==2 currently does not trigger the spent amount and spent scriptPubKey hashes that P2QPK requires.

```text
Implementation options:
1. Extend detection: scriptPubKey[0] == OP_1 || scriptPubKey[0] == OP_2
2. Preferably introduce a clearer uses_p2qpk flag that also triggers the same cache computations
```

**Required tests:** single P2QPK input; multiple P2QPK inputs; mixed legacy plus P2QPK; mixed Taproot plus P2QPK if Taproot exists in QOGE; missing spent-output data must fail, not silently hash zeroes.

### E. Test Mempool Standardness and Relay

**Issue:** The block-weight analysis is directionally fine, but it does not prove default mempool relay acceptance for a 17,088-byte witness item.

```text
Phase E test requirement:
Create a standard P2QPK spend.
Submit it through default mempool policy.
Confirm that it relays and mines without manual block injection.
```

## Additional Recommendations

### 1. Use a QOGE-Specific Tagged-Hash Domain

**Recommendation:** Consider changing the tag from `P2QPKSighash` to a project-specific string before activation, for example `QOGE/P2QPKSighash/v1`. This is not strictly required, but it reduces cross-chain or cross-protocol signature confusion if another Bitcoin-family project copies the same construction.

### 2. Strengthen Pre-Activation Warnings

**Recommendation:** Public documentation should clearly state that before activation, `bq1z...` P2QPK outputs are not SLH-DSA-protected and may be anyone-can-spend under current reserved witness-version semantics. Wallets should disable mainnet P2QPK receiving unless activation is locked in or active. Reference: [R1].

### 3. Clean Up SIP-02a Status Text

**Recommendation:** SIP-QOGE-PQC-02a contains a small internal inconsistency: it gives the resolved hash `8a17f83e...` but later says the hash value is TBD. Update the bottom status block to state that Open Item 2 is resolved and that the vector was independently recomputed in this review.

```text
Open Item 2 resolved. Independent recomputation confirmed:
8a17f83ed68457d5469f4bbcfc68ddaeaa70739522c1b6fb76685ba7b2008c38
```

## Suggested Repository Review Note

```text
Independent AI review conducted via OpenAI ChatGPT (GPT-5.5 Thinking), 20 June 2026.
Scope: SIP-QOGE-PQC-02 and SIP-QOGE-PQC-02a P2QPK consensus/sighash design.
Result: PASS for Phase C design review, with required Phase D safeguards.
No fatal sighash flaw found. Taproot/Tapscript rejection confirmed under the CRQC threat model.
Required before mainnet activation: exact SLH-DSA mode/length rules, reproducible pinned liboqs integration, precompute-gating tests, mempool relay tests, and independent human Bitcoin/PQC cryptography review.
```

## Reviewer Conclusion

**The P2QPK design is a credible and significantly cleaner PQC migration carrier than a Taproot script-path approach.** The sighash construction is compact, domain-separated, and appears to bind the critical transaction data needed to avoid known SegWit/Taproot digest pitfalls. The remaining concerns are not fatal design objections; they are implementation and activation safeguards that should be treated as blocking requirements for consensus code merge and especially for mainnet activation.

## References Used

- [R1] BIP 141 - Segregated Witness (Consensus layer): https://bips.dev/141/
- [R2] BIP 143 - Transaction Signature Verification for Version 0 Witness Program: https://bips.dev/143/
- [R3] BIP 341 - Taproot: SegWit version 1 spending rules: https://bips.dev/341/
- [R4] Bitcoin BIP 341 source - Taproot/Tapscript details: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- [R5] RFC 9814 - Use of the SLH-DSA Signature Algorithm in the Cryptographic Message Syntax: https://www.rfc-editor.org/rfc/rfc9814.html
- [R6] Open Quantum Safe - liboqs SLH-DSA algorithm page: https://openquantumsafe.org/liboqs/algorithms/sig/slh-dsa.html
- [R7] Open Quantum Safe - liboqs project repository: https://github.com/open-quantum-safe/liboqs
- [R8] Open Quantum Safe - liboqs-js algorithm table: https://github.com/open-quantum-safe/liboqs-js

## Internal Source Material Reviewed

Uploaded review pack: `qoge-pqc-sip-review-pack.md`, containing condensed SIP-QOGE-PQC-02 and SIP-QOGE-PQC-02a normative references. The review conclusions above are based on that supplied content plus the external references listed above.
