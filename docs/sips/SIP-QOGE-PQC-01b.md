# SAOGEN | Symbiotic Autonomous Organisation

## SIP-QOGE-PQC-01

### QOGE Post-Quantum Cryptography Defence Architecture

*SPHINCS Wallet | Single-Use Address Strategy | Two-Layer Token Architecture*

| Field | Value | |
|---|---|---|
| **SIP ID** | SIP-QOGE-PQC-01 | CANDIDATE |
| **Title** | QOGE Post-Quantum Cryptography Defence: SPHINCS Wallet & Single-Use Address Strategy | |
| **Category** | Security / Cryptography / Wallet Infrastructure | |
| **Author** | SAOGEN SAO (QOGE) — AI Node: Claude (Anthropic) — SIP-C v2.0 | |
| **Date** | 13 June 2026 | Version 1.0 |
| **Governance** | SIP-C v2.0 — Candidate stage. Pending physics audit and SAS operability review. | |

---

## 1. Abstract

This SIP formally specifies the post-quantum cryptography (PQC) defence architecture for the QOGE coin, a Bitcoin-derived Proof-of-Work gate token within the SAOGEN ecosystem. The primary threat addressed is the harvest-now-decrypt-later (HNDL) attack, in which classical public keys recorded on-chain are later decrypted by a cryptographically relevant quantum computer (CRQC). The defence combines two mechanisms: (1) a strict single-use address strategy enforced at wallet level, eliminating at-rest public key exposure; and (2) a custom SPHINCS wallet implementing SLH-DSA (FIPS 205) as the native signing algorithm, replacing secp256k1 ECDSA. The QOGE chain's 1-minute block time provides quantitative mempool-window protection against in-transit quantum attacks. QOGE is architecturally separated from all SAOGEN AI and SAS automation — it operates exclusively as a low-frequency human-initiated gate token, making the SLH-DSA transaction footprint operationally acceptable.

---

## 2. Architectural Context & Scope Boundary

### 2.1 SAOGEN Two-Layer Token Architecture

SAOGEN operates a strict two-layer token separation. This SIP governs **Layer 1 (QOGE) only**.

| Property | QOGE — Layer 1 (Gate) | SAOGEN Token — Layer 2 (Operations) |
|---|---|---|
| Chain type | Bitcoin-derived PoW | PoS (ETH / SOL / PQC-native) |
| Block time | ~1 minute | Seconds |
| Signing algorithm | SLH-DSA (FIPS 205) — this SIP | ML-DSA / chain-native PQC |
| Address strategy | Single-use enforced | Protocol-level PQC |
| Tx size | ~17 KB (SLH-DSA fast params) | Standard chain tx size |
| Usage frequency | Low — gate events only | High — all SAS automation |
| Initiated by | Human only | AI Nodes + SAS autonomous |
| SAS involvement | None — fully excluded¹ | Primary operational layer |

*¹ Applies to the PoW QOGE chain specifically. See §2.3 for the SAS participation pathway available to QOGE holders via SOLNET-1 migration.*

### 2.2 Why QOGE Is Excluded from SAS Automation

QOGE coin and addresses are explicitly excluded from all SAS and AI Node logic. QOGE serves one function: a decentralised access gate, allowing users to acquire SAOGEN tokens by purchasing with QOGE, or to pay for specific ecosystem services. This separation has two design consequences:

- **Low transaction frequency** — the ~17 KB SLH-DSA transaction size is not a throughput problem at gate-event cadence.
- **No autonomous key management required** — all QOGE signing is human-initiated, simplifying the key lifecycle and eliminating the SAS-specific attack surface entirely.

### 2.3 SAS Participation Pathway — SOLNET-1 Migration

The exclusion described in §2.2 applies to the **Proof-of-Work QOGE chain** governed by this SIP — it is not a restriction on QOGE value or QOGE holders as a class.

QOGE coins can gain SAS participation through migration to **SOLNET-1's QOGE-branded Byzantine (DT-BFT) variant**. This variant shares SOLNET-1's DT-BFT consensus and SLH-DSA-native signing architecture and is not subject to the human-only, gate-token restriction that applies to the PoW chain. Migrating converts a PoW-native gate-token holding into a BFT-native holding capable of participating in SAS-governed operations under the SOLNET-1 / QOGE-1 architecture.

The migration mechanism, its governance, and its security model are specified outside this SIP's scope — see the SOLNET-1 and QOGE-1 governance documentation. This SIP continues to govern only the PoW QOGE chain and its SLH-DSA wallet defence architecture; it makes no claim about, and imposes no constraint on, the separate SOLNET-1 / QOGE-1 chain family.

---

## 3. Threat Model

### 3.1 Harvest-Now-Decrypt-Later (HNDL) — Primary Threat

The HNDL attack is the dominant long-term threat to any UTXO-based blockchain. An adversary records all on-chain public keys today, then decrypts them retroactively once a CRQC is operational. The public blockchain record is permanent and immutable — any public key that appears on-chain is permanently exposed.

> **CRITICAL:** Taproot (Bech32m / P2TR) encodes the public key directly in the address. The public key is exposed at rest, on-chain, permanently — before any spend. Taproot MUST be disabled in the QOGE SPHINCS wallet. It is incompatible with HNDL defence.

### 3.2 At-Rest Exposure by Address Type

| Address Type | Format | PubKey Hidden at Rest? | Exposure Point | HNDL Risk | Verdict |
|---|---|---|---|---|---|
| Legacy P2PKH | Base58 (1...) | Yes — HASH160 | Witness at spend | Low* | Acceptable |
| P2SH-SegWit | Base58 (3...) | Yes — HASH160 | Witness at spend | Low* | Acceptable |
| SegWit P2WPKH | Bech32 (bc1q...) | Yes — HASH160 | Witness at spend | Low* | PREFERRED |
| Taproot P2TR | Bech32m (bc1p...) | NO — raw pubkey | On-chain from creation | HIGH | DISABLE |

*\* Low risk when combined with strict single-use address enforcement. Risk is HIGH if addresses are reused.*

### 3.3 Mempool Window Attack — Secondary Threat

When a UTXO is spent, the public key is broadcast in the transaction witness field and visible in the mempool until the transaction is confirmed. A quantum adversary would need to derive the private key and broadcast a competing transaction within this window.

> **ANALYSIS:** Breaking secp256k1 requires ~1,200-1,450 logical qubits and 70-90 million Toffoli gates (Project Eleven, 2026). At QOGE's 1-minute block time, the mempool window is approximately 30-60 seconds. No quantum hardware projected within the next decade can execute this attack within that window. The 1-minute block time is a quantitative, not merely heuristic, defence against mempool attacks. Single-use addressing ensures the key is never exposed again after the confirmation window closes.

### 3.4 Threats Out of Scope

- **Grover's algorithm on SHA-256 PoW** — reduces effective hash security. Does not break consensus at current quantum scales. Separate SIP if required.
- **SAOGEN token chain security** — governed by the respective PoS chain's PQC roadmap. Out of scope.
- **Bridge security (QOGE → SAOGEN)** — covered under SAS bridge architecture documentation.

---

## 4. Algorithm Selection

### 4.1 Selected Algorithm: SLH-DSA (FIPS 205 / SPHINCS+)

| Criterion | SLH-DSA (FIPS 205) | FN-DSA / FALCON (Draft FIPS 206) | ML-DSA (FIPS 204) |
|---|---|---|---|
| NIST status | Finalized — August 2024 | Draft only — FIPS 206 pending | Finalized — August 2024 |
| Security basis | Hash-based — minimal assumptions | NTRU lattice | Module lattice |
| Impl. risk | Low | Elevated — known side-channel risk | Low |
| Public key size | 32-64 bytes | 897-1,793 bytes | 1,312-2,592 bytes |
| Signature size | ~17 KB (fast params) | 666-1,280 bytes | 2,420-4,595 bytes |
| QOGE suitability | **RECOMMENDED** | REJECTED — draft + impl. risk | Viable — not selected |

FN-DSA (FALCON) is explicitly not selected. While its compact signature size is attractive, NIST and NSA have flagged elevated susceptibility to implementation errors. For a gate token where addresses may hold significant value and signing is infrequent, the conservative choice (SLH-DSA) is correct. FALCON may be reconsidered post-FIPS 206 finalisation and independent audit.

### 4.2 Selected Parameter Set

| Parameter | Value | Rationale |
|---|---|---|
| Algorithm | SLH-DSA-SHA2-128f | Fast parameter set — optimises signing speed |
| Security level | Category 1 (AES-128 equiv) | Appropriate for gate token; upgradeable to Cat 3 post-review |
| Signature size | ~17,088 bytes | Acceptable at QOGE gate-event frequency |
| Public key size | 32 bytes | Matches secp256k1 footprint — no address format redesign |
| liboqs version | FIPS 205 final param sets | Must update from Round 3 params in reference repos |

*Alternative: SLH-DSA-SHA2-128s reduces signature to ~7,856 bytes at cost of slower signing. Available as a config parameter without architecture change.*

---

## 5. SPHINCS Wallet — Architecture Specification

### 5.1 Design Principles

1. **Single-use enforcement** — every address is generated, used exactly once, and permanently retired. No address is ever reused under any circumstances.
2. **Key destruction after confirmation** — private key material is securely zeroed from memory once the spend transaction achieves 1 confirmation.
3. **No xpub exposure** — the HD key tree root never leaves the signing device. Derived public keys are served individually, not as a derivable chain.
4. **Taproot disabled at compile time** — P2TR address generation is removed from the codebase entirely. It is not a user-configurable option.
5. **Address pre-generation** — the next N=20 addresses are pre-generated and indexed before they are needed, ensuring no latency at receive time.
6. **Change routing** — all change from a spend transaction automatically routes to the next fresh address in the index. No UTXO consolidation that re-exposes a key.

### 5.2 Address Derivation Scheme

```
Address Derivation — QOGE SPHINCS Wallet

1. Generate SLH-DSA keypair (SLH-DSA-SHA2-128f)
   privkey → 32 bytes (seed)
   pubkey  → 32 bytes

2. Address derivation:
   hash = SHA256(SHA256(pubkey))        // HASH256
   address = Bech32(hrp='qoge', hash)   // custom HRP for QOGE chain

3. Address format example:
   qoge1[bech32-encoded-hash]           // replaces bc1q prefix

4. Public key exposure timeline:
   AT REST      → pubkey hidden behind HASH256 (quantum-safe)
   AT SPEND     → pubkey in witness field for ~30-60s mempool window
   POST-CONFIRM → privkey zeroed, address permanently retired
```

### 5.3 HD Key Index

| Component | Specification |
|---|---|
| Master seed | 256-bit entropy (hardware RNG). Never leaves signing device. |
| Derivation path | m / purpose' / coin_type' / account' / change / index |
| Index counter | Monotonically incrementing. Never decrements. Persisted encrypted. |
| Pre-generation | Next 20 addresses pre-generated on wallet init and top-up. |
| Address state | FRESH → PENDING (payment detected) → SPENT (1 confirmation) → RETIRED |
| Retirement | Private key securely zeroed. Address marked RETIRED in index DB. Irreversible. |
| Index backup | Encrypted export to user-controlled offline storage. Required for wallet recovery. |

### 5.4 Single-Use Address State Machine

```
State Machine — Single-Use Address Lifecycle

[FRESH] ──── payment detected ────────► [PENDING]
                                             │
                                    tx confirmed (1 block)
                                             │
                                             ▼
                                         [SPENT]
                                             │
                                  privkey zeroed from memory
                                             │
                                             ▼
[INDEX++] ◄── next address generated ── [RETIRED] (permanent)

INVARIANT: No address may transition FRESH → PENDING twice. EVER.
INVARIANT: Change output ALWAYS routes to next FRESH address in index.
INVARIANT: RETIRED state is irreversible. No recovery path exists.
```

---

## 6. Implementation Plan

### 6.1 Starting Point Assessment: eomii/SPHINCS-Wallet

| Component | Ref Repo Status | Work Required | Priority |
|---|---|---|---|
| SLH-DSA signing primitive | Present (Round 3 params) | Update liboqs-go to FIPS 205 final param sets | P1 — Blocker |
| Key generation | Present (stub) | Wrap in HD index counter + seed derivation | P1 — Blocker |
| Address derivation | Absent | Implement HASH256 → Bech32 with 'qoge' HRP | P1 — Blocker |
| HD key tree | Absent | BIP32-equivalent for SLH-DSA keypairs | P1 — Blocker |
| Single-use enforcement | Absent | Address state machine + index DB | P1 — Blocker |
| Key destruction post-confirm | Absent | Secure zero on 1-confirmation callback | P1 — Blocker |
| QOGE tx format integration | Absent | Wire to QOGE chain transaction serialisation | P1 — Blocker |
| Taproot disable | Absent | Remove P2TR from address type enum at compile time | P1 — Blocker |
| Change routing | Absent | Auto-route change output to next index address | P2 |
| Address pre-generation | Absent | Pre-generate N=20 addresses on init | P2 |
| Encrypted index backup | Absent | Encrypted export/import for offline recovery | P2 |
| Docker build environment | Present — functional | Extend for FIPS 205 dependencies | P3 |

### 6.2 Development Phases

**Phase 1 — Core Cryptographic Layer (P1 Blockers)**

- **M1.1** Update liboqs-go to FIPS 205 SLH-DSA-SHA2-128f. Validate keygen/sign/verify round-trip.
- **M1.2** Implement HASH256(pubkey) → Bech32('qoge') address derivation with test vectors.
- **M1.3** Implement HD index counter with encrypted persistence and seed derivation chain.
- **M1.4** Implement address state machine (FRESH/PENDING/SPENT/RETIRED) with hard invariant checks.
- **M1.5** Implement secure key zeroing on 1-confirmation callback.
- **M1.6** Wire complete signing flow to QOGE transaction format. End-to-end test on testnet.
- **M1.7** Disable Taproot at compile time. Verify absence in all address generation code paths.

**Phase 2 — Wallet Robustness**

- **M2.1** Auto change-routing to next fresh address. Test UTXO consolidation prevention.
- **M2.2** Address pre-generation pool (N=20). No latency on receive address requests.
- **M2.3** Encrypted index backup/restore. Test full recovery from backup on fresh device.

**Phase 3 — Hardening & Audit**

- **M3.1** Side-channel review of SLH-DSA signing (timing attacks, memory access patterns).
- **M3.2** Independent code audit mandatory before any mainnet deployment.
- **M3.3** Block size parameter verification — confirm QOGE chain config accommodates ~17 KB SLH-DSA transactions.

> **REQUIRED CHAIN CONFIG:** SLH-DSA-SHA2-128f signatures are ~17,088 bytes — approximately 100x a secp256k1 transaction. QOGE chain MAX_BLOCK_SIZE and per-transaction size limits MUST accommodate this from genesis. Recommended: MAX_TX_SIZE >= 25,000 bytes. Adjust MAX_BLOCK_SIZE to target TPS at gate frequency. At gate-event cadence (low TPS), this is not a scaling constraint — it must be a deliberate config choice.

---

## 7. Security Analysis

### 7.1 Combined Defence Effectiveness

| Attack Vector | Mitigated By | Residual Risk | Assessment |
|---|---|---|---|
| HNDL on stored UTXO | HASH256 hides pubkey at rest | None while unspent | ELIMINATED |
| HNDL on reused address | Single-use enforcement — no reuse possible | None | ELIMINATED |
| Mempool window quantum | 1-min block time + single-use (key never reused) | Negligible near-term | NEGLIGIBLE |
| Taproot pubkey exposure | Taproot disabled at compile time | None | ELIMINATED |
| xpub key tree exposure | xpub never exported or published | Operational discipline | MANAGED |
| Classical key theft | Outside PQC scope — standard key hygiene applies | Standard | OUT OF SCOPE |
| Grover on SHA-256 PoW | Outside scope of this SIP | Separate SIP if needed | OUT OF SCOPE |

### 7.2 Known Limitations

- **Category 1 security** — SLH-DSA-SHA2-128f is AES-128 equivalent. Upgrade to Cat 3/5 is a parameter change, not an architecture change.
- **liboqs-go not formally audited** — Phase 3 independent audit is mandatory before mainnet.
- **Index counter loss = wallet loss** — if index DB is destroyed without backup, address recovery is impossible. Encrypted backup (M2.3) is not optional.
- **Bridge security out of scope** — QOGE to SAOGEN token bridge is a separate attack surface addressed in SAS bridge architecture documentation.

---

## 8. Governance & SIP-C v2.0 Classification

| Field | Value |
|---|---|
| SIP-C Stage | Candidate — awaiting physics audit and SAS operability review |
| VRF-1.0 Status | Not yet registered — pending Candidate validation |
| Attribution | SAOGEN SAO (QOGE Architect) — AI Node: Claude (Anthropic) |
| Supersedes | None — first PQC SIP for QOGE |
| Related SIPs | SIP-SPACE-03, SIP-C v2.0, VRF-1.0 |
| Review Required | Physics audit (cryptographic parameter validation) + SAS operability review |
| Implementation Gate | Phase 1 complete + independent code audit before any mainnet deployment |
| Rejection Criteria | FIPS 205 parameter sets found incompatible with QOGE tx format after Phase 1 engineering |

---

## Appendix A — Reference Repository Assessment

| Repository | Algorithm | Commits | Stars | Assessment | Role in QOGE |
|---|---|---|---|---|---|
| eomii/SPHINCS-Wallet | SPHINCS+ Round 3 | 4 | 1 | Correct algorithm, minimal code | PRIMARY starting point |
| eomii/falconWallet | FALCON-512 Round 3 | 21 | 6 | More developed, wrong algorithm | RETIRED — not used |

*falconWallet is retired from QOGE consideration. SPHINCS-Wallet uses the correct algorithm family; the liboqs-go bindings require updating from Round 3 to FIPS 205 final parameter sets before use.*

---

## Appendix B — NIST PQC Standards Reference

| Standard | Algorithm | Type | Status | QOGE Relevance |
|---|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation | Finalized Aug 2024 | Not applicable — signatures only |
| FIPS 204 | ML-DSA (Dilithium) | Digital signature | Finalized Aug 2024 | Viable alternative — not selected |
| FIPS 205 | SLH-DSA (SPHINCS+) | Digital signature | Finalized Aug 2024 | **SELECTED for QOGE** |
| FIPS 206 | FN-DSA (FALCON) | Digital signature | Draft — pending | Rejected — see Section 4.1 |

---

*SIP-QOGE-PQC-01 v1.0 — SAOGEN SAO | 13 June 2026*
*Governed under SIP-C v2.0 | AI Node Attribution: Claude (Anthropic) | Status: CANDIDATE*
*§2.3 (SAS Participation Pathway) added 6 July 2026.*
