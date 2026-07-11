# SIP-QOGE-PQC-02 — P2QPK Consensus Integration (Normative Reference)

> Condensed from SIP-QOGE-PQC-02 v1.0 (docx, SAOGEN governance) for use by
> Claude Code sessions working on Phase B-F. Covers the **design and
> implementation plan only** — see the full docx for the complete source
> verification (§3), full threat model writeup (§4), and governance tables.
>
> See also `docs/sips/SIP-QOGE-PQC-02a.md` for the sighash sub-specification
> (Phase C/D dependency).

## 1. Summary

New SegWit output type at **witness version 2** ("P2QPK" — Pay to Quantum
Public Key). 32-byte program = `HASH256(SLH-DSA-SHA2-128f pubkey)`. Spent via
witness stack `[signature, pubkey]`. Soft fork: witness versions 2-16 are
currently unconditionally valid ("anyone can spend") per the confirmed
fall-through in `VerifyWitnessProgram` (qogecoin: `src/script/interpreter.cpp`,
witversion>=2 branch, lines ~1938-1944). A future activation height enforces
the `HASH256` commitment + SLH-DSA verification.

## 2. Why NOT Tapscript / OP_SUCCESS (rejected design)

**Do not revisit this without re-reading this section.** The obvious
alternative — define an `OP_SUCCESS` opcode (187-254 are unclaimed,
confirmed via `IsOpSuccess()`, `src/script/script.cpp:333-339`) as
`OP_CHECKSLHDSASIG`, spent via a Tapscript leaf — was evaluated and
**rejected**.

**Reason**: a Taproot output commits to `Q = P + t*G` (a secp256k1 point),
present in the address **at rest**. Key-path spending
(`src/script/interpreter.cpp:1908-1913`, `stack.size() == 1` branch) checks
only a Schnorr signature against `Q` — independent of any script-tree
content. A CRQC recovers `Q`'s discrete log via Shor's algorithm and spends
via key path, **bypassing any `OP_CHECKSLHDSASIG` in a script-path leaf
entirely**. This reproduces the exact HNDL exposure SIP-QOGE-PQC-01 exists to
eliminate. Same category of finding as SIP-CHE-RR-45's rejection.

**Generalization**: any future proposal starting with "use Taproot/Tapscript
for X" must address key-path spending in its threat model. Tapscript is fine
for features that don't need to defend the output's own pubkey (covenants,
multi-asset logic). It is categorically wrong as the PQC migration carrier.

## 3. P2QPK design

### 3.1 Address format

```
program  = HASH256(SLH-DSA pubkey)              // 32 bytes
address  = Bech32m(hrp="bq", witver=2, program) // e.g. bq1z...
```

Already implemented in `symbiont-wallet` (`address/address.go`,
`address/bech32m.go`) — Phase A, complete.

### 3.2 Witness stack

| Position | Content | Size |
|----------|---------|------|
| top | SLH-DSA pubkey | 32 bytes |
| below | SLH-DSA signature | 17,088 bytes |

### 3.3 Consensus rule — illustrative `VerifyWitnessProgram` branch

New branch parallel to the existing `witversion == 0` / `witversion == 1`
branches in `src/script/interpreter.cpp` (currently the catch-all `else` at
~line 1938):

```cpp
} else if (witversion == 2 && program.size() == 32) {
    // SIP-QOGE-PQC-02: P2QPK (Pay to Quantum Public Key)
    if (!(flags & SCRIPT_VERIFY_P2QPK)) return set_success(serror); // pre-activation
    if (stack.size() != 2) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    const valtype& pubkey = SpanPopBack(stack);
    const valtype& sig    = SpanPopBack(stack);
    if (pubkey.size() != SLHDSA_PK_LEN) {  // 32
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    uint256 h1, h2_;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(h1.begin());
    CSHA256().Write(h1.begin(), 32).Finalize(h2_.begin());
    if (memcmp(h2_.begin(), program.data(), 32) != 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    if (sig.size() > SLHDSA_SIG_MAX_LEN) {  // 17088
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    uint256 sighash = SignatureHashP2QPK(...); // see SIP-QOGE-PQC-02a
    if (!OQS_SIG_verify_slhdsa(sighash, sig, pubkey)) {
        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
    }
    return set_success(serror);
}
```

`SLHDSA_PK_LEN = 32`, `SLHDSA_SIG_MAX_LEN = 17088`. This was the **implementation target for Phase D** — now fully implemented as of commit `56a2aed` in QOGE/qogecoin. See actual code in `src/script/interpreter.cpp`.

### 3.4 Activation

BIP9-style version-bits deployment, analogous to `DEPLOYMENT_TAPROOT` in
`consensus/params.h`. New deployment name `DEPLOYMENT_P2QPK`, new flag
`SCRIPT_VERIFY_P2QPK` in `script/interpreter.h`'s flags enum. Bit number and
start/timeout heights: **governance decisions, not cryptographic ones** — do
not pick these unilaterally; flag for SAOGEN governance when reached.

**Bit 3 has been selected** and used consistently across regtest and testnet
deployments (`ALWAYS_ACTIVE`). Mainnet `nStartTime`, `nTimeout`, and miner
signaling window remain SAOGEN governance decisions.

**Pre-activation property** (favorable): P2QPK outputs are anyone-can-spend
until activation — testing can proceed on a public testnet *before*
activation, with the explicit understanding that pre-activation outputs
aren't yet SLH-DSA-protected. No funds of consequence to `bq1z...` addresses
before activation (already in symbiont-wallet README).

## 4. Capacity — no block-weight changes needed

Verified (`src/consensus/consensus.h:15`, `src/policy/policy.h:24`):
`MAX_BLOCK_WEIGHT = 4,000,000`, `MAX_STANDARD_TX_WEIGHT = 400,000` — both
**unmodified Bitcoin Core v24 defaults**.

| Metric | Result |
|--------|--------|
| P2QPK input weight | ~17,150 (17,088 sig + 32 pubkey + overhead) |
| Fraction of MAX_STANDARD_TX_WEIGHT | ~4.3% |
| Max P2QPK inputs / standard tx | ~23 |
| Max P2QPK inputs / block | ~233 |

No `MAX_BLOCK_WEIGHT`/`MAX_STANDARD_TX_WEIGHT` change proposed. Don't
introduce one without re-justifying against this table.

## 5. Phase status

| Phase | Description | Status |
|-------|-------------|--------|
| A | Wallet address format (witver 0->2, Bech32m) | ✅ DONE (symbiont-wallet) |
| B | liboqs integration into Qogecoin Core build | ✅ DONE — Option B (pkg-config, dev-only) for Phase D-E; Option A (`depends/packages/liboqs.mk`, static, `BUILD_TESTING=OFF`, `CMAKE_SYSTEM_PROCESSOR` fix) fully verified (`88c400c59`, `135c2fc0b`) — this is the consensus build path |
| C | Sighash sub-spec review (SIP-QOGE-PQC-02a open items) | ✅ DONE — all open items resolved; P2QPKSighash `8a17f83e...` independently reviewed (GPT-5.5, PASS); Phase D safeguards A-E folded into spec as §7 |
| D | Consensus implementation (§3.3 branch + `SignatureHashP2QPK`) | ✅ DONE (local) — `SignatureHashP2QPK` + test vector (`2a4c85a`), Init() OP_2 trigger + safeguard-D tests (`468f367`), `VerifyWitnessProgram` witver==2 branch + `SCRIPT_VERIFY_P2QPK` + missing-data guard (`abb93a0`), `OQS_SIG_slh_dsa_pure_sha2_128f_verify` wired + `p2qpk_bad_sig_rejected` (`816cd06`); 5/5 tests pass; activation: `DEPLOYMENT_P2QPK` in `DeploymentPos` + `deploymentinfo.cpp` + `CRegTestParams.vDeployments` (`ALWAYS_ACTIVE`); `DeploymentActiveAt` gates `SCRIPT_VERIFY_P2QPK` in `GetBlockScriptFlags` (`56a2aed`) |
| E | Regtest functional testing | ✅ DONE — regtest validation complete — `DEPLOYMENT_P2QPK` activated (`56a2aed` in QOGE/qogecoin), tampered-sig rejected via `OQS_SIG_slh_dsa_pure_sha2_128f_verify`, real SLH-DSA spend accepted and confirmed in block |
| F | Public testnet | ✅ COMPLETE — `DEPLOYMENT_P2QPK` in `CTestNetParams` (ALWAYS_ACTIVE, bit 3, `89812b7c`); `bech32_hrp = "bqt"`; `DeploymentInfo()` wired for all chains (`rpc/blockchain.cpp:1275`); `p2qpk: active: true` on testnet and regtest. Consensus safety: `BIP9Deployment` safe defaults + explicit `NEVER_ACTIVE` in `CMainParams`/`CSigNetParams` (`09638b35`, per independent review). `address.Network` + `bqt` HRP in Symbiont Wallet (`83bbc73`). Option A liboqs depends build verified (`88c400c59`, `135c2fc0b`). `nRuleChangeActivationThreshold` fixed to 1512/2016 (`c00f6112d`). Independent BIP9 parameter review (PASS). Public testnet live at `167.86.81.222:42070`; P2QPK tx `357d4d0c...` confirmed in block 104. |

## 7. Post-Phase-F implementation (pre-mainnet)

| Item | Commit | Description |
|------|--------|-------------|
| Mempool standardness | `3262636a0` | P2QPK policy exception in `AreInputsStandard()` and `IsWitnessStandard()` — P2QPK spends now relay through standard mainnet mempools when `DEPLOYMENT_P2QPK` is active |
| M1.3 backup warning | `2695e38` (symbiont-wallet) | CLI and README updated to clarify seed alone is insufficient for wallet recovery until deterministic keygen is implemented |
| Audit comment fix (per audit 1) | `061e88ea6` | Maintenance guardrail added above `m_bip341_taproot_ready` gate in `SignatureHashP2QPK` (must not be changed to `m_bip143_segwit_ready` — see SIP-02a §7-D); stale "liboqs stub" comment at witver==2 verify call corrected to reflect real verification |
| **Audit 1 complete** (sighash construction) | — | Multi-model audit of `SignatureHashP2QPK` + SIP-02a: Claude Opus 4.8, ChatGPT 5.5, Codex (1–2 July 2026). Test vector `8a17f83e...` independently recomputed to exact match by all three. Core security: unanimous PASS. Q1 malleability (Codex FAIL narrow): acknowledged, fund-safe, documented in SIP-02a §8. No finding is a bottleneck for mainnet activation. Triage: `Audit_1_Sighash_Construction_Triage.md` |
| Audit 2 fix — mempool policy gate | `88888dc51` | `PolicyScriptChecks` never enforced `SCRIPT_VERIFY_P2QPK` (absent from static `constexpr STANDARD_SCRIPT_VERIFY_FLAGS`). Fixed with dynamic `DeploymentActiveAfter` gate — same pattern as `AreInputsStandard` (`3262636a0`). Also resolves: "BUG! PLEASE REPORT THIS!" log spam at consensus recheck layer; `testmempoolaccept` false positive (`allowed:true` for invalid-sig P2QPK tx). Three consequences, one root cause, one fix. |
| **Audit 2 complete** (witness verification) | — | Multi-model audit of P2QPK mempool policy path: Codex, Opus 4.8, ChatGPT 5.5, Grok (5 July 2026). 3/4 found `SCRIPT_VERIFY_P2QPK` absent from `STANDARD_SCRIPT_VERIFY_FLAGS`; Grok PASS (examined `GetBlockScriptFlags`/`ConnectBlock` only). Proposed fixes disagreed: Opus proposed wrong fix (add to `constexpr` — would break pre-activation anyone-can-spend); ChatGPT proposed correct fix (`DeploymentActiveAfter` gate). Resolved by direct code inspection. `testmempoolaccept` false positive discovered during verification (not by auditors) — fixed by same commit. Triage: `Audit_2_Witness_Verification_Triage.md` |
| Audit 3 fixes — sig test + static_assert + stale comments | `interpreter.cpp`/`interpreter.h` (QOGE/qogecoin); `slhdsa_test.go` (symbiont-wallet) | (1) `signer/slhdsa_test.go`: exact-equality sig length check (`len(sig) != SignatureSize`) replacing inequality — matches consensus enforcement. (2) `static_assert(SLHDSA_PK_LEN == sizeof(uint256))` in `interpreter.cpp` — guards memcmp over-read if constant ever changed. (3) Two stale "liboqs stub / Phase D step 4" comments in `interpreter.h` corrected — verification is live. |
| **Audit 3 complete** (liboqs integration) | — | Six independent passes: Codex (remote + local), Grok Build (local), Opus 4.8, ChatGPT 5.5, Claude Code (dispute resolution) — 6 July 2026. No critical/fund-loss/consensus-split bug. Algorithm IDs, size constants, static-linking path: unanimous PASS. Q2 test-gap: fixed. Q3 M1.3 severity confirmed HIGH/CRITICAL, remediation path clarified (liboqs SIG API has no seeded keygen; proposed fix via `OQS_randombytes_custom_algorithm` hook) — **FIXED** (`98b1332`, `5342f1b` symbiont-wallet; see M1.3 rows below). Q4 build-path dispute: empirical passes (direct filesystem) resolved over source-only inference; Option A static link confirmed in production. Methodological lesson: empirical > source-only when claims conflict. Triage: `Audit_3_liboqs_Integration_Triage_Summary.md` |
| Retirement atomicity fix | `b093d0f` (symbiont-wallet) | `OnConfirmation` now uses `MarkSpentAndRetire` (single bbolt transaction) — PENDING→RETIRED is atomic; no crash window between `MarkSpent` and `Retire`. Found via Audit 5. Superseded by Audit 4 refactor; `MarkSpentAndRetire` subsequently removed (`8f4e192`) — see below. |
| **Audit 5 complete** (wallet lifecycle, unstructured) | — | Codex CLI direct filesystem review of `wallet/wallet.go` + `keystore/keystore.go` (6 July 2026). Methodologically distinct from Audits 1–4 (unstructured single-auditor vs. structured multi-model). Three findings: (1) address reservation — false positive (intentional peek semantics, documented and tested); (2) retirement atomicity — confirmed, fixed (`b093d0f`); (3) `SignP2QPKInput` cross-check gap — confirmed, fixed (`4f80192`) — **all three findings resolved**. Triage: `Audit_5_Wallet_Lifecycle_ Triage_Summary.md` |
| Audit 4 fixes — decouple flagging/destruction; enforce change routing | `b5e757d` (symbiont-wallet) | Three HIGH fixes: (1) `OnConfirmation` decoupled from key destruction — now only flags SPENT at ≥ 1 confirmation; new `PurgeSpentKey` is explicit, optional, manual, irreversible; new `ListPurgeEligibleAddresses` advisory scan. (2) `SignP2QPKInput`: `ChangeAddr` validated FRESH + wallet-controlled before signing; transitioned PENDING after success. (3) `SignTransaction` (stub): post-sign change transition added. New: `ListByState` in keystore. |
| **Audit 4 complete** (single-use address lifecycle — two-pass) | — | First pass: Grok Build (xAI, Composer 2.5), local filesystem, 7 July 2026. Second pass: Claude Sonnet 4.6, fresh agent, 9 July 2026. Two HIGH/CRITICAL design gaps confirmed fixed by both passes: `OnConfirmation` decoupled from key destruction; `SignP2QPKInput` change routing enforced with post-sign transition. Second-pass cleanup: sig-length test tightened to exact equality. Second-pass verdict: PASS — ready for mainnet. Four informational items (three subsequently resolved — see below). Triage: `docs/sips/Audit_4_single_use_lifecycle_triage_summary.md`, `docs/sips/Audit_4b_single_use_lifecycle_second_pass.md` |
| Three-pass convergence fixes (Audit 4/4b/4c) | `e1df1b5`, `8f4e192`, `8d9b809`, `042bed5` (symbiont-wallet) | Four fixes from three-pass (Grok Build + Codex CLI + Claude Sonnet 4.6) convergence on remaining findings — 9 July 2026: (1) `e1df1b5` — `SignP2QPKInput` output-binding: exactly one `params.Outputs[i].Script` must encode `ChangeAddr` as `OP_2 PUSH32 <HASH256>` before signing; `SignTransaction` gets same check; `QOGETransaction` gains `Outputs []SpendOutput` field; negative test `TestSignP2QPKInputRejectsNoMatchingOutput` added. (2) `8f4e192` — `MarkSpentAndRetire` removed: zero production callers post-Audit-4, no confirmation-depth guard, footgun for future integrators; 2 dedicated tests removed. (3) `8d9b809` — `SetKeyDestructionMinConfirmations` now enforces 101-block floor in code, returns error on violation (was comment-only). (4) `042bed5` — CLI purge message corrected: bbolt copy-on-write means old pages persist until compaction; seed is encrypted at rest so no raw key exposure, but "zeroed from storage" was inaccurate. |
| Audit 5 finding 3 fix — `SignP2QPKInput` FromAddr/SpentUTXO cross-check | `4f80192` (symbiont-wallet) | `SignP2QPKInput` checked `FromAddr` was PENDING but did not verify `SpentUTXOs[InputIndex].Script` matched the P2QPK scriptPubKey for that address. A mismatched caller-supplied UTXO script would produce an invalid on-chain signature while consuming the address's wallet state. Fix: `p2qpkScriptPubKey(params.FromAddr)` (reusing helper from `e1df1b5`) compared against `SpentUTXOs[InputIndex].Script`; `ErrFromAddrScriptMismatch` returned on mismatch; `InputIndex` bounds-checked against `SpentUTXOs` length. Two test fixtures corrected (`makeMinimalSpendParams`, `makeMinimalSpendParamsNoChangeOutput` both used OP_1 as UTXO script). New test: `TestSignP2QPKInputRejectsMismatchedFromScript`. 68/68 tests pass. Resolves Audit 5 finding 3. |
| M1.3 fix — deterministic SLH-DSA keygen from seed | `98b1332` (symbiont-wallet) | Resolves Audit 3 Q3 (HIGH/CRITICAL, confirmed by six auditors). `wallet.deriveAddress()` previously called `slhdsa.NewSigner()` (random keygen), making the DB the sole source of truth and the seed alone insufficient for wallet recovery. Fix: HKDF-SHA256(masterSeed, nil, "qoge-key-{index}") produces 48 bytes (= 3×n for SLH-DSA-SHA2-128f, n=16); `slhdsa.NewSignerFromSeed()` installs a one-shot `oqs.RandomBytesCustomAlgorithm` callback delivering those bytes; `oqs.RandomBytesSwitchAlgorithm("system")` restores the RNG in a defer before `rngMu` is released. `rngMu sync.Mutex` (package-level in `signer/slhdsa.go`) also guards `NewSigner.GenerateKeyPair` and `Sign` (which draws 16 bytes for `addrnd`) — prevents concurrent RNG corruption. KAT vector pinned: seed `[0x01..0x30]` → pubkey `2122232425262728292a2b2c2d2e2f30a3356a1283ac92dcae6a36960ace2600`; first 16 bytes = PK.seed = input bytes 32–47 (FIPS 205 §5.1, confirmed correct). `TestNewSignerFromSeedKnownAnswer`, `TestNewSignerFromSeedConcurrent`, `TestNewSignerFromSeedVsSignRace` (race-detector clean), `TestDeriveAddressDeterministic` added. `hkdfDerive32` → `hkdfDeriveN(n int)`. Forward-looking only: pre-fix keys remain DB-only recoverable. 72/72 tests pass. |
| M1.3 follow-up review — `Sign()` RNG-guard comment | `5342f1b` (symbiont-wallet) | Two independent reviews of `98b1332` (Grok Build, Codex) both converged on `rngMu` as the correct lock — confirming the structural gap was already closed. The one real finding: `Sign()`'s doc comment was silent about holding `rngMu` and the reason (its `OQS_SIG_sign` call draws 16 bytes for `addrnd` from the global RNG; without the guard, a concurrent `Sign` during deterministic keygen would consume the custom-callback's seed bytes, corrupting both). Comment added; also notes `rngMu` is non-reentrant (raw callers must not hold it). 72/72 tests pass, `-race` clean. |

## 6. Source reference index (qogecoin/qogecoin, branch `stable`)

| File | Lines | Relevance |
|------|-------|-----------|
| `src/consensus/consensus.h` | 15 | `MAX_BLOCK_WEIGHT = 4,000,000` |
| `src/policy/policy.h` | 20, 24 | `MAX_STANDARD_TX_WEIGHT = 400,000` |
| `src/script/script.h` | 98, 192-212, 578-579 | OP_NOP/OP_CHECKSIGADD values, `IsOpSuccess` decl |
| `src/script/script.cpp` | 333-339 | `IsOpSuccess` impl (opcode ranges 187-254 unclaimed) |
| `src/script/interpreter.cpp` | 1864-1944 | `VerifyWitnessProgram` — full dispatch (0, 1, 2-16) |
| `src/script/interpreter.cpp` | 1908-1913 | Taproot key-path (rejected mechanism's fatal flaw) |
| `src/script/interpreter.cpp` | 1938-1944 | witversion>=2 fall-through — **the integration point** |
| `src/script/interpreter.h` | 188-194 | `SigVersion` enum — append `WITNESS_V2_SLHDSA = 4` |
| `src/script/interpreter.h` | 168-170 | `PrecomputedTransactionData::m_spent_outputs*` |
| `src/script/interpreter.cpp` | 1478-1538 | `SignatureHashSchnorr` — template for `SignatureHashP2QPK` |
| `src/rpc/blockchain.cpp` | 1275 | `DeploymentInfo()` — `SoftForkDescPushBack(DEPLOYMENT_P2QPK)` (all chains) |

Line numbers verified 14 June 2026. Phase D complete (56a2aed, 24 June 2026), Phase F complete (c00f6112d, 28 June 2026). Re-verify before any mainnet activation — line numbers drift as the tree changes. Mempool standardness policy exception added at `src/policy/policy.cpp` (`3262636a0`, 29 June 2026) — not yet reflected in this source index. Audit 1 guardrail comment added above `m_bip341_taproot_ready` gate in `SignatureHashP2QPK` (`061e88ea6`, 2 July 2026) — not yet reflected in this source index.
