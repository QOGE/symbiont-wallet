# Audit 2 (Witness Verification) — Multi-Model Triage Summary

**Component:** `PolicyScriptChecks` (`src/validation.cpp`) and its use of
`STANDARD_SCRIPT_VERIFY_FLAGS` (`src/policy/policy.h`) for mempool script
verification of P2QPK witness inputs.

**Auditors (independent, fresh conversations, no shared context):**
- OpenAI Codex — 5 July 2026
- Claude Opus 4.8 (Anthropic) — 5 July 2026
- ChatGPT 5.5 (OpenAI) — 5 July 2026
- Grok (xAI) — 5 July 2026

**Methodology note:** Auditor verdicts on the specific question (does
`PolicyScriptChecks` enforce `SCRIPT_VERIFY_P2QPK` post-activation?) are
recorded as reported. Dispositions and the final resolution are recorded
separately. Auditor verdicts are NOT edited.

---

## Headline result

Three of four auditors (Codex, Opus 4.8, ChatGPT 5.5) independently
identified a mempool policy bug: `SCRIPT_VERIFY_P2QPK` was absent from
`STANDARD_SCRIPT_VERIFY_FLAGS`, causing `PolicyScriptChecks` to never
enforce SLH-DSA signature verification, even after `DEPLOYMENT_P2QPK`
activates. Bug confirmed by direct code inspection.

The two proposed fixes disagreed: Opus proposed adding `SCRIPT_VERIFY_P2QPK`
directly to `STANDARD_SCRIPT_VERIFY_FLAGS` (incorrect — would enforce
SLH-DSA verification before activation, breaking pre-activation
anyone-can-spend per SIP-QOGE-PQC-02 §3.4); ChatGPT correctly identified
this and proposed the dynamic `DeploymentActiveAfter` gate instead.
Resolution was determined by direct code inspection, not by trusting either
audit. The correct fix (`88888dc51`) was applied.

A third consequence of the same root cause — `testmempoolaccept` reporting
`allowed: true` for invalid-signature P2QPK transactions — was discovered
during verification, not by any auditor. Confirmed fixed by the same commit.

**No separate fix is required beyond `88888dc51`. All three consequences of
the single root cause are resolved.**

---

## Verdict matrix (auditor verdicts as reported)

| Question | Opus 4.8 | ChatGPT 5.5 | Codex | Grok |
|----------|----------|-------------|-------|------|
| Q1 — Does `PolicyScriptChecks` enforce `SCRIPT_VERIFY_P2QPK` post-activation? | **FAIL** — absent from `STANDARD_SCRIPT_VERIFY_FLAGS`; proposed wrong fix | **FAIL** — absent from `STANDARD_SCRIPT_VERIFY_FLAGS`; proposed correct fix | **FAIL** — absent from `STANDARD_SCRIPT_VERIFY_FLAGS` | **PASS** — examined `GetBlockScriptFlags`/`ConnectBlock` path (correct), did not specifically examine `STANDARD_SCRIPT_VERIFY_FLAGS` |

---

## Triage dispositions

### Q1 — `PolicyScriptChecks` does not enforce `SCRIPT_VERIFY_P2QPK`

**Three auditors: FAIL. Grok: PASS (on a different question).**

**Triage disposition: BUG CONFIRMED — FIXED in `88888dc51`.**

**Direct code inspection findings (validation, not audit):**

`src/policy/policy.h:60–79`:
```cpp
static constexpr unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE | SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;
    // SCRIPT_VERIFY_P2QPK: ABSENT
```

`src/validation.cpp:1002` (before fix):
```cpp
constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;  // static
```

`STANDARD_SCRIPT_VERIFY_FLAGS` is a compile-time `constexpr`. `SCRIPT_VERIFY_P2QPK`
is absent. `PolicyScriptChecks` used this static set — SLH-DSA verification was
never enforced at the mempool policy layer at any block height.

**Grok's PASS:** Grok correctly analyzed `GetBlockScriptFlags` (called by
`ConsensusScriptChecks`, which uses the tip dynamically) and `ConnectBlock`
(the block-validation path). Both correctly include `SCRIPT_VERIFY_P2QPK`
when `DEPLOYMENT_P2QPK` is active. Grok's analysis of those paths was
accurate. The gap was that `PolicyScriptChecks` — called before
`ConsensusScriptChecks` in `AcceptSingleTransaction`, and the sole check in
the `test_accept=true` path — was not separately examined. All four auditors
agree the consensus/block-connection path is correct.

---

### Fix disagreement — wrong fix (Opus) vs correct fix (ChatGPT)

**Opus 4.8 proposed:** add `SCRIPT_VERIFY_P2QPK` directly to
`STANDARD_SCRIPT_VERIFY_FLAGS`.

**Why this is wrong:** `STANDARD_SCRIPT_VERIFY_FLAGS` is a compile-time
`constexpr`. Adding `SCRIPT_VERIFY_P2QPK` there would enforce SLH-DSA
verification at ALL heights unconditionally — including before
`DEPLOYMENT_P2QPK` activates — which would break the intentional
pre-activation anyone-can-spend behavior that the public testnet has relied
on throughout (SIP-QOGE-PQC-02 §3.4). It would also be inconsistent with
how every other soft-fork flag (`SCRIPT_VERIFY_TAPROOT`, etc.) is handled:
they all gate on activation state, not unconditionally.

**ChatGPT 5.5 proposed:** gate dynamically in `PolicyScriptChecks` using
`DeploymentActiveAfter(tip, ...)` — the same pattern already used in
`PreChecks` for `AreInputsStandard` (commit `3262636a0`).

**Resolution:** direct code inspection confirmed `STANDARD_SCRIPT_VERIFY_FLAGS`
is `constexpr`, confirmed the correct fix is the dynamic gate. ChatGPT's
proposed fix was correct. Applied as `88888dc51`.

**The correct fix (`88888dc51`, `src/validation.cpp`):**
```cpp
// BEFORE (static, no P2QPK):
constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

// AFTER (dynamic, mirrors PreChecks pattern):
unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
if (DeploymentActiveAfter(m_active_chainstate.m_chain.Tip(),
                          args.m_chainparams.GetConsensus(),
                          Consensus::DEPLOYMENT_P2QPK)) {
    scriptVerifyFlags |= SCRIPT_VERIFY_P2QPK;
}
```

---

### Third consequence — `test_accept=true` false positive (discovered during verification)

**Not identified by any of the four auditors.**

**Triage disposition: CONFIRMED FIXED by the same commit (`88888dc51`).**

`AcceptMultipleTransactions` (called by `testmempoolaccept` RPC) runs only
`PolicyScriptChecks` when `args.m_test_accept == true` — it does not run
`ConsensusScriptChecks`. Before the fix, an invalid-signature P2QPK tx would
pass `PolicyScriptChecks` (no `SCRIPT_VERIFY_P2QPK`) and be reported as
`allowed: true` — a false positive. Application code using `testmempoolaccept`
to pre-validate P2QPK transactions before broadcasting would incorrectly
conclude they were valid.

`AcceptMultipleTransactions:1271` calls `PolicyScriptChecks(args, ws)` — the
same member function modified in `88888dc51`. No duplication; no separate fix
required.

**Verified via live `testmempoolaccept` call on regtest (post-fix):**
```json
{
  "txid": "10c1f19b833500744e5d038ae392273cc473cf1a2b90b739f768b0b09e566923",
  "allowed": false,
  "reject-reason": "non-mandatory-script-verify-flag (Witness program hash mismatch)"
}
```

---

### Three consequences of the single root cause — all resolved by `88888dc51`

| Consequence | Before fix | After fix |
|-------------|------------|-----------|
| `sendrawtransaction` with invalid P2QPK sig | Passed `PolicyScriptChecks`, rejected by `ConsensusScriptChecks` with "BUG! PLEASE REPORT THIS!" log | Rejected at `PolicyScriptChecks` — correct path, no log spam |
| `testmempoolaccept` with invalid P2QPK sig | `allowed: true` — false positive | `allowed: false` — correct |
| Block-connection (`ConnectBlock`) | Correctly rejected via `GetBlockScriptFlags` — unaffected | Unaffected (was never broken) |

---

## Summary

- **Root cause:** `STANDARD_SCRIPT_VERIFY_FLAGS` lacks `SCRIPT_VERIFY_P2QPK`; `PolicyScriptChecks` used it as a compile-time constant.
- **Bug identified by:** 3 of 4 auditors (Codex, Opus 4.8, ChatGPT 5.5). Grok's PASS was on the block-connection path, which is correct.
- **Fix disagreement:** Opus proposed incorrect fix (unconditional addition to `constexpr`). ChatGPT proposed correct fix (dynamic `DeploymentActiveAfter` gate). Resolved by direct code inspection.
- **Fix applied:** `88888dc51` — `PolicyScriptChecks` in `src/validation.cpp`.
- **Third consequence** (test_accept false positive): discovered during verification, not by any auditor. Fixed by the same commit.
- **No finding is a bottleneck for mainnet activation** — the bug existed post-activation on testnet but did not allow invalid signatures into mined blocks (block-connection path was always correct). However, the fix must be in place before mainnet activation to ensure mempool policy correctly matches consensus rules.

**Audit 2 overall: bug confirmed, correct fix applied, all consequences resolved.**

---

*Multi-model triage artifact for SIP-QOGE-PQC-02 witness verification audit.
Auditor verdicts recorded as reported; project dispositions recorded separately.
Prepared as part of the pre-mainnet review process for the P2QPK soft fork.*
