# Independent Technical Review: Qogecoin P2QPK Soft Fork — Phase F BIP9 Deployment Parameters

**Repository reviewed:** `QOGE/qogecoin`  
**Branch:** `stable`  
**Commit reviewed:** `89812b7c`  
**Wallet repository context:** `QOGE/symbiont-wallet`  
**Review scope:** Phase F BIP9 deployment parameters, deployment visibility, and activation-safety implications for P2QPK.  
**Out of scope:** P2QPK sighash construction, SLH-DSA cryptographic design, and wallet UX beyond HRP/address-format implications.  

> **Important repository note:** This review applies to `https://github.com/QOGE/qogecoin`. It does **not** evaluate `github.com/qogecoin/qogecoin`, which is the inactive upstream and does not contain the P2QPK implementation.

---

## 1. Executive Summary

The Phase F deployment choices are mostly sound for a public testnet whose purpose is to validate P2QPK transaction format, witness handling, SLH-DSA verification, wallet interoperability, and RPC visibility.

However, the current implementation contains one mainnet safety flaw that should be fixed before any public binary intended to also run mainnet:

> `DEPLOYMENT_P2QPK` is added to the deployment enum and used by validation/RPC logic, but it is not explicitly configured in `CMainParams`. In this QOGE tree, `BIP9Deployment` does not currently use Bitcoin Core v24-style safe default member initializers. Therefore, the unconfigured mainnet deployment may contain indeterminate values instead of cleanly defaulting to `NEVER_ACTIVE`.

This should be treated as a **release-blocking fix** for any build that includes mainnet support.

The correct mainnet interim state is:

```cpp
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].bit = 3;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].min_activation_height = 0;
```

Additionally, `BIP9Deployment` should restore safe default member initializers:

```cpp
int bit{28};
int64_t nStartTime{NEVER_ACTIVE};
int64_t nTimeout{NEVER_ACTIVE};
int min_activation_height{0};
```

This mirrors Bitcoin Core v24’s defensive behavior and prevents future unconfigured deployments from failing open or behaving unpredictably.

---

## 2. Scope and Reviewed Decisions

The review evaluates the following Phase F decisions:

1. Assign `DEPLOYMENT_P2QPK` to versionbit **bit 3**.
2. Use `nStartTime = ALWAYS_ACTIVE` on regtest and testnet.
3. Use `nTimeout = NO_TIMEOUT` on regtest and testnet.
4. Use `min_activation_height = 0`.
5. Leave `DEPLOYMENT_P2QPK` absent from `CMainParams` until governance selects mainnet activation parameters.
6. Use Bech32 HRPs:
   - mainnet: `bq`
   - testnet: `bqt`
   - regtest: `bq`
7. Add `DEPLOYMENT_P2QPK` to `DeploymentInfo()` RPC output via `SoftForkDescPushBack`.

---

## 3. Decision Matrix

| # | Decision | Verdict | Severity | Summary |
|---|---|---:|---:|---|
| 1 | Versionbit bit 3 | **PASS** | Low | Bit 3 is unused in the reviewed deployment table and is a normal BIP9 bit choice. |
| 2 | `ALWAYS_ACTIVE` on regtest/testnet | **PASS** | Low | Sound for transaction-format and validation testing, but not a replacement for later BIP9 activation rehearsal. |
| 3 | `NO_TIMEOUT` on regtest/testnet | **PASS** | Low | Harmless with `ALWAYS_ACTIVE`; consistent with Bitcoin Core regtest/signet style. |
| 4 | `min_activation_height = 0` | **PASS** | Low | Harmless for always-active test chains. |
| 5 | P2QPK absent from `CMainParams` | **FAIL** | **High / release-blocking** | Unsafe because QOGE’s `BIP9Deployment` struct lacks safe default initializers. |
| 6 | HRP `bqt` for testnet, `bq` for mainnet/regtest | **PASS** | Low/Medium UX | `bqt` is good for public testnet. Regtest sharing `bq` is acceptable short-term but should be cleaned up later. |
| 7 | `DeploymentInfo()` RPC hardcoded list fix | **PASS** | Low | Correct place for `getdeploymentinfo`; `VersionBitsDeploymentInfo` is also updated. |

---

## 4. Detailed Findings

## 4.1 Bit Assignment: `bit = 3`

### Verdict

**PASS**

### Reasoning

`DEPLOYMENT_TESTDUMMY` uses bit 28 and `DEPLOYMENT_TAPROOT` uses bit 2. P2QPK uses bit 3 consistently on regtest and testnet.

Bit 3 is a safe and conventional choice as long as no other planned QOGE deployment is already reserving it.

### Recommendation

Keep bit 3 for P2QPK across regtest, testnet, and future mainnet activation unless QOGE governance explicitly reserves bit 3 for another deployment before mainnet activation.

Using the same bit across testnet and mainnet is not strictly required, because each chain has separate parameters. However, keeping the same bit is operationally cleaner and reduces documentation and tooling confusion.

---

## 4.2 `nStartTime = ALWAYS_ACTIVE` on Regtest and Testnet

### Verdict

**PASS for Phase F**

### Reasoning

For a Phase F public testnet focused on validating P2QPK transaction behavior, `ALWAYS_ACTIVE` is reasonable. It removes BIP9 signaling complexity and allows immediate testing of:

- witness version 2 outputs,
- P2QPK spend validation,
- SLH-DSA signature verification path,
- wallet address generation and spend flow,
- RPC deployment visibility,
- miner/block inclusion behavior on the test network.

Bitcoin Core uses `ALWAYS_ACTIVE` for testing contexts where the goal is to avoid activation-window mechanics. For Taproot, Bitcoin Core used `ALWAYS_ACTIVE` on regtest and signet, while public testnet used real start/timeout parameters.

### Important Limitation

This does **not** test the mainnet BIP9 transition itself. Before mainnet activation, QOGE should separately test:

- `DEFINED -> STARTED`,
- `STARTED -> LOCKED_IN`,
- `LOCKED_IN -> ACTIVE`,
- `STARTED -> FAILED`,
- boundary blocks at period transitions,
- reorg behavior around lock-in and activation boundaries,
- `getblocktemplate` behavior during `STARTED`, `LOCKED_IN`, and `ACTIVE`,
- RPC reporting through `getdeploymentinfo`.

### Recommendation

Keep `ALWAYS_ACTIVE` for Phase F public testnet if the goal is protocol-format validation.

Create a separate activation rehearsal later, either on regtest, signet-like infrastructure, or a temporary dedicated test chain using real BIP9 parameters.

---

## 4.3 `nTimeout = NO_TIMEOUT` on Regtest and Testnet

### Verdict

**PASS**

### Reasoning

With `nStartTime = ALWAYS_ACTIVE`, timeout is effectively irrelevant because versionbits returns `ACTIVE` immediately.

`NO_TIMEOUT` is consistent with the test-oriented use of the deployment.

### Recommendation

Keep `NO_TIMEOUT` for always-active regtest/testnet Phase F.

For a future BIP9 rehearsal, use a real timeout so failure behavior is also tested.

---

## 4.4 `min_activation_height = 0`

### Verdict

**PASS**

### Reasoning

For always-active deployments, `min_activation_height` is bypassed because the deployment state immediately resolves to `ACTIVE`.

No meaningful genesis-block edge case was identified from `min_activation_height = 0` in this configuration.

### Recommendation

Keep `min_activation_height = 0` for Phase F regtest/testnet.

For mainnet, choose a governance-approved activation schedule later. If using Speedy Trial-style logic, a nonzero `min_activation_height` may be useful to provide predictable activation timing after lock-in.

---

## 4.5 `DEPLOYMENT_P2QPK` Absent from `CMainParams`

### Verdict

**FAIL — release-blocking for mainnet-capable builds**

### Why This Is Unsafe

The enum entry exists:

```cpp
DEPLOYMENT_P2QPK
```

Validation logic checks whether P2QPK is active:

```cpp
if (DeploymentActiveAt(block_index, consensusparams, Consensus::DEPLOYMENT_P2QPK)) {
    flags |= SCRIPT_VERIFY_P2QPK;
}
```

RPC logic also exposes P2QPK through `getdeploymentinfo`.

However, `CMainParams` does not explicitly initialize `consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK]`.

In Bitcoin Core v24, this would be less dangerous because `BIP9Deployment` has defensive defaults:

```cpp
int bit{28};
int64_t nStartTime{NEVER_ACTIVE};
int64_t nTimeout{NEVER_ACTIVE};
int min_activation_height{0};
```

In the reviewed QOGE commit, the struct fields are plain members without default initializers:

```cpp
int bit;
int64_t nStartTime;
int64_t nTimeout;
int min_activation_height{0};
```

This means an unconfigured deployment entry may contain indeterminate values, depending on object lifetime and initialization behavior. Versionbits reads these values when computing activation state and block versions.

### Mainnet Consequences

Possible consequences include:

- `getdeploymentinfo` reporting nonsensical P2QPK state on mainnet,
- block-version computation reading an unintended bit,
- `DeploymentActiveAt()` resolving incorrectly,
- `SCRIPT_VERIFY_P2QPK` being accidentally enabled or behaving unpredictably,
- mainnet consensus behavior depending on uninitialized deployment parameters.

This is a consensus-safety issue.

### Correct Fix

Explicitly configure P2QPK in `CMainParams` as inactive:

```cpp
// Deployment of SIP-QOGE-PQC-02 P2QPK SLH-DSA.
// Mainnet activation is deliberately deferred to governance.
// Until then, fail closed.
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].bit = 3;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].min_activation_height = 0;
```

Also restore safe default initializers in `src/consensus/params.h`:

```cpp
struct BIP9Deployment {
    int bit{28};
    int64_t nStartTime{NEVER_ACTIVE};
    int64_t nTimeout{NEVER_ACTIVE};
    int min_activation_height{0};

    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
    static constexpr int64_t NEVER_ACTIVE = -2;
};
```

### Additional Recommendation

Initialize P2QPK in the signet stub as `NEVER_ACTIVE` too, even if signet is not supported. The signet params object exists and should not carry an uninitialized deployment slot.

---

## 4.6 P2QPK Pre-Activation Behavior on Mainnet

### Expected Design

Before activation, P2QPK witness v2 outputs should behave like future witness programs: anyone-can-spend from the perspective of old/non-upgraded consensus rules.

The interpreter path appears to follow this intended model:

```cpp
if (witversion == 2 && program.size() == SLHDSA_PK_LEN && !is_p2sh) {
    if (!(flags & SCRIPT_VERIFY_P2QPK)) return set_success(serror);
    ...
}
```

So, if `SCRIPT_VERIFY_P2QPK` is not set, the spend succeeds.

### Risk

This is only safe if `SCRIPT_VERIFY_P2QPK` is definitely not set before activation.

Because mainnet P2QPK deployment is currently unconfigured, the inactive state is not guaranteed. This is why the `CMainParams` fix is mandatory.

---

## 4.7 HRP Decisions

### Verdict

**PASS for Phase F**

### Testnet HRP: `bqt`

`bqt` is a sound testnet HRP choice. It distinguishes public testnet P2QPK addresses from mainnet `bq` addresses and follows the same broad principle as Bitcoin’s `bc` vs `tb`.

### Regtest HRP: `bq`

Using `bq` on regtest is not a consensus risk because regtest is isolated. The main risk is UX/tooling confusion:

- test harnesses may produce mainnet-looking addresses,
- copied logs/screenshots may confuse users,
- scripts may accidentally treat regtest addresses as mainnet addresses,
- future wallet tests may miss address-network separation bugs.

### Recommendation

Do not block Phase F public testnet on regtest HRP.

However, plan a future cleanup to use a distinct regtest HRP such as:

```text
bqrt
```

This should be done before broader public wallet release if possible.

### Bech32m Warning

P2QPK uses witness version 2. Witness versions 1 through 16 should use Bech32m, not legacy Bech32.

Therefore, both core and wallet address encoding should ensure:

- witness v0 uses Bech32,
- witness v2 P2QPK uses Bech32m.

The HRP choice is acceptable, but the checksum encoding must be correct for v2.

---

## 4.8 `DeploymentInfo()` RPC Hardcoded List Fix

### Verdict

**PASS**

### Reasoning

Adding:

```cpp
SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_P2QPK);
```

to `DeploymentInfo()` is the correct fix for `getdeploymentinfo` visibility.

The required `VersionBitsDeploymentInfo` entry also exists:

```cpp
{
    /*.name =*/ "p2qpk",
    /*.gbt_force =*/ true,
},
```

### Other Hardcoded Lists

No additional hardcoded deployment list of the same kind was identified as missing.

The important deployment paths already iterate over `MAX_VERSION_BITS_DEPLOYMENTS`, including:

- versionbits block-version computation,
- `getblocktemplate` versionbits handling,
- versionbits state cache.

### Recommendation

Keep the RPC fix.

Add a regression test that asserts `getdeploymentinfo` contains `p2qpk` on regtest and testnet.

---

## 5. Additional Issues Found During Review

## 5.1 Testnet BIP9 Threshold Appears Internally Inconsistent

Current reviewed testnet values:

```cpp
consensus.nRuleChangeActivationThreshold = 8064;
consensus.nMinerConfirmationWindow = 2016;
```

This makes real BIP9 activation impossible on testnet because the threshold is greater than the window.

This does not matter while P2QPK is `ALWAYS_ACTIVE`, but it will matter if QOGE later attempts to test real BIP9 signaling on testnet.

### Recommendation

If testnet is ever used for actual BIP9 signaling, change the threshold to a value less than or equal to the confirmation window.

For a 75% threshold with a 2016-block window, the value should be:

```cpp
consensus.nRuleChangeActivationThreshold = 1512;
consensus.nMinerConfirmationWindow = 2016;
```

Alternatively, if QOGE wants an 8064-block testnet window, set:

```cpp
consensus.nMinerConfirmationWindow = 8064;
consensus.nRuleChangeActivationThreshold = 6048; // 75%
```

The current `8064 / 2016` pairing is not usable for real BIP9 signaling.

---

## 5.2 Mainnet Standardness / Mempool Policy May Reject P2QPK Spends

The policy layer currently classifies witness versions other than v0 and v1 as `WITNESS_UNKNOWN`.

`AreInputsStandard()` rejects `WITNESS_UNKNOWN`.

On mainnet, `fRequireStandard = true`. On testnet/regtest, standardness is relaxed. Therefore, Phase F may not catch a mainnet mempool-relay problem.

### Impact

After mainnet activation, P2QPK spends may be consensus-valid but non-standard, meaning they may not relay through normal mempools and may require direct miner submission unless policy is updated.

### Recommendation

Before mainnet activation:

1. Add a P2QPK-specific output type or policy exception.
2. Ensure P2QPK spends are standard after activation.
3. Ensure P2QPK spends are not standard before activation unless this is intentionally allowed.
4. Add tests covering:
   - mempool acceptance before activation,
   - mempool acceptance after activation,
   - block acceptance before activation,
   - block acceptance after activation.

---

## 6. Mainnet Safety Checklist Before Activation

Before configuring real mainnet BIP9 parameters, the following should be completed:

- [ ] Explicitly initialize `DEPLOYMENT_P2QPK` in `CMainParams` as `NEVER_ACTIVE`.
- [ ] Restore safe default initializers in `BIP9Deployment`.
- [ ] Initialize P2QPK in signet params as `NEVER_ACTIVE` or `ALWAYS_ACTIVE`, but not unconfigured.
- [ ] Add tests for unconfigured deployments failing closed.
- [ ] Add tests for `getdeploymentinfo` showing `p2qpk`.
- [ ] Add tests for P2QPK inactive behavior on mainnet params.
- [ ] Add tests for P2QPK active behavior on regtest/testnet.
- [ ] Add a real BIP9 activation rehearsal.
- [ ] Fix or document testnet threshold/window inconsistency.
- [ ] Add P2QPK mempool standardness policy.
- [ ] Confirm Bech32m encoding for witness v2 addresses.
- [ ] Confirm miner `getblocktemplate` behavior during `STARTED`, `LOCKED_IN`, and `ACTIVE`.

---

## 7. Recommended Patch Summary

### Required Before Public Mainnet-Capable Release

```cpp
// src/consensus/params.h
struct BIP9Deployment {
    int bit{28};
    int64_t nStartTime{NEVER_ACTIVE};
    int64_t nTimeout{NEVER_ACTIVE};
    int min_activation_height{0};

    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
    static constexpr int64_t NEVER_ACTIVE = -2;
};
```

```cpp
// src/chainparams.cpp, inside CMainParams
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].bit = 3;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].min_activation_height = 0;
```

### Strongly Recommended Before Mainnet Activation

```cpp
// Example only: actual governance values TBD.
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].bit = 3;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nStartTime = <governance_selected_start_time>;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].nTimeout = <governance_selected_timeout>;
consensus.vDeployments[Consensus::DEPLOYMENT_P2QPK].min_activation_height = <governance_selected_min_activation_height>;
```

---

## 8. Final Verdict

The Phase F testnet deployment choices are acceptable with one critical correction.

### Pass

- bit 3,
- `ALWAYS_ACTIVE` on regtest/testnet,
- `NO_TIMEOUT` on regtest/testnet,
- `min_activation_height = 0`,
- testnet HRP `bqt`,
- temporary regtest HRP `bq`,
- `getdeploymentinfo` RPC visibility fix.

### Fail / Must Fix

- `DEPLOYMENT_P2QPK` must not remain unconfigured in `CMainParams`.

### Mainnet Consensus Safety Risk

The unconfigured mainnet deployment entry can be read by validation, RPC, and versionbits logic. Because the deployment struct lacks safe defaults in this codebase, this is a consensus-safety risk.

### Mainnet Activation Risk

The current policy layer may classify P2QPK spends as unknown witness programs and reject them from standard mainnet mempools unless policy is updated before activation.

---

## 9. Reviewer Conclusion

The Phase F strategy is technically reasonable: activate P2QPK immediately on test chains to validate the new transaction and signature-verification path without forcing testers through BIP9 signaling windows.

But the mainnet deployment slot must fail closed. The safest immediate state is:

> P2QPK active on regtest/testnet, explicitly `NEVER_ACTIVE` on mainnet, with safe defaults restored in `BIP9Deployment`.

After this correction, the Phase F deployment parameter set is suitable for public testnet validation.
