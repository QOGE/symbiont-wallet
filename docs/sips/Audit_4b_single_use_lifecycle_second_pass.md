# Audit 4b (Single-Use Address Lifecycle — Second Independent Pass) — Triage Summary

**Component:** Address state machine, key destruction timing, change-output
routing (`keystore/keystore.go`, `wallet/wallet.go`, `wallet/wallet_test.go`).

**Auditor:** Claude Sonnet 4.6 (Anthropic) — fresh agent, no prior conversation
context from Audit 4, direct filesystem read access — 9 July 2026.

**Methodology note:** This is the second structured pass on the redesigned code,
as recommended in `Audit_4_single_use_lifecycle_triage_summary.md` and
`CLAUDE.md`. The agent was given structured questions and asked to form its own
view before reading the prior audit. It had access to the full source files
(`wallet.go`, `keystore.go`, `wallet_test.go`) and the CLAUDE.md architecture
overview. This satisfies the "second independent model" recommendation made in
Audit 4.

**Reviewed at:** `b5e757d` (post-Audit-4 redesign). One cleanup applied in this
session: `wallet_test.go` sig-length check (`>` → `!=`) — see Q9 below.

**Post-audit fixes (three-pass convergence + Audit 5 follow-up):** Three of four
informational items subsequently resolved — see "Post-audit dispositions" section
at the end. Two additional findings surfaced after this pass that were not caught
here (change-output binding in `SignP2QPKInput`; FromAddr/SpentUTXO script
cross-check) — both documented in the post-audit section.

---

## Headline result

**PASS — ready for mainnet.**

All structural redesign properties verified: flagging decoupled from
destruction, change-address preconditions enforced before signing, transitions
applied only on success, state machine invariants preserved. Four INFORMATIONAL
items surfaced — none approach blocking severity. Prior Audit 4 triage confirmed
accurate; two HIGH/CRITICAL findings confirmed fixed.

---

## Verdict matrix

| Q# | Verdict | Summary |
|---|---|---|
| Q1 | PASS | `OnConfirmation` calls only `MarkSpent`; `confirmations < 1` no-ops; pool refill follows |
| Q2 | PASS | Confirmation floor checked before `Retire`; FRESH/PENDING/RETIRED all return `ErrAddressNotSpent`; double-call on RETIRED fails |
| Q3 | PASS + INFORMATIONAL | Preconditions and post-sign transition correct; TOCTOU resolves safely (see below) |
| Q4 | PASS | `SignTransaction` stub applies same ordering: FRESH check → sign → `MarkPending`; failure leaves change FRESH |
| Q5 | PASS | `ListByState` uses `db.View`; no mutations; iteration deterministic (bbolt big-endian uint64 keys) |
| Q6 | PASS | Only `StateSpent` records enter eligibility loop; advisory only; no transitions triggered |
| Q7 | PASS + INFORMATIONAL → RESOLVED | No backward transitions; `MarkSpentAndRetire` shortcut removed entirely (`8f4e192`) |
| Q8 | PASS | Tests verify the right properties at the right stack level (detailed below) |
| Q9 | INFORMATIONAL (×2) | Sig-length check inconsistency (FIXED); `SetKeyDestructionMinConfirmations` floor now enforced in code (`8d9b809`) |

---

## Findings and dispositions

### Q3 — INFORMATIONAL: TOCTOU between change-address check and MarkPending

`SignP2QPKInput` calls `GetRecord(params.ChangeAddr)` (acquires and releases the
keystore mutex) and then `MarkPending(params.ChangeAddr)` (re-acquires). Between
the two acquisitions a concurrent goroutine could claim the same address.

**Disposition — safe by construction, not a bug:** `MarkPending` calls
`transition` under the lock, which re-checks state before applying. If another
goroutine claimed the address in the gap, `MarkPending` returns
`ErrAddressAlreadyUsed` and `SignP2QPKInput` returns `(nil, nil, error)` — no
computed signature leaks, no state inconsistency. The wallet ends in a
consistent state; the caller can retry with a different address.

Eliminating this inherent two-step gap would require a single-transaction
reserve-and-sign primitive, which is a larger architectural change. The current
behaviour is safe for all single-wallet-instance deployments and most concurrent
scenarios. **Not a mainnet blocker.**

### Q7 — INFORMATIONAL → RESOLVED: `MarkSpentAndRetire` PENDING→RETIRED shortcut

`MarkSpentAndRetire` (keystore.go) transitioned PENDING→RETIRED in one bolt
transaction, bypassing SPENT as a persisted intermediate state. No `wallet.go`
code path called it — the Audit 4 redesign left it with zero production callers.

**Disposition at audit time:** intentional, not reachable from wallet API,
not a mainnet blocker.

**Subsequently resolved (`8f4e192`):** `MarkSpentAndRetire` removed entirely from
`keystore.go`. Rationale: zero production callers after the Audit 4 redesign; no
confirmation-depth guard (a caller could invoke it at confirmation depth 0); the
method was the Audit 5 atomicity fix for the old `OnConfirmation`, which no longer
destroys keys. The two-step `MarkSpent` + `Retire` path through `OnConfirmation`
+ `PurgeSpentKey` is the correct replacement. `TestMarkSpentAndRetireIsAtomic` and
`TestMarkSpentAndRetireRequiresPending` removed from `keystore_test.go`.

### Q9 — INFORMATIONAL (FIXED): `TestSignAndVerifyMessage` sig-length check inconsistency

`TestSignAndVerifyMessage` used `len(sig) > slhdsa.SignatureSize` (upper-bound
only) while `TestSignP2QPKInputTransitionsChangeAfterSigning` used
`len(sig) != slhdsa.SignatureSize` (exact equality — the Audit 3 fix). SLH-DSA-
SHA2-128f always produces exactly 17,088 bytes per FIPS 205, so the loose check
never triggers in practice, but it is inconsistent with the Audit 3 fix applied
to the same type of assertion elsewhere.

**Fix applied:** `wallet_test.go` line 207 changed to `!= slhdsa.SignatureSize`.
This session's commit.

### Q9 — INFORMATIONAL → PARTIALLY RESOLVED: `keyDestructionMinConfirmations` is package-level state

`keyDestructionMinConfirmations` is a package-level `var` (wallet.go). In a
process running multiple `Wallet` instances (e.g., mainnet and testnet in the
same binary), `SetKeyDestructionMinConfirmations` affects all instances.

**Disposition at audit time:** not an issue in current deployment (CLI creates
one wallet instance); recorded for future integrators. Not a mainnet blocker.

**Subsequently partially resolved (`8d9b809`):** `SetKeyDestructionMinConfirmations`
now returns `error` and enforces a hard 101-block floor — calls with values below
`KeyDestructionMinConfirmations` (101) are rejected in code, not just as a comment.
The package-level variable itself remains unchanged (a per-instance field would
require an API break); the API is now safe against misconfiguration below the
coinbase maturity depth.

---

## Q8 — Test coverage verification

**`TestOnConfirmationFlagsWithoutDestroying`:** asserts `rec.State == StateSpent`
and `rec.EncSeedBlob != nil` after `OnConfirmation(addr, 1)`. Directly tests the
redesign's core property.

**`TestPurgeSpentKeyRequiresSpentState`:** exercises FRESH rejection, PENDING
rejection, SPENT acceptance with full RETIRED + nil-seed assertion, and RETIRED
re-call rejection. Four cases, all correct.

**`TestSignP2QPKInputTransitionsChangeAfterSigning`:** asserts ChangeAddr is FRESH
before signing, PENDING after, and `fromAddr` remains PENDING (unchanged by the
signing path). The `fromAddr` post-sign check is explicitly present — confirms
signing does not advance the spending address's state.

**`TestSignMessageAfterSpendFails`:** confirms a SPENT address cannot sign,
without a prior `SignMessage`. Tests that state transitions gate signing
independently of whether a sign has occurred.

---

## Summary of dispositions

| Finding | Disposition |
|---|---|
| Q3 TOCTOU (check/MarkPending gap) | INFORMATIONAL — resolves safely; retry semantics correct; deferred |
| Q7 `MarkSpentAndRetire` keystore shortcut | RESOLVED — removed entirely (`8f4e192`); zero callers, footgun API |
| Q9 sig-length check inconsistency | FIXED — `wallet_test.go` updated to exact equality |
| Q9 package-level confirmation var | PARTIALLY RESOLVED — hard 101-block floor enforced in code (`8d9b809`) |

**Audit 4b overall: PASS. The Audit 4 redesign is structurally sound. No
finding is a mainnet blocker. The two HIGH/CRITICAL findings from Audit 4 are
confirmed fixed. The second-pass recommendation in Audit 4 and CLAUDE.md is
satisfied.**

---

## Post-audit dispositions (three-pass convergence fixes, 9 July 2026)

After this audit, three independent passes (Grok Build, Codex CLI, Claude Sonnet
4.6) converged on the following in the same session:

**Change-output binding in `SignP2QPKInput` — NOT caught by this pass (commit `e1df1b5`):**
`SignP2QPKInput` validated that `ChangeAddr` was FRESH and wallet-controlled but
did not verify that any `params.Outputs[i].Script` actually routes change to that
address. A mismatched output list would cause the wallet to transition the change
address to PENDING while the transaction sends change elsewhere. Fix: before
signing, exactly one entry in `params.Outputs` must have a script equal to the
P2QPK scriptPubKey of `ChangeAddr` (`OP_2 | PUSH32 | HASH256(changeAddr)`);
`ErrChangeOutputMissing` / `ErrChangeOutputAmbiguous` returned otherwise. Same
check added to `SignTransaction`. `QOGETransaction` gained `Outputs []SpendOutput`.
Helper `p2qpkScriptPubKey` added to wallet.go. Test
`TestSignP2QPKInputRejectsNoMatchingOutput` added.

**`MarkSpentAndRetire` removal — resolves Q7 (commit `8f4e192`):** see above.

**`SetKeyDestructionMinConfirmations` hard floor — resolves Q9 partial (commit `8d9b809`):** see above.

**CLI purge message honesty (commit `042bed5`):** purge success message corrected
from "zeroed from memory and storage" to accurately describe bbolt copy-on-write
semantics — old pages may persist until compaction, but the seed is encrypted at
rest so residual pages do not expose the raw key.

**`SignP2QPKInput` FromAddr/SpentUTXO cross-check — NOT caught by this pass (commit `4f80192`):**
`SignP2QPKInput` checked that `FromAddr` was PENDING but did not verify that
`SpentUTXOs[InputIndex].Script` matched the P2QPK scriptPubKey for that address.
A caller supplying a mismatched UTXO script would produce a signature that fails
on-chain while consuming the address's wallet state. Surfaced by Audit 5 (Codex
CLI, 6 July 2026); fixed in a subsequent session. Fix: `p2qpkScriptPubKey(params.FromAddr)`
(reusing the helper from `e1df1b5`) compared against `params.SpentUTXOs[params.InputIndex].Script`;
`ErrFromAddrScriptMismatch` returned on mismatch; `InputIndex` bounds-checked
against `SpentUTXOs` length. Two test fixtures corrected (`makeMinimalSpendParams`,
`makeMinimalSpendParamsNoChangeOutput` both used OP_1 as the UTXO script).
New test: `TestSignP2QPKInputRejectsMismatchedFromScript`. 68/68 tests pass.

---

*Second-pass audit artifact for SIP-QOGE-PQC-01, Symbiont Wallet. Part of
the pre-mainnet review series. This pass satisfies the "second independent
model" recommendation in `Audit_4_single_use_lifecycle_triage_summary.md`.*
