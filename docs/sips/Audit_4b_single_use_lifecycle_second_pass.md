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
| Q7 | PASS + INFORMATIONAL | No backward transitions; `MarkSpentAndRetire` shortcut noted (see below) |
| Q8 | PASS | Tests verify the right properties at the right stack level (detailed below) |
| Q9 | INFORMATIONAL (×2) | Sig-length check inconsistency (FIXED); `SetKeyDestructionMinConfirmations` package-level state |

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

### Q7 — INFORMATIONAL: `MarkSpentAndRetire` provides PENDING→RETIRED shortcut at keystore layer

`MarkSpentAndRetire` (keystore.go) transitions PENDING→RETIRED in one bolt
transaction, bypassing SPENT as a persisted intermediate state. It correctly
enforces `rec.State != StatePending` before acting and zeroes the seed blob.

**Disposition — intentional and not reachable from wallet.go:** No `wallet.go`
code path calls `MarkSpentAndRetire`. The wallet API always routes through
`OnConfirmation` → `MarkSpent` (PENDING→SPENT) then `PurgeSpentKey` → `Retire`
(SPENT→RETIRED). The shortcut is available for code using the keystore directly
(e.g., the Audit 5 atomicity fix) and is intentional.

**Recommendation for future keystore API documentation:** explicitly note that
`MarkSpentAndRetire` bypasses the SPENT state and is intended for trusted
internal callers, not general integrators. **Not a mainnet blocker.**

### Q9 — INFORMATIONAL (FIXED): `TestSignAndVerifyMessage` sig-length check inconsistency

`TestSignAndVerifyMessage` used `len(sig) > slhdsa.SignatureSize` (upper-bound
only) while `TestSignP2QPKInputTransitionsChangeAfterSigning` used
`len(sig) != slhdsa.SignatureSize` (exact equality — the Audit 3 fix). SLH-DSA-
SHA2-128f always produces exactly 17,088 bytes per FIPS 205, so the loose check
never triggers in practice, but it is inconsistent with the Audit 3 fix applied
to the same type of assertion elsewhere.

**Fix applied:** `wallet_test.go` line 207 changed to `!= slhdsa.SignatureSize`.
This session's commit.

### Q9 — INFORMATIONAL: `keyDestructionMinConfirmations` is package-level state

`keyDestructionMinConfirmations` is a package-level `var` (wallet.go:71). In a
process running multiple `Wallet` instances (e.g., mainnet and testnet in the
same binary), `SetKeyDestructionMinConfirmations` affects all instances.

**Disposition — not an issue in current deployment:** The CLI creates one wallet
instance; nothing in the current codebase creates two. Recorded for future
integrators who embed the wallet library with multiple instances. **Not a
mainnet blocker.**

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
| Q3 TOCTOU (check/MarkPending gap) | INFORMATIONAL — resolves safely; retry semantics correct |
| Q7 `MarkSpentAndRetire` keystore shortcut | INFORMATIONAL — intentional, not reachable from wallet API |
| Q9 sig-length check inconsistency | FIXED — `wallet_test.go` updated to exact equality |
| Q9 package-level confirmation var | INFORMATIONAL — document for multi-instance integrators |

**Audit 4b overall: PASS. The Audit 4 redesign is structurally sound. No
finding is a mainnet blocker. The two HIGH/CRITICAL findings from Audit 4 are
confirmed fixed. The second-pass recommendation in Audit 4 and CLAUDE.md is
satisfied.**

---

*Second-pass audit artifact for SIP-QOGE-PQC-01, Symbiont Wallet. Part of
the pre-mainnet review series. This pass satisfies the "second independent
model" recommendation in `Audit_4_single_use_lifecycle_triage_summary.md`.*
