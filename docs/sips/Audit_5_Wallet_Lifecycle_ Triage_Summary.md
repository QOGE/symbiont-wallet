# Audit 5 (Wallet Lifecycle — Unstructured Direct Review) — Triage Summary

**Component:** Symbiont Wallet address issuance and retirement lifecycle
(`wallet/wallet.go`, `keystore/keystore.go`).

**Auditor:** OpenAI Codex CLI (0.142.5) — 6 July 2026.

**Methodology note — this audit differs from Audits 1–4:** Audits 1–4 use
four pre-written structured prompts (sighash, witness verification, liboqs
integration, single-use lifecycle), each run across multiple models for
cross-comparison. Audit 5 was run with Codex CLI given direct, read-only
filesystem access to `~/symbiont-wallet` and asked to perform a general
security review, without a pre-written structured prompt. This produced a
different kind of output — self-directed findings rather than answers to
fixed questions — so it is not directly comparable to the verdict-matrix
format used in Audits 1–4. It is recorded as its own audit rather than
folded into Audit 3 or 4, which retain their original scope and are still
pending in structured form.

**Operational note:** Codex CLI's sandbox failed to initialize in this VM,
so it operated in read-only escalated mode with per-command approval,
explicitly avoided running `go test` (to prevent creating build/cache
artifacts during a read-only pass), and did not modify any files during
the review itself.

---

## Findings and dispositions

### Finding 1 — Address reservation ("same address issued twice")

**Codex claim:** `NextReceiveAddress` can return the same address on
successive calls without an intervening `MarkPaymentReceived`, allegedly
breaking the single-use model.

**Triage disposition: FALSE POSITIVE — CONFIRMED NOT A BUG.**

Verified via direct code inspection (Claude Code, `wallet.go:150-156`,
`keystore.go:307-327`): `NextReceiveAddress` calls `NextFreshAddress`,
which opens a **read-only** `db.View` transaction and returns the lowest
FRESH-state address without changing its state. This is confirmed as
**intentional, documented, and tested** behavior:

- `wallet_test.go:105-123` explicitly asserts this exact "peek" behavior
  and passes.
- `CLAUDE.md` already documents: "The address is NOT yet marked PENDING —
  call `MarkPaymentReceived` when a payment is detected in the mempool."

Codex read the code correctly but did not account for the accompanying
test and documentation that establish this as by-design read-only peek
semantics, not a reservation mechanism. No fix required.

---

### Finding 2 — Retirement atomicity

**Codex claim:** `OnConfirmation` performs `MarkSpent` and `Retire` as two
separate database writes; a crash between them could leave an address in
`SPENT` state with the seed still present, contradicting `CLAUDE.md`'s
claim that the operation is atomic.

**Triage disposition: CONFIRMED — FIXED.**

Verified via direct code inspection: `wallet.go:186-191` (pre-fix) called
`MarkSpent` then `Retire` as two independent bbolt `Update` transactions.
`CLAUDE.md:68` stated "runs MarkSpent + Retire + pool refill atomically" —
this was factually false prior to the fix.

**Fix applied (`b093d0f`):** new `KeyIndex.MarkSpentAndRetire(addr string)
error` in `keystore.go` performs the PENDING→SPENT→RETIRED transition
(state change + seed zeroing) inside a single `db.Update` callback.
Because bbolt's `Update` is all-or-nothing at the write-ahead-log level,
there is no longer a "between" for a crash to land in — the intermediate
SPENT state (with seed still present) is now unreachable from outside the
transaction.

`wallet.go`'s `OnConfirmation` updated to call `MarkSpentAndRetire`
directly instead of the two-call sequence. Pool refill remains a separate,
non-atomic operation (by design — it is not security-critical the way
seed destruction is), and `CLAUDE.md:68` was corrected to state this
precisely rather than claim blanket atomicity.

**Test coverage added:** `TestMarkSpentAndRetireIsAtomic` (confirms the
intermediate SPENT state is never observable, seed is cleared, operation
is terminal) and `TestMarkSpentAndRetireRequiresPending` (confirms
rejection from FRESH and SPENT starting states). 63/63 tests pass
(61 original + 2 new).

**Note on verification methodology:** direct crash-injection between the
two writes is not testable from Go test code, since bbolt's transaction
guarantee operates below the application layer with no interceptable seam.
The added tests instead verify the functional consequence of atomicity —
no partial state ever observable — which is the correct and only testable
proxy for this guarantee.

---

### Finding 3 — `SignP2QPKInput` missing input/output cross-check

**Codex claim:** `SignP2QPKInput` signs whatever `P2QPKSpendParams` are
supplied after only checking wallet-side state (that `FromAddr` is
`PENDING`) — it does not verify that `SpentUTXOs[InputIndex]`'s
`scriptPubKey` actually corresponds to `FromAddr` before signing.

**Triage disposition: CONFIRMED — OPEN, NOT YET FIXED.**

Verified via direct code inspection: `wallet.go:416-449` looks up
`FromAddr` in the keystore and checks `StatePending`, then computes the
sighash (which does commit to `SpentUTXOs[InputIndex]` via
`hashScriptPubkeys`) and signs it — without ever cross-checking that the
`scriptPubKey` at `InputIndex` actually matches the address being signed
from.

**Impact:** a caller bug supplying a mismatched `FromAddr`/`SpentUTXOs`
pair would produce a signature that is not silently accepted — the
resulting transaction would fail on-chain, since the sighash commits to
the actual (mismatched) `scriptPubKey`. This is not a fund-loss bug today
because nothing currently calls `SignP2QPKInput` with real chain data
(M1.6/`SignTransaction` remains a stub). It becomes a real safety concern
once M1.6 is wired to production transaction construction, where a caller
bug could otherwise fail silently at signing time rather than loudly and
immediately.

**Status: deferred to a future session.** Recommended fix: before signing,
derive the expected P2QPK script/program from the keystore record's
`PublicKey` and require it match `SpentUTXOs[InputIndex].Script`, failing
loudly if not.

---

## Summary

| Finding | Disposition | Action |
|---|---|---|
| 1 — Address reservation | False positive | None — confirmed intended, tested, documented |
| 2 — Retirement atomicity | Confirmed | Fixed (`b093d0f`), 2 new tests, CLAUDE.md corrected |
| 3 — SignP2QPKInput cross-check | Confirmed | Open — deferred, not urgent until M1.6 |

**Audit 5 overall: one real bug found and fixed, one false positive
correctly ruled out via verification against existing tests/docs, one
real but lower-urgency finding deferred.** Not a bottleneck for mainnet
activation — Finding 2 is resolved and Finding 3 does not affect any
currently-active code path.

---

*Unstructured audit artifact, part of the pre-mainnet review process for
Symbiont Wallet / SIP-QOGE-PQC-01. Auditor claims preserved and verified
independently before any fix; false positives recorded as such rather than
silently dropped.*
