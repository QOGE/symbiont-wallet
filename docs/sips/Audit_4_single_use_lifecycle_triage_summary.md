# Audit 4 (Single-Use Address Lifecycle) — Triage Summary

**Component:** Address state machine, key destruction timing, change-output
routing, and confirmation-depth logic (`keystore/keystore.go`,
`wallet/wallet.go`).

**Auditor:** Grok Build (xAI, Composer 2.5) — local, direct filesystem
access, read-only inspection — 7 July 2026.

**Methodology note:** this audit ran as a single structured pass (not yet
cross-validated by a second independent model, unlike Audits 1-3). The
findings were substantial and specific enough — and corroborated closely
enough with prior findings from Audit 5 — that remediation proceeded
directly rather than waiting for additional passes. A second independent
review of the redesigned code (Steps below) is recommended before mainnet,
consistent with the project's general practice of not relying on a single
audit pass alone for consensus- or fund-adjacent logic.

**Reviewed at:** `symbiont-wallet@10c6c1fa` (pre-fix). Post-fix commit:
`b5e757d`.

---

## Headline result

**Two real, HIGH/CRITICAL-severity design gaps found and fixed via a
structural redesign, not a patch.** Rather than adding guards to the
existing automatic-destruction model, the underlying design was changed:
address *flagging* (reuse prevention) is now fully decoupled from private
key *destruction*, which becomes optional, manual, and the integrator's
explicit responsibility. This resolves the two most severe findings as a
side effect of the redesign rather than requiring separate patches for
each.

**No finding blocks Phase F or the current public testnet** — this is a
wallet-library design change, not a consensus change, and does not affect
any already-confirmed on-chain transaction.

---

## Verdict summary (single pass)

| # | Question | Verdict | Severity |
|---|---|---|---|
| 1 | FRESH→PENDING twice (core guard) | PASS | — |
| 1/6 | Change address reuse after signing | **FAIL** | HIGH |
| 2 | Confirmation-depth enforcement (core guard) | PASS | — |
| 2 | `OnConfirmation` receive-vs-spend ambiguity | **FAIL (design)** | CRITICAL (integration risk) |
| 3 | Key zeroing correctness | PASS | — |
| 4 | AES-256-GCM nonce handling | PASS | — |
| 5 | Reorg edge case / 101-confirmation threshold | INFORMATIONAL | CRITICAL *if* reorg occurs post-destruction (see disposition) |
| 6 | Change-output enforcement (`SignP2QPKInput`) | **FAIL** | HIGH |

---

## Findings and dispositions

### Q1/Q6 — Change address never transitioned after use: CONFIRMED, FIXED

`SignTransaction` (stub) validated the change address was FRESH before
signing but never transitioned it afterward — it remained FRESH and could
be reused as change or receive address, producing a second SLH-DSA
signature under the same key. `SignP2QPKInput` (the actual production
P2QPK signing path) had **no enforcement at all**: no check that any
output routed to a wallet-controlled FRESH address, no post-sign
transition. A caller could route change to a PENDING, RETIRED, or
external address with zero guard.

**Fix applied (`b5e757d`):** `SignP2QPKInput` now verifies the change
output decodes to a wallet-known address in `FRESH` state before signing,
and transitions it to `PENDING` immediately after a successful sign
(never on failure). The same enforcement was added to the `SignTransaction`
stub for consistency. New tests: `TestSignP2QPKInputRejectsNonFreshChange`,
`TestSignP2QPKInputTransitionsChangeAfterSigning`.

This is the fix that makes the wallet's own design guarantee (SIP-QOGE-
PQC-01 §5.1, principle 6 — change always routes to a fresh address) an
enforced property of the production signing path rather than an
unenforced intention.

### Q2 — `OnConfirmation` receive-vs-spend ambiguity: CONFIRMED, RESOLVED VIA REDESIGN

The original `OnConfirmation` destroyed the private key once confirmations
reached the threshold, with nothing in the API distinguishing "this
confirmation count is for the transaction that PAID this address" from
"this confirmation count is for the transaction that SPENT this address."
Calling it at the wrong moment — e.g. on receive-confirmation instead of
spend-confirmation — would destroy the key before the address was ever
spent, permanently orphaning the funds.

**Resolved by design change, not a targeted patch:** `OnConfirmation` no
longer destroys any key. It only flags the address `SPENT` (via
`MarkSpent`), now gated at a minimal `confirmations >= 1` rather than the
101-block threshold — since flagging is reuse-prevention only and carries
no irreversible consequence, there is no reason to delay it. Key
destruction moved to an entirely separate, explicitly-named,
manually-invoked method (`PurgeSpentKey`) that is never called by any
wallet-internal logic. An integrator confusing receive- and
spend-confirmation now produces, at worst, an address flagged SPENT a
turn earlier than ideal — not fund loss.

### Q5 — Reorg-after-key-destruction / 101-confirmation appropriateness: RESOLVED VIA REDESIGN

**Original finding:** on a network where ~95-99% of hashrate is held by 3
cooperating miners, no confirmation-depth threshold provides real
protection against those miners choosing to reorg — 101 blocks (or any
number) offers no adversarial guarantee against a colluding majority,
though it comfortably covers ordinary accidental reorgs (realistically
1-3 blocks on this network; Grok Build's suggested 6-12 block margin for
non-adversarial safety). The CRITICAL consequence previously was that if a
spend reorged out *after* automatic key destruction, funds became
permanently and unrecoverably lost — no un-retire, no key resurrection.

**Disposition — the design change dissolves the fund-loss consequence
rather than trying to pick a better number.** Since key destruction is no
longer automatic or tied to any single transaction's confirmation count,
a reorg occurring after a `SPENT` flag (but before any *manual*
`PurgeSpentKey` call) simply leaves the key intact — the wallet retains
full ability to re-sign or recover as needed. The 101-confirmation floor
is retained, unchanged, but repurposed: it is now a conservative minimum
gate on the *optional* `PurgeSpentKey` action, not a countdown to
automatic, unavoidable destruction. Given manual invocation carries no
urgency, keeping the more conservative 101 rather than a shorter window
was judged the right choice — an integrator/user who purges is choosing
to accept that risk deliberately, at a time of their choosing, rather than
having it imposed by a timer.

**What remains true and unfixable by any wallet-side parameter:** 101
confirmations (or any depth) still provides no protection against the 3
cooperating miners choosing to reorg. This is a property of the network's
mining concentration, not something a confirmation threshold can address
— documented as such rather than treated as solvable.

### Q3, Q4 — Key zeroing, GCM nonce handling: CONFIRMED SOUND, no action

Both PASS with only standard, inherent (not implementation-specific)
caveats — Go/CGo memory-retention limits and bbolt page-compaction
forensic exposure, neither of which are defects. No change made.

---

## Design change summary (commit `b5e757d`)

The redesign, beyond fixing the two specific findings above, restructures
the address lifecycle around a general principle: **automatic actions
must be reversible; irreversible actions must be manual.**

| Action | Trigger | Reversible? |
|---|---|---|
| `OnConfirmation` (flag SPENT) | Automatic, ≥1 confirmation | Yes — key intact, no consequence if reorged |
| `PurgeSpentKey` (destroy key) | Manual only, ≥101 confirmations | **No** — explicit, deliberate, integrator's/user's responsibility |
| `ListPurgeEligibleAddresses` | Manual query | N/A — advisory scan only, purges nothing |

`MarkSpentAndRetire` (the atomic Audit-5 fix) remains available in
`keystore.go` unchanged, for any caller who explicitly wants combined
flag+destroy in one call — it is simply no longer invoked automatically.

New CLI options in `cmd/main.go` (7 total) separate the reversible
"confirm" action from the explicitly-labeled-irreversible "purge" action,
with a third option to list purge-eligible addresses as a recommendation
surface — nothing is auto-purged.

**Test coverage:** 75/75 (up from 63/63 pre-fix) — 6 new tests covering
flag-without-destroy behavior, purge preconditions (state + confirmation
floor), eligibility-list filtering, and change-address enforcement
(rejection when non-fresh, transition after successful signing).

---

## Summary of dispositions

| Finding | Disposition |
|---|---|
| Change address reused after signing (Q1/Q6) | **FIXED** — enforced in `SignP2QPKInput` and `SignTransaction` |
| `OnConfirmation` receive/spend ambiguity (Q2) | **RESOLVED** — key destruction removed from this path entirely |
| Reorg-after-destruction fund loss (Q5) | **RESOLVED** — destruction no longer automatic or transaction-tied |
| 101 confirmations vs. 3-miner collusion (Q5) | **DOCUMENTED, not fixable by threshold** — mining-topology limitation, not a wallet defect |
| Key zeroing (Q3) | No action — sound |
| GCM nonces (Q4) | No action — sound |

**Audit 4 overall: no bottleneck for Phase F or current testnet. The
redesign meaningfully reduces fund-loss risk surface ahead of mainnet.
Recommended before mainnet: a second independent audit pass on the
redesigned `SignP2QPKInput`/`PurgeSpentKey`/`ListPurgeEligibleAddresses`
code, consistent with the multi-model cross-validation applied to Audits
1-3.**

---

*Single-pass audit artifact for SIP-QOGE-PQC-01, Symbiont Wallet. Part of
the pre-mainnet review series alongside Audits 1, 2, 3, and 5. Unlike
those, this audit's remediation was a structural redesign rather than a
targeted patch — recorded here for future sessions to understand why the
lifecycle model changed, not just that it did.*
