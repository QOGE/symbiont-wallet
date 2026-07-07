# Audit 3 (liboqs Integration) — Multi-Model Triage Summary

**Component:** liboqs integration across the C++ node (`QOGE/qogecoin`) and
the Go wallet (`QOGE/symbiont-wallet`) — algorithm identifiers, key/signature
size constants, randomness source, static/dynamic linking, and version
pinning.

**Auditors (six independent passes):**
- OpenAI Codex — remote (GitHub-fetched), 6 July 2026
- OpenAI Codex — local (direct filesystem access, dev VM), 6 July 2026
- Grok Build (xAI, `grok-build-0.1`) — local (direct filesystem access, dev VM), 6 July 2026
- Claude Opus 4.8 (Anthropic) — remote (cloned + hash-verified liboqs tarball, did not compile), 6 July 2026
- ChatGPT 5.5 (OpenAI) — remote (source-only, did not compile), 6 July 2026
- Claude Code (local, direct filesystem, dev VM) — used to resolve two disputed claims, 6 July 2026

**Reviewed commits:** `QOGE/qogecoin@111c05fb` (`stable`), `QOGE/symbiont-wallet@10c6c1fa` (`main`), liboqs `0.15.0` (sha256 `3983f7cd...84b5c`, independently downloaded and hash-verified by Opus).

**Methodology note:** this audit surfaced a genuine methodological lesson,
recorded here explicitly because it should inform how future audit
disagreements are resolved. Two passes (Opus, ChatGPT) worked from cloned
source only, without compiling or executing anything. Two passes (Codex
local, Grok Build) had direct filesystem access to an already-built VM and
could run empirical checks (`ldd`, `readelf`, live `go test`) against real
binaries. When a build-configuration claim was disputed between these
groups (see Q4 below), the empirically-verified local passes were treated
as authoritative over the source-only inference — correctly, as the
resolution confirmed.

---

## Headline result

**No critical, fund-loss-today, or consensus-split bug found in the liboqs
integration itself.** The algorithm identifiers, size constants, and
production linking design are all sound and unanimously confirmed across
six independent passes. The one already-known critical issue (M1.3,
non-deterministic keygen) had its severity confirmed unanimously and its
remediation path substantially clarified — this audit did real, valuable
work on a known problem rather than merely re-flagging it.

**No finding in Audit 3 blocks Phase F or public testnet.** Two findings
(M1.3 remediation scope, testnet liboqs version) should be resolved before
mainnet activation.

---

## Verdict matrix

| # | Question | Remote Codex | Local Codex | Grok Build | Opus 4.8 | ChatGPT 5.5 |
|---|---|---|---|---|---|---|
| 1 | Algorithm identifier consistency | PASS | PASS | PASS | PASS | PASS |
| 2 | Size constants (32/64/17088) | PASS* | PASS* | PASS* | PASS* | PASS* |
| 3 | Randomness source (master seed) | — | — | PASS | PASS | PASS |
| 3 | M1.3 deterministic keygen | FAIL, "not minor" | FAIL, HIGH | FAIL, HIGH | **FAIL, CRITICAL** | FAIL, HIGH/CRITICAL |
| 3b | liboqs seeded SIG keygen exists? | — | — | NO (confirmed) | NO (confirmed, w/ FIPS 205 Alg 21 detail) | NO (confirmed) |
| 4 | Static linking used in production | PASS | PASS (empirical: `ldd`/`readelf`) | PASS | **DISPUTED — claimed Option B is committed** | PASS (source-only, cautious framing) |
| 5 | Version pin mechanism | PASS | PASS | PASS | PASS (hash independently re-verified) | PASS |
| 5b | 0.15.0 vs 0.16.0-rc1 testnet skew | WARN | RISK | LOW-MEDIUM RISK | Low but avoidable | WARN, reproducibility gap |

*\* All five passes that reached Q2 independently flagged the same wallet test-gap: `slhdsa_test.go` checks `len(sig) > SignatureSize` / `<= 17088` rather than exact equality.*

---

## Triage dispositions

### Q1 — Algorithm identifier consistency: RESOLVED, no action needed

Unanimous PASS across all five substantive passes. `SLH_DSA_PURE_SHA2_128F`
(wallet) and `OQS_SIG_slh_dsa_pure_sha2_128f_*` (node) resolve to the
identical liboqs algorithm table entry. Opus additionally confirmed via
direct source inspection that liboqs 0.15.0 uses the underscore FIPS-style
string (not a hyphenated one), correcting an initial assumption mid-audit
— a good example of the audit process self-correcting before finalizing.

### Q2 — Size constants: CONFIRMED CORRECT, ONE TEST FIX NEEDED

All five passes confirm 32/64/17088 match across wallet, node, and live
liboqs headers. **Unanimous test-gap finding:** the wallet's own signature
test checks an inequality (`>` or `<=`) rather than exact equality, weaker
than the node's actual consensus-layer rule (`!=`, exact).

**Disposition: FIX QUEUED.** Tighten `signer/slhdsa_test.go` to assert
`len(sig) == SignatureSize` exactly, matching consensus enforcement.

### Q3 — M1.3 (non-deterministic keygen): CONFIRMED CRITICAL, REMEDIATION PATH NOW CLARIFIED

All five passes that reached this question independently confirm M1.3 is
still open and rate it HIGH or CRITICAL severity — a "users WILL lose
funds" issue, not a minor inconvenience, under the realistic scenario of
seed-only backup + lost/corrupted database.

**New, valuable output from this audit round — the fix is now scoped
concretely, corroborated across three independent passes (Grok Build,
Opus, ChatGPT):**

liboqs 0.15.0's SIG API (`sig.h`, `sig_slh_dsa.h`) has **zero** seeded or
derandomized keygen entry points — confirmed by direct grep of the header
tree by two passes independently, and confirmed against liboqs's KEM API
(which *does* have `keypair_derand`) as the contrasting proof that this
capability was deliberately scoped to KEM only, not omitted by oversight.

Opus additionally traced the actual FIPS 205 Algorithm 21 keygen
implementation inside liboqs and identified the exact randomness draw: a
single 48-byte call (`3n` bytes, `n=16`) in fixed order `SK.seed ‖ SK.prf ‖
PK.seed`.

**Proposed remediation (Opus, not yet implemented or reviewed for
correctness beyond this audit — treat as a serious candidate, not a
finalized plan):** use liboqs's `OQS_randombytes_custom_algorithm()` global
RNG hook to install a deterministic HKDF-derived 48-byte generator
immediately before calling `GenerateKeyPair()`, then restore the default
RNG. Constraints identified: the RNG hook is global process state and
requires a package-level mutex to prevent cross-goroutine key corruption;
requires confirming the liboqs-go binding actually exposes this hook
(**confirmed clean/unmodified from upstream in this session, so the hook's
presence can be checked directly against public upstream source**); and
requires a fixed `seed → pubkey` test vector to guard against a future
liboqs version silently changing derivation.

**Disposition: OPEN, remediation path scoped, NOT a Phase F/testnet
blocker. Recommend its own dedicated implementation session** — this is
real engineering work (RNG hook, mutex, HKDF derivation, test vectors), not
a quick patch, and deserves the same careful, one-thing-at-a-time treatment
already applied to the mempool policy fix in Audit 2.

**Interim mitigation (do now, cheap):** the existing backup warnings
(`2695e38`, plus the Audit 3 Fix 2 already queued re: stale-backup
scenarios) remain the correct stopgap until M1.3 is actually resolved.

### Q4 — Static vs dynamic linking: RESOLVED via empirical evidence, no code fix needed

**This question surfaced a direct three-way disagreement, now resolved.**

Opus (working from cloned source only, did not compile) asserted "the
committed integration is Option B," citing a `README.md` passage describing
`PKG_CHECK_MODULES`. This directly conflicted with **local Codex's**
empirical finding — `ldd`/`readelf` run against the actual compiled
`qogecoind` binary in this VM, confirming **no `liboqs.so` runtime
dependency exists**, i.e. genuine static linking. ChatGPT (also source-only,
also did not compile) took a more cautious middle position ("PASS for
Option A, WARN/FAIL if Option B used"), not asserting Option B was the
actual committed state.

**Resolution:** the two passes with direct execution/filesystem evidence
(Codex local, and Grok Build's independent confirmation of the same
Option A configure logic) are authoritative here over source-only
inference. The actual built binary in this development environment is
confirmed statically linked via Option A. Opus's claim is best explained
as reading an incomplete or stale README passage rather than reflecting
the actual build outcome once the depends step is run.

**What remains legitimately open (all five passes that reached this
question agree on this part):** `configure.ac` selects Option A vs B by
mere file-presence with no fail-closed guard — a fresh clone that skipped
the `depends` build step would silently fall through to Option B with no
warning.

**Disposition: DOCUMENTATION/PROCESS FIX, not urgent.** Add a pre-mainnet
release checklist item: distribution/mainnet builds must assert
`configure` output explicitly reports "Option A — static lib" before
shipping any binary; consider a hard `configure` failure if the static
archive is absent, rather than a silent fallback. Not a Phase F blocker.

### Q5 — Version pinning mechanism: CONFIRMED SOUND

Unanimous PASS. `depends/packages/liboqs.mk` pins `0.15.0` with a sha256
hash; the depends build framework enforces this at fetch/extract time —
confirmed as a real, build-breaking check (not documentation) by multiple
passes, and Opus independently re-downloaded the live tarball and
confirmed the hash matches byte-for-byte.

**One supply-chain nuance from Opus, worth recording:** the pin targets a
GitHub auto-generated archive tarball rather than a maintainer-uploaded
release asset; GitHub has regenerated such archives before industry-wide.
Low current risk, worth knowing.

### Q5b — 0.15.0 vs 0.16.0-rc1 testnet/production discrepancy: CONFIRMED, LOW-MEDIUM RISK, FIX QUEUED

All five passes agree: this is a real reproducibility gap, not an emergency.
SLH-DSA verification is fully specified and randomness-free, so two
*correct* implementations must agree — the risk is specifically an
implementation bug or behavioral difference existing in one version and
not the other, which is inherently more likely between a tagged release
(0.15.0) and a release candidate (0.16.0-rc1) than between two releases.

**Disposition: FIX QUEUED, not urgent, not a Phase F blocker.** Rebuild the
public testnet node against the same pinned Option A liboqs 0.15.0 used
elsewhere in the project. Before mainnet, run an explicit cross-version
verification corpus (valid signature, tampered signature, tampered
message, tampered pubkey, boundary-length signatures) against both liboqs
versions to positively confirm no divergence, rather than relying on
FIPS 205's specification alone.

### Additional finding — liboqs-go binding provenance: RESOLVED, minor process gap

Opus raised a methodologically important concern: `symbiont-wallet`'s
`go.mod` points its liboqs-go dependency at a local filesystem path
(`/home/ion/liboqs-go`) via an unpinned `replace` directive, meaning the
actual CGo binding code lives outside the audited repository.

**Verified via direct inspection (Claude Code):** the local fork is
**clean and unmodified from upstream** `open-quantum-safe/liboqs-go`
(confirmed via `git remote -v`, `git log`, `git status`/`git diff` — no
local changes). This means every wallet-side crypto claim across all six
audit passes rests on stock, unaltered binding code, not a hidden fork —
the reassuring half of the finding.

**What remains open:** the reference is a shallow, unpinned clone (HEAD
`75451133`, no commit hash recorded anywhere in `go.mod`/`go.sum`). A
future `go mod tidy` or re-clone could silently pull a newer upstream
commit with zero visible diff.

**Disposition: FIX QUEUED, low urgency.** Either vendor the liboqs-go
dependency, or pin the `replace` directive to a specific commit hash /
proper Go pseudo-version rather than a bare local path, so the binding
layer has an immutable, auditable reference.

### Bonus findings (Opus) — minor, queued

- **Stale "stubbed" comments** in `interpreter.h` (lines ~147, ~274) claim
  the SLH-DSA verifier is inert pending "Phase D step 4," contradicting the
  live, working verification path. Distinct from the comment already fixed
  in Audit 1 (which was in `interpreter.cpp`, not `.h`). **Fix queued.**
- **Hardening suggestion:** add `static_assert(SLHDSA_PK_LEN ==
  sizeof(uint256))` at the `memcmp` commitment-check site — currently safe
  only because both happen to be 32 bytes; the assert would catch this
  becoming unsafe if `SLHDSA_PK_LEN` ever changed. **Fix queued, cheap.**

---

## Summary of queued fixes (none blocking Phase F / current testnet)

| Fix | Priority | Effort |
|---|---|---|
| Exact-length signature test (`slhdsa_test.go`) | Medium | Trivial |
| M1.3 stale-backup warning strengthening | Medium | Trivial (already drafted) |
| M1.3 full remediation (RNG hook + mutex + HKDF + test vector) | High | Substantial — own session |
| Pre-mainnet checklist: assert Option A before shipping | Medium | Trivial (checklist item) |
| Rebuild testnet node on pinned liboqs 0.15.0 | Medium | VPS operational task |
| Cross-version (0.15.0 vs 0.16.0-rc1) verification corpus | Medium, pre-mainnet gate | Moderate |
| Pin/vendor liboqs-go binding reference | Low | Small |
| Fix stale comments in `interpreter.h` | Low | Trivial |
| Add `static_assert` on PK length | Low | Trivial |

**Audit 3 overall: no bottleneck for Phase F or current public testnet
operation. M1.3 full remediation and the testnet liboqs version alignment
are the two items worth resolving before mainnet activation.**

---

*Six-pass multi-model triage artifact for SIP-QOGE-PQC-01/02. Auditor
verdicts preserved verbatim in their original sections above; disputed
claims resolved via direct empirical verification rather than majority
vote, consistent with the methodology established in the Audit 2 triage.*
