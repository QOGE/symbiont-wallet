# On SLH-DSA Parameter Selection and the 2022 SPHINCS+ Forgery Attack

With Phase D consensus implementation now complete — the full P2QPK
verification path implemented and tested in `qogecoin/qogecoin`, with Phase E
(regtest) and public testnet ahead — we want to address a research paper that
has been circulating in post-quantum cryptography discussions: the 2022
Perlner-Kelsey-Cooper forgery attack on SPHINCS+. Several people have asked
whether this affects QOGE's post-quantum design.

The short answer is no. Here is the precise explanation.

---

## What the paper shows

In 2022, Ray Perlner, John Kelsey, and David Cooper (researchers at NIST)
published a complete forgery attack against SPHINCS+ at Category 5 security
parameters — specifically the `SPHINCS+-SHA-256-256f-simple` and
`SPHINCS+-SHA-256-256s-simple` parameter sets. The attack extends an earlier
observation by Sydney Antonov about the DM-SPR (distinct-function
multi-target second-preimage resistance) property of SHA-256.

The result: those specific parameter sets fail to meet their claimed ~256-bit
classical security, with the forgery attack costing approximately 2²¹⁷
operations rather than the claimed 2²⁵⁶. Still practically infeasible today,
but a real, formal failure of the claimed security level — not something to
dismiss.

The root cause is structural: SHA-256 is a Merkle-Damgård hash function, and
using it to achieve 256-bit security (Category 5) is fundamentally difficult.
The attack exploits properties of SHA-256's internal construction — diamond
structures, multi-target preimage attacks — that would not apply to a random
oracle. As the authors note, this is not a flaw in SPHINCS+'s overall
design philosophy; it is a flaw in applying SHA-256 to a security level it
cannot cleanly support.

---

## Why this does not affect Symbiont Wallet

Symbiont Wallet uses **SLH-DSA-SHA2-128f**, standardized as FIPS 205 by NIST.
Three independent reasons this attack does not apply:

**1. Wrong security category.**
SLH-DSA-SHA2-128f targets Category 1 — 128-bit classical security. The
Perlner-Kelsey-Cooper attack is specific to Category 5 (256-bit) SHA-256
parameter sets. At Category 1, SHA-256 is entirely appropriate for the
security level being claimed, and the mathematical premise of the attack
— that SHA-256 cannot cleanly provide 256-bit security — simply does not
arise. Our parameter set is not "a weaker version of the broken one"; it is
a different parameter set operating in the regime where SHA-256 is sound.

**2. The fix is already in the standard.**
Before FIPS 205 was finalized, NIST incorporated Andreas Hülsing's proposed
tweak: for Category 3 and Category 5 parameter sets, the Tℓ tweakable hash
function now uses SHA-512 instead of SHA-256. This blocks both Antonov's
original observation and the full Perlner-Kelsey-Cooper forgery extension,
since building the required diamond structure against SHA-512 requires at
least 2²⁵⁶ hash computations. Symbiont Wallet targets FIPS 205 via liboqs —
the post-fix, post-standardization implementation — not the pre-standardization
SPHINCS+ submission that contained the vulnerable parameter sets.

**3. We use liboqs, not a custom implementation.**
`liboqs` implements FIPS 205 as standardized, including all parameter-set
decisions made during the NIST process. The algorithm identifier we pin is
`SLH_DSA_PURE_SHA2_128F` — confirmed against the installed header
`/usr/local/include/oqs/sig.h` before any consensus code was written.
This is documented in `docs/sips/SIP-QOGE-PQC-02a.md` §7-B in the
repository, including the requirement that any production deployment verify
the liboqs build postdates the August 2022 SHA-512 tweak.

---

## What this means for QOGE's threat model

The HNDL (harvest-now-decrypt-later) threat that Symbiont Wallet is designed
to address is a CRQC running Shor's algorithm against secp256k1 keys — the
classical elliptic curve cryptography used in existing QOGE addresses. SLH-DSA
is the defence: its security rests entirely on the hardness of symmetric
cryptographic primitives (hash functions), with no algebraic structure for
Shor's algorithm to exploit.

The Perlner-Kelsey-Cooper attack is a classical attack on a specific SHA-256
parameter set, requiring an attacker to first collect ~2⁵⁸ legitimate
signatures from the same key. It has no quantum speedup that changes the
picture for QOGE's use case. It does not affect the single-use address model
(each Symbiont Wallet key signs exactly once, making large signature
collection impossible by construction), and it does not affect the parameter
set we use.

---

## Where to verify this yourself

Everything above is checkable in the public repository:

- **Parameter choice and rationale**: `docs/sips/SIP-QOGE-PQC-02a.md` §7-B
- **Algorithm identifier confirmation**: `signer/slhdsa.go`,
  `const AlgorithmName = "SLH_DSA_PURE_SHA2_128F"`
- **Independent review**: `docs/sips/QOGE_P2QPK_PQC_Independent_Review.md`
  — GPT-5.5 Thinking independently reviewed the sighash design and confirmed
  the parameter selection (20 June 2026)
- **The paper itself**: Perlner, Kelsey, Cooper — "Breaking Category Five
  SPHINCS+ with SHA-256", NIST, 2022

The repository is at **github.com/QOGE/symbiont-wallet**.

---

We raise this not because it represents a risk to QOGE, but because the
community deserves to know that these questions have been asked, checked, and
answered precisely — not assumed away. That is the standard we intend to
hold throughout this project.
