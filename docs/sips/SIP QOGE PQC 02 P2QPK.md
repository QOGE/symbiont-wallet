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

`SLHDSA_PK_LEN = 32`, `SLHDSA_SIG_MAX_LEN = 17088`. This is **illustrative
pseudocode for Phase D**, not ready to apply — `SignatureHashP2QPK` depends
on SIP-QOGE-PQC-02a Phase C being resolved first, and the liboqs call
signature needs checking against the actual liboqs C API
(`OQS_SIG_slh_dsa_pure_sha2_128f_verify` or via the generic `OQS_SIG` struct
— Phase B used pkg-config/linking only, didn't touch call sites).

### 3.4 Activation

BIP9-style version-bits deployment, analogous to `DEPLOYMENT_TAPROOT` in
`consensus/params.h`. New deployment name `DEPLOYMENT_P2QPK`, new flag
`SCRIPT_VERIFY_P2QPK` in `script/interpreter.h`'s flags enum. Bit number and
start/timeout heights: **governance decisions, not cryptographic ones** — do
not pick these unilaterally; flag for SAOGEN governance when reached.

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
| B | liboqs integration into Qogecoin Core build | ✅ DONE — Option B (pkg-config, dev-only); Option A (`depends/packages/liboqs.mk`, CMake) deferred to Phase F+, see CLAUDE.md and §7-C |
| C | Sighash sub-spec review (SIP-QOGE-PQC-02a open items) | ✅ DONE — all open items resolved; P2QPKSighash `8a17f83e...` independently reviewed (GPT-5.5, PASS); Phase D safeguards A-E folded into spec as §7 |
| D | Consensus implementation (§3.3 branch + `SignatureHashP2QPK`) | 🔄 IN PROGRESS — step 1 complete: `SignatureHashP2QPK` implemented and test vector `8a17f83e...` reproduced in C++ (`2a4c85a`, local); `VerifyWitnessProgram` witver==2 branch is next step |
| E | Regtest functional testing | ⏳ Pending |
| F | Public testnet | ⏳ Pending |

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

Line numbers verified 14 June 2026 against the shallow clone at `~/qogecoin`.
**Re-verify before Phase D** — lines drift as the tree changes (Phase B
already added ~18 lines to `configure.ac`/`Makefile.am`, unrelated files but
a reminder that line numbers aren't permanent).
