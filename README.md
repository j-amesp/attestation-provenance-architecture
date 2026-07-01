# APA reference implementation — classification profile

A running reference for the Attested Provenance Architecture. This is a
demonstration of the architecture's claims with **real** cryptography and
protocol flows — not a hardened product, but no longer a set of stubs.

## What is now REAL (previously seams)

| Component | Status |
|-----------|--------|
| Manifest signing | **Real PQC.** Ed25519, ML-DSA-65 (FIPS 204, `dilithium-py`), SLH-DSA-SHA2-128s (FIPS 205, `pyspx`). The demo signs manifests with the **hash-based archival profile**. |
| Attestation | **Real RATS flow** (RFC 9334): signed evidence → verifier appraisal against a real engine-code measurement → signed attestation result consumed by the PDP. Tampering the engine flips the appraisal to *contraindicated*. |
| Ontology | **Real signed, versioned, freshness-checked artifact** — verified before use. |
| Revocation | **Real signed snapshot** with `as_of` staleness bound — verified before use; a revoked authority is denied. |
| STANAG 4778 profile | **Real W3C XML-DSIG** (`signxml`) over a STANAG 4774-style label, bound to the object digest. Second binding profile alongside COSE/CBOR. |

## The one seam that cannot be closed here

**The attestation root of trust is software.** A production Attester roots its
evidence in a hardware TEE/TPM quote; this environment has no TEE, so the
Attester holds a software key. The *flow, signatures, freshness and
reference-value match are real* — only the hardware anchor is modelled. This is
labelled in `attestation.py`, not hidden. Likewise, the ontology is signed and
verified but not *governed*: agreeing the cross-national mapping is the §10
research/policy problem, which no code can close.

## Files

| File | Role |
|------|------|
| `apm-classification.cddl` | CDDL schema (RFC 8610), COSE/CBOR binding profile |
| `crypto.py` | Canonical CBOR, hashing, three real signature algorithms |
| `attestation.py` | RATS-style evidence / verifier / attestation result |
| `trust.py` | Signed ontology + signed revocation snapshot |
| `apm.py` | Manifest build/sign/verify, Merkle binding, selective disclosure, lineage, declared-transition state machine, point-of-use PDP |
| `apm_xmldsig.py` | STANAG 4778 XML-DSIG binding profile (real W3C signature) |
| `demo.py` | 12-step end-to-end walkthrough |

## Run

```bash
pip install cbor2 cryptography dilithium-py pyspx signxml lxml
python3 demo.py
```

## What the demo proves (each step maps to a section)

0. **Attestation** — engine measured, verifier affirms integrity (§7.2).
1. **Create** — manifest signed with real SLH-DSA (7856-byte signature) (§5, §6.2).
2. **Permit** — cleared, in-coalition analyst on an attested engine (§8).
3. **Releasability** — higher-cleared but out-of-coalition subject denied (§10).
4. **Selective disclosure** — `ai-lineage` withheld, signature still valid (§7.5, §13.1).
5. **Transform** — excerpt yields a child manifest; classification propagates (§9.2).
6. **Cross-domain** — release to an ITA partner via signed ontology equivalence (§10, §13.4).
7. **Tamper** — one flipped byte breaks the hard binding → fail-closed (§3, §5).
8. **Revocation** — revoked signing authority → deny (§11).
9. **Disconnected declassification** — resolves to UNCLASSIFIED offline against attested time (§9.2, §12).
10. **Staleness** — offline trust material past its bound → fail-closed (§12).
11. **Tampered engine** — attestation contraindicated → fail-closed (§7.2, §13.3).
12. **STANAG 4778 profile** — real XML-DSIG label verified; tamper breaks the binding (§6.1).

## Honest limits that remain by design

- **Hardware attestation root** — modelled, not real (needs a TEE).
- **Ontology governance** — signed, not agreed (§10).
- **Aggregation** — emergent transitions out of scope (§9.3).
- **Selective-disclosure scheme** — salted-hash SD has known linkability subtleties at scale; treat as illustrative.
- **Merkle construction** — deliberately simple; pin to a spec (e.g. RFC 6962) for production sub-object addressing.
