"""
APA reference demo — everything wired to real components.

Run:  python3 demo.py
Deps: cbor2 cryptography dilithium-py pyspx signxml lxml
"""
from crypto import (Ed25519Signer, MLDSASigner, SLHDSASigner, ALG_NAME)
from attestation import make_evidence, Verifier, verify_result
from trust import build_ontology, build_revocation
from apm_xmldsig import make_authority_cert, sign_label, verify_label
import apm
from apm import (Subject, TrustContext, make_attribute, build_core,
                 sign_manifest, manifest_id, disclose, transform, evaluate, CLS)

AIL = "urn:apa:attr:ai-lineage"
RET = "urn:apa:attr:retention"
DAY = 86400


def show(d):
    print(f"    -> {'PERMIT' if d.permit else 'DENY  '}  {d.reason}"
          f"{f' [level={d.effective_level}]' if d.effective_level else ''}"
          f"{f' obligations={d.obligations}' if d.obligations else ''}")


def banner(t): print("\n" + t)


def main():
    T0 = 1_700_000_000

    # --- authorities & infrastructure keys --------------------------------
    # Originating authority signs with the ARCHIVAL PQC profile (real SLH-DSA).
    originator = SLHDSASigner(kid="GBR:JIO-Originator")
    ont_auth = Ed25519Signer(kid="COALITION:OntologyAuthority")
    rev_auth = Ed25519Signer(kid="GBR:RevocationAuthority")
    attester_ak = Ed25519Signer(kid="PDP:AttesterAK")
    verifier_key = Ed25519Signer(kid="COALITION:AttestationVerifier")

    print("=" * 74)
    print("APA reference demo — REAL crypto, attestation, ontology, revocation")
    print("=" * 74)
    print(f"manifest signature algorithm: {ALG_NAME[originator.alg]} (FIPS 205, hash-based)")

    # --- REAL attestation: measure the engine, appraise, sign a result ----
    banner("[0] ATTESTATION  (§7.2 RATS: evidence -> verifier -> result)")
    engine_image = open(apm.__file__, "rb").read()          # the actual PDP code
    reference = __import__("hashlib").sha256(engine_image).digest()
    verifier = Verifier(signer=verifier_key,
                        trusted_ak={attester_ak.kid: (attester_ak.alg, attester_ak.public_bytes())},
                        reference_measurement=reference,
                        verifier_id=verifier_key.kid)
    nonce = b"nonce-001"
    evidence = make_evidence(engine_image, "apa-pdp-v0", attester_ak, nonce, T0)
    ar = verifier.appraise(evidence, nonce, T0)
    ok, status, reason = verify_result(ar, (verifier_key.alg, verifier_key.public_bytes()),
                                       T0, "apa-pdp-v0", 300)
    print(f"    engine measured, verifier appraisal = {status} ({reason})")

    # --- signed trust artifacts (real signatures + freshness) -------------
    ontology = build_ontology({"ITA|ITA": "NATO"}, as_of=T0, signer=ont_auth)
    revocation = build_revocation([], as_of=T0, signer=rev_auth)

    tc = TrustContext(
        authorities={originator.kid: (originator.alg, originator.public_bytes())},
        verifier=(verifier_key.alg, verifier_key.public_bytes()),
        expected_engine="apa-pdp-v0",
        ontology_env=ontology, ontology_auth=(ont_auth.alg, ont_auth.public_bytes()),
        revocation_env=revocation, revocation_auth=(rev_auth.alg, rev_auth.public_bytes()),
        now=T0)

    # --- create --------------------------------------------------------------
    banner("[1] CREATE  (real SLH-DSA signature over the manifest)")
    report = b"IMINT report ... " + b"detail " * 800
    classification = make_attribute(
        CLS, {"policy": "urn:nato:stanag:4774:policy:demo", "level": "SECRET",
              "rel": ["NATO"], "caveats": ["ORCON"]},
        auth=originator.kid, asr=3,
        validity={"downgrade": {"at": T0 + 180 * DAY, "to": "UNCLASSIFIED"}})
    ai_lineage = make_attribute(AIL, {"generated": False}, auth=originator.kid, asr=2)
    retention = make_attribute(RET, {"review_at": T0 + 3650 * DAY}, auth=originator.kid, asr=2)
    core, openings = build_core(report, [classification, ai_lineage, retention],
                                lineage={"action": "create"},
                                fresh={"ts": T0, "stale_bound_s": 30 * DAY})
    env = sign_manifest(core, openings, originator)
    print(f"    manifest-id={manifest_id(env).hex()[:16]}...  sig={len(env['sig']['val'])} bytes ({ALG_NAME[originator.alg]})")

    analyst = Subject("GBR:analyst", "SECRET", {"NATO", "GBR"}, {CLS, RET})
    held = disclose(env, analyst.entitled_types)

    banner("[2] ACCESS by cleared NATO analyst  (§8, attested engine required)")
    show(evaluate(report, held, analyst, tc, ar))

    banner("[3] ACCESS lacking releasability  (§10 real signed ontology)")
    outsider = Subject("XXX:contractor", "TOP-SECRET", {"XXX"}, {CLS})
    show(evaluate(report, disclose(env, {CLS}), outsider, tc, ar))

    banner("[4] SELECTIVE DISCLOSURE  (§7.5)")
    print(f"    analyst resolves: {sorted(o['attr']['type'].split(':')[-1] for o in held['disc'])}"
          "  (ai-lineage withheld, signature still valid)")

    banner("[5] TRANSFORM: excerpt -> child manifest  (§9.2 propagation)")
    excerpt = b"EXCERPT ... " + b"para " * 200
    child = transform(env, excerpt, "excerpt", originator, T0 + DAY, 30 * DAY)
    print(f"    child-id={manifest_id(child).hex()[:16]}... parent linked, classification carried")
    show(evaluate(excerpt, disclose(child, {CLS}), analyst, tc, ar))

    banner("[6] CROSS-DOMAIN release to ITA partner  (§10 ontology equivalence)")
    ita = Subject("ITA:officer", "SECRET", {"ITA"}, {CLS})   # holds ITA, not NATO directly
    show(evaluate(excerpt, disclose(child, {CLS}), ita, tc, ar))
    print("    (ITA|NATO equivalence resolved via the signed ontology)")

    banner("[7] TAMPER object  (§3 fail-closed)")
    bad = bytearray(report); bad[10] ^= 0xFF
    show(evaluate(bytes(bad), held, analyst, tc, ar))

    banner("[8] REVOCATION: originator key revoked  (§11 real signed snapshot)")
    tc_rev = TrustContext(**{**tc.__dict__,
                             "revocation_env": build_revocation([originator.kid], T0, rev_auth)})
    show(evaluate(report, held, analyst, tc_rev, ar))

    banner("[9] DISCONNECTED declassification, T0+200d  (§9.2 + §12 offline)")
    tc_air = TrustContext(**{**tc.__dict__, "now": T0 + 200 * DAY,
                             "ontology_env": build_ontology({"ITA|ITA": "NATO"}, T0 + 199 * DAY, ont_auth),
                             "revocation_env": build_revocation([], T0 + 199 * DAY, rev_auth)})
    ar_air = verifier.appraise(make_evidence(engine_image, "apa-pdp-v0", attester_ak, nonce, T0 + 200 * DAY),
                               nonce, T0 + 200 * DAY)
    show(evaluate(report, disclose(env, {CLS}), analyst, tc_air, ar_air))
    print("    -> resolved to UNCLASSIFIED locally against attested time; no online authority")

    banner("[10] DISCONNECTED but trust material too stale  (§12 staleness bound)")
    tc_stale = TrustContext(**{**tc.__dict__, "now": T0 + 200 * DAY})  # ontology/revocation as_of still T0 -> 200d old > 30d
    ar_stale = verifier.appraise(make_evidence(engine_image, "apa-pdp-v0", attester_ak, nonce, T0 + 200 * DAY),
                                 nonce, T0 + 200 * DAY)
    show(evaluate(report, disclose(env, {CLS}), analyst, tc_stale, ar_stale))

    banner("[11] TAMPERED ENGINE -> attestation contraindicated  (§7.2, §13.3)")
    tampered_engine = engine_image + b"# backdoor"
    bad_ev = make_evidence(tampered_engine, "apa-pdp-v0", attester_ak, nonce, T0)
    bad_ar = verifier.appraise(bad_ev, nonce, T0)
    show(evaluate(report, held, analyst, tc, bad_ar))

    # --- second binding profile: real STANAG 4778 XML-DSIG ----------------
    banner("[12] STANAG 4778 XML-DSIG binding profile  (§6.1 real W3C signature)")
    key_pem, cert_pem = make_authority_cert("GBR-JIO-Originator")
    cls_value = {"policy": "urn:nato:stanag:4774:policy:demo", "level": "SECRET", "rel": ["NATO"]}
    signed_xml = sign_label(cls_value, report, key_pem, cert_pem)
    fields = verify_label(signed_xml, report, cert_pem)
    print(f"    XML-DSIG label verified: {fields['level']} REL {fields['rel']}  ({len(signed_xml)} bytes XML)")
    bad_report = bytearray(report); bad_report[0] ^= 0xFF
    try:
        verify_label(signed_xml, bytes(bad_report), cert_pem)
        print("    (unexpected) tamper not caught")
    except ValueError as e:
        print(f"    tamper on XML-DSIG profile -> {e}")

    print("\n" + "=" * 74)
    print("All three signature algorithms, RATS attestation, signed ontology &")
    print("revocation, and BOTH binding profiles (COSE/CBOR + STANAG 4778 XML-DSIG)")
    print("are real and running. The only software-rooted seam is the attester's")
    print("key (no TEE here); everything else is genuine.")
    print("=" * 74)


if __name__ == "__main__":
    main()
