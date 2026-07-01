"""
RATS-style attestation (RFC 9334), software-modelled.

Roles are faithful to the RATS architecture:
  Attester      -> produces signed Evidence about the policy-engine it runs
  Verifier      -> appraises Evidence against a Reference Value, emits a signed
                   Attestation Result
  Relying Party -> the PDP (apm.evaluate) consumes the Attestation Result

What is REAL here: the signatures over evidence and results, the nonce for
freshness, and the reference-value match. The "measurement" is a real SHA-256
over the engine's code image, so tampering the engine actually flips the
appraisal to 'contraindicated'.

What is NOT real: the root of trust. A production Attester roots its evidence
in a hardware TEE/TPM quote; here the Attester simply holds a software key.
This is the one seam that cannot be closed without hardware — labelled, not
hidden (§7.2).
"""
from __future__ import annotations

from dataclasses import dataclass

from crypto import Signer, cc, sha256, verify_sig
import cbor2


def make_evidence(engine_image: bytes, engine_id: str, ak: Signer,
                  nonce: bytes, ts: int) -> dict:
    """Attester: measure the engine image and sign the evidence."""
    payload = {"engine_id": engine_id, "measurement": sha256(engine_image),
               "nonce": nonce, "ts": ts}
    pb = cc(payload)
    return {"payload": pb, "alg": ak.alg, "kid": ak.kid, "sig": ak.sign(pb)}


@dataclass
class Verifier:
    signer: Signer                          # the verifier's own signing key
    trusted_ak: dict                        # kid -> (alg, pub) of trusted Attesters
    reference_measurement: bytes            # known-good engine hash
    verifier_id: str

    def appraise(self, evidence: dict, expected_nonce: bytes, now: int,
                 max_skew_s: int = 300) -> dict:
        p = cbor2.loads(evidence["payload"])
        ak = self.trusted_ak.get(evidence["kid"])
        measurement_ok = False
        status = "contraindicated"
        if (ak and evidence["alg"] == ak[0]
                and verify_sig(ak[0], ak[1], evidence["payload"], evidence["sig"])
                and p["nonce"] == expected_nonce
                and abs(now - p["ts"]) <= max_skew_s):
            measurement_ok = (p["measurement"] == self.reference_measurement)
            status = "affirming" if measurement_ok else "contraindicated"
        result = {"engine_id": p["engine_id"], "status": status,
                  "measurement_ok": measurement_ok, "ts": now,
                  "verifier_id": self.verifier_id}
        rb = cc(result)
        return {"payload": rb, "alg": self.signer.alg, "kid": self.signer.kid,
                "sig": self.signer.sign(rb)}


def verify_result(ar: dict, trusted_verifier: tuple, now: int,
                  expected_engine: str, max_age_s: int) -> tuple[bool, str, str]:
    """Relying-Party check of an Attestation Result. Returns (ok, status, reason)."""
    alg, pub = trusted_verifier
    if ar["alg"] != alg or not verify_sig(alg, pub, ar["payload"], ar["sig"]):
        return False, "invalid", "attestation result not signed by trusted verifier"
    p = cbor2.loads(ar["payload"])
    if p["status"] != "affirming":
        return False, p["status"], "verifier did not affirm engine integrity"
    if p["engine_id"] != expected_engine:
        return False, p["status"], f"unexpected engine '{p['engine_id']}'"
    if now - p["ts"] > max_age_s:
        return False, p["status"], "attestation result stale"
    return True, "affirming", "engine attested"
