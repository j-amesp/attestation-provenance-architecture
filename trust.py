"""
Signed trust artifacts: the federated ontology and the revocation snapshot.

These were dicts in the first cut. Now they are real signed, versioned, dated
objects that the PDP VERIFIES and freshness-checks before use. The signature
and staleness handling are real; the hard part the architecture names in §10 —
governing and agreeing the ontology across nations — is not something code can
close, and isn't claimed to be.
"""
from __future__ import annotations

import cbor2
from crypto import Signer, cc, verify_sig


# --- Federated ontology (§10) ---------------------------------------------
def build_ontology(entries: dict[str, str], as_of: int, signer: Signer) -> dict:
    """entries: 'NATION|TOKEN' -> local releasability token."""
    payload = cc({"v": 1, "as_of": as_of, "entries": entries})
    return {"payload": payload, "alg": signer.alg, "kid": signer.kid,
            "sig": signer.sign(payload)}


def open_ontology(env: dict, authority: tuple, now: int, max_age_s: int):
    """Verify signature + freshness; return (entries, as_of). Raises on failure."""
    alg, pub = authority
    if env["alg"] != alg or not verify_sig(alg, pub, env["payload"], env["sig"]):
        raise ValueError("ontology signature invalid")
    p = cbor2.loads(env["payload"])
    if now - p["as_of"] > max_age_s:
        raise ValueError("ontology stale beyond bound")
    return p["entries"], p["as_of"]


# --- Revocation snapshot (§11, §12) ---------------------------------------
def build_revocation(revoked: list[str], as_of: int, signer: Signer) -> dict:
    payload = cc({"as_of": as_of, "revoked": sorted(revoked)})
    return {"payload": payload, "alg": signer.alg, "kid": signer.kid,
            "sig": signer.sign(payload)}


def open_revocation(env: dict, authority: tuple, now: int, max_age_s: int):
    """Verify signature + freshness; return (revoked_set, as_of). Raises on failure."""
    alg, pub = authority
    if env["alg"] != alg or not verify_sig(alg, pub, env["payload"], env["sig"]):
        raise ValueError("revocation signature invalid")
    p = cbor2.loads(env["payload"])
    if now - p["as_of"] > max_age_s:
        raise ValueError("revocation data stale beyond bound")
    return set(p["revoked"]), p["as_of"]
