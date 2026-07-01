"""
Attested Provenance Architecture (APA) — core library, classification profile.

Now wired to REAL components:
  - real PQC signing (crypto.py: Ed25519 / ML-DSA-65 / SLH-DSA-128s)
  - real RATS-style attestation result as an input to the PDP (attestation.py)
  - real signed, freshness-checked ontology + revocation (trust.py)

Still honestly limited: attestation is software-rooted (no TEE here), and the
ontology mapping is signed but not governed (§10). Aggregation is out of scope
by design (§9.3).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import cbor2

from crypto import Signer, cc, sha256, verify_sig
from attestation import verify_result
from trust import open_ontology, open_revocation

LEVELS = ["UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP-SECRET"]
LEVEL_RANK = {n: i for i, n in enumerate(LEVELS)}
CLS = "urn:apa:attr:classification"
LEAF = 4096


# --- hard binding (Merkle) -------------------------------------------------
def merkle_root(data: bytes) -> tuple[bytes, int]:
    leaves = [sha256(data[i:i + LEAF]) for i in range(0, max(len(data), 1), LEAF)] or [sha256(b"")]
    n, level = len(leaves), leaves
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], n


def hard_binding(data: bytes) -> dict:
    root, n = merkle_root(data)
    return {"alg": "sha-256", "root": root, "n": n}


def hard_binding_ok(data: bytes, hb: dict) -> bool:
    return merkle_root(data)[0] == hb["root"]


# --- attributes + selective disclosure ------------------------------------
def make_attribute(type_uri: str, val: Any, auth: str, asr: int,
                   validity: dict | None = None) -> dict:
    a = {"type": type_uri, "val": val, "auth": auth, "asr": asr}
    if validity:
        a["validity"] = validity
    return a


def _commit(attr: dict) -> tuple[bytes, dict]:
    salt = os.urandom(16)
    return sha256(salt + cc(attr)), {"salt": salt, "attr": attr}


# --- manifest build / sign / verify ---------------------------------------
def build_core(object_bytes: bytes, attributes: list[dict], lineage: dict,
               fresh: dict, soft: list[dict] | None = None):
    commitments, openings = [], []
    for a in attributes:
        c, o = _commit(a)
        commitments.append(c)
        openings.append(o)
    commitments.sort()
    obj = {"hard": hard_binding(object_bytes)}
    if soft:
        obj["soft"] = soft
    return {"v": 1, "obj": obj, "attr": commitments, "lin": lineage, "fresh": fresh}, openings


def sign_manifest(core: dict, openings: list[dict], signer: Signer) -> dict:
    cb = cc(core)
    return {"core": cb, "sig": {"alg": signer.alg, "kid": signer.kid, "val": signer.sign(cb)},
            "disc": openings}


def manifest_id(env: dict) -> bytes:
    return sha256(env["core"])


def disclose(env: dict, entitled_types: set[str]) -> dict:
    kept = [o for o in env.get("disc", []) if o["attr"]["type"] in entitled_types]
    return {"core": env["core"], "sig": env["sig"], "disc": kept}


# --- context / subject / decision -----------------------------------------
@dataclass
class TrustContext:
    authorities: dict                      # kid -> (alg, pub)  attribute authorities
    verifier: tuple                        # (alg, pub) trusted attestation verifier
    expected_engine: str
    ontology_env: dict
    ontology_auth: tuple
    revocation_env: dict
    revocation_auth: tuple
    now: int
    max_attestation_age_s: int = 300


@dataclass
class Subject:
    name: str
    clearance: str
    coalitions: set
    entitled_types: set

    def nation(self) -> str:
        return self.name.split(":")[0]


@dataclass
class Decision:
    permit: bool
    reason: str
    effective_level: str | None = None
    obligations: list = field(default_factory=list)


# --- declared-transition state machine (§9.2) -----------------------------
def effective_classification(val: dict, validity: dict | None, now: int) -> dict:
    if validity and "downgrade" in validity and now >= validity["downgrade"]["at"]:
        return {"policy": val["policy"], "level": validity["downgrade"]["to"]}
    return dict(val)


# --- point-of-use PDP (§8) -------------------------------------------------
def evaluate(object_bytes: bytes, env: dict, subject: Subject,
             tc: TrustContext, attestation_result: dict) -> Decision:
    core = cbor2.loads(env["core"])
    stale_bound = core["fresh"]["stale_bound_s"]

    # (0) Attestation of the point-of-use engine (§7.2, §13.3).
    ok, status, reason = verify_result(
        attestation_result, tc.verifier, tc.now, tc.expected_engine, tc.max_attestation_age_s)
    if not ok:
        return Decision(False, f"attestation {status}: {reason} -> fail-closed")

    # (1) Authenticity by a trusted authority (§8, §13.2).
    sig = env["sig"]
    auth = tc.authorities.get(sig["kid"])
    if auth is None or sig["alg"] != auth[0] or not verify_sig(auth[0], auth[1], env["core"], sig["val"]):
        return Decision(False, "signature untrusted or invalid -> fail-closed")

    # (2) Revocation: verified snapshot, freshness-bounded, authority not revoked (§11, §12).
    try:
        revoked, _ = open_revocation(tc.revocation_env, tc.revocation_auth, tc.now, stale_bound)
    except ValueError as e:
        return Decision(False, f"revocation unusable ({e}) -> fail-closed")
    if sig["kid"] in revoked:
        return Decision(False, f"signing authority '{sig['kid']}' revoked -> deny")

    # (3) Integrity (§5, §3).
    if not hard_binding_ok(object_bytes, core["obj"]["hard"]):
        return Decision(False, "hard binding broken (object altered) -> fail-closed")

    # (4) Resolve disclosed attributes (§7.5).
    signed = set(core["attr"])
    resolved = {o["attr"]["type"]: o["attr"]
                for o in env.get("disc", []) if sha256(o["salt"] + cc(o["attr"])) in signed}

    cls = resolved.get(CLS)
    if cls is None:
        return Decision(False, "no resolvable classification -> fail-closed")
    eff = effective_classification(cls["val"], cls.get("validity"), tc.now)

    # (5) Federated releasability via verified, fresh ontology (§10).
    rel = eff.get("rel", [])
    if rel:
        try:
            ont, _ = open_ontology(tc.ontology_env, tc.ontology_auth, tc.now, stale_bound)
        except ValueError as e:
            return Decision(False, f"ontology unusable ({e}) -> fail-closed", effective_level=eff["level"])
        # subject satisfies required token r if it holds r directly, or holds a
        # national token t that the signed ontology maps to r (federation, §10)
        released = any(
            r in subject.coalitions
            or any(ont.get(f"{subject.nation()}|{t}") == r for t in subject.coalitions)
            for r in rel)
        if not released:
            return Decision(False, f"not releasable to subject (rel={rel}) -> deny", effective_level=eff["level"])

    # (6) Clearance dominance.
    if LEVEL_RANK[subject.clearance] < LEVEL_RANK[eff["level"]]:
        return Decision(False, f"clearance {subject.clearance} < {eff['level']} -> deny", effective_level=eff["level"])

    obligations = [f"noted:{t.split(':')[-1]}" for t in resolved if t != CLS]
    return Decision(True, "permit", effective_level=eff["level"], obligations=obligations)


# --- transformation / lineage (§9.2) --------------------------------------
def transform(parent_env: dict, new_object: bytes, action: str, signer: Signer,
              now: int, stale_bound_s: int) -> dict:
    carried = [o["attr"] for o in parent_env.get("disc", [])]
    core, openings = build_core(
        new_object, carried,
        lineage={"parents": [manifest_id(parent_env)], "action": action},
        fresh={"ts": now, "stale_bound_s": stale_bound_s})
    return sign_manifest(core, openings, signer)
