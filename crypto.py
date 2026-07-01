"""
APA crypto primitives — canonical encoding, hashing, and an algorithm-agile
signer/verifier with THREE real algorithms:

  Ed25519           (-8)   operational stand-in / infrastructure keys
  ML-DSA-65         (-49)  FIPS 204, operational PQC   (dilithium-py, pure Python)
  SLH-DSA-SHA2-128s (-60)  FIPS 205, ARCHIVAL PQC      (pyspx / SPHINCS+)

The archival profile is genuinely hash-based, not a classical fallback — the
deliberate divergence from commercial provenance (ML-DSA-only) is now real in
code, and you can see the ~7.8 KB SLH-DSA signature vs ~3.3 KB ML-DSA vs 64 B
Ed25519 as the size cost of longevity.

PQC code points (-49, -60) are provisional pending IANA COSE registration.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from dilithium_py.ml_dsa import ML_DSA_65
from pyspx import sha2_128s as _slh

ALG_EDDSA = -8
ALG_ML_DSA_65 = -49
ALG_SLH_DSA_128S = -60
ALG_NAME = {ALG_EDDSA: "Ed25519", ALG_ML_DSA_65: "ML-DSA-65",
            ALG_SLH_DSA_128S: "SLH-DSA-SHA2-128s"}


def cc(obj: Any) -> bytes:
    """Canonical CBOR (RFC 8949 core deterministic)."""
    return cbor2.dumps(obj, canonical=True)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


class Signer:
    alg: int
    kid: str
    def sign(self, msg: bytes) -> bytes: ...
    def public_bytes(self) -> bytes: ...


class Ed25519Signer(Signer):
    def __init__(self, kid: str, sk: Ed25519PrivateKey | None = None):
        self.alg, self.kid = ALG_EDDSA, kid
        self._sk = sk or Ed25519PrivateKey.generate()

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)

    def public_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class MLDSASigner(Signer):
    """FIPS 204 ML-DSA-65 — operational PQC profile (real)."""
    def __init__(self, kid: str):
        self.alg, self.kid = ALG_ML_DSA_65, kid
        self._pk, self._sk = ML_DSA_65.keygen()

    def sign(self, msg: bytes) -> bytes:
        return ML_DSA_65.sign(self._sk, msg)

    def public_bytes(self) -> bytes:
        return self._pk


class SLHDSASigner(Signer):
    """FIPS 205 SLH-DSA-SHA2-128s — ARCHIVAL PQC profile (real, hash-based)."""
    def __init__(self, kid: str):
        self.alg, self.kid = ALG_SLH_DSA_128S, kid
        seed = os.urandom(_slh.crypto_sign_SEEDBYTES)
        self._pk, self._sk = _slh.generate_keypair(seed)

    def sign(self, msg: bytes) -> bytes:
        return _slh.sign(msg, self._sk)

    def public_bytes(self) -> bytes:
        return self._pk


def verify_sig(alg: int, pub: bytes, msg: bytes, sig: bytes) -> bool:
    if alg == ALG_EDDSA:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except InvalidSignature:
            return False
    if alg == ALG_ML_DSA_65:
        return bool(ML_DSA_65.verify(pub, msg, sig))
    if alg == ALG_SLH_DSA_128S:
        return bool(_slh.verify(msg, sig, pub))
    raise NotImplementedError(f"no verifier wired for alg {alg}")
