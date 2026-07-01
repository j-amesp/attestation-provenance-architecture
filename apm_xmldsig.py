"""
STANAG 4778 binding profile — real W3C XML Digital Signatures.

The COSE/CBOR profile (apm.py) is the modern/embedded binding. This is the
NATO-interop profile: it renders the classification attribute as a
STANAG 4774-style ConfidentialityLabel and binds it to the data with a real
XML-DSIG detached signature (signxml), exactly as 4778 does today with
classical RSA/ECDSA. This demonstrates the architecture's claim of two
semantically-identical binding profiles — and shows the seam where a versioned
successor profile would swap XML-DSIG for a PQC signature suite.
"""
from __future__ import annotations

import datetime
import hashlib
import base64

from lxml import etree
from signxml import XMLSigner, XMLVerifier
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NSMAP = {"slab": "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0"}


def make_authority_cert(common_name: str):
    """A self-signed cert standing in for a national labelling authority CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


def _label_xml(cls_value: dict, data: bytes) -> etree._Element:
    """STANAG 4774-style label bound to a digest of the data object."""
    digest = base64.b64encode(hashlib.sha256(data).digest()).decode()
    root = etree.Element("{%s}OriginatorConfidentialityLabel" % NSMAP["slab"], nsmap=NSMAP)
    etree.SubElement(root, "{%s}PolicyIdentifier" % NSMAP["slab"]).text = cls_value["policy"]
    cls = etree.SubElement(root, "{%s}Classification" % NSMAP["slab"])
    cls.text = cls_value["level"]
    for tok in cls_value.get("rel", []):
        etree.SubElement(root, "{%s}Releasability" % NSMAP["slab"]).text = tok
    # bind the label to the data by embedding the object digest (4778 binding)
    b = etree.SubElement(root, "{%s}DataObjectDigest" % NSMAP["slab"])
    b.set("Algorithm", "sha-256")
    b.text = digest
    return root


def sign_label(cls_value: dict, data: bytes, key_pem: bytes, cert_pem: bytes) -> bytes:
    """Produce a 4778 XML-DSIG-bound confidentiality label. Returns XML bytes."""
    root = _label_xml(cls_value, data)
    signed = XMLSigner(signature_algorithm="rsa-sha256",
                       digest_algorithm="sha256").sign(root, key=key_pem, cert=cert_pem)
    return etree.tostring(signed)


def verify_label(signed_xml: bytes, data: bytes, cert_pem: bytes) -> dict:
    """Verify the XML signature AND the data binding. Returns the label fields."""
    verified = XMLVerifier().verify(signed_xml, x509_cert=cert_pem).signed_xml
    ns = NSMAP["slab"]
    got = verified.findtext("{%s}DataObjectDigest" % ns)
    want = base64.b64encode(hashlib.sha256(data).digest()).decode()
    if got != want:
        raise ValueError("label/data binding broken (digest mismatch)")
    return {
        "policy": verified.findtext("{%s}PolicyIdentifier" % ns),
        "level": verified.findtext("{%s}Classification" % ns),
        "rel": [e.text for e in verified.findall("{%s}Releasability" % ns)],
    }
