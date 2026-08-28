"""SPDM identity + attestation (DSP0274 §11-12):
GET_DIGESTS -> GET_CERTIFICATE -> CHALLENGE -> GET_MEASUREMENTS.

libspdm's responder tracks connection state, so every test here runs the
opening handshake (spdm_helpers.establish_connection) first.
"""

import os

import spdm
from spdm_helpers import (
    establish_connection,
    full_attestation_prelude,
    get_full_cert_chain,
    send_spdm_command,
    send_spdm_recorded,
)
from config import (
    DMTF_MEAS_VALUE_TYPE_IMMUTABLE_ROM,
    EXPECTED_MEASUREMENT_BLOCK_COUNT,
    MEASUREMENT_BLOCK_INDEX,
    POPULATED_CERT_SLOTS,
)


def test_get_digests(bridge):
    """GET_DIGESTS returns a DIGESTS response whose slot mask has slot 0
    populated, with one negotiated-hash-size digest per set bit."""
    conn = establish_connection(bridge)
    d = send_spdm_command(bridge, spdm.build_get_digests(version=conn["version"]))
    assert d["code"] == spdm.RESP_DIGESTS, f"expected DIGESTS, got {d['code_name']}"
    parsed = spdm.parse_digests(d, conn["hash_size"])
    print(f"digests: slot_mask=0x{parsed['slot_mask']:02x}, "
          f"{[h.hex() for h in parsed['digests']]}")
    for slot in POPULATED_CERT_SLOTS:
        assert parsed["slot_mask"] & (1 << slot), f"slot {slot} not in digest mask"
    assert parsed["digests"] and len(parsed["digests"][0]) == conn["hash_size"], (
        f"digest length {len(parsed['digests'][0]) if parsed['digests'] else 0} "
        f"!= negotiated hash size {conn['hash_size']}"
    )


def test_get_certificate_slot0_is_a_der_x509_cert(bridge):
    """GET_CERTIFICATE for slot 0, walked to completion, yields a DER
    X.509 certificate (a single self-signed cert on this platform).

    The payload is the DSP0274 cert-chain: Length(2 LE) Reserved(2)
    RootHash(48, SHA-384 of the leaf DER) then the 474 B cert
    (526 B total). parse_cert_chain also accepts a bare-DER payload for
    forward/backward compatibility.
    """
    conn = establish_connection(bridge)
    chain = get_full_cert_chain(bridge, conn, slot=0)
    print(f"cert chain: {len(chain)} bytes, wrapped={spdm.parse_cert_chain(chain).get('wrapped')}")
    der = spdm.parse_cert_chain(chain)["der"]
    assert der[:2] == b"\x30\x82", f"not a DER SEQUENCE: {der[:8].hex(' ')}"
    cert_len = spdm.der_cert_len(der)
    assert cert_len is not None, "DER length header not the expected 0x82 form"
    # single-cert: the first cert consumes essentially the whole blob.
    assert abs(len(der) - cert_len) <= 4, (
        f"expected a single-cert chain (first cert ~{cert_len} B), got {len(der)} B"
    )


def test_challenge_slot0_returns_signed_challenge_auth(bridge):
    """CHALLENGE against slot 0 with a fresh nonce returns CHALLENGE_AUTH
    carrying a CertChainHash, a responder Nonce, and a Signature of the
    negotiated size."""
    conn = establish_connection(bridge)
    full_attestation_prelude(bridge, conn, slot=0)
    d = send_spdm_command(bridge, spdm.build_challenge(
        slot=0, measurement_summary_hash_type=0x00, version=conn["version"]))
    assert d["code"] == spdm.RESP_CHALLENGE_AUTH, (
        f"expected CHALLENGE_AUTH, got {d['code_name']}"
        + (f" ({d['error_name']})" if d["code"] == spdm.RESP_ERROR else "")
    )
    ca = spdm.parse_challenge_auth(d, conn["hash_size"], conn["sig_size"], meas_summary=False)
    print(f"challenge_auth: cert_hash={ca['cert_chain_hash'].hex()[:16]}..., "
          f"nonce={ca['nonce'].hex()[:16]}..., sig={len(ca['signature'])} B")
    assert len(ca["cert_chain_hash"]) == conn["hash_size"]
    assert len(ca["nonce"]) == 32
    assert len(ca["signature"]) == conn["sig_size"], (
        f"signature {len(ca['signature'])} B != negotiated {conn['sig_size']} B"
    )
    assert any(ca["signature"]), "signature is all zeros"


def test_get_measurements_total_count(bridge):
    """GET_MEASUREMENTS with operation = 'request total number' returns a
    MEASUREMENTS response with NumberOfBlocks 0 and the total count in
    Param1 (1 on this platform)."""
    conn = establish_connection(bridge)
    d = send_spdm_command(bridge, spdm.build_get_measurements(
        operation=spdm.MEAS_OP_TOTAL_NUMBER, version=conn["version"]))
    assert d["code"] == spdm.RESP_MEASUREMENTS, f"expected MEASUREMENTS, got {d['code_name']}"
    m = d["measurements"]
    print(f"total measurement blocks (Param1): {m['total_number_via_param1']}")
    assert m["number_of_blocks"] == 0
    assert m["total_number_via_param1"] == EXPECTED_MEASUREMENT_BLOCK_COUNT


def test_get_measurements_all_blocks(bridge):
    """GET_MEASUREMENTS operation 0xFF returns the IMMUTABLE_ROM block
    (index 1) and, with a signature requested, a signature of the
    negotiated size; the digest of the fixed 32 KB flash window is
    stable across reads."""
    conn = establish_connection(bridge)
    full_attestation_prelude(bridge, conn, slot=0)

    def read_all(sign):
        d = send_spdm_command(bridge, spdm.build_get_measurements(
            operation=spdm.MEAS_OP_ALL_BLOCKS, request_attributes=(0x01 if sign else 0x00),
            version=conn["version"]))
        assert d["code"] == spdm.RESP_MEASUREMENTS, f"expected MEASUREMENTS, got {d['code_name']}"
        return d["measurements"]

    m = read_all(sign=True)
    assert len(m["blocks"]) == EXPECTED_MEASUREMENT_BLOCK_COUNT
    blk = m["blocks"][0]
    assert blk["index"] == MEASUREMENT_BLOCK_INDEX
    assert blk["spec"] == spdm.MEAS_SPEC_DMTF
    assert blk.get("value_type") == DMTF_MEAS_VALUE_TYPE_IMMUTABLE_ROM
    assert len(blk["value"]) in (32, 48)
    assert len(m["signature"]) == conn["sig_size"] and any(m["signature"])
    assert read_all(sign=False)["blocks"][0]["value"] == blk["value"], (
        "measurement digest changed between reads -- should be stable"
    )


def test_challenge_auth_signature_verifies(bridge):
    """The real attestation check: verify the CHALLENGE_AUTH ECDSA
    signature against the slot-0 leaf certificate's public key over the
    reconstructed M2 transcript.

    M2 (DSP0274 1.1) = every SPDM message, SPDMVersion byte onward, in
    order:  GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES,
    NEGOTIATE_ALGORITHMS, ALGORITHMS, GET_DIGESTS, DIGESTS,
    GET_CERTIFICATE(s), CERTIFICATE(s), CHALLENGE,
    CHALLENGE_AUTH-without-its-Signature.  Signature = ECDSA_Sign(priv,
    negotiated_hash(M2)).  No 1.2+ signing-context prefix at v1.1.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    from cryptography.x509 import load_der_x509_certificate

    ver = spdm.V11
    t = bytearray()

    v = send_spdm_recorded(bridge, spdm.build_get_version(), t)
    assert v["code"] == spdm.RESP_VERSION
    send_spdm_recorded(bridge, spdm.build_get_capabilities(version=ver), t)
    a = send_spdm_recorded(bridge, spdm.build_negotiate_algorithms(version=ver), t)
    assert a["code"] == spdm.RESP_ALGORITHMS
    algs = spdm.parse_algorithms(a)
    hash_size = spdm.HASH_SIZE[algs["base_hash_sel"]]
    sig_size = spdm.ASYM_SIG_SIZE[algs["base_asym_sel"]]

    dg = send_spdm_recorded(bridge, spdm.build_get_digests(version=ver), t)
    assert dg["code"] == spdm.RESP_DIGESTS

    chain = bytearray()
    offset = 0
    for _ in range(64):
        r = send_spdm_recorded(bridge, spdm.build_get_certificate(
            slot=0, offset=offset, length=0x200, version=ver), t)
        assert r["code"] == spdm.RESP_CERTIFICATE
        c = spdm.parse_certificate(r)
        chain += c["cert_chain_portion"]
        offset += c["portion_length"]
        if c["remainder_length"] == 0:
            break

    nonce = os.urandom(32)
    chal = spdm.build_challenge(slot=0, measurement_summary_hash_type=0x00,
                               nonce=nonce, version=ver)
    t += bytes(chal[1:])                      # CHALLENGE request
    ca = send_spdm_command(bridge, chal)
    assert ca["code"] == spdm.RESP_CHALLENGE_AUTH, f"got {ca['code_name']}"
    parsed = spdm.parse_challenge_auth(ca, hash_size, sig_size, meas_summary=False)
    signature = parsed["signature"]
    assert len(signature) == sig_size
    t += ca["_spdm_msg"][:-sig_size]          # CHALLENGE_AUTH minus Signature

    # leaf cert public key
    der = spdm.parse_cert_chain(bytes(chain))["der"]
    cert = load_der_x509_certificate(der[:spdm.der_cert_len(der)])
    pub = cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey), f"unexpected key type {type(pub)}"

    # SPDM ECDSA signatures are raw r||s (fixed-width, big-endian); the
    # `cryptography` API wants a DER-encoded (r, s) pair.
    half = sig_size // 2
    der_sig = encode_dss_signature(
        int.from_bytes(signature[:half], "big"),
        int.from_bytes(signature[half:], "big"),
    )
    hash_alg = {32: hashes.SHA256(), 48: hashes.SHA384(), 64: hashes.SHA512()}[hash_size]
    try:
        pub.verify(der_sig, bytes(t), ec.ECDSA(hash_alg))
    except InvalidSignature:
        raise AssertionError(
            f"CHALLENGE_AUTH signature did NOT verify against the slot-0 cert "
            f"(transcript {len(t)} B, {hash_alg.name}, {pub.curve.name})"
        )
    print(f"CHALLENGE_AUTH signature verified: {pub.curve.name} / {hash_alg.name}, "
          f"M2 transcript {len(t)} B, cert CN="
          f"{cert.subject.rfc4514_string()}")
