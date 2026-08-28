"""SPDM identity + attestation (DSP0274 §11-12):
GET_DIGESTS -> GET_CERTIFICATE -> CHALLENGE -> GET_MEASUREMENTS.

libspdm's responder tracks connection state, so every test here runs the
opening handshake (spdm_helpers.establish_connection) first.
"""

import pytest

import spdm
from spdm_helpers import (
    establish_connection,
    full_attestation_prelude,
    get_full_cert_chain,
    not_implemented,
    send_spdm_command,
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

    NOTE: this build returns the raw DER with no DSP0274 cert-chain
    wrapper (Length/Reserved/RootHash) -- see spdm.parse_cert_chain and
    the open question with the firmware peer. Once the wrapper is added
    this test still passes (parse_cert_chain handles both).
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


@not_implemented(
    "responder returns ERROR/Unspecified (0x05) for CHALLENGE from this requester, "
    "even after the full VERSION->CAPABILITIES->ALGORITHMS->DIGESTS->CERTIFICATE "
    "prelude. Every UNSIGNED op works (digests, cert, measurement count); every "
    "SIGNED op (this + signed GET_MEASUREMENTS) returns Unspecified -- points at "
    "the responder's signing/crypto path, not the request framing. Flagged to the "
    "firmware peer 2026-08-28."
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


@not_implemented(
    "responder returns ERROR/Unspecified (0x05) for GET_MEASUREMENTS operation 0xFF "
    "(return the actual measurement records) -- signed OR unsigned, with or without "
    "the DIGESTS->CERTIFICATE prelude. Operation 0x00 (total count) works and "
    "reports 1 block. So record retrieval + signing are broken responder-side, not "
    "the request framing. Flagged to the firmware peer 2026-08-28. When fixed this "
    "should assert: 1 block, index 1, DMTF IMMUTABLE_ROM, a 256/384-bit digest, a "
    "signature of the negotiated size, and digest stability across two reads."
)
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


@not_implemented(
    "cryptographic signature verification not implemented yet: needs the "
    "`cryptography` package plus SPDM L1/L2 (measurements) and M1/M2 (challenge) "
    "transcript-hash reconstruction to verify the ECDSA signature against the "
    "slot-0 cert's public key. Structural checks (size, non-zero, stability) are "
    "in the tests above; this is the real attestation check and its own task."
)
def test_challenge_auth_signature_verifies(bridge):
    """Verify the CHALLENGE_AUTH signature against the slot-0 leaf
    certificate's public key over the reconstructed M2 transcript."""
    pytest.fail("not implemented -- see marker reason")
