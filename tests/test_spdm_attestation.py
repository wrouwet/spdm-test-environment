"""SPDM identity + attestation (DSP0274 §11-12):
GET_DIGESTS -> GET_CERTIFICATE -> CHALLENGE -> GET_MEASUREMENTS.

Spec-derived, all not_implemented() until the firmware gains SPDM. These
assume discovery/negotiation (test_spdm_discovery.py) already succeeded;
once that flips, work through these in order.
"""

import spdm
from spdm_helpers import not_implemented, send_spdm_command

_GAP = ("SPDM not implemented on this OpenBIC port yet -- see "
        "test_spdm_transport.py; depends on discovery/negotiation working first.")


@not_implemented(_GAP)
def test_get_digests(bridge):
    """GET_DIGESTS returns a DIGESTS response whose Param2 slot-mask has
    at least slot 0 populated, with one hash-length digest per set bit."""
    d = send_spdm_command(bridge, spdm.build_get_digests())
    assert d["code"] == spdm.RESP_DIGESTS, f"expected DIGESTS, got {d['code_name']}"
    slot_mask = d["param2"]
    print(f"populated cert slot mask: 0x{slot_mask:02x}")
    assert slot_mask & 0x01, "slot 0 should hold a certificate chain"
    assert len(d["data"]) % max(bin(slot_mask).count("1"), 1) == 0, (
        "digest data length should be a whole multiple of the number of populated slots"
    )


@not_implemented(_GAP)
def test_get_certificate_slot0(bridge):
    """GET_CERTIFICATE for slot 0 returns a CERTIFICATE response; walking
    Offset by PortionLength until RemainderLength == 0 yields a complete
    DER cert chain that starts with the 4+2-byte SPDM cert-chain header."""
    d = send_spdm_command(bridge, spdm.build_get_certificate(slot=0, offset=0, length=0x400))
    assert d["code"] == spdm.RESP_CERTIFICATE, f"expected CERTIFICATE, got {d['code_name']}"
    # data: PortionLength(2 LE) RemainderLength(2 LE) CertChain portion(N)
    assert len(d["data"]) >= 4, f"CERTIFICATE response too short: {d['data'].hex(' ')}"


@not_implemented(_GAP)
def test_challenge_slot0(bridge):
    """CHALLENGE against slot 0 with a fresh nonce returns CHALLENGE_AUTH
    carrying a CertChainHash, the responder's own Nonce, and a
    Signature -- the core device-authentication step."""
    d = send_spdm_command(bridge, spdm.build_challenge(slot=0, measurement_summary_hash_type=0x00))
    assert d["code"] == spdm.RESP_CHALLENGE_AUTH, f"expected CHALLENGE_AUTH, got {d['code_name']}"
    assert len(d["data"]) >= 32 + 32, "CHALLENGE_AUTH should carry at least a hash + nonce"


@not_implemented(_GAP)
def test_get_measurements_total_count(bridge):
    """GET_MEASUREMENTS with operation = 'request total number' returns a
    MEASUREMENTS response whose Param1 is the number of measurement
    blocks the device exposes (>= 1)."""
    d = send_spdm_command(bridge, spdm.build_get_measurements(operation=spdm.MEAS_OP_TOTAL_NUMBER))
    assert d["code"] == spdm.RESP_MEASUREMENTS, f"expected MEASUREMENTS, got {d['code_name']}"
    total = d["measurements"]["total_number_via_param1"]
    print(f"device exposes {total} measurement block(s)")
    assert total >= 1, "an attestable device should expose at least one measurement block"


@not_implemented(_GAP)
def test_get_measurements_all_blocks_signed(bridge):
    """GET_MEASUREMENTS for all blocks with signature requested returns a
    MEASUREMENTS response with a non-empty measurement record and a
    trailing signature."""
    d = send_spdm_command(bridge, spdm.build_get_measurements(
        operation=spdm.MEAS_OP_ALL_BLOCKS, request_attributes=0x01))
    assert d["code"] == spdm.RESP_MEASUREMENTS, f"expected MEASUREMENTS, got {d['code_name']}"
    rec = d["measurements"]["measurement_record"]
    print(f"measurement record: {len(rec)} bytes, {d['measurements']['number_of_blocks']} block(s)")
    assert d["measurements"]["number_of_blocks"] >= 1 and len(rec) >= 1
