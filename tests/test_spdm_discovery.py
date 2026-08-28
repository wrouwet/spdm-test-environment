"""SPDM discovery / capability negotiation (DSP0274 §10):
GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS.

Every test is spec-derived and not_implemented() until the firmware
gains SPDM. Bodies assert the real compliant behaviour so they become
live tests unchanged once the xfail flips.
"""

import spdm
from spdm_helpers import not_implemented, send_spdm_command
from config import MIN_SPDM_VERSION

_GAP = ("SPDM not implemented on this OpenBIC port yet -- MCTP message type 0x05 "
        "absent, GET_VERSION gets no response (observed 2026-08-27).")


@not_implemented(_GAP)
def test_get_version(bridge):
    """GET_VERSION returns a VERSION response listing at least one
    supported SPDM version, including 1.0."""
    d = send_spdm_command(bridge, spdm.build_get_version())
    assert d["code"] == spdm.RESP_VERSION, f"expected VERSION, got {d['code_name']}"
    versions = d.get("versions") or []
    print(f"supported SPDM versions: {versions}")
    assert MIN_SPDM_VERSION in versions, f"expected {MIN_SPDM_VERSION} in {versions}"


@not_implemented(_GAP)
def test_get_capabilities(bridge):
    """GET_CAPABILITIES returns a CAPABILITIES response. A BIC acting as
    an attestation responder should at least advertise CERT_CAP and one
    of the MEAS_CAP levels."""
    d = send_spdm_command(bridge, spdm.build_get_capabilities(version=spdm.V11))
    assert d["code"] == spdm.RESP_CAPABILITIES, f"expected CAPABILITIES, got {d['code_name']}"
    caps = d.get("capabilities", {})
    print(f"capability flags: {caps.get('flag_names')}")
    assert "CERT_CAP" in caps.get("flag_names", []), "responder should advertise CERT_CAP"
    assert any(n.startswith("MEAS_CAP") for n in caps.get("flag_names", [])), (
        "responder should advertise a MEAS_CAP level"
    )


@not_implemented(_GAP)
def test_negotiate_algorithms(bridge):
    """NEGOTIATE_ALGORITHMS returns an ALGORITHMS response (echoing a
    selected BaseHashAlgo / BaseAsymAlgo), not an ERROR."""
    d = send_spdm_command(bridge, spdm.build_negotiate_algorithms(version=spdm.V11))
    assert d["code"] == spdm.RESP_ALGORITHMS, (
        f"expected ALGORITHMS, got {d['code_name']}"
        + (f" ({d['error_name']})" if d["code"] == spdm.RESP_ERROR else "")
    )


@not_implemented(_GAP)
def test_unsupported_version_is_rejected(bridge):
    """A request at an SPDM version the responder doesn't support must
    come back as ERROR/VersionMismatch (0x41), not silence or success."""
    d = send_spdm_command(bridge, spdm.build_request(spdm.REQ_GET_CAPABILITIES, version=0x1F))
    assert d["code"] == spdm.RESP_ERROR and d["error_code"] == 0x41, (
        f"expected ERROR/VersionMismatch, got {d['code_name']}"
    )
