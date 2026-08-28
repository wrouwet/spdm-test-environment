"""SPDM discovery / capability negotiation (DSP0274 §10):
GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS.
"""

import spdm
from spdm_helpers import send_spdm_command
from config import EXPECTED_SPDM_VERSIONS, MIN_SPDM_VERSION


def test_get_version(bridge):
    """GET_VERSION returns a VERSION response listing the supported SPDM
    versions, including at least 1.0."""
    d = send_spdm_command(bridge, spdm.build_get_version())
    assert d["code"] == spdm.RESP_VERSION, f"expected VERSION, got {d['code_name']}"
    versions = d.get("versions") or []
    print(f"supported SPDM versions: {versions}")
    assert MIN_SPDM_VERSION in versions, f"expected {MIN_SPDM_VERSION} in {versions}"
    assert set(versions) == set(EXPECTED_SPDM_VERSIONS), (
        f"version list changed: {versions} vs {list(EXPECTED_SPDM_VERSIONS)}"
    )


def test_get_capabilities(bridge):
    """GET_CAPABILITIES returns CAPABILITIES advertising, for an
    attestation responder, at least CERT_CAP, CHAL_CAP and a MEAS_CAP
    level."""
    d = send_spdm_command(bridge, spdm.build_get_capabilities(version=spdm.V11))
    assert d["code"] == spdm.RESP_CAPABILITIES, f"expected CAPABILITIES, got {d['code_name']}"
    flags = d.get("capabilities", {}).get("flag_names", [])
    print(f"capability flags: {flags}")
    assert "CERT_CAP" in flags, "responder should advertise CERT_CAP"
    assert "CHAL_CAP" in flags, "responder should advertise CHAL_CAP"
    assert any(n.startswith("MEAS_CAP") for n in flags), "responder should advertise a MEAS_CAP level"


def test_negotiate_algorithms(bridge):
    """NEGOTIATE_ALGORITHMS returns ALGORITHMS selecting an ECDSA base
    asym algorithm and a SHA-2 base hash -- matching the responder's
    advertised ECDSA P-256/P-384 + SHA-256/384."""
    a = send_spdm_command(bridge, spdm.build_negotiate_algorithms(version=spdm.V11))
    assert a["code"] == spdm.RESP_ALGORITHMS, (
        f"expected ALGORITHMS, got {a['code_name']}"
        + (f" ({a['error_name']})" if a["code"] == spdm.RESP_ERROR else "")
    )
    algs = spdm.parse_algorithms(a)
    print(f"selected algorithms: {algs}")
    assert algs["base_asym_sel"] in (spdm.ASYM_ECDSA_P256, spdm.ASYM_ECDSA_P384), (
        f"unexpected BaseAsymSel 0x{algs['base_asym_sel']:x}"
    )
    assert algs["base_hash_sel"] in (spdm.HASH_SHA_256, spdm.HASH_SHA_384), (
        f"unexpected BaseHashSel 0x{algs['base_hash_sel']:x}"
    )


def test_garbage_version_is_rejected(bridge):
    """A request carrying an SPDM version byte the responder doesn't
    support comes back as an SPDM ERROR (VersionMismatch or
    UnexpectedRequest), never a success or silence."""
    d = send_spdm_command(bridge, spdm.build_request(spdm.REQ_GET_CAPABILITIES, version=0x1F))
    assert d["code"] == spdm.RESP_ERROR, f"expected ERROR, got {d['code_name']}"
    assert d["error_code"] in (0x41, 0x04), (
        f"expected VersionMismatch(0x41) or UnexpectedRequest(0x04), got {d['error_name']}"
    )
