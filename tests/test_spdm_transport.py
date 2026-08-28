"""SPDM at the MCTP transport boundary.

These are the only tests in this suite that touch the current firmware:
they pin down *that* SPDM isn't wired into MCTP yet, so the moment it is,
the suite makes noise.
"""

from spdm_helpers import get_mctp_message_types, not_implemented, send_spdm_command
import spdm
from config import CURRENT_MCTP_MSG_TYPES, SPDM_MSG_TYPE


def test_current_mctp_message_types_are_the_known_set(bridge):
    """Pins the endpoint's advertised MCTP message types to what was
    observed on 2026-08-27: {Control, PLDM, Vendor-PCI}. This test
    PASSES today and is a deliberate canary -- when SPDM (0x05) or any
    other type is added it fails loudly, prompting an update here and in
    the sibling mctp-test-environment, and a look at whether the SPDM
    tests below should come off not_implemented().
    """
    types = get_mctp_message_types(bridge)
    print(f"advertised MCTP message types: {[hex(t) for t in types]}")
    assert set(types) == set(CURRENT_MCTP_MSG_TYPES), (
        f"MCTP message type set changed: got {[hex(t) for t in types]}, "
        f"expected {[hex(t) for t in CURRENT_MCTP_MSG_TYPES]}. If 0x05 is now "
        f"present, SPDM has landed -- start un-xfailing the tests in this suite."
    )


@not_implemented(
    "SPDM (MCTP message type 0x05) is not advertised by the endpoint -- observed "
    "2026-08-27, Get Message Type Support reports only {0x00, 0x01, 0x7E}. Firmware "
    "peer confirms SPDM is roadmapped but not yet implemented."
)
def test_endpoint_advertises_spdm_message_type(bridge):
    """Once SPDM is implemented the MCTP endpoint must advertise message
    type 0x05 in Get Message Type Support (DSP0275)."""
    types = get_mctp_message_types(bridge)
    assert SPDM_MSG_TYPE in types, (
        f"MCTP message type 0x05 (SPDM) not advertised; got {[hex(t) for t in types]}"
    )


@not_implemented(
    "No SPDM responder on the MCTP endpoint yet -- GET_VERSION over MCTP message "
    "type 0x05 gets no response at all (observed 2026-08-27)."
)
def test_get_version_gets_a_response(bridge):
    """A minimal end-to-end check: GET_VERSION must produce an SPDM
    VERSION response (or at worst a well-formed SPDM ERROR), not silence.
    """
    decoded = send_spdm_command(bridge, spdm.build_get_version())
    assert decoded["code"] in (spdm.RESP_VERSION, spdm.RESP_ERROR), (
        f"GET_VERSION got an unexpected response code {decoded['code_name']}"
    )
