"""SPDM at the MCTP transport boundary."""

from spdm_helpers import get_mctp_message_types, send_spdm_command
import spdm
from config import CURRENT_MCTP_MSG_TYPES, SPDM_MSG_TYPE


def test_mctp_message_types_are_the_known_set(bridge):
    """Pins the endpoint's advertised MCTP message types. A deliberate
    canary: it fails loudly if the set changes, prompting an update here
    and in the sibling mctp-test-environment.
    """
    types = get_mctp_message_types(bridge)
    print(f"advertised MCTP message types: {[hex(t) for t in types]}")
    assert set(types) == set(CURRENT_MCTP_MSG_TYPES), (
        f"MCTP message type set changed: got {[hex(t) for t in types]}, "
        f"expected {[hex(t) for t in CURRENT_MCTP_MSG_TYPES]}"
    )


def test_endpoint_advertises_spdm_message_type(bridge):
    """The MCTP endpoint advertises message type 0x05 (SPDM) per DSP0275."""
    types = get_mctp_message_types(bridge)
    assert SPDM_MSG_TYPE in types, (
        f"MCTP message type 0x05 (SPDM) not advertised; got {[hex(t) for t in types]}"
    )


def test_get_version_gets_a_response(bridge):
    """The minimum end-to-end check: GET_VERSION produces an SPDM
    VERSION response (not silence, not a malformed frame)."""
    decoded = send_spdm_command(bridge, spdm.build_get_version())
    assert decoded["code"] == spdm.RESP_VERSION, (
        f"GET_VERSION got {decoded['code_name']}"
        + (f" ({decoded['error_name']})" if decoded["code"] == spdm.RESP_ERROR else "")
    )
