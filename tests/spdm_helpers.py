"""Shared plumbing for every SPDM test -- the request/response round trip
over MCTP (message type 0x05), and the not_implemented() backlog marker.

Mirrors pldm-test-environment/tests/pldm_helpers.py exactly, only the
MCTP message body differs (SPDM instead of PLDM). SPDM responses
(certificates especially) can be large, so reassembly of a multi-packet
SOM..EOM response is handled here.
"""

import itertools

import pytest

import mctp
import spdm
from config import MCTP_TARGET_ADDR, OUR_EID, OUR_I2C_ADDR, TARGET_EID

_next_msg_tag = itertools.count()


def next_msg_tag():
    return next(_next_msg_tag) % 8


def _verify_and_strip_pec(raw):
    if len(raw) < 1:
        raise ValueError("captured frame too short for a PEC byte")
    data, pec_received = raw[:-1], raw[-1]
    pec = mctp.smbus_pec_byte(0, (OUR_I2C_ADDR << 1) | 0)
    pec = mctp.smbus_pec_buf(pec, data)
    if pec != pec_received:
        raise ValueError(f"SMBus PEC mismatch: expected 0x{pec:02x}, got 0x{pec_received:02x}")
    return data


def send_spdm_command(bridge, message_body, max_fragments=64, max_drain=3):
    """Send one SPDM request (a spdm.build_*() result, msg-type/IC byte
    onward) and return the decoded response dict from
    spdm.parse_response(). Reassembles a multi-packet response. Raises
    AssertionError / BridgeError on no response -- which is the current
    reality until SPDM is implemented, hence every caller is
    not_implemented()-marked.
    """
    tag = next_msg_tag()
    transport = mctp.build_transport_header(
        TARGET_EID, OUR_EID, msg_tag=tag, tag_owner=1, som=1, eom=1, pkt_seq=0
    )
    payload = transport + bytes(message_body)
    wrapper = mctp.build_smbus_block_wrapper(OUR_I2C_ADDR, payload)
    print(f"request (wrapper + MCTP + SPDM): {(wrapper + payload).hex(' ')}")
    bridge.smbus_write(MCTP_TARGET_ADDR, wrapper + payload)

    body = bytearray()
    fragments = 0
    drains = 0
    while fragments < max_fragments:
        raw = bridge.listen(OUR_I2C_ADDR)
        print(f"captured: {raw.hex(' ')}")
        try:
            after_pec = _verify_and_strip_pec(raw)
            _, packet = mctp.parse_smbus_block_wrapper(after_pec)
            hdr = mctp.parse_transport_header(packet)
        except ValueError as exc:
            if fragments == 0:
                drains += 1
                if drains > max_drain:
                    raise AssertionError(f"only malformed frames after {max_drain} tries ({exc})")
                print(f"discarding malformed frame ({exc}); still listening...")
                continue
            raise AssertionError(f"malformed fragment {fragments + 1} ({exc})")
        chunk = packet[4:]
        if fragments == 0:
            if hdr["msg_tag"] != tag or hdr["tag_owner"] != 0:
                drains += 1
                if drains > max_drain:
                    raise AssertionError(f"never saw a fragment for msg_tag={tag}")
                print(f"discarding stale fragment (msg_tag={hdr['msg_tag']}); still listening...")
                continue
            if not hdr["som"]:
                raise AssertionError(f"first matching fragment isn't SOM: {hdr}")
        elif hdr["msg_tag"] != tag:
            raise AssertionError(f"fragment {fragments + 1} msg_tag={hdr['msg_tag']} != {tag}")
        body += chunk
        fragments += 1
        if hdr["eom"]:
            break
    else:
        raise AssertionError(f"no EOM after {max_fragments} fragments")

    decoded = spdm.parse_response(bytes(body))
    print(f"decoded: {decoded}")
    return decoded


def get_mctp_message_types(bridge):
    """Ask the MCTP endpoint (Get Message Type Support, cmd 0x05) which
    message types it handles. Returns a list of type bytes. Used by the
    transport-level gap test -- this is the one thing in this suite that
    works against the current firmware.
    """
    inst_id = 0
    msg_type_ic = mctp.MSG_TYPE_CONTROL & 0x7F
    rq_d_inst = (1 << 7) | inst_id
    ctrl_body = bytes([msg_type_ic, rq_d_inst, 0x05])
    tag = next_msg_tag()
    transport = mctp.build_transport_header(
        TARGET_EID, OUR_EID, msg_tag=tag, tag_owner=1, som=1, eom=1, pkt_seq=0
    )
    payload = transport + ctrl_body
    wrapper = mctp.build_smbus_block_wrapper(OUR_I2C_ADDR, payload)
    bridge.smbus_write(MCTP_TARGET_ADDR, wrapper + payload)

    raw = bridge.listen(OUR_I2C_ADDR)
    after_pec = _verify_and_strip_pec(raw)
    _, packet = mctp.parse_smbus_block_wrapper(after_pec)
    decoded = mctp.parse_control_response(
        mctp.build_transport_header(OUR_EID, TARGET_EID, tag_owner=0, som=1, eom=1)
        + packet[4:]
    )
    print(f"Get Message Type Support: {decoded}")
    if decoded["completion_code"] != 0x00 or not decoded["data"]:
        return []
    count = decoded["data"][0]
    return list(decoded["data"][1:1 + count])


def not_implemented(reason):
    """xfail(strict=True), identical mechanism to the sibling suites: the
    moment SPDM support lands and the test passes, the run FAILS loudly
    (XPASS) forcing this back to a real test.
    """
    return pytest.mark.xfail(reason=reason, strict=True)
