"""SPDM (DMTF DSP0274) message framing over MCTP (binding DSP0275).

Sibling to ipmi-/mctp-/pldm-test-environment: same host-PC-through-the-
FRDM-MCXA153-bridge setup, same "responder becomes bus master and writes
the response back" capture pattern, same test style. SPDM rides as MCTP
message type 0x05.

SPDM-over-MCTP message body (what a builder here returns -- the
msg-type/IC byte onward; hand straight to
spdm_helpers.send_spdm_command(), which prepends the MCTP transport
header + DSP0237 SMBus wrapper and handles PEC + fragment reassembly):

    byte0: msg-type/IC byte    -- 0x05 (SPDM), ic=0 (DSP0275: SPDM does
                                 not use the MCTP message integrity check)
    byte1: SPDMVersion         -- 0x10 = 1.0, 0x11 = 1.1, 0x12 = 1.2, 0x13 = 1.3
    byte2: RequestResponseCode
    byte3: Param1
    byte4: Param2
    byte5..: request/response payload

NOTE (2026-08-27): this OpenBIC port does NOT implement SPDM yet -- MCTP
message type 0x05 is not advertised by the endpoint. Every test in this
suite is written against the DSP0274 spec and marked
spdm_helpers.not_implemented() until the firmware gains SPDM support, at
which point each xfail flips to a loud XPASS and gets turned into a real
assertion. This is exactly how mctp-test-environment was built before
its hardware existed.
"""

import struct

MSG_TYPE_SPDM = 0x05

# ----- version byte encodings -----------------------------------------
V10 = 0x10
V11 = 0x11
V12 = 0x12
V13 = 0x13
VERSION_NAMES = {0x10: "1.0", 0x11: "1.1", 0x12: "1.2", 0x13: "1.3"}

# ----- request codes (bit7 set) and matching response codes ----------
REQ_GET_VERSION = 0x84
REQ_GET_CAPABILITIES = 0xE1
REQ_NEGOTIATE_ALGORITHMS = 0xE3
REQ_GET_DIGESTS = 0x81
REQ_GET_CERTIFICATE = 0x82
REQ_CHALLENGE = 0x83
REQ_GET_MEASUREMENTS = 0xE0

RESP_VERSION = 0x04
RESP_CAPABILITIES = 0x61
RESP_ALGORITHMS = 0x63
RESP_DIGESTS = 0x01
RESP_CERTIFICATE = 0x02
RESP_CHALLENGE_AUTH = 0x03
RESP_MEASUREMENTS = 0x60
RESP_ERROR = 0x7F

CODE_NAMES = {
    0x84: "GET_VERSION", 0x04: "VERSION",
    0xE1: "GET_CAPABILITIES", 0x61: "CAPABILITIES",
    0xE3: "NEGOTIATE_ALGORITHMS", 0x63: "ALGORITHMS",
    0x81: "GET_DIGESTS", 0x01: "DIGESTS",
    0x82: "GET_CERTIFICATE", 0x02: "CERTIFICATE",
    0x83: "CHALLENGE", 0x03: "CHALLENGE_AUTH",
    0xE0: "GET_MEASUREMENTS", 0x60: "MEASUREMENTS",
    0x7F: "ERROR",
}

# ----- SPDM error codes (Param1 of an ERROR response) ----------------
ERROR_NAMES = {
    0x01: "InvalidRequest", 0x02: "InvalidSession", 0x03: "Busy",
    0x04: "UnexpectedRequest", 0x05: "Unspecified", 0x06: "DecryptError",
    0x07: "UnsupportedRequest", 0x08: "RequestInFlight", 0x09: "InvalidResponseCode",
    0x0A: "SessionLimitExceeded", 0x41: "VersionMismatch", 0x42: "ResponseNotReady",
    0x43: "RequestResynch", 0xFF: "ResponseTooLarge",
}

# ----- GET_CAPABILITIES Flags bits (DSP0274) -------------------------
CAP_FLAG_BITS = {
    0: "CACHE_CAP", 1: "CERT_CAP", 2: "CHAL_CAP", 3: "MEAS_CAP(1)", 4: "MEAS_CAP(2)",
    5: "MEAS_FRESH_CAP", 6: "ENCRYPT_CAP", 7: "MAC_CAP", 8: "MUT_AUTH_CAP",
    9: "KEY_EX_CAP", 10: "PSK_CAP(1)", 11: "PSK_CAP(2)", 12: "ENCAP_CAP",
    13: "HBEAT_CAP", 14: "KEY_UPD_CAP", 15: "HANDSHAKE_IN_THE_CLEAR_CAP",
    16: "PUB_KEY_ID_CAP", 17: "CHUNK_CAP", 18: "ALIAS_CERT_CAP",
}

# ----- MeasurementSpecification / algorithm bits --------------------
MEAS_SPEC_DMTF = 0x01

# GET_MEASUREMENTS Param2 = the measurement operation.
MEAS_OP_TOTAL_NUMBER = 0x00       # request total number of measurement blocks
MEAS_OP_ALL_BLOCKS = 0xFF        # request all measurement blocks


def build_request(code, param1=0, param2=0, payload=b"", version=V10):
    """Build a full SPDM request message body (msg-type/IC byte onward)."""
    msg_type_ic = MSG_TYPE_SPDM & 0x7F  # ic = 0
    return bytes([msg_type_ic, version & 0xFF, code & 0xFF,
                  param1 & 0xFF, param2 & 0xFF]) + bytes(payload)


def build_get_version():
    """GET_VERSION is always sent at version byte 0x10 (DSP0274)."""
    return build_request(REQ_GET_VERSION, 0, 0, b"", version=V10)


def build_get_capabilities(version=V11, ct_exponent=0, flags=0,
                           data_transfer_size=0x1000, max_spdm_msg_size=0x1000):
    """GET_CAPABILITIES. 1.0 carries no body; 1.1 carries
    Reserved(1) CTExponent(1) Reserved(2) Flags(4 LE); 1.2+ additionally
    DataTransferSize(4 LE) MaxSPDMmsgSize(4 LE)."""
    if version <= V10:
        return build_request(REQ_GET_CAPABILITIES, 0, 0, b"", version=version)
    payload = bytes([0x00, ct_exponent & 0xFF, 0x00, 0x00]) + struct.pack("<I", flags & 0xFFFFFFFF)
    if version >= V12:
        payload += struct.pack("<I", data_transfer_size) + struct.pack("<I", max_spdm_msg_size)
    return build_request(REQ_GET_CAPABILITIES, 0, 0, payload, version=version)


def build_negotiate_algorithms(version=V11, base_asym_algo=0, base_hash_algo=0):
    """A minimal NEGOTIATE_ALGORITHMS with no ReqAlgStruct tables
    (Param1 = 0): Length(2 LE) MeasurementSpecification(1) Reserved(1)
    BaseAsymAlgo(4 LE) BaseHashAlgo(4 LE) Reserved(12) ExtAsymCount(1)=0
    ExtHashCount(1)=0 Reserved(2). Enough to elicit an ALGORITHMS or
    ERROR response; not a real negotiation."""
    body = bytearray()
    body += bytes([MEAS_SPEC_DMTF, 0x00])
    body += struct.pack("<I", base_asym_algo)
    body += struct.pack("<I", base_hash_algo)
    body += bytes(12)
    body += bytes([0x00, 0x00])  # ExtAsymCount, ExtHashCount
    body += bytes([0x00, 0x00])  # Reserved
    length = 4 + len(body)       # + the fixed 4-byte SPDM message header
    payload = struct.pack("<H", length) + bytes(body)
    return build_request(REQ_NEGOTIATE_ALGORITHMS, 0, 0, payload, version=version)


def build_get_digests(version=V11):
    return build_request(REQ_GET_DIGESTS, 0, 0, b"", version=version)


def build_get_certificate(slot=0, offset=0, length=0x400, version=V11):
    """GET_CERTIFICATE: Param1 = slot id, then Offset(2 LE) Length(2 LE)."""
    payload = struct.pack("<H", offset) + struct.pack("<H", length)
    return build_request(REQ_GET_CERTIFICATE, slot & 0x0F, 0, payload, version=version)


def build_challenge(slot=0, measurement_summary_hash_type=0x00, nonce=None, version=V11):
    """CHALLENGE: Param1 = slot id, Param2 = measurement-summary-hash
    type, payload = Nonce(32)."""
    if nonce is None:
        nonce = bytes(range(32))
    return build_request(REQ_CHALLENGE, slot & 0x0F, measurement_summary_hash_type,
                         bytes(nonce[:32]), version=version)


def build_get_measurements(operation=MEAS_OP_TOTAL_NUMBER, slot=0,
                           request_attributes=0x00, nonce=None, version=V11):
    """GET_MEASUREMENTS: Param1 = request attributes (bit0 =
    signature-requested), Param2 = operation (0x00 total count,
    0xFF all blocks, or a 1-based block index). When a signature is
    requested the payload carries Nonce(32) + SlotIDParam(1)."""
    payload = b""
    if request_attributes & 0x01:
        if nonce is None:
            nonce = bytes(range(0x20, 0x40))
        payload = bytes(nonce[:32]) + bytes([slot & 0x0F])
    return build_request(REQ_GET_MEASUREMENTS, request_attributes & 0xFF,
                         operation & 0xFF, payload, version=version)


def parse_response(body):
    """Split a reassembled SPDM response body. Raises ValueError if it
    isn't an SPDM message. Fills code-specific fields for ERROR / VERSION
    / CAPABILITIES / MEASUREMENTS."""
    if len(body) < 5:
        raise ValueError(f"SPDM response too short: {len(body)} bytes")
    if (body[0] & 0x7F) != MSG_TYPE_SPDM:
        raise ValueError(f"not an SPDM message (msg_type=0x{body[0] & 0x7F:02x})")
    version, code, param1, param2 = body[1], body[2], body[3], body[4]
    data = bytes(body[5:])
    out = {
        "version": version,
        "version_name": VERSION_NAMES.get(version, f"0x{version:02x}"),
        "code": code,
        "code_name": CODE_NAMES.get(code, f"0x{code:02x}"),
        "param1": param1,
        "param2": param2,
        "data": data,
    }
    if code == RESP_ERROR:
        out["error_code"] = param1
        out["error_name"] = ERROR_NAMES.get(param1, f"0x{param1:02x}")
        out["error_data"] = param2
    elif code == RESP_VERSION:
        out["versions"] = _parse_version_entries(data)
    elif code == RESP_CAPABILITIES:
        out["capabilities"] = _parse_capabilities(version, data)
    elif code == RESP_MEASUREMENTS:
        out["measurements"] = _parse_measurements(param1, data)
    return out


def _parse_version_entries(data):
    """VERSION response data: Reserved(1) VersionNumberEntryCount(1) then
    count * VersionNumberEntry(2 LE). Entry:
    Major(15:12) Minor(11:8) UpdateVersion(7:4) Alpha(3:0)."""
    if len(data) < 2:
        return []
    count = data[1]
    out = []
    for i in range(count):
        off = 2 + i * 2
        if off + 2 > len(data):
            break
        entry = int.from_bytes(data[off:off + 2], "little")
        out.append(f"{(entry >> 12) & 0xF}.{(entry >> 8) & 0xF}")
    return out


def _parse_capabilities(version, data):
    """CAPABILITIES response data: Reserved(1) CTExponent(1) Reserved(2)
    Flags(4 LE) [1.2+: DataTransferSize(4 LE) MaxSPDMmsgSize(4 LE)]."""
    if len(data) < 8:
        return {"raw": data.hex(" ")}
    flags = int.from_bytes(data[4:8], "little")
    out = {
        "ct_exponent": data[1],
        "flags": flags,
        "flag_names": [n for b, n in CAP_FLAG_BITS.items() if (flags >> b) & 1],
    }
    if version >= V12 and len(data) >= 16:
        out["data_transfer_size"] = int.from_bytes(data[8:12], "little")
        out["max_spdm_msg_size"] = int.from_bytes(data[12:16], "little")
    return out


def _parse_measurements(param1, data):
    """MEASUREMENTS response data: NumberOfBlocks(1) MeasurementRecordLength(3 LE)
    MeasurementRecord(N) then Nonce(32) OpaqueLength(2 LE) OpaqueData(M)
    [Signature(...)]. For the 'total number' query (Param2=0 in the
    request) NumberOfBlocks is 0 and Param1 of the response carries the
    total count instead."""
    if len(data) < 4:
        return {"raw": data.hex(" ")}
    number_of_blocks = data[0]
    record_len = int.from_bytes(data[1:4], "little")
    return {
        "total_number_via_param1": param1,
        "number_of_blocks": number_of_blocks,
        "measurement_record_length": record_len,
        "measurement_record": data[4:4 + record_len],
    }
