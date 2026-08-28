"""Shared constants for the SPDM test suite.

STATUS (2026-08-28): SPDM is live on this OpenBIC port -- a full DMTF
libspdm 3.8.2 responder (branch full-board-port @ ad3e65ab), MCTP
message type 0x05 on the shared bus. Capabilities CERT_CAP | CHAL_CAP |
MEAS_CAP(SIG); ECDSA P-256/P-384, SHA-256/384; slot 0 only with a
single-cert P-256 self-signed dev chain; one IMMUTABLE_ROM measurement
block. No secure sessions / key exchange / PSK / mutual auth / chunking
on the SPDM side.

The measurement digest is a SHA-256/384 hash of a fixed 32 KB flash
window (stable across reboots, NOT a whole-image hash) -- tests assert
its length and stability, not a literal value. Cryptographic signature
verification against the cert's public key is a separate follow-up (see
test_spdm_attestation.py::test_challenge_auth_signature_verifies).
"""

# --- bus / transport (shared with mctp-/pldm-test-environment) ----------
# The SPDM/MCTP endpoint shares one physical bus (flexcomm2_lpi2c2) with
# IPMB at 0x20 since the 2026-08-27 consolidation.
MCTP_TARGET_ADDR = 0x10
TARGET_EID = 0x09
OUR_I2C_ADDR = 0x08
OUR_EID = 0x08

SPDM_MSG_TYPE = 0x05

# MCTP message types the endpoint advertises (Get Message Type Support).
# Canary set -- test_spdm_transport.py breaks loudly when this changes.
CURRENT_MCTP_MSG_TYPES = (0x00, 0x01, 0x05, 0x7E)

# SPDM versions the responder offers in its VERSION response.
EXPECTED_SPDM_VERSIONS = ("1.0", "1.1", "1.2", "1.3")
MIN_SPDM_VERSION = "1.0"

# Certificate slots populated (single-cert P-256 self-signed chain in slot 0).
POPULATED_CERT_SLOTS = (0,)

# GET_MEASUREMENTS: one block, index 1, DMTF value type IMMUTABLE_ROM.
EXPECTED_MEASUREMENT_BLOCK_COUNT = 1
MEASUREMENT_BLOCK_INDEX = 1
DMTF_MEAS_VALUE_TYPE_IMMUTABLE_ROM = 0x00
