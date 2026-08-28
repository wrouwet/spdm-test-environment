"""Shared constants for the SPDM test suite.

STATUS (2026-08-27): this OpenBIC port does NOT implement SPDM yet. MCTP
Get Message Type Support reports {0x00 Control, 0x01 PLDM, 0x7E
Vendor-PCI} -- 0x05 (SPDM) is absent -- and GET_VERSION over MCTP gets
no response at all. Every test here is spec-derived (DSP0274 / DSP0275)
and marked spdm_helpers.not_implemented() until the firmware gains SPDM,
at which point the xfail flips to a loud XPASS. Confirmed with the
firmware peer that SPDM is on the roadmap but not on the current plate
(they're doing PLDM Type 2 / async events first).
"""

# --- bus / transport (shared with mctp-/pldm-test-environment) ----------
# SPDM would ride the same MCTP endpoint as PLDM. Since the 2026-08-27
# bus consolidation that endpoint shares one physical bus
# (flexcomm2_lpi2c2) with IPMB at 0x20.
MCTP_TARGET_ADDR = 0x10
TARGET_EID = 0x09
OUR_I2C_ADDR = 0x08
OUR_EID = 0x08

# MCTP message type for SPDM (DSP0275). Currently NOT in the endpoint's
# Get Message Type Support list -- see test_spdm_transport.py.
SPDM_MSG_TYPE = 0x05

# MCTP message types the endpoint currently DOES advertise, for the
# transport-level gap test.
CURRENT_MCTP_MSG_TYPES = (0x00, 0x01, 0x7E)

# What a compliant SPDM 1.x responder must support at minimum, for the
# discovery tests to assert once SPDM lands.
MIN_SPDM_VERSION = "1.0"
