# SPDM Test Environment

A pytest-based test suite, run from a host PC, for exercising an
[OpenBIC](https://github.com/facebook/OpenBIC) controller's **SPDM**
(DMTF DSP0274) implementation carried over MCTP (binding DSP0275) as
message type `0x05`, over I2C via a USB-to-I2C bridge.

One of a family of sibling suites that each test the same OpenBIC
controller over the same one I2C bus, named by protocol:

| Repo | Layer |
|---|---|
| `ipmi-test-environment` | IPMI over IPMB |
| `mctp-test-environment` | MCTP transport + Control Protocol |
| **`spdm-test-environment`** (this repo) | SPDM (DSP0274) over MCTP |
| `pldm-test-environment` | PLDM over MCTP |
| `openbic-discovery` | no assertions — reads every layer and prints an inventory |

## Status: SPDM not implemented on the target yet

As of 2026-08-27 this OpenBIC port does **not** implement SPDM. MCTP Get
Message Type Support reports `{0x00 Control, 0x01 PLDM, 0x7E Vendor-PCI}`
— `0x05` (SPDM) is absent — and a GET_VERSION over MCTP gets no response
at all. The firmware peer confirms SPDM is roadmapped but not on the
current plate.

So this suite is built the way `mctp-test-environment` was before its
hardware existed: every test is written against DSP0274 / DSP0275 and
marked `spdm_helpers.not_implemented()` (`xfail(strict=True)`). The
moment SPDM lands and a test starts genuinely passing, the run **fails
loudly** (XPASS), forcing it to be turned into a real assertion.

Two tests in `test_spdm_transport.py` run against the current firmware:
- `test_current_mctp_message_types_are_the_known_set` — **passes today**,
  a canary that breaks the moment the advertised message-type set changes.
- `test_endpoint_advertises_spdm_message_type` — xfail; flips to XPASS
  when `0x05` appears.

Expected run against current hardware: **1 passed, N xfailed**.

## What's covered (once SPDM lands)

- **Discovery** (`test_spdm_discovery.py`): GET_VERSION, GET_CAPABILITIES
  (expects CERT_CAP + a MEAS_CAP level), NEGOTIATE_ALGORITHMS,
  unsupported-version rejection.
- **Identity + attestation** (`test_spdm_attestation.py`): GET_DIGESTS,
  GET_CERTIFICATE (slot 0), CHALLENGE (slot 0, fresh nonce →
  CHALLENGE_AUTH), GET_MEASUREMENTS (total count, and all-blocks-signed).
- **Transport** (`test_spdm_transport.py`): message-type advertisement,
  GET_VERSION round trip.

Not covered: secure-session establishment (KEY_EXCHANGE / FINISH / PSK),
key update, heartbeat — a later phase once basic attestation works.

## Requirements

Same as the sibling suites: Linux, Python 3.9+, `dialout` group
membership, the FRDM-MCXA153 bridge (SMBus `WS`/`RS`/`XS` firmware
support) on its **"MCU USB"** port, wired to the OpenBIC target and
powered on. The SPDM/MCTP endpoint (`0x10`) shares one physical bus
(`flexcomm2_lpi2c2`) with IPMB (`0x20`) since the 2026-08-27
consolidation. See `ipmi-test-environment`'s README for the full
hardware / `dialout` walkthrough.

## Run

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest tests/
```

`./run_tests.sh` also tees a clean copy to `test_report.txt` (git-ignored).

## Layout

```
bridge.py           bridge client — vendored from mctp-test-environment
mctp.py             MCTP transport + SMBus PEC + fragmentation — vendored from mctp-test-environment
spdm.py             SPDM-over-MCTP request framing + response/measurement parsers (DSP0274/DSP0275)
conftest.py         session-scoped bridge fixture
tests/config.py     target addr/EID, current-vs-target MCTP message-type sets
tests/spdm_helpers.py  send_spdm_command() round trip (MCTP wrap + PEC + reassembly), not_implemented()
tests/test_spdm_transport.py
tests/test_spdm_discovery.py
tests/test_spdm_attestation.py
```

`bridge.py` / `mctp.py` are vendored copies, not a shared package —
same choice as the siblings.
