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

## Status: live and green — 13 passed, 0 xfailed

As of 2026-08-28 this OpenBIC port runs a full DMTF **libspdm 3.8.2**
responder (branch `full-board-port` @ `a210e2b7`). MCTP Get Message Type
Support reports `{0x00 Control, 0x01 PLDM, 0x05 SPDM, 0x7E Vendor-PCI}`.
Capabilities `CERT_CAP | CHAL_CAP | MEAS_CAP(SIG)`; negotiates
**ECDSA-P256 + SHA-384** (hash 48, sig 64); slot 0 only, single-cert
P-256 self-signed dev chain (DSP0274-wrapped: `Length|Reserved|RootHash|
DER`); one `IMMUTABLE_ROM` measurement block over a fixed 32 KB flash
window. No secure sessions / key exchange / PSK / mutual auth / chunking.

**The full attestation chain works end-to-end and is verified, not just
parsed:** `GET_VERSION` → `GET_CAPABILITIES` → `NEGOTIATE_ALGORITHMS` →
`GET_DIGESTS` → `GET_CERTIFICATE` → `CHALLENGE` → and the returned ECDSA
signature is **cryptographically verified** against the device
certificate's public key over a reconstructed SPDM 1.1 M2 transcript
(`test_challenge_auth_signature_verifies`), plus signed
`GET_MEASUREMENTS`.

Getting there took two firmware bugfix flashes (unwrapped cert buffer;
P-384 advertised but only a P-256 sign key; measurement-hash algo
constant off by one bit) — each caught on first contact by this suite.

## What's covered

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
powered on. Plus the `cryptography` package (in `requirements.txt`) for
the ECDSA signature-verification test. The SPDM/MCTP endpoint (`0x10`) shares one physical bus
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
