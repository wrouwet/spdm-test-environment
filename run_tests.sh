#!/bin/bash
# Run the suite and tee a clean copy to test_report.txt, same convention
# as the sibling ipmi-/mctp-/pldm-test-environment run scripts.
set -euo pipefail
cd "$(dirname "$0")"
.venv/bin/pytest tests/ "$@" 2>&1 | tee >(sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' > test_report.txt)
