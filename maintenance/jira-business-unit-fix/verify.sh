#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

sha256sum --check CHECKSUMS.sha256
python3 -m py_compile files/business_unit_fix.py
python3 -m unittest discover -s tests -v
bash -n install.sh verify.sh

echo "OpsPilot Jira Business Unit fix verification: PASS"
