#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

sha256sum --check CHECKSUMS.sha256
python3 -m py_compile files/opspilot_cpu_alert.py
python3 -m unittest discover -s tests -v
for script in install.sh enable-live.sh disable-live.sh test-high-cpu.sh status.sh verify.sh; do
    bash -n "$script"
done

grep -Fq 'if ! sudo test -f "$config_file"; then' install.sh
grep -Fq 'Run ./install.sh successfully before enabling live mode.' enable-live.sh
grep -Fq 'NOT INSTALLED:' status.sh

if command -v systemd-analyze >/dev/null 2>&1; then
    unit_test_dir="$(mktemp -d)"
    sed \
        's|^ExecStart=.*|ExecStart=/usr/bin/true|' \
        files/opspilot-cpu-alert.service \
        >"$unit_test_dir/opspilot-cpu-alert.service"
    cp files/opspilot-cpu-alert.timer "$unit_test_dir/opspilot-cpu-alert.timer"
    systemd-analyze verify \
        "$unit_test_dir/opspilot-cpu-alert.service" \
        "$unit_test_dir/opspilot-cpu-alert.timer"
fi

echo "OpsPilot automatic Jira package verification: PASS"
