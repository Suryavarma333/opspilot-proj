#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 -m py_compile \
    dashboard/files/opspilot_dashboard_agent.py \
    automation/cpu-alert/files/opspilot_cpu_alert.py \
    automation/roster-rotation/files/opspilot-roster-rotation.py \
    maintenance/jira-business-unit-fix/files/business_unit_fix.py

python3 -m unittest discover automation/cpu-alert/tests -v
python3 automation/roster-rotation/tests/test_rotation.py
python3 -m unittest discover maintenance/jira-business-unit-fix/tests -v

while IFS= read -r script; do
    bash -n "$script"
done < <(find . -type f -name '*.sh' -not -path './.git/*' | sort)

for component in \
    dashboard \
    automation/cpu-alert \
    automation/roster-rotation \
    maintenance/jira-business-unit-fix; do
    (
        cd "$component"
        sha256sum --check --quiet CHECKSUMS.sha256
    )
done

echo "OpsPilot repository verification: PASS"
