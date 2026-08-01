#!/usr/bin/env bash

set -euo pipefail

duration_seconds="${1:-150}"
workers="${2:-$(nproc)}"

if ! [[ "$duration_seconds" =~ ^[0-9]+$ ]] || [ "$duration_seconds" -lt 90 ] || [ "$duration_seconds" -gt 300 ]; then
    echo "Duration must be between 90 and 300 seconds."
    exit 1
fi
if ! [[ "$workers" =~ ^[0-9]+$ ]] || [ "$workers" -lt 1 ] || [ "$workers" -gt "$(nproc)" ]; then
    echo "Workers must be between 1 and $(nproc)."
    exit 1
fi

mode="$(curl --fail --silent --show-error --max-time 5 \
    http://127.0.0.1:3100/api/v1/integrations/status | \
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("mode", "unknown"))')"
if [ "$mode" != "live" ]; then
    echo "Safety stop: OpsPilot mode is $mode, not live."
    echo "Run ./enable-live.sh first."
    exit 1
fi

pids=()
cleanup() {
    if [ "${#pids[@]}" -gt 0 ]; then
        kill "${pids[@]}" >/dev/null 2>&1 || true
        wait "${pids[@]}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

echo "Starting $workers controlled CPU workers for $duration_seconds seconds."
echo "They stop automatically; press Ctrl+C to stop early."
for _worker in $(seq 1 "$workers"); do
    timeout "${duration_seconds}s" yes >/dev/null &
    pids+=("$!")
done

echo "Watch controller events in another SSH window with:"
echo "sudo journalctl -fu opspilot-cpu-alert.service"
wait "${pids[@]}" || true
echo "Controlled CPU load stopped."
