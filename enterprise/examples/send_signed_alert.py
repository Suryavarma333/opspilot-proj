#!/usr/bin/env python3
"""Send an example alert without placing the HMAC secret in argv."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
import urllib.request
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: send_signed_alert.py ALERT_JSON")
    secret = os.environ.get("OPSPILOT_WEBHOOK_HMAC_SECRET", "")
    if not secret:
        raise SystemExit("OPSPILOT_WEBHOOK_HMAC_SECRET is required")
    body = Path(sys.argv[1]).read_bytes()
    timestamp = int(time.time())
    base = f"v1:{timestamp}:".encode() + body
    signature = "v1=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        "http://127.0.0.1:8088/v1/alerts",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-OpsPilot-Timestamp": str(timestamp),
            "X-OpsPilot-Signature": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.read().decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

