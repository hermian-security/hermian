#!/usr/bin/env python3
"""Verify fresh attack evidence from HERMIAN's JSON alert store, never text logs."""

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import sys
import time


def parse_timestamp(value):
    # Chrono emits nanoseconds; Python 3.8 accepts only 3 or 6 fractional digits.
    value = re.sub(
        r"\.(\d+)", lambda match: "." + match.group(1)[:6].ljust(6, "0"), value
    )
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("alert timestamps must include a timezone")
    return stamp


def matching_alert(output, since, until, pattern):
    if not pattern:
        raise ValueError("title pattern must not be empty")
    match = None
    for line in output.splitlines():
        if not line.strip():
            continue
        alert = json.loads(line)
        if not isinstance(alert, dict) or not all(
            isinstance(alert.get(key), str)
            for key in ("ts", "title", "severity", "ref_id")
        ):
            raise ValueError("invalid alert JSON record")
        if alert["severity"] not in ("Info", "Low", "High", "Critical"):
            raise ValueError("invalid alert severity")
        stamp = parse_timestamp(alert["ts"])
        if (
            since <= stamp <= until
            and alert["severity"] in ("High", "Critical")
            and pattern in alert["title"]
            and match is None
        ):
            match = alert
    # Validate the entire response before accepting even an earlier matching row.
    return match


def wait_for_alert(since, pattern, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        result = subprocess.run(
            ["hermian", "alerts", "-n", "50", "-s", "high", "--json"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=min(5, remaining),
        )
        alert = matching_alert(
            result.stdout, since, datetime.now(timezone.utc), pattern
        )
        if alert is not None:
            return alert
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("since", help="scenario start time with timezone")
    parser.add_argument("pattern", help="literal substring of the expected alert title")
    args = parser.parse_args()
    try:
        if not args.pattern:
            raise ValueError("title pattern must not be empty")
        alert = wait_for_alert(parse_timestamp(args.since), args.pattern)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("Alert verification failed: {}".format(error), file=sys.stderr)
        return 2
    if alert is None:
        print("No fresh matching HIGH/CRITICAL alert within 30 seconds", file=sys.stderr)
        return 1
    print("Evidence: {} {}".format(alert["ref_id"], alert["title"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
