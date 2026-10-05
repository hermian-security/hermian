#!/bin/sh
# Emit the soak's headline numbers as JSON, for publishing (hermian.me reads
# this). Only aggregate figures leave the host: no alert text, no hostnames.
#
#   sh tests/soak/metrics.sh                      # print to stdout
#   sh tests/soak/metrics.sh /srv/www/metrics.json  # write atomically, 0644
#
# Attack results come from /var/lib/hermian/attacks.json, written by hand
# after a run of tests/run_suite.sh. Without that file they're null: this
# script never makes up a score. Doesn't take a new snapshot, so the
# percentiles match report.sh for the same soak.jsonl.
set -eu
OUT="${1:-}"
JSON=$(python3 - <<'EOF'
import json, sys, datetime as dt
SOAK = "/var/log/hermian/soak.jsonl"
try:
    with open(SOAK) as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
except FileNotFoundError:
    sys.exit("no soak snapshots yet (%s missing); run tests/soak/start.sh" % SOAK)
if not rows:
    sys.exit("no soak snapshots yet")
last = rows[-1]
f = "%Y-%m-%dT%H:%M:%SZ"
hours = (dt.datetime.strptime(last["snapshot"], f) - dt.datetime.strptime(last["since"], f)).total_seconds() / 3600
cpu = [r["status"].get("cpu_avg_1h", 0.0) for r in rows if r.get("status")]
rss = [r["status"].get("rss_mb", 0) for r in rows if r.get("status")]
# Same percentile as report.sh, so the published and reported numbers agree.
def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
c = last["counts"]
caught = total = None
try:
    with open("/var/lib/hermian/attacks.json") as fh:
        a = json.load(fh)
    if isinstance(a.get("caught"), int) and isinstance(a.get("total"), int):
        caught, total = a["caught"], a["total"]
except (OSError, ValueError, AttributeError):
    pass
p50, p99 = pct(cpu, .5), pct(cpu, .99)
print(json.dumps({
    "snapshot": last["snapshot"],
    "since": last["since"],
    "hours": round(hours, 1),
    "cpu_p50": round(p50, 2) if p50 is not None else None,
    "cpu_p99": round(p99, 2) if p99 is not None else None,
    "rss_max": max(rss) if rss else None,
    "high_plus_count": c.get("High", 0) + c.get("Critical", 0),
    "info_low_count": c.get("Info", 0) + c.get("Low", 0),
    "attacks_caught": caught,
    "attacks_total": total,
    "ebpf": (last.get("status") or {}).get("ebpf"),
}))
EOF
)
if [ -z "$OUT" ]; then
    printf '%s\n' "$JSON"
    exit 0
fi
# Write next to the target and rename, so a reader never sees a partial or
# empty file and a failure above leaves the old one in place.
TMP=$(mktemp "$OUT.XXXXXX")
trap 'rm -f "$TMP"' EXIT
printf '%s\n' "$JSON" > "$TMP"
chmod 0644 "$TMP"
mv -f "$TMP" "$OUT"
trap - EXIT
