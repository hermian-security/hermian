#!/bin/sh
# Summarise a soak: HIGH+ alerts since start (by rule), and CPU/RSS p50/p99
# from the hourly snapshots. Exit 1 if any HIGH+ occurred (the Phase 2 gate).
set -eu
/usr/local/bin/hermian-soak-snapshot 2>/dev/null || true
python3 - <<'EOF'
import json, statistics, datetime, sys
rows = [json.loads(l) for l in open("/var/log/hermian/soak.jsonl")]
if not rows:
    print("no snapshots yet"); sys.exit(0)
last = rows[-1]
start = datetime.datetime.strptime(last["since"], "%Y-%m-%dT%H:%M:%SZ")
now = datetime.datetime.strptime(last["snapshot"], "%Y-%m-%dT%H:%M:%SZ")
hours = (now - start).total_seconds() / 3600
cpu = [r["status"].get("cpu_avg_1h", 0.0) for r in rows if r.get("status")]
rss = [r["status"].get("rss_mb", 0) for r in rows if r.get("status")]
def pct(v, p):
    if not v: return 0
    v = sorted(v); return v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
print("HERMIAN soak report")
print("-" * 72)
print("since       %s  (%.1f h, %d snapshots)" % (last["since"], hours, len(rows)))
c = last["counts"]
print("alerts      critical %d  high %d  low %d  info %d" % (c.get("Critical", 0), c.get("High", 0), c.get("Low", 0), c.get("Info", 0)))
print("cpu %%       p50 %.2f  p99 %.2f  max %.2f" % (pct(cpu, .5), pct(cpu, .99), max(cpu) if cpu else 0))
print("rss MB      p50 %d  p99 %d  max %d" % (pct(rss, .5), pct(rss, .99), max(rss) if rss else 0))
st = last["status"]
print("coverage    ebpf=%s watches=%s (failed %s) pending_notify=%s" % (st.get("ebpf"), st.get("watches_active"), st.get("watches_failed"), st.get("pending_notifications")))
hp = last["high_plus"]
print("-" * 72)
if hp:
    print("HIGH/CRITICAL by rule:")
    for k, v in sorted(hp.items(), key=lambda kv: -kv[1]): print("  %4d  %s" % (v, k))
    print("\nRESULT: FAIL - review each with `hermian alerts -s high`; log verdicts in docs/fp-log.md")
    sys.exit(1)
ok = hours >= 72 and pct(cpu, .5) < 1.0 and (max(rss) if rss else 0) < 80
print("HIGH/CRITICAL: none")
print("\nRESULT: %s" % ("PASS (72 h gate met)" if ok else "PASS so far (gate needs 72 h, cpu<1%%, rss<80MB; at %.1f h)" % hours))
EOF
