#!/bin/sh
# HERMIAN Phase 2 validation suite.
#
# 1. Every simulated attack must produce a HIGH/CRITICAL alert.
# 2. Every false-positive workload must run with ZERO HIGH/CRITICAL alerts
#    (72h by default; --quick runs 5 minutes per workload).
#
# Usage: sudo sh run_suite.sh [--quick] [--fp-hours=72] [--skip-fp]
set -eu

QUICK=0
SKIP_FP=0
FP_HOURS=72

for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --skip-fp) SKIP_FP=1 ;;
        --fp-hours=*) FP_HOURS="${arg#*=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi
if ! command -v hermian >/dev/null 2>&1; then
    echo "hermian is not installed on PATH" >&2
    exit 1
fi

FAILS=0
echo "=== HERMIAN validation suite ==="
echo

echo "--- Self-test (synthetic detections) ---"
hermian test || FAILS=$((FAILS + 1))
echo

echo "--- Attack simulations (expect HIGH/CRITICAL alerts) ---"
run_attack() {
    "$DIR/attacks/run_attack.sh" "$1" "$2" || FAILS=$((FAILS + 1))
}
run_attack webshell            "Web server"
run_attack ssh-key-injection   "SSH key"
run_attack cron-persistence    "Cron"
run_attack systemd-persistence "systemd unit"
run_attack ld-preload          "ld.so.preload"
run_attack brute-force         "authentication burst"
run_attack memfd               "Fileless"
run_attack suid-drop           "setuid"
echo

if [ "$SKIP_FP" -eq 0 ]; then
    if [ "$QUICK" -eq 1 ]; then
        FP_SECONDS=300
    else
        FP_SECONDS=$((FP_HOURS * 3600))
    fi
    echo "--- False-positive workloads (expect ZERO HIGH/CRITICAL) ---"
    echo "(running each for ${FP_SECONDS}s; use --quick for a smoke check)"
    for env in idle admin-edit web dev ssh-ansible ci; do
        "$DIR/false_positives/run_false_positive.sh" "$env" "$FP_SECONDS" || FAILS=$((FAILS + 1))
    done
    echo
fi

echo "--- Cleanup of test artifacts ---"
rm -f /etc/cron.d/hermian-test-backdoor
rm -f /etc/systemd/system/hermian-test.service
rm -f /tmp/.hermian-test-suid
systemctl daemon-reload || true
sed -i '/hermian-libevil/d' /etc/ld.so.preload 2>/dev/null || true
sed -i '/HERMIANATTACKSIM/d' /root/.ssh/authorized_keys 2>/dev/null || true
echo "done."
echo

if [ "$FAILS" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL ($FAILS check(s) failed)" >&2
    exit 1
fi
