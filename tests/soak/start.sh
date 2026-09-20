#!/bin/sh
# Start (or restart) the false-positive soak clock on this host and install
# the hourly snapshot. Run AFTER the attack simulations so they are excluded.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
DIR="$(cd "$(dirname "$0")" && pwd)"
install -m 0755 "$DIR/hermian-soak-snapshot" /usr/local/bin/hermian-soak-snapshot
date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/hermian/soak-start
echo '17 * * * * root /usr/local/bin/hermian-soak-snapshot' > /etc/cron.d/hermian-soak
/usr/local/bin/hermian-soak-snapshot
echo "soak started at $(cat /var/lib/hermian/soak-start); hourly snapshots -> /var/log/hermian/soak.jsonl"
echo "read with: $DIR/report.sh"
