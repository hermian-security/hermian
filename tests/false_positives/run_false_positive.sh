#!/bin/sh
# HERMIAN false-positive workload: run one environment and assert ZERO
# HIGH/CRITICAL alerts were raised while it ran.
#
# Usage: run_false_positive.sh <environment> <duration-seconds>
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <environment> [duration-seconds]" >&2
    exit 2
fi

ENV="$1"
DURATION="${2:-300}"
DIR="$(cd "$(dirname "$0")" && pwd)"

. "$DIR/../helpers/disposable_host.sh"
require_disposable_host

cleanup() {
    rm -f /etc/cron.d/hermian-fp-test /tmp/hermian-fp-installer.sh
    sed -i '/HERMIAN_FP/d' /root/.bashrc 2>/dev/null || true
    [ -n "${NGINX_PID:-}" ] && kill "$NGINX_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END=$(( $(date +%s) + DURATION ))

case "$ENV" in
    idle)
        sleep "$DURATION"
        ;;
    admin-edit)
        # The single most common FP source: an operator editing persistence
        # surfaces from an interactive session. Every edit here must be INFO.
        while [ "$(date +%s)" -lt "$END" ]; do
            printf '# hermian fp test\n' > /etc/cron.d/hermian-fp-test
            printf 'export HERMIAN_FP=1\n' >> /root/.bashrc
            sed -i '/HERMIAN_FP/d' /root/.bashrc
            rm -f /etc/cron.d/hermian-fp-test
            visudo -c >/dev/null 2>&1 || true
            systemctl daemon-reload >/dev/null 2>&1 || true
            sleep 10
        done
        ;;
    web)
        NGINX_PID=""
        if command -v nginx >/dev/null 2>&1; then
            nginx -g 'daemon off;' &
            NGINX_PID=$!
        fi
        while [ "$(date +%s)" -lt "$END" ]; do
            for _ in $(seq 1 50); do
                curl -s -o /dev/null http://127.0.0.1/ 2>/dev/null || true
            done
            sleep 1
        done
        [ -n "$NGINX_PID" ] && kill "$NGINX_PID" 2>/dev/null || true
        ;;
    dev)
        while [ "$(date +%s)" -lt "$END" ]; do
            cargo build --manifest-path "$DIR/../../Cargo.toml" -p hermian-core >/dev/null 2>&1 || true
            docker pull hello-world >/dev/null 2>&1 || true
            git -C "$DIR/../.." status >/dev/null 2>&1 || true
            # pip/rustup-style: run an installer from /tmp interactively.
            printf '#!/bin/sh\nexit 0\n' > /tmp/hermian-fp-installer.sh && sh /tmp/hermian-fp-installer.sh
            sleep 2
        done
        ;;
    ssh-ansible)
        while [ "$(date +%s)" -lt "$END" ]; do
            ansible localhost -m command -a "echo hi" >/dev/null 2>&1 || true
            ssh -o BatchMode=yes -o StrictHostKeyChecking=no localhost true >/dev/null 2>&1 || true
            sleep 2
        done
        ;;
    ci)
        while [ "$(date +%s)" -lt "$END" ]; do
            cargo test --manifest-path "$DIR/../../Cargo.toml" -p hermian-core >/dev/null 2>&1 || true
            apt-get -s upgrade >/dev/null 2>&1 || true
            sleep 5
        done
        ;;
    *)
        echo "unknown environment: $ENV" >&2
        exit 2
        ;;
esac

# Count HIGH/CRITICAL alerts raised since START (excluding self-protection).
N=$(hermian alerts -n 500 -s high --json 2>/dev/null \
    | awk -v s="$START" '
        { if (match($0, /"ts":"[^"]+"/)) { ts = substr($0, RSTART + 6, RLENGTH - 7); if (ts >= s && $0 !~ /"detection":"Self_"/) n++ } }
        END { print n + 0 }')

if [ "$N" -gt 0 ]; then
    echo "FAIL  $ENV produced $N HIGH/CRITICAL alert(s) during normal operation:" >&2
    hermian alerts -n "$N" -s high >&2 || true
    exit 1
fi
echo "PASS  $ENV produced zero HIGH/CRITICAL alerts over ${DURATION}s"
