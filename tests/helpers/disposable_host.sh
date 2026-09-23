# Sourced by the attack, false-positive and soak scripts. They write to
# /etc/ld.so.preload, cron, authorized_keys, sudoers and systemd, so they must
# only run on a host someone has explicitly marked as disposable.
#
# Mark a host with either:
#   sudo touch /etc/hermian-disposable-host
#   HERMIAN_DISPOSABLE_HOST=1 sudo -E sh tests/run_suite.sh ...

require_disposable_host() {
    if [ "${HERMIAN_DISPOSABLE_HOST:-}" = "1" ] || [ -e /etc/hermian-disposable-host ]; then
        return 0
    fi
    cat >&2 <<'EOF'
refusing to run: this script modifies auth and persistence files
(ld.so.preload, cron, authorized_keys, sudoers, systemd units).

Only run it on a disposable test host. To mark one:
  sudo touch /etc/hermian-disposable-host
or set HERMIAN_DISPOSABLE_HOST=1 for a single run.
EOF
    exit 3
}
