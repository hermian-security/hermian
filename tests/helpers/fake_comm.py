#!/usr/bin/env python3
"""Impersonate a service process by comm name, optionally spawning a child.

Used by the HERMIAN attack simulation suite to stand in for services
(nginx, mysqld, ...) without installing them. The process renames itself
via prctl(PR_SET_NAME) so `/proc/<pid>/comm` reads as NAME, then either
sleeps or runs the given command as its child, exactly like a compromised
service spawning a shell would.

Usage:
    fake_comm.py NAME [seconds]
    fake_comm.py NAME [seconds] -- CMD [ARGS...]
"""
import ctypes
import os
import subprocess
import sys
import time

PR_SET_NAME = 15

try:
    _libc = ctypes.CDLL(None, use_errno=True)
except OSError:  # pragma: no cover - non-Linux
    _libc = None


def set_comm(name: str) -> None:
    if _libc is None:
        return
    try:
        _libc.prctl(PR_SET_NAME, name.encode()[:15], 0, 0, 0)
    except Exception:
        pass


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    name = argv[0]
    cmd = None
    if "--" in argv:
        i = argv.index("--")
        cmd = argv[i + 1:]
        argv = argv[:i]
    seconds = float(argv[1]) if len(argv) > 1 else 300.0

    set_comm(name)
    if cmd:
        # Brief pause so the exec watcher sees NAME before the child appears.
        time.sleep(0.3)
        child = subprocess.Popen(cmd)
        try:
            child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            child.kill()
        return 0
    time.sleep(seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
