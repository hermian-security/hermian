#!/usr/bin/env python3
"""Execute a payload from an anonymous memfd (fileless exec).

Simulates the 'fileless exec via memfd_create + execveat/fexecve' technique.
HERMIAN D1 should fire HIGH (execution from memory / deleted inode).

The fd must NOT be MFD_CLOEXEC: the kernel needs it open across the exec so
`/proc/self/fd/N` resolves. A static-ish payload (`/bin/sleep`) is copied in
so the result is a real running process whose exe is `/memfd:... (deleted)`.
"""
import ctypes
import os
import shutil
import sys

libc = ctypes.CDLL(None, use_errno=True)

fd = libc.memfd_create(b"hermian-payload", 0)
if fd < 0:
    print("memfd_create failed", file=sys.stderr)
    sys.exit(1)

with open("/bin/sleep", "rb") as src, os.fdopen(os.dup(fd), "wb", closefd=True) as dst:
    shutil.copyfileobj(src, dst)

# Prefer execveat(fd, "", AT_EMPTY_PATH) which is exactly what fexecve does.
AT_EMPTY_PATH = 0x1000
argv = (ctypes.c_char_p * 3)(b"hermian-payload", b"30", None)
envp = (ctypes.c_char_p * 2)(b"PATH=/usr/bin:/bin", None)
libc.execveat(fd, b"", argv, envp, AT_EMPTY_PATH)
# Fallback for kernels without execveat.
os.execve("/proc/self/fd/%d" % fd, ["hermian-payload", "30"], {"PATH": "/usr/bin:/bin"})
