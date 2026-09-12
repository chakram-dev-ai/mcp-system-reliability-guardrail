"""Cross-process advisory file locks, stdlib only.

Two uses, both about keeping the hash chain honest once more than one process
can touch the log:

  * EventStore.append takes a lock around read-tip / write / fsync, so the MCP
    server's probe markers and the monitor's events cannot interleave into a
    duplicate seq or a broken prev pointer.
  * gm.monitor takes a non-blocking lock for its whole lifetime, so a second
    monitor on the same log refuses to start instead of splitting hook events
    between two processes and forking the chain.

The OS drops these locks when the process dies, so a crash never leaves a
stale lock behind -- unlike a pid file or an O_EXCL marker.
"""

from __future__ import annotations

import os
import time

if os.name == "nt":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class LockTimeout(OSError):
    pass


class FileLock:
    """An exclusive lock on `path`. The file is created if absent and never
    deleted: removing it would let two processes lock two different inodes."""

    def __init__(self, path: str):
        self.path = str(path)
        self._fd: int | None = None
        self.held = False

    def _open(self) -> int:
        if self._fd is None:
            self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        return self._fd

    def acquire(self, blocking: bool = True, timeout: float = 10.0) -> bool:
        fd = self._open()
        deadline = time.time() + timeout
        while True:
            if _try_lock(fd):
                self.held = True
                return True
            if not blocking:
                return False
            if time.time() >= deadline:
                raise LockTimeout("timed out waiting for lock %s" % self.path)
            time.sleep(0.005)

    def release(self) -> None:
        if self.held and self._fd is not None:
            try:
                _unlock(self._fd)
            finally:
                self.held = False

    def close(self) -> None:
        self.release()
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False
