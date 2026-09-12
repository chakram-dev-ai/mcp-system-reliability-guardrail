"""Append-only, hash-chained event log.

Each record embeds the hash of its predecessor, so any deletion or edit of a
past record breaks the chain and is detectable by verify(). This is the whole
anti-tamper story at the file level -- it does not stop an attacker with write
access from truncating and rebuilding the chain, which is why you should also
ship records off-box (syslog/S3) and run the collector as a different uid than
the agent.

More than one process touches this file: the monitor appends every event, and
the MCP server appends probe markers and reads concurrently. So:

  * append() holds a cross-process lock (gm.filelock) around "read the tip,
    write, fsync", and re-reads the tip whenever the file changed under it.
    A cached tip alone forked the chain the moment a second writer appeared.
  * Constructing a store touches nothing on disk. A read-only query process
    must be able to open a log it has no right to create.
  * Readers skip a trailing line with no newline -- that is a record another
    process is still writing, not damage. A complete line that is not a
    record is damage: queries skip it, verify() reports it.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from .filelock import FileLock

GENESIS = "0" * 64


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


class Malformed(object):
    """Marker yielded by _lines() for a complete line that is not a record."""

    def __init__(self, lineno: int):
        self.lineno = lineno


class EventStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._flock: FileLock | None = None
        self._seq, self._tip = 0, GENESIS
        # File size right after our own last write. Anything else means
        # another writer appended, and the cached tip is stale.
        self._size: int | None = None

    # --- reading ----------------------------------------------------------

    def _lines(self) -> Iterator[Any]:
        """Records in order; Malformed markers for damaged complete lines."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8", newline="") as fh:
            lineno = 0
            for raw in fh:
                lineno += 1
                if not raw.endswith("\n"):
                    return          # in-progress write by another process, or a torn tail
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    yield Malformed(lineno)
                    continue
                if not isinstance(rec, dict) or "seq" not in rec or "hash" not in rec:
                    yield Malformed(lineno)
                    continue
                yield rec

    def scan(self) -> Iterator[dict]:
        for item in self._lines():
            if not isinstance(item, Malformed):
                yield item

    # --- writing ----------------------------------------------------------

    def _refresh_tip(self) -> bool:
        """Re-read seq/tip from disk if the file changed. Caller holds both locks.

        Returns True when the file ends mid-line (a writer crashed mid-record),
        so append() can start its record on a fresh line instead of gluing it
        onto the fragment.
        """
        try:
            size = os.path.getsize(str(self.path))
        except OSError:
            size = 0
        torn = False
        if size and self._size != size:
            seq, tip = 0, GENESIS
            for rec in self.scan():
                seq, tip = rec["seq"], rec["hash"]
            self._seq, self._tip = seq, tip
            with self.path.open("rb") as fh:
                fh.seek(-1, os.SEEK_END)
                torn = fh.read(1) != b"\n"
        elif not size:
            self._seq, self._tip = 0, GENESIS
        return torn

    def append(
        self,
        *,
        src: str,
        kind: str,
        session: str = "unknown",
        pid: int | None = None,
        ppid: int | None = None,
        comm: str | None = None,
        uid: int | None = None,
        data: dict[str, Any] | None = None,
        verdicts: list[dict] | None = None,
    ) -> dict:
        with self._lock:
            if self._flock is None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._flock = FileLock(str(self.path) + ".lock")
            with self._flock:
                torn = self._refresh_tip()
                rec = {
                    "seq": self._seq + 1,
                    "ts": time.time(),
                    "src": src,
                    "kind": kind,
                    "session": session,
                    "pid": pid,
                    "ppid": ppid,
                    "comm": comm,
                    "uid": uid,
                    "data": data or {},
                    "verdicts": verdicts or [],
                    "prev": self._tip,
                }
                rec["hash"] = _digest(rec)
                line = json.dumps(rec, default=str) + "\n"
                with self.path.open("a", encoding="utf-8", newline="") as fh:
                    fh.write(("\n" if torn else "") + line)
                    fh.flush()
                    os.fsync(fh.fileno())
                self._seq, self._tip = rec["seq"], rec["hash"]
                self._size = os.path.getsize(str(self.path))
                return rec

    def close(self) -> None:
        with self._lock:
            if self._flock is not None:
                self._flock.close()
                self._flock = None

    # --- queries ----------------------------------------------------------

    def query(
        self,
        *,
        session: str | None = None,
        kinds: list[str] | None = None,
        src: str | None = None,
        since: float | None = None,
        until: float | None = None,
        only_flagged: bool = False,
        limit: int = 200,
    ) -> list[dict]:
        out: list[dict] = []
        for rec in self.scan():
            if session and rec.get("session") != session:
                continue
            if kinds and rec.get("kind") not in kinds:
                continue
            if src and rec.get("src") != src:
                continue
            if since and rec.get("ts", 0) < since:
                continue
            if until and rec.get("ts", 0) > until:
                continue
            if only_flagged and not rec.get("verdicts"):
                continue
            out.append(rec)
        return out[-limit:]

    def verify(self) -> dict:
        """Recompute the chain. Returns the first break, if any."""
        prev = GENESIS
        expected_seq = 1
        count = 0
        for rec in self._lines():
            if isinstance(rec, Malformed):
                return {"ok": False, "reason": "malformed", "at_line": rec.lineno,
                        "checked": count}
            if rec.get("prev") != prev:
                return {"ok": False, "reason": "chain_break", "at_seq": rec["seq"], "checked": count}
            if rec["seq"] != expected_seq:
                return {"ok": False, "reason": "seq_gap", "at_seq": rec["seq"], "checked": count}
            if _digest(rec) != rec["hash"]:
                return {"ok": False, "reason": "hash_mismatch", "at_seq": rec["seq"], "checked": count}
            prev = rec["hash"]
            expected_seq += 1
            count += 1
        return {"ok": True, "checked": count, "tip": prev}
