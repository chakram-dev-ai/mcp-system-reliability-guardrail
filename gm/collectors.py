"""Sensors. These run in the monitor process, not the agent process.

Three flavours:

  IngestServer      - a unix socket the Claude Code hook writes to. Gives you
                      SEMANTIC intent (tool name, args) but is in-band: it only
                      sees what the agent's tool layer chose to surface.

  ProcTreeCollector - psutil polling of the agent's process subtree. Portable,
                      no root, but POLLS -- it will miss anything short-lived.
                      Treat it as a development fallback, never as the control.

  LineJSONCollector - wraps an external ground-truth tracer that emits one JSON
                      object per line: `eslogger` on macOS 13+, an auditd tail
                      on Linux, or a bpftrace/Falco script. This is what you
                      actually depend on in production.

Diagnostics go to stderr, never stdout. stdout belongs to whatever launched
the process, and when that was an MCP client over stdio, every stray line
was a JSON-RPC parse error that swallowed the message.

Design rule: the agent must not be able to signal, ptrace, or write to any of
these. Run the monitor as a different uid and put the agent in its own cgroup.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

Emit = Callable[[dict], None]  # takes a canonical event dict


def canonical(
    src: str,
    kind: str,
    *,
    session: str = "unknown",
    pid: int | None = None,
    ppid: int | None = None,
    comm: str | None = None,
    uid: int | None = None,
    **data,
) -> dict:
    return {
        "src": src,
        "kind": kind,
        "session": session,
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "uid": uid,
        "data": {k: v for k, v in data.items() if v is not None},
    }


# ---------------------------------------------------------------------------
# 1. Hook ingest
# ---------------------------------------------------------------------------

class IngestServer(threading.Thread):
    """Accepts newline-delimited JSON from hooks/gm_hook.py.

    Socket is created 0666 so the agent's uid can write, but the monitor owns
    it. Writes are append-only by construction: the hook can only add events,
    never read or remove them.
    """

    daemon = True

    def __init__(self, sock_path: str, emit: Emit):
        super().__init__(name="gm-ingest")
        self.sock_path = sock_path
        self.emit = emit
        # NOT self._stop: threading.Thread already defines a private _stop()
        # method and uses it from _wait_for_tstate_lock(). Shadowing it with an
        # Event makes is_alive() and join() raise TypeError once the thread has
        # finished -- so server.control_coverage(), which calls is_alive() on
        # every collector, blew up exactly when a collector had died, which is
        # the one moment it has something important to report.
        self._stopping = threading.Event()

    def run(self) -> None:
        Path(self.sock_path).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(self.sock_path):
            os.unlink(self.sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock_path)
        os.chmod(self.sock_path, 0o666)
        srv.listen(64)
        srv.settimeout(1.0)
        while not self._stopping.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        srv.close()

    def _serve(self, conn: socket.socket) -> None:
        with conn, conn.makefile("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.emit(self._to_canonical(payload))

    @staticmethod
    def _to_canonical(p: dict) -> dict:
        event = p.get("hook_event_name", "")
        kind = {"PreToolUse": "tool.pre", "PostToolUse": "tool.post"}.get(event, "tool.other")
        ti = p.get("tool_input") or {}
        return canonical(
            "hook",
            kind,
            session=p.get("session_id", "unknown"),
            # The shim reports its parent, which is the agent process itself.
            # gm.sessions binds this pid to the session and every descendant
            # inherits it, which is what makes the reconciler work at all.
            # gm_agent_pid is accepted too: a shim from a different build of
            # this project uses that spelling, and an ingest that silently
            # dropped the pid would take session attribution down with it.
            pid=p.get("agent_pid") or p.get("gm_agent_pid"),
            agent_pid=p.get("agent_pid") or p.get("gm_agent_pid"),
            hook_pid=p.get("hook_pid") or p.get("gm_hook_pid"),
            tool_name=p.get("tool_name"),
            tool_use_id=p.get("tool_use_id"),
            permission_mode=p.get("permission_mode"),
            cwd=p.get("cwd"),
            agent_type=p.get("agent_type"),
            command=ti.get("command"),
            path=ti.get("file_path") or ti.get("notebook_path"),
            content=ti.get("content"),
            new_string=ti.get("new_string"),
            url=ti.get("url"),
            raw_input=ti,
        )

    def stop(self) -> None:
        self._stopping.set()


# ---------------------------------------------------------------------------
# 2. Process-tree polling (portable fallback)
# ---------------------------------------------------------------------------

def _proc_uid(p):
    """Real uid of a psutil.Process, or None where the concept does not exist.

    psutil.Process has no uids() on Windows -- there is no uid, only a SID. The
    unguarded call raised AttributeError on the very first process, which is
    not in the loop's `except (NoSuchProcess, AccessDenied)`, so the whole
    gm-proctree thread died before emitting a single event. The monitor then
    ran on with a collector it believed was live.
    """
    uids = getattr(p, "uids", None)
    if uids is None:
        return None
    try:
        return uids().real
    except Exception:
        return None


class ProcTreeCollector(threading.Thread):
    daemon = True

    def __init__(self, root_pid: int, emit: Emit, session: str = "unknown", interval: float = 0.25):
        super().__init__(name="gm-proctree")
        self.root_pid = root_pid
        self.emit = emit
        self.session = session
        self.interval = interval
        self._seen_pids: set[int] = set()
        self._seen_conns: set[tuple] = set()
        # NOT self._stop: threading.Thread already defines a private _stop()
        # method and uses it from _wait_for_tstate_lock(). Shadowing it with an
        # Event makes is_alive() and join() raise TypeError once the thread has
        # finished -- so server.control_coverage(), which calls is_alive() on
        # every collector, blew up exactly when a collector had died, which is
        # the one moment it has something important to report.
        self._stopping = threading.Event()

    def run(self) -> None:
        import psutil  # imported lazily so the rest of the package works without it

        try:
            root = psutil.Process(self.root_pid)
        except psutil.NoSuchProcess:
            return

        while not self._stopping.is_set():
            try:
                procs = [root, *root.children(recursive=True)]
            except psutil.NoSuchProcess:
                break
            for p in procs:
                try:
                    if p.pid not in self._seen_pids:
                        self._seen_pids.add(p.pid)
                        self.emit(
                            canonical(
                                "proc",
                                "process.exec",
                                session=self.session,
                                pid=p.pid,
                                ppid=p.ppid(),
                                comm=p.name(),
                                uid=_proc_uid(p),
                                exe=p.exe(),
                                argv=p.cmdline(),
                            )
                        )
                    for c in p.net_connections(kind="inet"):
                        if not c.raddr:
                            continue
                        key = (p.pid, c.raddr.ip, c.raddr.port)
                        if key in self._seen_conns:
                            continue
                        self._seen_conns.add(key)
                        self.emit(
                            canonical(
                                "proc",
                                "net.connect",
                                session=self.session,
                                pid=p.pid,
                                comm=p.name(),
                                host=c.raddr.ip,
                                port=c.raddr.port,
                            )
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as exc:
                    # One awkward process must not end the poll loop; a
                    # collector that stops silently is the failure this whole
                    # project is built to detect.
                    print(f"[gm] proctree: skipping pid {p.pid}: {exc!r}", file=sys.stderr, flush=True)
                    continue
            self._stopping.wait(self.interval)

    def stop(self) -> None:
        self._stopping.set()


# ---------------------------------------------------------------------------
# 3. External tracer adapters (the real ground truth)
# ---------------------------------------------------------------------------

class LineJSONCollector(threading.Thread):
    """Run an external tracer and normalize each stdout line into an event."""

    daemon = True

    def __init__(self, argv: list[str], normalizer: Callable[[str], Iterable[dict]], emit: Emit):
        super().__init__(name=f"gm-{argv[0]}")
        self.argv = argv
        self.normalizer = normalizer
        self.emit = emit
        self.proc: subprocess.Popen | None = None
        # NOT self._stop: threading.Thread already defines a private _stop()
        # method and uses it from _wait_for_tstate_lock(). Shadowing it with an
        # Event makes is_alive() and join() raise TypeError once the thread has
        # finished -- so server.control_coverage(), which calls is_alive() on
        # every collector, blew up exactly when a collector had died, which is
        # the one moment it has something important to report.
        self._stopping = threading.Event()

    def run(self) -> None:
        try:
            self.proc = subprocess.Popen(
                self.argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
        except OSError as exc:
            # A missing tracer binary is a configuration error, not a reason to
            # take the monitor down -- but it must be loud, because the result
            # is a log with no ground truth in it.
            print(f"[gm] ERROR cannot start tracer {self.argv[0]!r}: {exc!r}",
                  file=sys.stderr, flush=True)
            return

        assert self.proc.stdout
        try:
            for line in self.proc.stdout:
                if self._stopping.is_set():
                    break
                for ev in self.normalizer(line):
                    self.emit(ev)
        except Exception as exc:
            print(f"[gm] ERROR tracer {self.argv[0]!r} reader stopped: {exc!r}",
                  file=sys.stderr, flush=True)

    def stop(self) -> None:
        """Terminate the tracer and reap it.

        terminate() alone leaves a zombie and an unclosed stdout pipe. That is
        a slow leak in a process meant to run for weeks, and it holds the
        tracer's file descriptors open long after the collector is gone.
        """
        self._stopping.set()
        proc = self.proc
        if not proc:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass


def eslogger_normalize(line: str) -> Iterable[dict]:
    """macOS 13+: `sudo eslogger exec open connect` emits Endpoint Security
    events as JSON lines. This is a first-class kernel-level source."""
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    proc = (e.get("process") or {}).get("audit_token", {})
    base = {
        "pid": proc.get("pid"),
        # ppid is what lets gm.sessions walk a session down the process tree.
        "ppid": (e.get("process") or {}).get("ppid"),
        "comm": ((e.get("process") or {}).get("executable") or {}).get("path"),
        "uid": proc.get("euid"),
    }
    ev = e.get("event") or {}
    if "exec" in ev:
        t = ev["exec"]["target"]
        yield canonical(
            "eslogger", "process.exec",
            exe=(t.get("executable") or {}).get("path"), argv=t.get("args", []), **base
        )
    elif "open" in ev:
        yield canonical(
            "eslogger", "file.open", path=(ev["open"].get("file") or {}).get("path"), **base
        )
    elif "connect" in ev:
        addr = ev["connect"].get("address") or {}
        yield canonical(
            "eslogger", "net.connect",
            host=addr.get("address"), port=addr.get("port"), **base
        )


_AUDIT_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def auditd_normalize(line: str) -> Iterable[dict]:
    """Linux: tail /var/log/audit/audit.log after installing collectors/audit.rules.

    Minimal parser -- production deployments should use auparse or ship to a
    SIEM. Kept here so the pipeline is runnable end to end.
    """
    if "key=" not in line and "key=\"" not in line:
        return
    kv = {k: v.strip('"') for k, v in _AUDIT_KV.findall(line)}
    key = kv.get("key", "")
    base = {
        "pid": int(kv["pid"]) if kv.get("pid", "").isdigit() else None,
        # SYSCALL records carry ppid; gm.sessions needs it to inherit the
        # session from the parent that spawned this process.
        "ppid": int(kv["ppid"]) if kv.get("ppid", "").isdigit() else None,
        "comm": kv.get("comm"),
        "uid": int(kv["uid"]) if kv.get("uid", "").isdigit() else None,
    }
    if key.startswith("gm-exec"):
        yield canonical("auditd", "process.exec", exe=kv.get("exe"), argv=[kv.get("exe", "")], **base)
    elif key.startswith("gm-file"):
        kind = "file.write" if "O_WRONLY" in line or "O_RDWR" in line else "file.open"
        yield canonical("auditd", kind, path=kv.get("name"), **base)
    elif key.startswith("gm-net"):
        yield canonical("auditd", "net.connect", host=kv.get("saddr"), **base)
