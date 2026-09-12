"""Attribute OS events to agent sessions, and find the agents in the first place.

The problem this solves
-----------------------
Hook events carry a session_id. Kernel events carry a PID. Without a bridge
between the two, every auditd/Sysmon event lands under session "unknown",
`session_summary` shows only hook events, and `find_blind_spots` compares hook
events against an empty set of effects -- reporting "nothing undeclared"
regardless of what actually happened.

How the bridge is built
-----------------------
1. The hook shim runs as a CHILD of the agent process, so it can report the
   agent's own PID (walking up past any intermediate shell). That gives us
   session_id -> root PID with no configuration and no guessing.
2. Every subsequent `process.exec` carries a ppid. If the parent is in the map,
   the child inherits its session. Process trees are how attribution
   propagates -- a bash subprocess of a subprocess still resolves.
3. For a PID we have never seen (the collector started mid-session), walk the
   live ancestry with psutil until we hit something we know.

PID reuse is handled by recording process create-time alongside the mapping.
Without it, a recycled PID silently inherits a dead session's attribution,
which is the kind of bug that makes an audit trail worse than useless.

Nothing here ever guesses. An unattributable event stays "unknown" rather than
being assigned to whichever session happens to be active: a wrong attribution
puts one agent's actions in another agent's summary, which is worse than a gap
you can see and measure. `server.attribution_health()` is how you measure it.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

UNKNOWN = "unknown"

# Process names that indicate an agent runtime. The launch surface (CLI vs
# editor) is determined from the ancestor chain, not from these.
AGENT_PATTERNS = [
    (re.compile(r"(^|/|\\)claude(\.exe|\.cmd)?$", re.I), "claude-code"),
    (re.compile(r"claude[-_]?code", re.I), "claude-code"),
    (re.compile(r"(^|/|\\)(aider|goose|cursor-agent)(\.exe)?$", re.I), "other-agent"),
]

# Ancestors that tell you WHERE the agent was launched from.
#
# Anchored to a path separator or start-of-string, and ssh is tested BEFORE
# cli. Both matter: an unanchored "sh" alternative matches inside "sshd", so a
# loose CLI pattern checked first labels every SSH session "cli" -- and the
# surface is the one field here you cannot re-derive later from the log.
SURFACE_PATTERNS = [
    (re.compile(r"(^|[/\\])sshd\b", re.I), "ssh"),
    (re.compile(r"(^|[/\\])(code|code-server)(\.exe)?\b|electron", re.I), "vscode"),
    (re.compile(r"(^|[/\\])(idea|pycharm|webstorm|goland|rider)", re.I), "jetbrains"),
    (re.compile(r"(^|[/\\])(windowsterminal|conhost|bash|zsh|fish|sh|dash|ksh"
                r"|tmux|screen|cmd|powershell|pwsh)(\.exe)?\b", re.I), "cli"),
]

STALE_AFTER = 6 * 3600  # forget sessions whose root died this long ago

# Hard ceiling on the pid table. reap() clears dead sessions, but a monitor
# watching a build that forks tens of thousands of short-lived processes must
# not grow without bound between reaps -- this is a daemon meant to run for
# weeks.
MAX_TRACKED_PIDS = 65536


@dataclass
class Session:
    session_id: str
    root_pid: int
    root_started: float | None = None
    cwd: str | None = None
    surface: str = "unknown"
    agent: str = "unknown"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    pids: set = field(default_factory=set)


class SessionRegistry:
    """Thread-safe PID -> session_id resolution. One instance per monitor."""

    def __init__(self, max_pids: int = MAX_TRACKED_PIDS):
        self._lock = threading.RLock()
        self._sessions: dict = {}
        # pid -> (session_id, create_time). Ordered so eviction is oldest-first.
        self._pid_map: OrderedDict = OrderedDict()
        self._max = max_pids

    # --- registration -----------------------------------------------------

    def register(self, session_id: str, root_pid: int, cwd: str | None = None) -> Session:
        """Called when a hook reports its agent's PID. Idempotent."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                s = Session(session_id=session_id, root_pid=root_pid, cwd=cwd)
                s.root_started = _create_time(root_pid)
                s.agent, s.surface = classify(root_pid)
                self._sessions[session_id] = s
            else:
                s.last_seen = time.time()
                if cwd:
                    s.cwd = cwd
                # An agent can be restarted under the same session id.
                if root_pid != s.root_pid:
                    s.root_pid = root_pid
                    s.root_started = _create_time(root_pid)
                    s.agent, s.surface = classify(root_pid)
            self._bind(root_pid, session_id)
            return s

    def _bind(self, pid: int, session_id: str) -> None:
        """Record pid -> session. Caller holds the lock."""
        if not pid or not session_id or session_id == UNKNOWN:
            return
        self._pid_map[pid] = (session_id, _create_time(pid))
        self._pid_map.move_to_end(pid)
        while len(self._pid_map) > self._max:
            evicted, _ = self._pid_map.popitem(last=False)
            for sess in self._sessions.values():
                sess.pids.discard(evicted)
        s = self._sessions.get(session_id)
        if s:
            s.pids.add(pid)
            s.last_seen = time.time()

    def bind(self, pid: int | None, session_id: str | None) -> None:
        """Public bind, for a collector that already knows the session."""
        if not pid or not session_id or session_id == UNKNOWN:
            return
        with self._lock:
            self._bind(pid, session_id)

    def forget(self, pid: int | None) -> None:
        if not pid:
            return
        with self._lock:
            self._pid_map.pop(pid, None)
            for s in self._sessions.values():
                s.pids.discard(pid)

    # --- resolution -------------------------------------------------------

    def resolve(self, pid: int | None, ppid: int | None = None) -> str:
        """Best-effort session for an OS event. Returns 'unknown' on a miss."""
        if not pid:
            return UNKNOWN
        with self._lock:
            hit = self._pid_map.get(pid)
            if hit and _same_process(pid, hit[1]):
                return hit[0]
            if hit:
                # The PID was recycled: this is a different process wearing a
                # dead one's number. Drop the stale binding rather than
                # inheriting its session.
                del self._pid_map[pid]
                for s in self._sessions.values():
                    s.pids.discard(pid)

            # Direct parent known -> inherit and memoize.
            if ppid:
                phit = self._pid_map.get(ppid)
                if phit and _same_process(ppid, phit[1]):
                    self._bind(pid, phit[0])
                    return phit[0]

            # Cold start: walk live ancestry.
            sid = self._walk_ancestry(pid)
            if sid:
                self._bind(pid, sid)
                return sid
            return UNKNOWN

    def _walk_ancestry(self, pid: int, max_depth: int = 24) -> str | None:
        """Follow live parents until one is known. Caller holds the lock.

        This is what rescues a monitor started mid-session: the process tree
        already exists, we just have not seen its execs. It costs a psutil
        walk per unattributed pid, which is why the result is memoized by the
        caller -- an unknown pid is looked up once, not once per event.
        """
        try:
            import psutil

            p = psutil.Process(pid)
            for _ in range(max_depth):
                p = p.parent()
                if p is None:
                    return None
                hit = self._pid_map.get(p.pid)
                if hit and _same_process(p.pid, hit[1]):
                    return hit[0]
        except Exception:
            return None
        return None

    # --- the funnel entry point ------------------------------------------

    def annotate(self, ev: dict) -> dict:
        """Fill in ev["session"]; mutates and returns ev.

        Called once per event from Monitor.ingest(), so every collector gets the
        same treatment and no source can opt out of it.
        """
        kind = ev.get("kind", "")
        data = ev.get("data") or {}
        declared = ev.get("session") or UNKNOWN

        # A hook event is ground truth for the mapping: it carries both halves.
        if ev.get("src") == "hook" or kind.startswith("tool.") or kind == "session.start":
            root = data.get("agent_pid") or data.get("gm_agent_pid") or ev.get("pid")
            if root and declared != UNKNOWN:
                try:
                    self.register(declared, int(root), cwd=data.get("cwd"))
                except (TypeError, ValueError):
                    pass
            return ev

        if declared != UNKNOWN:
            # A collector that already knows (ProcTreeCollector) stays
            # authoritative, but still teaches the map about this pid.
            self.bind(ev.get("pid"), declared)
            return ev

        ev["session"] = self.resolve(ev.get("pid"), ev.get("ppid"))
        return ev

    # --- introspection ----------------------------------------------------

    def sessions(self, include_dead: bool = False) -> list:
        with self._lock:
            out = []
            for s in self._sessions.values():
                alive = _alive(s.root_pid, s.root_started)
                if not alive and not include_dead:
                    continue
                out.append({
                    "session_id": s.session_id,
                    "agent": s.agent,
                    "surface": s.surface,
                    "root_pid": s.root_pid,
                    # Carried so a reader in another process (gm.server) can
                    # re-check liveness with the same PID-reuse guard.
                    "root_started": s.root_started,
                    "cwd": s.cwd,
                    "alive": alive,
                    "tracked_pids": len(s.pids),
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                })
            return out

    def workspace(self, session_id: str | None) -> str | None:
        """The cwd the agent reported, used for per-session containment."""
        if not session_id or session_id == UNKNOWN:
            return None
        with self._lock:
            s = self._sessions.get(session_id)
            return s.cwd if s else None

    def tracked(self) -> int:
        with self._lock:
            return len(self._pid_map)

    def reap(self) -> int:
        """Drop dead sessions and their PID bindings.

        Called on a timer started by gm.monitor; without that this table
        only ever grows, and a monitor is meant to run for weeks.
        """
        now = time.time()
        with self._lock:
            dead = [
                sid for sid, s in self._sessions.items()
                if not _alive(s.root_pid, s.root_started) and now - s.last_seen > STALE_AFTER
            ]
            for sid in dead:
                for pid in self._sessions[sid].pids:
                    self._pid_map.pop(pid, None)
                del self._sessions[sid]
            return len(dead)


class SessionReaper(threading.Thread):
    """Periodically drops dead sessions. Nothing else calls reap()."""

    daemon = True

    def __init__(self, registry: SessionRegistry, interval: float = 900.0):
        super().__init__(name="gm-session-reaper")
        self.registry = registry
        self.interval = interval
        self._stopping = threading.Event()   # NOT _stop: see collectors.py

    def run(self) -> None:
        while not self._stopping.wait(self.interval):
            try:
                self.registry.reap()
            except Exception as exc:            # pragma: no cover - defensive
                print(f"[gm] session reaper: {exc!r}", file=sys.stderr, flush=True)

    def stop(self) -> None:
        self._stopping.set()


# ---------------------------------------------------------------------------
# Discovery -- for agents that cannot report themselves
# ---------------------------------------------------------------------------

def discover_agents() -> list:
    """Scan for running agent processes and identify their launch surface.

    Use this for agents with no hook support (Cursor, Aider, homegrown), where
    nothing can self-report. It is a fallback: process-name matching is
    heuristic and will both miss renamed binaries and catch unrelated ones.
    Prefer hook self-registration wherever the agent supports it.
    """
    try:
        import psutil
    except ImportError:
        return []

    found = []
    for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            name = p.info.get("name") or ""
            cmd = " ".join(p.info.get("cmdline") or [])
            agent = None
            for pat, label in AGENT_PATTERNS:
                if pat.search(name) or pat.search(cmd):
                    agent = label
                    break
            if not agent:
                continue
            try:
                cwd = p.cwd()
            except Exception:
                cwd = None
            _, surface = classify(p.info["pid"])
            found.append({
                "pid": p.info["pid"],
                "agent": agent,
                "surface": surface,
                "cwd": cwd,
                "cmdline": cmd[:200],
                "started": p.info.get("create_time"),
            })
        except Exception:
            continue
    return found


def classify(pid: int) -> tuple:
    """Return (agent_kind, launch_surface) by inspecting the ancestor chain.

    VS Code and JetBrains both spawn the agent under the IDE process, so the
    surface is visible in the parents -- the agent binary itself is identical
    whether launched from a terminal or an editor.
    """
    agent, surface = "unknown", "unknown"
    try:
        import psutil

        p = psutil.Process(pid)
        name = p.name() or ""
        for pat, label in AGENT_PATTERNS:
            if pat.search(name):
                agent = label
                break
        for _ in range(24):
            p = p.parent()
            if p is None:
                break
            try:
                pname = (p.name() or "") + " " + " ".join((p.cmdline() or [])[:2])
            except Exception:
                break
            for pat, label in SURFACE_PATTERNS:
                if pat.search(pname):
                    return agent, label
    except Exception:
        pass
    return agent, surface


def _create_time(pid: int) -> float | None:
    try:
        import psutil

        return psutil.Process(pid).create_time()
    except Exception:
        return None


def _same_process(pid: int, recorded_start: float | None) -> bool:
    """Guard against PID reuse."""
    if recorded_start is None:
        return True  # cannot verify; accept rather than drop attribution
    now = _create_time(pid)
    return now is None or abs(now - recorded_start) < 1.0


def root_alive(pid: int | None, started: float | None) -> bool:
    """Is `pid` still the process that was registered at `started`?

    Public for gm.server, which reads session rows from the monitor's status
    file and must not trust a liveness flag that may be seconds old.
    """
    if not pid:
        return False
    return _alive(pid, started)


def _alive(pid: int, started: float | None) -> bool:
    try:
        import psutil

        return psutil.pid_exists(pid) and _same_process(pid, started)
    except Exception:
        return False
