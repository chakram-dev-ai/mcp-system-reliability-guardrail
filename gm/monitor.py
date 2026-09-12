"""The monitor process: collectors, policy, enforcement, alerts, health.

    python -m gm.monitor

This is the long-running half. It used to live inside gm.server, whose main()
started the collectors and then handed the process to `mcp.run()` -- a stdio
loop that returns as soon as stdin closes. Started as a service, a scheduled
task or anything else with no client attached, the process exited within
milliseconds and took every (daemon) collector thread with it. So "start the
monitor before the agent" had no working meaning outside a chat session.

Now the monitor never touches stdin or stdout and runs until signalled. The
MCP server (gm.server) is a separate, read-only query process over what this
one writes:

    events log   GM_LOG        every event, hash-chained      (gm.store)
    alerts log   GM_ALERT_LOG  one JSON line per `action: alert`
    status file  GM_STATUS     collectors alive, sessions, heartbeat

Only one monitor may write a given log. A second one refuses to start rather
than splitting hook events between two processes and forking the chain.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .filelock import FileLock
from .policy import Policy
from .sessions import SessionReaper, SessionRegistry
from .store import EventStore

# SIGKILL does not exist on Windows. Python's os.kill() there ignores the
# signal number for everything except the console-control events and calls
# TerminateProcess, so SIGTERM is the portable spelling of "stop this now".
KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)

# Seconds collectors get to fail before the first health check. A subscription
# that dies here (no Sysmon, no right to read Security) is recorded as dead
# rather than counted as running.
STARTUP_GRACE = 1.0


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


@dataclass
class Collector:
    label: str
    thread: Any
    kernel: bool = False


class Monitor:
    def __init__(self, store: EventStore, policy: Policy, *,
                 sessions: SessionRegistry | None = None,
                 alert_log: str | None = None,
                 status_path: str | None = None,
                 policy_path: str | None = None,
                 sock_path: str = "/run/gm/ingest.sock",
                 status_interval: float = 5.0):
        self.store = store
        self.policy = policy
        self.sessions = sessions or SessionRegistry()
        self.alert_log = alert_log
        self.status_path = status_path
        self.policy_path = policy_path
        self.sock_path = sock_path
        self.status_interval = status_interval
        self.collectors: list[Collector] = []
        self.started = time.time()
        self.stopped: float | None = None
        self._reported_dead: set = set()
        self._warned_no_kernel = False

    @classmethod
    def from_settings(cls, s: Settings) -> "Monitor":
        return cls(EventStore(s.log), Policy.load(s.policy), alert_log=s.alert_log,
                   status_path=s.status, policy_path=s.policy, sock_path=s.sock,
                   status_interval=s.status_interval)

    # --- the funnel ---------------------------------------------------------

    def ingest(self, ev: dict) -> None:
        """Single funnel: attribute, evaluate policy, persist, act.

        This never raises. It runs on collector threads -- and on Windows, on
        the EvtSubscribe callback thread and the named-pipe accept loop --
        where an escaping exception silently takes the sensor down and leaves
        a log that looks healthy.
        """
        try:
            # Bridge process tree -> agent session BEFORE the store sees the
            # event, so session-filtered queries can match kernel-side events
            # against hook-side ones.
            self.sessions.annotate(ev)
            ev["verdicts"] = self.policy.evaluate(
                ev, workspace=self.sessions.workspace(ev.get("session")))
            rec = self.store.append(**ev)
        except Exception as exc:
            _stderr(f"[gm] ERROR ingest failed for {ev.get('kind')!r}: {exc!r}")
            return

        for v in rec["verdicts"]:
            try:
                if v["action"] == "kill" and rec.get("pid"):
                    self._enforce_kill(rec)
                elif v["action"] == "alert":
                    self._alert(rec, v)
            except Exception as exc:
                _stderr(f"[gm] ERROR action {v.get('action')!r} for rule "
                        f"{v.get('rule')!r} failed: {exc!r}")

    def _alert(self, rec: dict, verdict: dict) -> None:
        """One line on stderr for a human, one JSON line in the alerts log for a pager.

        Not stdout: when this lived in the MCP server, stdout was the JSON-RPC
        stream, and the client dropped every alert as a parse error. Tail
        GM_ALERT_LOG into your paging path; keep that path out of the agent's
        reach.
        """
        _stderr(f"[gm] {verdict['severity'].upper()} {verdict['rule']} "
                f"seq={rec['seq']} {rec['data']}")
        if not self.alert_log:
            return
        entry = {
            "ts": rec["ts"], "seq": rec["seq"], "rule": verdict["rule"],
            "severity": verdict["severity"], "verdict": verdict["verdict"],
            "kind": rec["kind"], "src": rec["src"], "session": rec["session"],
            "pid": rec["pid"], "data": rec["data"],
        }
        os.makedirs(os.path.dirname(os.path.abspath(self.alert_log)), exist_ok=True)
        with open(self.alert_log, "a", encoding="utf-8", newline="") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
            fh.flush()

    def _enforce_kill(self, rec: dict) -> None:
        pid = rec["pid"]
        # Refuse to shoot the monitor. A rule matching our own probe traffic
        # (or a collector reading a watched path) would otherwise disarm the
        # monitor itself, which is strictly worse than the violation.
        if pid in (os.getpid(), os.getppid()):
            self.store.append(src="gm", kind="enforce.refused", session=rec["session"], pid=pid,
                              data={"reason": "target is the monitor process",
                                    "reason_seq": rec["seq"]})
            return
        try:
            os.kill(pid, KILL_SIGNAL)
            self.store.append(src="gm", kind="enforce.kill", session=rec["session"], pid=pid,
                              data={"signal": int(KILL_SIGNAL), "reason_seq": rec["seq"]})
        except OSError as exc:
            # OSError covers ProcessLookupError, PermissionError, and the plain
            # WinError that os.kill raises when TerminateProcess fails.
            self.store.append(src="gm", kind="enforce.failed", session=rec["session"], pid=pid,
                              data={"error": repr(exc), "reason_seq": rec["seq"]})

    # --- collectors ---------------------------------------------------------

    def add_collector(self, label: str, thread, kernel: bool = False) -> None:
        thread.start()
        self.collectors.append(Collector(label, thread, kernel))

    def start_collectors(self, agent_pid: int | None = None) -> list:
        """Start this platform's sources. Returns the labels started."""
        before = len(self.collectors)
        tracer = os.environ.get("GM_TRACER", "auto")

        if sys.platform == "win32":
            from . import collectors_win

            win = collectors_win.start_windows_collectors(
                self.ingest,
                security_log=os.environ.get("GM_SECURITY_LOG", "1") == "1",
                powershell=os.environ.get("GM_PWSH_LOG", "1") == "1",
            )
            # start_windows_collectors starts its own threads.
            for t in win:
                self.collectors.append(Collector(t.name, t, kernel=t.name == "gm-sysmon"))
        else:
            from . import collectors

            self.add_collector("hook-ingest", collectors.IngestServer(self.sock_path, self.ingest))
            if tracer in ("auto", "eslogger") and sys.platform == "darwin":
                self.add_collector("eslogger", collectors.LineJSONCollector(
                    ["eslogger", "exec", "open", "connect"],
                    collectors.eslogger_normalize, self.ingest), kernel=True)
            elif tracer in ("auto", "auditd") and os.path.exists("/var/log/audit/audit.log"):
                self.add_collector("auditd", collectors.LineJSONCollector(
                    ["tail", "-F", "-n0", "/var/log/audit/audit.log"],
                    collectors.auditd_normalize, self.ingest), kernel=True)

        # psutil works on all three platforms, so the fallback is portable. It
        # is still a poller -- never let it be the only source.
        if agent_pid:
            from .collectors import ProcTreeCollector
            self.add_collector("proctree", ProcTreeCollector(agent_pid, self.ingest))

        # The session table only ever grows otherwise.
        self.add_collector("session-reaper", SessionReaper(self.sessions))
        return [c.label for c in self.collectors[before:]]

    # --- health -------------------------------------------------------------

    def check_health(self) -> dict:
        """Record newly dead collectors, warn when no ground truth is live, write status.

        Checks is_alive(), not what was started. A dead collector is recorded
        in the event log itself (monitor.collector_died), because a quiet log
        and a deaf monitor otherwise look exactly alike.
        """
        alive = [c for c in self.collectors if c.thread.is_alive()]
        for c in self.collectors:
            if c in alive or c.label in self._reported_dead:
                continue
            self._reported_dead.add(c.label)
            _stderr(f"[gm] ERROR collector {c.label!r} is not running")
            self.store.append(src="gm", kind="monitor.collector_died",
                              data={"collector": c.label, "thread": c.thread.name,
                                    "kernel": c.kernel})

        kernel_alive = any(c.kernel for c in alive)
        if not kernel_alive and not self._warned_no_kernel:
            # Loud, because a monitor running on hooks or the poller alone
            # gives you a log that looks healthy and misses anything the tool
            # layer did not announce.
            _stderr("[gm] WARNING: no kernel-level collector is running. Run the "
                    "probe suite before trusting this log.")
            self._warned_no_kernel = True
        elif kernel_alive:
            self._warned_no_kernel = False

        self.write_status()
        return {"alive": [c.label for c in alive],
                "dead": sorted(self._reported_dead),
                "kernel_alive": kernel_alive}

    def status(self) -> dict:
        return {
            "pid": os.getpid(),
            "started": self.started,
            "updated": time.time(),
            "stopped": self.stopped,
            "interval": self.status_interval,
            "log": str(self.store.path),
            "policy": self.policy_path,
            "collectors": [{"name": c.label, "thread": c.thread.name,
                            "alive": c.thread.is_alive(), "kernel": c.kernel}
                           for c in self.collectors],
            "kernel_collector_alive": any(c.kernel and c.thread.is_alive()
                                          for c in self.collectors),
            "tracked_pids": self.sessions.tracked(),
            "sessions": self.sessions.sessions(include_dead=True),
        }

    def write_status(self) -> None:
        """Atomically replace the status file. Never raises."""
        if not self.status_path:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.status_path)), exist_ok=True)
            tmp = self.status_path + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="") as fh:
                json.dump(self.status(), fh, default=str)
            for _ in range(50):
                try:
                    os.replace(tmp, self.status_path)
                    return
                except PermissionError:
                    # Windows refuses to replace a file a reader has open.
                    time.sleep(0.01)
            _stderr(f"[gm] ERROR could not replace {self.status_path}: a reader held it")
        except Exception as exc:
            _stderr(f"[gm] ERROR writing status: {exc!r}")

    # --- lifecycle ----------------------------------------------------------

    def run(self, stop_event: threading.Event, agent_pid: int | None = None,
            grace: float = STARTUP_GRACE) -> None:
        started = self.start_collectors(agent_pid)
        self.store.append(src="gm", kind="monitor.start",
                          data={"collectors": started, "policy": self.policy_path,
                                "pid": os.getpid()})
        if not stop_event.wait(grace):
            self._health_safely()
            while not stop_event.wait(self.status_interval):
                self._health_safely()

    def _health_safely(self) -> None:
        try:
            self.check_health()
        except Exception as exc:
            _stderr(f"[gm] ERROR health check failed: {exc!r}")

    def stop(self) -> None:
        for c in self.collectors:
            stop = getattr(c.thread, "stop", None)
            if stop:
                try:
                    stop()
                except Exception as exc:
                    _stderr(f"[gm] ERROR stopping {c.label!r}: {exc!r}")
        self.stopped = time.time()
        try:
            self.store.append(src="gm", kind="monitor.stop", data={"pid": os.getpid()})
        except Exception as exc:
            _stderr(f"[gm] ERROR recording monitor.stop: {exc!r}")
        self.write_status()


def main() -> int:
    s = Settings.from_env()
    log_dir = os.path.dirname(os.path.abspath(s.log))
    os.makedirs(log_dir, exist_ok=True)
    lock = FileLock(os.path.abspath(s.log) + ".monitor.lock")
    if not lock.acquire(blocking=False):
        _stderr(f"[gm] ERROR another monitor is already writing {s.log}; refusing to "
                "start a second one (it would split hook events and fork the chain)")
        return 2

    stop = threading.Event()

    def _on_signal(signum, frame):
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass

    mon = Monitor.from_settings(s)
    pid = os.environ.get("GM_AGENT_PID")
    _stderr(f"[gm] monitor pid={os.getpid()} log={s.log} policy={s.policy}")
    try:
        mon.run(stop, agent_pid=int(pid) if pid else None)
    finally:
        mon.stop()
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
