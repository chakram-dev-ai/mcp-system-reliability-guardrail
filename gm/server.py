"""MCP server: the read-only query surface over what gm.monitor writes.

    python -m gm.server        # launched by an MCP client, over stdio

IMPORTANT: do not attach this server to the agent you are monitoring. Attach it
to a separate supervisor session (your own Claude Desktop / Claude Code, a CI
job, or a reviewing agent). An agent that can query and reason about its own
monitor can also learn exactly which of its actions were invisible.

This process runs no collectors. It lives exactly as long as the client that
launched it, which is fine for a query surface and was fatal for a sensor --
see gm.monitor for why the two were split. Everything it knows comes from
three files the monitor maintains: the event log, the alerts log, and the
status file (collectors alive, sessions, heartbeat).

Importing it touches no files. stdout carries the protocol and nothing else.

Every tool is read-only except run_probe_suite, which fires canaries and
records probe.start markers. There is deliberately no tool to mute a rule,
delete events, or stop a collector -- those are config-file operations, done
out of band.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter

from mcp.server.fastmcp import FastMCP

from . import paths
from .config import Settings
from .policy import Policy
from .probes import run_suite
from .reconcile import reconcile
from .sessions import discover_agents, root_alive
from .store import EventStore

mcp = FastMCP("guardrail-monitor")

# Records the monitor and the probe suite write about themselves. They are not
# the agent's activity, so they never count as unattributed.
BOOKKEEPING_SOURCES = {"hook", "gm", "probe"}


class _Context:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = EventStore(settings.log)     # no disk access until used
        self._policy: Policy | None = None

    @property
    def policy(self) -> Policy:
        if self._policy is None:
            self._policy = Policy.load(self.settings.policy)
        return self._policy


_ctx: _Context | None = None


def configure(settings: Settings | None = None) -> None:
    """Bind the tools to a log/policy/status. Defaults to the environment."""
    global _ctx
    _ctx = _Context(settings or Settings.from_env())


def _context() -> _Context:
    if _ctx is None:
        configure()
    return _ctx


def _read_status() -> dict:
    """The monitor's heartbeat, judged for staleness.

    A status file that stopped updating is a monitor that died or hung. Every
    tool that reports on collectors or sessions says so rather than presenting
    a frozen snapshot as current.
    """
    path = _context().settings.status
    doc = None
    for _ in range(5):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            break
        except FileNotFoundError:
            return {"running": False, "collectors": [], "sessions": [], "tracked_pids": 0,
                    "reason": "no status file at %s: the monitor has not run against "
                              "this log, or GM_STATUS differs between monitor and "
                              "server" % path}
        except PermissionError:
            time.sleep(0.01)             # mid-replace on Windows
        except (OSError, ValueError) as exc:
            return {"running": False, "collectors": [], "sessions": [], "tracked_pids": 0,
                    "reason": "status file unreadable: %r" % (exc,)}
    if doc is None:
        return {"running": False, "collectors": [], "sessions": [], "tracked_pids": 0,
                "reason": "status file stayed locked"}

    age = time.time() - float(doc.get("updated") or 0)
    stale_after = max(3 * float(doc.get("interval") or 5), 15.0)
    if doc.get("stopped"):
        running, reason = False, "the monitor stopped at %s" % time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(float(doc["stopped"])))
    elif age > stale_after:
        running, reason = False, ("status is %.0fs old (stale after %.0fs): the monitor "
                                  "is not running or is hung" % (age, stale_after))
    else:
        running, reason = True, None
    return {
        "running": running,
        "reason": reason,
        "age_s": round(age, 1),
        "pid": doc.get("pid"),
        "collectors": doc.get("collectors") or [],
        "kernel_collector_alive": bool(doc.get("kernel_collector_alive")) and running,
        "tracked_pids": doc.get("tracked_pids", 0),
        "sessions": doc.get("sessions") or [],
    }


def _monitor_summary(st: dict) -> dict:
    return {
        "running": st["running"],
        "reason": st["reason"],
        "age_s": st.get("age_s"),
        "pid": st.get("pid"),
        "kernel_collector_alive": st.get("kernel_collector_alive", False),
        "dead_collectors": [c["name"] for c in st["collectors"] if not c.get("alive")],
    }


def _live_sessions(st: dict, include_dead: bool) -> list:
    try:
        import psutil  # noqa: F401
        can_check = True
    except ImportError:
        can_check = False
    out = []
    for row in st["sessions"]:
        row = dict(row)
        if can_check:
            row["alive"] = root_alive(row.get("root_pid"), row.get("root_started"))
        if row.get("alive") or include_dead:
            out.append(row)
    return out


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def query_events(
    session: str | None = None,
    kinds: list[str] | None = None,
    minutes: int = 60,
    only_flagged: bool = False,
    limit: int = 100,
) -> dict:
    """Query the telemetry log. `kinds` filters on canonical event kinds such as
    process.exec, file.write, net.connect, tool.pre."""
    events = _context().store.query(
        session=session, kinds=kinds, since=time.time() - minutes * 60,
        only_flagged=only_flagged, limit=limit,
    )
    return {"count": len(events), "events": events}


@mcp.tool()
def list_violations(session: str | None = None, minutes: int = 1440, min_severity: str = "medium") -> dict:
    """Every event that tripped a rule at or above `min_severity`."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    floor = order.get(min_severity, 1)
    hits = []
    for e in _context().store.query(session=session, since=time.time() - minutes * 60,
                                    only_flagged=True, limit=10000):
        keep = [v for v in e["verdicts"] if order.get(v["severity"], 0) >= floor and v["verdict"] != "allow"]
        if keep:
            hits.append({"seq": e["seq"], "ts": e["ts"], "kind": e["kind"], "src": e["src"],
                         "pid": e["pid"], "data": e["data"], "verdicts": keep})
    return {"count": len(hits), "violations": hits}


@mcp.tool()
def session_summary(session: str, minutes: int = 1440) -> dict:
    """Activity profile for one agent session: event mix, rules tripped,
    binaries executed, hosts contacted, files written."""
    events = _context().store.query(session=session, since=time.time() - minutes * 60, limit=100000)
    if not events:
        return {"session": session, "found": False}
    rules = Counter(v["rule"] for e in events for v in e["verdicts"])
    return {
        "session": session,
        "found": True,
        "span_s": round(events[-1]["ts"] - events[0]["ts"], 1),
        "events": len(events),
        "by_kind": dict(Counter(e["kind"] for e in events)),
        "by_source": dict(Counter(e["src"] for e in events)),
        "rules_tripped": dict(rules),
        "binaries": sorted({paths.basename(e["data"].get("exe", "")) for e in events
                            if e["kind"] == "process.exec" and e["data"].get("exe")}),
        "hosts": sorted({e["data"]["host"] for e in events
                         if e["kind"] == "net.connect" and e["data"].get("host")}),
        "files_written": sorted({e["data"]["path"] for e in events
                                 if e["kind"].startswith("file.w") and e["data"].get("path")})[:100],
    }


@mcp.tool()
def find_blind_spots(session: str, minutes: int = 1440, window_seconds: float = 30.0) -> dict:
    """Diff what the agent's hooks declared against what the OS actually saw.

    High `undeclared_rate` means the agent is acting through paths your hooks
    don't cover -- that is a guardrail gap, whether or not it was malicious."""
    events = _context().store.query(session=session, since=time.time() - minutes * 60, limit=100000)
    result = reconcile(events, window=window_seconds)
    result["undeclared"] = result["undeclared"][:50]
    result["unobserved"] = result["unobserved"][:50]
    return result


@mcp.tool()
def verify_log_integrity() -> dict:
    """Recompute the hash chain end to end. A break means records were edited
    or removed after the fact."""
    return _context().store.verify()


@mcp.tool()
def run_probe_suite(settle_seconds: float = 2.0) -> dict:
    """Fire canary probes and report which controls actually fired.

    Run this on a schedule, not just on demand. A control that silently stopped
    working looks identical to an agent that behaved well."""
    ctx = _context()
    st = _read_status()
    result = run_suite(ctx.store, ctx.policy.vars.get("canary_dir", "~/.gm-canaries"),
                       settle=settle_seconds)
    # Every probe FAILs when the monitor is down. Say which it was.
    result["monitor"] = _monitor_summary(st)
    return result


@mcp.tool()
def control_coverage(days: int = 7) -> dict:
    """Which policy rules have ever fired, and which have never fired. A rule
    that has never fired is either well-targeted or broken -- the probe suite
    is what tells you which. Also reports which collectors are actually alive."""
    ctx = _context()
    since = time.time() - days * 86400
    fired = Counter(v["rule"] for e in ctx.store.query(since=since, only_flagged=True, limit=100000)
                    for v in e["verdicts"])
    all_rules = ctx.policy.rule_ids()
    st = _read_status()
    return {
        "window_days": days,
        "fired": {r: fired[r] for r in all_rules if fired[r]},
        "never_fired": [r for r in all_rules if not fired[r]],
        "collectors_running": [c["name"] for c in st["collectors"]
                               if c.get("alive") and st["running"]],
        "tracked_pids": st["tracked_pids"],
        "monitor": _monitor_summary(st),
    }


@mcp.tool()
def list_sessions(include_dead: bool = False) -> dict:
    """Agent sessions the monitor has seen, with their launch surface (cli,
    vscode, jetbrains), working directory, and whether they are still alive.

    Sessions register themselves on the agent's first tool call, so an agent
    appears here without any configuration -- but only if its hooks are
    installed. An agent running without hooks shows up in list_agents() and
    not here, which is itself the finding."""
    st = _read_status()
    found = _live_sessions(st, include_dead)
    return {"count": len(found), "sessions": found, "tracked_pids": st["tracked_pids"],
            "monitor": _monitor_summary(st)}


@mcp.tool()
def list_agents() -> dict:
    """Scan the host for agent processes, whether or not they are registered.

    Cross-reference with list_sessions(): a process here with no matching
    session is an agent running WITHOUT hook coverage. Its kernel activity is
    still captured, but it has no declared intent to reconcile against, so
    find_blind_spots cannot help you for that agent."""
    running = discover_agents()
    st = _read_status()
    registered = {s["root_pid"] for s in _live_sessions(st, include_dead=False)}
    for r in running:
        r["hooks_registered"] = r["pid"] in registered
    unmonitored = [r for r in running if not r["hooks_registered"]]
    if not st["running"]:
        note = ("The monitor is not running (%s), so no agent can be reporting "
                "hooks to it." % st["reason"])
    elif unmonitored:
        note = ("Agents without hook coverage have OS telemetry but no "
                "declared intent -- reconciliation is unavailable for them.")
    else:
        note = "All discovered agents are reporting hooks."
    return {
        "count": len(running),
        "agents": running,
        "without_hook_coverage": len(unmonitored),
        "note": note,
        "monitor": _monitor_summary(st),
    }


@mcp.tool()
def attribution_health(minutes: int = 60) -> dict:
    """How many recent OS events could not be attributed to a session.

    A high unknown_rate means the PID->session bridge is failing, which
    silently empties every per-session view -- a broken bridge and a
    well-behaved agent produce the same empty session_summary. Check this
    before trusting a quiet report, the same way you check the probe suite
    before trusting a quiet log."""
    events = _context().store.query(since=time.time() - minutes * 60, limit=100000)
    os_events = [e for e in events if e["src"] not in BOOKKEEPING_SOURCES]
    unknown = [e for e in os_events if e["session"] == "unknown"]
    rate = (len(unknown) / len(os_events)) if os_events else 0.0
    return {
        "os_events": len(os_events),
        "unattributed": len(unknown),
        "unknown_rate": round(rate, 4),
        "by_kind": dict(Counter(e["kind"] for e in unknown)),
        "healthy": rate < 0.1,
        "note": "Two usual causes: the collector started mid-session and the "
                "ancestry walk failed, or an agent has no hooks installed so "
                "nothing ever registered a root PID -- check list_agents().",
    }


def main() -> None:
    configure()
    mcp.run()


if __name__ == "__main__":
    main()
