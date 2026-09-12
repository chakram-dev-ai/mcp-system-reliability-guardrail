"""Control-efficacy probes.

Detection rots silently. A collector that dies, a policy path that stopped
matching after a refactor, an eBPF program that failed to load -- none of these
announce themselves, and the log just gets quieter. The only way to know your
guardrails still work is to trip them on purpose, on a schedule.

Every probe here is a *canary*: it touches a decoy file, execs a decoy binary,
or resolves a decoy hostname. Nothing here is an evasion technique and nothing
touches a real secret. The probe's job is only to answer "did the control fire?"

Run probes in the same execution context as the agent -- same container, same
uid, same cgroup -- or you are testing a different code path than the one you
care about.
"""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# RFC 5737 TEST-NET-1. A literal address on purpose: an unresolvable name like
# "gm-canary.invalid" fails in getaddrinfo, so no connect() syscall is ever
# issued and a connect-based collector (auditd -S connect, Sysmon 3) sees
# nothing -- the probe then reports FAIL forever and looks like a dead control.
# TEST-NET-1 is guaranteed never routed, so the connect is issued and then
# times out, which is exactly the observable event we want.
CANARY_IP = os.environ.get("GM_CANARY_IP", "192.0.2.1")
CANARY_PORT = int(os.environ.get("GM_CANARY_PORT", "443"))

# Separately resolvable name, for the DNS-visibility probe on platforms that
# report queries (Sysmon 22). Never resolves, which is the point.
CANARY_HOST = "gm-canary.invalid"


@dataclass
class Probe:
    id: str
    expects_rule: str
    description: str
    setup: Callable[[Path], None]
    action: Callable[[Path], None]


def _setup_file(canary_dir: Path) -> None:
    canary_dir.mkdir(parents=True, exist_ok=True)
    f = canary_dir / "fake_id_rsa"
    f.write_text("NOT A REAL KEY - guardrail monitor canary\n", encoding="utf-8")
    f.chmod(0o600)


def _action_file(canary_dir: Path) -> None:
    (canary_dir / "fake_id_rsa").read_text(encoding="utf-8")


def _canary_exec_path(canary_dir: Path) -> Path:
    # A "#!/bin/sh" file is not executable on Windows -- CreateProcess rejects
    # it with WinError 193 and the probe reports ERROR rather than testing
    # anything. Both names contain "gm-canary-exec" so one argv_regex rule
    # covers the pair.
    return canary_dir / ("gm-canary-exec.cmd" if os.name == "nt" else "gm-canary-exec")


def _setup_exec(canary_dir: Path) -> None:
    canary_dir.mkdir(parents=True, exist_ok=True)
    p = _canary_exec_path(canary_dir)
    if os.name == "nt":
        p.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
    else:
        p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _action_exec(canary_dir: Path) -> None:
    subprocess.run([str(_canary_exec_path(canary_dir))], check=False, capture_output=True)


def _setup_noop(canary_dir: Path) -> None:
    canary_dir.mkdir(parents=True, exist_ok=True)


def _action_net(canary_dir: Path) -> None:
    # Resolve first so a DNS-visibility collector (Sysmon 22) has something to
    # see; the failure is expected and ignored.
    try:
        socket.getaddrinfo(CANARY_HOST, CANARY_PORT)
    except OSError:
        pass
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((CANARY_IP, CANARY_PORT))
    except OSError:
        pass  # the attempt is what we are measuring, not the outcome
    finally:
        s.close()


ESCAPE_SUFFIX = "-escape"


def escape_dir(canary_dir: Path) -> Path:
    """Where the containment probe writes: a fixed, watchable spot that is
    deliberately NOT allowlisted.

    Not tempfile.gettempdir().parent, which the original used: on Linux that is
    "/", unwritable by a non-root monitor, so the open never happened and the
    probe reported a dead control that was in fact alive.

    A sibling of the canary dir rather than somewhere in $HOME, because the
    sensor needs a *specific* path to watch -- an auditd -w on a home directory
    or a SACL on one buries the log. It sits outside `canary_dir` (the path
    test is boundary-anchored, so "...gm-canaries-escape" is not under
    "...gm-canaries") and outside the workspace, which is exactly what
    fs.write_outside_workspace should fire on.
    """
    return canary_dir.parent / (canary_dir.name + ESCAPE_SUFFIX)


def _setup_escape(canary_dir: Path) -> None:
    escape_dir(canary_dir).mkdir(parents=True, exist_ok=True)


def _action_write_outside(canary_dir: Path) -> None:
    target = escape_dir(canary_dir) / f"gm-canary-outside-{os.getpid()}.txt"
    try:
        target.write_text("canary\n", encoding="utf-8")
    except OSError:
        pass  # blocked by a sandbox is a valid outcome; the syscall still fired
    try:
        target.unlink()   # not unlink(missing_ok=True): that is Python 3.8+
    except OSError:
        pass


DEFAULT_PROBES = [
    Probe("file-read", "canary.file", "Credential-shaped file read is observed", _setup_file, _action_file),
    Probe("exec", "canary.exec", "Process execution is observed", _setup_exec, _action_exec),
    Probe("egress", "canary.net", "Outbound connect to non-allowlisted host is observed", _setup_noop, _action_net),
    Probe("fs-escape", "fs.write_outside_workspace", "Write outside the workspace is observed", _setup_escape, _action_write_outside),
]


def _probe_account() -> str:
    """Who is firing the probes. Recorded because it decides whether they can pass."""
    for var in ("USERNAME", "USER", "LOGNAME"):
        who = os.environ.get(var)
        if who:
            return who
    return "unknown"


def run_suite(store, canary_dir: str, probes=None, settle: float = 2.0) -> dict:
    """Fire each probe, then check whether its rule appeared in the log.

    `settle` covers collector latency. Tune it up if you use a batching
    tracer; a probe that reports FAIL because you did not wait long enough is
    worse than no probe at all.

    EXECUTION CONTEXT IS PART OF THE TEST. Called through the MCP tool, this
    runs inside the MCP server process, under the SUPERVISOR's account -- while the
    shipped sensor configs are scoped to the AGENT's account (`-F auid=` in
    collectors/audit.rules, `<User condition="contains">agent</User>` in
    collectors/sysmon-config.xml). A probe filtered out at the sensor reports
    FAIL for a control that is working perfectly, which is the same false alarm
    in the other direction.

    Both configs therefore carry canary-specific rules keyed on the canary
    artifacts themselves -- path, image name, address -- so the suite is
    meaningful from either account. The account is recorded on every
    probe.start so a FAIL can be told apart from a scoping artifact.
    """
    probes = probes or DEFAULT_PROBES
    cdir = Path(os.path.expanduser(canary_dir))
    account = _probe_account()
    results = []

    for probe in probes:
        try:
            probe.setup(cdir)
            setup_error = None
        except Exception as exc:
            # One unwritable canary dir must not abort the remaining probes --
            # a partial suite silently reporting 0/0 is the failure mode this
            # whole module exists to prevent.
            setup_error = f"setup failed: {exc!r}"
        t0 = time.time()
        marker_error = None
        try:
            store.append(
                src="probe", kind="probe.start", session="gm-probe", pid=os.getpid(),
                data={"probe": probe.id, "expects_rule": probe.expects_rule,
                      "account": account, "canary_dir": str(cdir)},
            )
        except OSError as exc:
            # The supervisor may only have read access to the log. The probe
            # is still worth firing -- its verdict comes from what the MONITOR
            # recorded -- but the missing marker is reported, not hidden.
            marker_error = "probe.start not recorded: %r" % (exc,)
        error = setup_error
        if setup_error is None:
            try:
                probe.action(cdir)
            except Exception as exc:  # a probe that crashes is an inconclusive probe
                error = repr(exc)
        time.sleep(settle)

        fired = [
            e for e in store.query(since=t0, only_flagged=True, limit=5000)
            if any(v["rule"] == probe.expects_rule for v in e["verdicts"])
        ]
        results.append({
            "probe": probe.id,
            "expects_rule": probe.expects_rule,
            "description": probe.description,
            "status": "PASS" if fired else ("ERROR" if error else "FAIL"),
            "matching_events": len(fired),
            "error": error,
            "latency_s": round(fired[0]["ts"] - t0, 3) if fired else None,
            "marker_error": marker_error,
        })

    passed = sum(r["status"] == "PASS" for r in results)
    return {
        "ran_at": time.time(),
        "passed": passed,
        "total": len(results),
        "results": results,
        # Surfaced because it is the first thing to check on a FAIL: if the
        # sensor is scoped to the agent account and the probes ran as the
        # monitor, the control may be fine and the test wrong.
        "ran_as": account,
        "canary_dir": str(cdir),
        "note": "FAIL means the control did not fire. Check that the sensor "
                "covers the account in `ran_as` and the paths under "
                "`canary_dir`, then investigate the collector -- before "
                "trusting any quiet period in the log.",
    }
