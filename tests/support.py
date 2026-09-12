"""Shared test helpers: dependency handling, fixtures, event builders.

Two rules this module exists to enforce:

1. A missing OPTIONAL dependency skips a test, it never silently passes one.
   `mcp` in particular needs Python 3.10+, so gm.server cannot be imported at
   all on older interpreters -- we substitute a minimal FastMCP so the tool
   functions themselves stay testable, and say so in the skip reason when even
   that is not enough.

2. Nothing here writes outside a temp directory. The probe tests exec a canary
   and open a socket, but never touch a real credential or a real host.
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

HOOKS = REPO / "hooks"
COLLECTORS = REPO / "collectors"

IS_WINDOWS = sys.platform == "win32"


# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

def have(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def requires(module: str):
    """Skip decorator for a genuinely optional dependency."""
    return unittest.skipUnless(have(module), f"requires {module}")


requires_yaml = requires("yaml")
requires_psutil = requires("psutil")
requires_pywin32 = unittest.skipUnless(
    IS_WINDOWS and have("win32pipe"), "requires Windows + pywin32"
)
windows_only = unittest.skipUnless(IS_WINDOWS, "Windows-only behaviour")
posix_only = unittest.skipIf(IS_WINDOWS, "POSIX-only behaviour")


class _FastMCPStub:
    """Just enough FastMCP to import gm.server and call its tools directly.

    The @mcp.tool() decorator must return the function unchanged so the tests
    can invoke the real implementation; anything cleverer would be testing the
    stub instead of the server.
    """

    def __init__(self, name):
        self.name = name
        self.tools = []

    def tool(self, *a, **k):
        def deco(fn):
            self.tools.append(fn.__name__)
            return fn
        return deco

    def run(self):  # never called in tests
        raise AssertionError("mcp.run() must not be called from tests")


def stub_mcp_if_missing() -> bool:
    """Returns True if a stub was installed (i.e. the real mcp is absent)."""
    if have("mcp.server.fastmcp"):
        return False
    pkg = sys.modules.setdefault("mcp", types.ModuleType("mcp"))
    srv = sys.modules.setdefault("mcp.server", types.ModuleType("mcp.server"))
    fast = sys.modules.setdefault("mcp.server.fastmcp", types.ModuleType("mcp.server.fastmcp"))
    fast.FastMCP = _FastMCPStub
    srv.fastmcp = fast
    pkg.server = srv
    return True


# ---------------------------------------------------------------------------
# Temp fixtures
# ---------------------------------------------------------------------------

class captured_output:
    """Swallow stdout/stderr for tests that deliberately trip an error path.

    Those paths print on purpose -- that is the design -- but a release gate
    whose output is full of expected tracebacks trains people not to read it.
    """

    def __enter__(self):
        import io
        self._out, self._err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        return sys.stdout

    def __exit__(self, *exc):
        self.out = sys.stdout.getvalue()
        self.err = sys.stderr.getvalue()
        sys.stdout, sys.stderr = self._out, self._err
        return False


class TempDirCase(unittest.TestCase):
    """TestCase with a per-test temp directory, cleaned up afterwards."""

    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp(prefix="gmtest-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)

    def path(self, *parts) -> Path:
        return self.tmp.joinpath(*parts)

    def write_policy(self, doc: dict, name: str = "policy.yaml") -> str:
        """Serialise a policy dict to real YAML on disk and return the path."""
        import yaml
        p = self.path(name)
        p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        return str(p)

    def new_store(self, name: str = "events.jsonl"):
        from gm.store import EventStore
        store = EventStore(self.path(name))
        # The store keeps its lock file open; Windows will not delete a temp
        # directory with an open handle in it.
        self.addCleanup(store.close)
        return store


# ---------------------------------------------------------------------------
# Event builders -- keep the shape in one place so a schema change is one edit
# ---------------------------------------------------------------------------

def event(kind: str, src: str = "auditd", session: str = "unknown",
          pid=None, ppid=None, comm=None, uid=None, **data) -> dict:
    """A canonical event as the collectors emit it (None data fields dropped)."""
    return {
        "src": src, "kind": kind, "session": session,
        "pid": pid, "ppid": ppid, "comm": comm, "uid": uid,
        "data": {k: v for k, v in data.items() if v is not None},
    }


def stored(kind: str, seq: int = 1, ts: float = 0.0, verdicts=None, **kw) -> dict:
    """An event as it looks AFTER the store has written it."""
    rec = event(kind, **kw)
    rec.update({"seq": seq, "ts": ts, "verdicts": verdicts or []})
    return rec


def hook_payload(tool_name="Bash", command="echo hi", session="sess-1",
                 agent_pid=4242, event_name="PreToolUse", **tool_input) -> dict:
    """The JSON Claude Code hands the hook, plus the fields the shim adds."""
    ti = {}
    if command is not None:
        ti["command"] = command
    ti.update(tool_input)
    return {
        "hook_event_name": event_name,
        "session_id": session,
        "tool_name": tool_name,
        "tool_input": ti,
        "cwd": "/home/agent/project",
        "agent_pid": agent_pid,
        "hook_pid": agent_pid + 1,
    }


# ---------------------------------------------------------------------------
# Minimal policies used by several suites
# ---------------------------------------------------------------------------

def minimal_policy(agent_home="/home/agent", extra_rules=None) -> dict:
    doc = {
        "vars": {
            "agent_home": agent_home,
            "workspace": "${agent_home}/project",
            "canary_dir": "${agent_home}/.gm-canaries",
        },
        "rules": [
            {"id": "cred.read", "kind": ["file.open", "file.read"],
             "severity": "critical", "verdict": "violation", "action": "alert",
             "match": {"path_glob": ["~/.ssh/**"]}},
            {"id": "exec.privilege", "kind": ["process.exec"],
             "severity": "critical", "verdict": "violation", "action": "kill",
             "match": {"argv_regex": [r"\bsudo\b"]}},
            {"id": "net.egress_allowlist", "kind": ["net.connect"],
             "severity": "high", "verdict": "violation", "action": "alert",
             "match": {"host_not_in": ["github.com"]}},
        ],
    }
    if extra_rules:
        doc["rules"].extend(extra_rules)
    return doc


# ---------------------------------------------------------------------------
# The two processes, bound to the same throwaway files
# ---------------------------------------------------------------------------

def settings_for(tmp: Path, policy_path: str):
    """Settings pointing every GM_* path into `tmp`."""
    from gm.config import Settings
    tmp = Path(tmp)
    return Settings(log=str(tmp / "events.jsonl"), policy=str(policy_path),
                    sock=str(tmp / "ingest.sock"), alert_log=str(tmp / "alerts.jsonl"),
                    status=str(tmp / "status.json"), status_interval=5.0)


def make_monitor(case: unittest.TestCase, tmp: Path, policy_path: str):
    """A gm.monitor.Monitor writing under `tmp`. Nothing is started."""
    from gm.monitor import Monitor
    mon = Monitor.from_settings(settings_for(tmp, policy_path))
    case.addCleanup(mon.store.close)
    return mon


def load_server(tmp: Path, policy_path: str):
    """gm.server bound to the files a make_monitor(tmp, ...) writes.

    The server reads what the monitor wrote -- events, alerts, status -- and
    never shares memory with it, so tests exercise the same boundary a real
    deployment has.
    """
    stub_mcp_if_missing()
    import gm.server as server
    server.configure(settings_for(tmp, policy_path))
    return server


def read_jsonl(path) -> list:
    out = []
    with open(str(path), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
