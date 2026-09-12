"""Smoke: the package imports, exports what it documents, and starts up.

Cheap and first. If this tier fails, nothing else is worth reading.
"""

import ast
import importlib
import os
import sys
import threading
import unittest

from tests.support import (REPO, TempDirCase, captured_output, make_monitor, minimal_policy,
                           requires_yaml, stub_mcp_if_missing)

MODULES = ["gm", "gm.store", "gm.policy", "gm.sessions", "gm.reconcile",
           "gm.probes", "gm.collectors", "gm.collectors_win", "gm.paths",
           "gm.filelock", "gm.config", "gm.monitor"]

# Every read-only tool the server exposes. Kept here so adding one is a
# deliberate change and removing one cannot happen silently.
EXPECTED_TOOLS = {
    "query_events", "list_violations", "session_summary", "find_blind_spots",
    "verify_log_integrity", "run_probe_suite", "control_coverage",
    "list_sessions", "list_agents", "attribution_health",
}


class TestImports(unittest.TestCase):
    def test_every_module_imports(self):
        for name in MODULES:
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_server_imports_once_mcp_is_available(self):
        stub_mcp_if_missing()
        importlib.import_module("gm.server")

    def test_importing_the_server_touches_no_files(self):
        # gm.server used to build its EventStore at import time, so on a POSIX
        # host `import gm.server` raised PermissionError for anyone who could
        # not create /var/log/gm. Point every path somewhere uncreatable -- a
        # directory under a regular file -- and import and configure anyway.
        import tempfile
        stub_mcp_if_missing()
        fd, blocker = tempfile.mkstemp(prefix="gm-not-a-dir-")
        os.close(fd)
        self.addCleanup(os.unlink, blocker)
        bad = os.path.join(blocker, "sub", "events.jsonl")
        saved = {k: os.environ.get(k) for k in ("GM_LOG", "GM_STATUS", "GM_ALERT_LOG")}
        self.addCleanup(self._restore, saved)
        os.environ["GM_LOG"] = bad
        server = importlib.reload(importlib.import_module("gm.server"))
        server.configure()
        self.assertFalse(os.path.exists(os.path.dirname(bad)))

    @staticmethod
    def _restore(saved):
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_windows_collectors_import_on_any_platform(self):
        # collectors_win must be importable everywhere -- the pywin32 imports
        # are inside the methods on purpose -- or `python -m gm.monitor` fails
        # to start on a POSIX host that merely has the file present.
        mod = importlib.import_module("gm.collectors_win")
        self.assertTrue(callable(mod.sysmon_normalize))

    def test_no_module_imports_pywin32_at_module_level(self):
        for name in ("win32evtlog", "win32pipe", "win32file", "win32security"):
            src = (REPO / "gm" / "collectors_win.py").read_text(encoding="utf-8")
            for line in src.splitlines():
                if line.startswith("import %s" % name) or line.startswith("from %s" % name):
                    self.fail("%s imported at module level in collectors_win.py" % name)

    def test_lazy_package_exports(self):
        import gm
        for name in gm.__all__:
            self.assertIsNotNone(getattr(gm, name), name)

    def test_unknown_attribute_still_raises(self):
        import gm
        with self.assertRaises(AttributeError):
            gm.no_such_thing

    def test_version_is_declared(self):
        import gm
        self.assertRegex(gm.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_exposed_tool_set_is_exactly_what_is_documented(self):
        stub_mcp_if_missing()
        server = importlib.import_module("gm.server")
        exposed = {name for name in EXPECTED_TOOLS
                   if callable(getattr(server, name, None))}
        self.assertEqual(exposed, EXPECTED_TOOLS,
                         "missing: %s" % sorted(EXPECTED_TOOLS - exposed))

        readme = (REPO / "README.md").read_text(encoding="utf-8")
        design = (REPO / "DESIGN.md").read_text(encoding="utf-8")
        for tool in sorted(EXPECTED_TOOLS):
            self.assertIn(tool, readme, "%s is not in the README tool table" % tool)
            self.assertIn(tool, design, "%s is not in DESIGN.md" % tool)


class TestNothingWritesToStdout(unittest.TestCase):
    """stdout is not ours.

    When the monitor lived inside the MCP stdio server, every print() -- the
    alert line, the "no kernel-level collector" warning, ten diagnostics --
    went into the JSON-RPC stream, and the client discarded each one as a
    parse error. Nobody saw the alerts. Enforced by AST so a new print()
    without file=sys.stderr fails here rather than in someone's client log.
    """

    def test_every_print_in_gm_goes_to_stderr(self):
        offenders = []
        for path in sorted((REPO / "gm").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "print":
                    target = [k.value for k in node.keywords if k.arg == "file"]
                    if not target or getattr(target[0], "attr", None) != "stderr":
                        offenders.append("%s:%d" % (path.name, node.lineno))
        self.assertEqual(offenders, [], "print() without file=sys.stderr")

    def test_nothing_in_gm_touches_sys_stdout(self):
        offenders = []
        for path in sorted((REPO / "gm").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Attribute) and node.attr == "stdout"
                        and getattr(node.value, "id", None) == "sys"):
                    offenders.append("%s:%d" % (path.name, node.lineno))
        self.assertEqual(offenders, [])


class TestDependencies(unittest.TestCase):
    def test_mcp_is_pinned_below_2(self):
        # mcp 2.x renamed FastMCP to MCPServer; an unpinned install produced a
        # gm.server that could not be imported at all.
        lines = [l.split("#")[0].strip() for l in
                 (REPO / "requirements.txt").read_text(encoding="utf-8").splitlines()]
        mcp = [l for l in lines if l.startswith("mcp")]
        self.assertEqual(len(mcp), 1, mcp)
        self.assertIn("<2", mcp[0])


class _Thread(threading.Thread):
    """A collector stand-in that lives until stopped, or dies at once."""

    def __init__(self, name, dies=False):
        super().__init__(name=name, daemon=True)
        self.dies = dies
        self._stopping = threading.Event()

    def run(self):
        if not self.dies:
            self._stopping.wait(30)

    def stop(self):
        self._stopping.set()


@requires_yaml
class TestMonitorStartup(TempDirCase):
    def monitor(self):
        mon = make_monitor(self, self.tmp, self.write_policy(minimal_policy()))
        self.addCleanup(self._quiet_stop, mon)
        return mon

    @staticmethod
    def _quiet_stop(mon):
        with captured_output():
            mon.stop()

    def fake_platform(self, kernel_dies=False, no_kernel=False):
        """Stub the platform sensors. The wiring and the health check are under
        test, not Sysmon or auditd."""
        if sys.platform == "win32":
            import gm.collectors_win as win
            original = win.start_windows_collectors
            self.addCleanup(setattr, win, "start_windows_collectors", original)

            def fake(emit, **kw):
                threads = [_Thread("gm-ingest")]
                if not no_kernel:
                    threads.insert(0, _Thread("gm-sysmon", dies=kernel_dies))
                for t in threads:
                    t.start()
                return threads
            win.start_windows_collectors = fake
        else:
            import gm.collectors as col
            original = col.IngestServer
            self.addCleanup(setattr, col, "IngestServer", original)
            col.IngestServer = lambda path, emit: _Thread("gm-ingest")

    def test_start_collectors_reports_what_it_started(self):
        self.fake_platform()
        started = self.monitor().start_collectors()
        self.assertIn("gm-sysmon" if sys.platform == "win32" else "hook-ingest", started)
        self.assertIn("session-reaper", started)

    def test_warns_loudly_on_stderr_when_no_kernel_collector_is_running(self):
        self.fake_platform(no_kernel=True)
        mon = self.monitor()
        cap = captured_output()
        with cap:
            mon.start_collectors()
            mon.check_health()
        self.assertIn("no kernel-level collector", cap.err,
                      "a monitor with no ground-truth source must say so loudly")
        self.assertEqual(cap.out, "")

    def test_a_kernel_collector_that_dies_at_startup_is_not_counted(self):
        mon = self.monitor()
        dying = _Thread("gm-sysmon", dies=True)
        mon.add_collector("sysmon", dying, kernel=True)
        dying.join(5)
        cap = captured_output()
        with cap:
            health = mon.check_health()
        self.assertFalse(health["kernel_alive"])
        self.assertEqual(health["dead"], ["sysmon"])
        self.assertIn("no kernel-level collector", cap.err)
        kinds = [r["kind"] for r in mon.store.scan()]
        self.assertIn("monitor.collector_died", kinds)

    def test_monitor_start_is_recorded_with_the_policy_it_loaded(self):
        self.fake_platform()
        mon = self.monitor()
        stop = threading.Event()
        stop.set()                      # return straight after startup
        mon.run(stop, grace=0.0)
        rec = [r for r in mon.store.scan() if r["kind"] == "monitor.start"]
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["data"]["policy"], mon.policy_path)


if __name__ == "__main__":
    unittest.main()
