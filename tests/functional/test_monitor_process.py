"""Functional: gm.monitor as a real process, started the way a service starts it.

No stdin, no console, nobody attached. The monitor used to be gm.server's
main(), which handed the process to an MCP stdio loop that returns the moment
stdin closes -- so a service, a scheduled task or a detached launch exited in
milliseconds and took every collector with it. These tests are the regression
guard for that, over the real hook transport.
"""

import json
import os
import subprocess
import sys
import time
import unittest

from tests.support import (HOOKS, IS_WINDOWS, REPO, TempDirCase, have, hook_payload,
                           minimal_policy, posix_only, requires_yaml)

needs_transport = unittest.skipIf(IS_WINDOWS and not have("win32pipe"),
                                  "the Windows ingest pipe needs pywin32")


def wait_for(predicate, timeout=30.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@requires_yaml
@needs_transport
class TestMonitorProcess(TempDirCase):
    def setUp(self):
        super().setUp()
        self.policy = self.write_policy(minimal_policy())
        self.log = self.path("log", "events.jsonl")
        self.status = self.path("log", "status.json")
        self.pipe = r"\\.\pipe\gm-proc-%d-%s" % (os.getpid(), self.id().rsplit(".", 1)[-1][:24])

    def env(self):
        env = dict(os.environ)
        env.update({
            "PYTHONPATH": str(REPO),
            "GM_LOG": str(self.log),
            "GM_POLICY": self.policy,
            "GM_STATUS_INTERVAL": "0.5",
            # Keep side effects to the sensor under test: no Security or
            # PowerShell log subscriptions, no auditd tail.
            "GM_SECURITY_LOG": "0",
            "GM_PWSH_LOG": "0",
            "GM_TRACER": "none",
            "GM_PIPE": self.pipe,
            "GM_SOCK": str(self.path("ingest.sock")),
        })
        return env

    def start(self):
        out = open(str(self.path("stdout.txt")), "wb")
        err = open(str(self.path("stderr.txt")), "wb")
        self.addCleanup(out.close)
        self.addCleanup(err.close)
        proc = subprocess.Popen([sys.executable, "-m", "gm.monitor"], cwd=str(self.tmp),
                                env=self.env(), stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
        self.addCleanup(self._kill, proc)
        self.assertTrue(wait_for(self.status.exists),
                        "no status file; stderr: %s" % self.stderr())
        return proc

    @staticmethod
    def _kill(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(15)

    def stderr(self):
        p = self.path("stderr.txt")
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""

    def records(self):
        from gm.store import EventStore
        return list(EventStore(self.log).scan())

    def status_doc(self):
        for _ in range(20):
            try:
                return json.loads(self.status.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                time.sleep(0.02)
        self.fail("status file never became readable")

    def test_it_keeps_running_with_no_stdin_attached(self):
        proc = self.start()
        first = self.status_doc()["updated"]
        self.assertTrue(wait_for(lambda: self.status_doc()["updated"] > first, timeout=10),
                        "the heartbeat stopped advancing")
        time.sleep(1.5)
        self.assertIsNone(proc.poll(),
                          "the monitor exited with nothing on stdin; stderr: %s" % self.stderr())
        self.assertIn("monitor.start", [r["kind"] for r in self.records()])

    def test_a_hook_event_reaches_the_log_through_the_real_shim(self):
        self.start()
        env = dict(self.env())
        env["GM_HOOK_TIMEOUT"] = "5"
        proc = subprocess.run([sys.executable, str(HOOKS / "gm_hook.py")],
                              input=json.dumps(hook_payload(session="proc-test")).encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(b"unreachable", proc.stderr)
        self.assertTrue(wait_for(lambda: any(r["session"] == "proc-test"
                                             for r in self.records()), timeout=15),
                        "the hook event never reached the log")

    def test_a_second_monitor_on_the_same_log_refuses_to_start(self):
        self.start()
        second = subprocess.run([sys.executable, "-m", "gm.monitor"], cwd=str(self.tmp),
                                env=self.env(), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertIn(b"another monitor", second.stderr)

    def test_nothing_is_written_to_stdout(self):
        proc = self.start()
        time.sleep(1.5)
        proc.kill()
        proc.wait(15)
        self.assertEqual(self.path("stdout.txt").read_bytes(), b"")

    def test_the_status_file_reports_collectors_by_liveness(self):
        self.start()
        self.assertTrue(wait_for(lambda: len(self.status_doc()["collectors"]) >= 2, timeout=10))
        names = {c["name"]: c["alive"] for c in self.status_doc()["collectors"]}
        ingest = "gm-ingest" if IS_WINDOWS else "hook-ingest"
        self.assertTrue(names.get(ingest), names)

    @posix_only
    def test_sigterm_stops_it_cleanly_and_says_so(self):
        proc = self.start()
        proc.terminate()
        self.assertEqual(proc.wait(20), 0, self.stderr())
        self.assertEqual(self.records()[-1]["kind"], "monitor.stop")
        self.assertIsNotNone(self.status_doc()["stopped"])


if __name__ == "__main__":
    unittest.main()
