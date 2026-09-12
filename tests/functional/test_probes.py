"""Functional: the probe suite really fires, and run_suite really reports.

These execute a canary binary and open a real socket. Nothing touches a
credential or a routable host: the file canary is a decoy, and the egress
canary targets TEST-NET-1, which is guaranteed never routed.

The point of the suite is to distinguish "the control is dead" from "the agent
behaved". A probe that cannot perform its action produces the same FAIL as a
dead control, so each probe's ACTION is verified independently of its verdict.
"""

import os
import socket
import subprocess
import unittest
from pathlib import Path

from tests.support import TempDirCase, requires_yaml, windows_only, posix_only


class ProbeCase(TempDirCase):
    def setUp(self):
        super().setUp()
        from gm import probes
        self.probes = probes
        self.canary = self.path(".gm-canaries")


class TestCanarySetup(ProbeCase):
    def test_file_canary_is_created_and_is_not_a_real_key(self):
        self.probes._setup_file(self.canary)
        f = self.canary / "fake_id_rsa"
        self.assertTrue(f.is_file())
        body = f.read_text(encoding="utf-8")
        self.assertIn("NOT A REAL KEY", body)
        self.assertNotIn("PRIVATE KEY", body,
                         "the decoy must not itself look like a secret to a scanner")

    def test_exec_canary_is_executable_on_this_platform(self):
        self.probes._setup_exec(self.canary)
        exe = self.probes._canary_exec_path(self.canary)
        self.assertTrue(exe.is_file())
        rc = subprocess.run([str(exe)], capture_output=True).returncode
        self.assertEqual(rc, 0, "the canary binary must actually run here")

    @windows_only
    def test_exec_canary_is_a_cmd_file_on_windows(self):
        self.assertEqual(self.probes._canary_exec_path(self.canary).suffix, ".cmd",
                         "a #!/bin/sh script raises WinError 193 and the probe "
                         "reports ERROR instead of testing anything")

    @posix_only
    def test_exec_canary_has_the_exec_bit_on_posix(self):
        self.probes._setup_exec(self.canary)
        exe = self.probes._canary_exec_path(self.canary)
        self.assertTrue(os.access(str(exe), os.X_OK))

    def test_setup_is_idempotent(self):
        for _ in range(3):
            self.probes._setup_file(self.canary)
            self.probes._setup_exec(self.canary)
            self.probes._setup_escape(self.canary)
        self.assertTrue(self.probes.escape_dir(self.canary).is_dir())

    def test_escape_dir_is_a_sibling_not_a_child(self):
        esc = self.probes.escape_dir(self.canary)
        self.assertEqual(esc.parent, self.canary.parent)
        self.assertNotEqual(esc, self.canary)
        self.assertTrue(esc.name.endswith("-escape"))


class TestCanaryActions(ProbeCase):
    def test_file_action_actually_reads(self):
        self.probes._setup_file(self.canary)
        self.probes._action_file(self.canary)      # must not raise

    def test_file_action_without_setup_raises_for_the_suite_to_catch(self):
        with self.assertRaises(OSError):
            self.probes._action_file(self.canary)

    def test_exec_action_runs_the_canary(self):
        self.probes._setup_exec(self.canary)
        self.probes._action_exec(self.canary)

    def test_net_action_issues_a_real_connect(self):
        # The regression this guards: an unresolvable NAME fails in
        # getaddrinfo, so no connect() syscall is ever made and a
        # connect-based collector sees nothing -- permanent FAIL that looks
        # exactly like a dead control.
        self.assertRegex(self.probes.CANARY_IP, r"^\d+\.\d+\.\d+\.\d+$",
                         "the egress canary target must be a literal address")
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((self.probes.CANARY_IP, self.probes.CANARY_PORT))
        except socket.gaierror:
            self.fail("CANARY_IP does not resolve; no connect() would be issued")
        except OSError:
            pass       # timeout/refused is the expected, observable outcome
        finally:
            s.close()

    def test_net_action_completes_quickly_and_does_not_raise(self):
        self.probes._action_net(self.canary)

    def test_canary_target_is_a_reserved_test_network(self):
        self.assertTrue(self.probes.CANARY_IP.startswith("192.0.2."),
                        "RFC 5737 TEST-NET-1 only; never point a canary at a real host")

    def test_write_outside_action_creates_then_removes_its_file(self):
        self.probes._setup_escape(self.canary)
        esc = self.probes.escape_dir(self.canary)
        self.probes._action_write_outside(self.canary)
        self.assertEqual(list(esc.glob("gm-canary-outside-*")), [],
                         "the probe must clean up after itself")

    def test_write_outside_target_is_writable(self):
        # The old target was tempdir's parent -- "/" on Linux, unwritable by a
        # non-root monitor, so the syscall never happened.
        self.probes._setup_escape(self.canary)
        target = self.probes.escape_dir(self.canary) / "probe.txt"
        target.write_text("x", encoding="utf-8")
        self.assertTrue(target.is_file())


@requires_yaml
class TestRunSuite(ProbeCase):
    """run_suite against a store fed by a stand-in 'collector'.

    A real kernel collector is not available in a test, so a fake one turns
    each probe's action into the canonical event auditd/Sysmon would have
    produced. That leaves the parts under test genuine: the probe actions, the
    shipped policy rules, the store, and run_suite's PASS/FAIL logic.
    """

    def build(self, observe=True):
        from gm.policy import Policy
        from gm.store import EventStore
        store = EventStore(self.path("events.jsonl"))
        canary = self.canary
        policy = Policy.load(self.write_policy({
            "vars": {"agent_home": str(self.tmp), "workspace": str(self.path("project")),
                     "canary_dir": str(canary)},
            "rules": [
                {"id": "canary.file", "kind": ["file.read"], "severity": "low",
                 "verdict": "warn", "match": {"path_glob": [str(canary / "fake_id_rsa")]}},
                {"id": "canary.exec", "kind": ["process.exec"], "severity": "low",
                 "verdict": "warn", "match": {"argv_regex": ["(?i)gm-canary-exec"]}},
                {"id": "canary.net", "kind": ["net.connect"], "severity": "low",
                 "verdict": "warn", "match": {"host_not_in": ["github.com"]}},
                {"id": "fs.write_outside_workspace", "kind": ["file.write"],
                 "severity": "high", "verdict": "violation",
                 "match": {"path_not_under": ["${workspace}", "${canary_dir}"]}},
            ],
        }))

        def sensor(kind, **data):
            """Stand in for the kernel: normalize, evaluate, store."""
            if not observe:
                return
            ev = {"src": "auditd", "kind": kind, "session": "unknown", "pid": os.getpid(),
                  "ppid": None, "comm": "python", "uid": None, "data": data}
            ev["verdicts"] = policy.evaluate(ev)
            store.append(**ev)

        return store, policy, sensor

    def instrumented_probes(self, sensor):
        """The real probes, each followed by the event a sensor would emit."""
        from gm.probes import Probe, DEFAULT_PROBES
        out = []
        for p in DEFAULT_PROBES:
            out.append(Probe(p.id, p.expects_rule, p.description, p.setup,
                             self.wrap(p, sensor)))
        return out

    def wrap(self, probe, sensor):
        probes = self.probes

        def action(canary_dir):
            probe.action(canary_dir)
            if probe.id == "file-read":
                sensor("file.read", path=str(canary_dir / "fake_id_rsa"))
            elif probe.id == "exec":
                sensor("process.exec", argv=[str(probes._canary_exec_path(canary_dir))])
            elif probe.id == "egress":
                sensor("net.connect", host=probes.CANARY_IP, port=probes.CANARY_PORT)
            elif probe.id == "fs-escape":
                sensor("file.write",
                       path=str(probes.escape_dir(canary_dir) / "gm-canary-outside-1.txt"))
        return action

    def test_all_probes_pass_when_the_controls_are_live(self):
        store, policy, sensor = self.build(observe=True)
        res = self.probes.run_suite(store, str(self.canary),
                                    probes=self.instrumented_probes(sensor), settle=0.0)
        statuses = {r["probe"]: r["status"] for r in res["results"]}
        self.assertEqual(statuses, {"file-read": "PASS", "exec": "PASS",
                                    "egress": "PASS", "fs-escape": "PASS"}, res)
        self.assertEqual((res["passed"], res["total"]), (4, 4))

    def test_all_probes_fail_when_the_collector_is_dead(self):
        # DESIGN.md 6.2: a dead collector produces no log entry at all. The
        # only way to see it is to trip the control on purpose.
        store, policy, sensor = self.build(observe=False)
        res = self.probes.run_suite(store, str(self.canary),
                                    probes=self.instrumented_probes(sensor), settle=0.0)
        self.assertEqual({r["status"] for r in res["results"]}, {"FAIL"})
        self.assertEqual(res["passed"], 0)

    def test_probe_start_is_recorded_even_on_failure(self):
        store, policy, sensor = self.build(observe=False)
        self.probes.run_suite(store, str(self.canary),
                              probes=self.instrumented_probes(sensor), settle=0.0)
        starts = [r for r in store.scan() if r["kind"] == "probe.start"]
        self.assertEqual(len(starts), 4)
        self.assertIn("expects_rule", starts[0]["data"])

    def test_probe_start_records_the_account_that_ran_it(self):
        # A FAIL caused by an agent-scoped sensor filtering out a
        # monitor-account probe is not a dead control; `ran_as` is how you tell.
        store, policy, sensor = self.build()
        res = self.probes.run_suite(store, str(self.canary),
                                    probes=self.instrumented_probes(sensor), settle=0.0)
        self.assertTrue(res["ran_as"])
        self.assertEqual(store.query(kinds=["probe.start"])[0]["data"]["account"],
                         res["ran_as"])

    def test_latency_is_reported_for_a_passing_probe(self):
        store, policy, sensor = self.build()
        res = self.probes.run_suite(store, str(self.canary),
                                    probes=self.instrumented_probes(sensor), settle=0.0)
        for r in res["results"]:
            self.assertIsNotNone(r["latency_s"])
            self.assertGreaterEqual(r["latency_s"], 0.0)

    def test_a_crashing_probe_reports_error_and_does_not_stop_the_suite(self):
        from gm.probes import Probe
        store, policy, sensor = self.build()

        def explode(canary_dir):
            raise RuntimeError("probe blew up")

        probes = [Probe("boom", "canary.file", "d", lambda d: None, explode)] + \
                 self.instrumented_probes(sensor)
        res = self.probes.run_suite(store, str(self.canary), probes=probes, settle=0.0)
        self.assertEqual(res["results"][0]["status"], "ERROR")
        self.assertIn("probe blew up", res["results"][0]["error"])
        self.assertEqual(res["total"], 5, "the remaining probes must still run")
        self.assertEqual(res["passed"], 4)

    def test_a_failing_setup_does_not_abort_the_suite(self):
        from gm.probes import Probe
        store, policy, sensor = self.build()

        def bad_setup(canary_dir):
            raise OSError("cannot create canary dir")

        probes = [Probe("badsetup", "canary.file", "d", bad_setup, lambda d: None)] + \
                 self.instrumented_probes(sensor)
        res = self.probes.run_suite(store, str(self.canary), probes=probes, settle=0.0)
        self.assertEqual(res["results"][0]["status"], "ERROR")
        self.assertIn("setup failed", res["results"][0]["error"])
        self.assertEqual(res["passed"], 4)

    def test_result_shape_is_stable(self):
        store, policy, sensor = self.build()
        res = self.probes.run_suite(store, str(self.canary),
                                    probes=self.instrumented_probes(sensor), settle=0.0)
        for key in ("ran_at", "passed", "total", "results", "ran_as", "canary_dir", "note"):
            self.assertIn(key, res)
        for r in res["results"]:
            for key in ("probe", "expects_rule", "description", "status",
                        "matching_events", "error", "latency_s"):
                self.assertIn(key, r)

    def test_the_suite_leaves_the_chain_intact(self):
        store, policy, sensor = self.build()
        self.probes.run_suite(store, str(self.canary),
                              probes=self.instrumented_probes(sensor), settle=0.0)
        self.assertTrue(store.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
