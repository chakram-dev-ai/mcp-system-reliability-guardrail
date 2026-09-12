"""Functional: the whole funnel, hook event to MCP answer, across the process split.

Events go through gm.monitor.Monitor.ingest() -- the single function DESIGN.md
3.1 says nothing bypasses -- and are then queried through gm.server's real MCP
tool implementations, which share no memory with the monitor: they read the
event log, the alerts log and the status file, exactly as a separate process
would. If this file passes, the two halves are wired to each other and not
merely correct in isolation.
"""

import io
import json
import os
import sys
import time
import unittest

from tests.support import (TempDirCase, event, minimal_policy, make_monitor, load_server,
                           hook_payload, read_jsonl, requires_yaml)


class FakeThread(object):
    """Stands in for a collector thread in health/status tests."""

    def __init__(self, name, alive=True):
        self.name = name
        self.alive = alive

    def is_alive(self):
        return self.alive

    def start(self):
        pass


@requires_yaml
class PipelineCase(TempDirCase):
    POLICY = None

    def setUp(self):
        super().setUp()
        policy = self.write_policy(self.POLICY or minimal_policy())
        self.monitor = make_monitor(self, self.tmp, policy)
        self.server = load_server(self.tmp, policy)
        # Alerts and errors go to stderr; capture both so a test can assert
        # that NOTHING reaches stdout.
        self._out, self._err = io.StringIO(), io.StringIO()
        real_out, real_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = self._out, self._err
        self.addCleanup(lambda: (setattr(sys, "stdout", real_out),
                                 setattr(sys, "stderr", real_err)))

    def out(self):
        return self._out.getvalue()

    def err(self):
        return self._err.getvalue()

    def feed(self, ev):
        self.monitor.ingest(ev)
        return ev

    def publish(self):
        """What the monitor's health loop does every few seconds."""
        self.monitor.write_status()

    def records(self):
        return list(self.monitor.store.scan())


class TestIngestFunnel(PipelineCase):
    def test_event_is_evaluated_then_persisted(self):
        self.feed(event("file.read", pid=1, path="/home/agent/.ssh/id_rsa"))
        rec, = self.records()
        self.assertEqual(rec["kind"], "file.read")
        self.assertEqual([v["rule"] for v in rec["verdicts"]], ["cred.read"])
        self.assertEqual(rec["verdicts"][0]["severity"], "critical")

    def test_alert_line_carries_what_an_operator_needs(self):
        self.feed(event("file.read", pid=1, path="/home/agent/.ssh/id_rsa"))
        line = self.err()
        self.assertIn("CRITICAL", line)
        self.assertIn("cred.read", line)
        self.assertIn("seq=1", line)
        self.assertIn("id_rsa", line)

    def test_alert_is_written_to_the_alerts_log(self):
        # The pageable sink: one JSON object per alert, tail-able by anything.
        self.feed(event("file.read", pid=7, path="/home/agent/.ssh/id_rsa"))
        alert, = read_jsonl(self.path("alerts.jsonl"))
        self.assertEqual((alert["rule"], alert["severity"], alert["seq"], alert["pid"]),
                         ("cred.read", "critical", 1, 7))
        self.assertIn("id_rsa", alert["data"]["path"])

    def test_non_alert_verdicts_do_not_reach_the_alerts_log(self):
        self.feed(event("file.read", pid=1, path="/home/agent/project/main.py"))
        self.assertFalse(self.path("alerts.jsonl").exists())

    def test_nothing_is_ever_written_to_stdout(self):
        # stdout belonged to the MCP stdio transport when the monitor lived in
        # the server; every alert printed there was dropped by the client as a
        # JSON-RPC parse error. The monitor has no stdout contract at all now,
        # and keeps it that way.
        self.feed(event("file.read", pid=1, path="/home/agent/.ssh/id_rsa"))
        self.monitor.ingest({"src": "x", "kind": "process.exec"})
        self.feed(event("process.exec", pid=999_999_999, argv=["sudo", "id"]))
        self.monitor.check_health()
        self.assertEqual(self.out(), "")
        self.assertIn("ERROR ingest failed", self.err())

    def test_non_matching_event_is_still_persisted(self):
        self.feed(event("file.read", pid=1, path="/home/agent/project/main.py"))
        rec, = self.records()
        self.assertEqual(rec["verdicts"], [],
                         "the log is the evidence; unflagged events belong in it too")

    def test_hash_chain_survives_the_whole_run(self):
        for i in range(20):
            self.feed(event("file.read", pid=i + 1, path="/tmp/%d" % i))
        self.assertTrue(self.server.verify_log_integrity()["ok"])

    def test_ingest_never_raises_on_a_malformed_event(self):
        # A collector thread dying here is the silent-monitor failure mode.
        for bad in ({}, {"kind": "process.exec"}, {"src": "x"},
                    {"src": "x", "kind": "process.exec"},
                    {"src": "x", "kind": "e", "data": None, "session": "s",
                     "pid": None, "ppid": None, "comm": None, "uid": None}):
            self.monitor.ingest(dict(bad))
        self.assertTrue(self.monitor.store.verify()["ok"])

    def test_ingest_survives_an_action_that_explodes(self):
        def boom(rec, verdict):
            raise RuntimeError("pager is down")

        self.monitor._alert = boom
        self.feed(event("file.read", pid=1, path="/home/agent/.ssh/id_rsa"))
        self.assertEqual(len(self.records()), 1,
                         "the event must be recorded even if alerting fails")


class TestEnforcement(PipelineCase):
    def test_kill_on_an_impossible_pid_is_recorded_not_raised(self):
        self.feed(event("process.exec", pid=999_999_999, argv=["sudo", "id"]))
        kinds = [r["kind"] for r in self.records()]
        self.assertIn("enforce.failed", kinds)

    def test_kill_refuses_to_target_the_monitor(self):
        self.feed(event("process.exec", pid=os.getpid(), argv=["sudo", "id"]))
        rec = [r for r in self.records() if r["kind"] == "enforce.refused"]
        self.assertEqual(len(rec), 1,
                         "a rule matching our own activity must not disarm the monitor")

    def test_kill_is_skipped_when_there_is_no_pid(self):
        # tool.pre events carry no pid, so an in-band kill is impossible; it
        # must degrade to a recorded verdict rather than an error.
        self.feed(event("tool.pre", src="hook", command="sudo id"))
        kinds = [r["kind"] for r in self.records()]
        self.assertNotIn("enforce.failed", kinds)
        self.assertNotIn("enforce.kill", kinds)

    def test_kill_signal_exists_on_this_platform(self):
        from gm import monitor
        self.assertIsNotNone(monitor.KILL_SIGNAL)


class TestMultipleAgents(PipelineCase):
    """Several agents against one monitor.

    Nothing about the design is single-agent: the store carries a `session` on
    every record and every query filters on it. What has to hold is that two
    concurrent agents never borrow each other's attribution -- if they did,
    find_blind_spots would credit agent A's hooks for agent B's effects and
    both reports would be quietly wrong.
    """

    def agent(self, session, agent_pid, command="python helper.py"):
        from gm.collectors import IngestServer
        self.feed(IngestServer._to_canonical(hook_payload(
            tool_name="Bash", command=command, session=session, agent_pid=agent_pid)))

    def test_two_agents_keep_separate_sessions(self):
        self.agent("agent-A", 1000)
        self.agent("agent-B", 2000)
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("process.exec", pid=2001, ppid=2000, exe="/usr/bin/python"))
        self.feed(event("file.open", pid=1001, path="/home/agent/.ssh/id_rsa"))
        self.feed(event("file.open", pid=2001, path="/home/agent/project/ok.py"))

        by_session = {}
        for r in self.records():
            by_session.setdefault(r["session"], []).append(r)
        self.assertEqual(sorted(by_session), ["agent-A", "agent-B"])
        self.assertEqual(len(by_session["agent-A"]), 3)
        self.assertEqual(len(by_session["agent-B"]), 3)

    def test_a_violation_is_attributed_to_the_agent_that_caused_it(self):
        self.agent("agent-A", 1000)
        self.agent("agent-B", 2000)
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("process.exec", pid=2001, ppid=2000, exe="/usr/bin/python"))
        self.feed(event("file.open", pid=2001, path="/home/agent/.ssh/id_rsa"))

        self.assertEqual(self.server.session_summary("agent-A")["rules_tripped"], {})
        self.assertEqual(self.server.session_summary("agent-B")["rules_tripped"],
                         {"cred.read": 1})

    def test_blind_spots_are_computed_per_agent(self):
        self.agent("agent-A", 1000)
        self.agent("agent-B", 2000)
        # A behaves: its exec is explained by its own Bash call.
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        # B acts outside its tool layer.
        self.feed(event("process.exec", pid=2001, ppid=2000, exe="/usr/bin/python"))
        self.feed(event("file.open", pid=2001, path="/home/agent/.ssh/id_rsa"))

        a = self.server.find_blind_spots("agent-A")
        b = self.server.find_blind_spots("agent-B")
        self.assertEqual(a["undeclared"], [], "A's activity was fully declared")
        self.assertEqual([e["data"]["path"] for e in b["undeclared"]],
                         ["/home/agent/.ssh/id_rsa"])

    def test_one_agent_without_hooks_does_not_pollute_the_other(self):
        # The unhooked agent's effects stay "unknown" rather than being
        # attributed to whichever session happens to be bound.
        self.agent("agent-A", 1000)
        self.feed(event("process.exec", pid=5001, ppid=5000, exe="/usr/bin/curl"))
        self.feed(event("net.connect", pid=5001, host="evil.example", port=443))

        sessions = {r["session"] for r in self.records()}
        self.assertEqual(sessions, {"agent-A", "unknown"})
        self.assertEqual(self.server.session_summary("agent-A")["events"], 1)

    def test_an_unhooked_agents_violations_are_still_recorded_and_alertable(self):
        # Losing session attribution must not mean losing the finding.
        self.feed(event("net.connect", pid=5001, host="evil.example", port=443))
        v = self.server.list_violations(min_severity="high")
        self.assertEqual(v["count"], 1)
        self.assertEqual(v["violations"][0]["verdicts"][0]["rule"], "net.egress_allowlist")

    def test_a_recycled_pid_rebinds_to_the_newer_agent(self):
        self.agent("agent-A", 1000)
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        # The OS reuses pid 1000 for a different agent process.
        self.agent("agent-B", 1000)
        self.feed(event("process.exec", pid=1002, ppid=1000, exe="/usr/bin/python"))
        sessions = [r["session"] for r in self.records()]
        self.assertEqual(sessions[-1], "agent-B",
                         "the newest binding must win over a stale one")

    def test_policy_is_global_not_per_agent(self):
        # A documented limitation, pinned so it is a deliberate constraint
        # rather than a surprise: one policy file, one ${workspace}. Two agents
        # with different workspaces cannot both be contained correctly by the
        # single fs.write_outside_workspace rule.
        pol = self.monitor.policy
        self.assertEqual(len(pol.rules), len(set(r.id for r in pol.rules)))
        self.assertIn("workspace", pol.vars)
        self.assertIsInstance(pol.vars["workspace"], str)


class TestPerSessionContainment(PipelineCase):
    """outside_session_workspace: containment that follows the agent.

    A single global ${workspace} is wrong the moment two agents work in two
    repos -- whichever repo is not in policy.yaml has every write flagged.
    """

    POLICY = {
        "vars": {"agent_home": "/home/agent"},
        "rules": [{
            "id": "fs.outside_session_workspace",
            "kind": ["file.write"], "severity": "high", "verdict": "violation",
            "action": "alert",
            "match": {"outside_session_workspace": ["/tmp"]},
        }],
    }

    def register(self, session, pid, cwd):
        from gm.collectors import IngestServer
        payload = hook_payload(session=session, agent_pid=pid)
        payload["cwd"] = cwd
        self.feed(IngestServer._to_canonical(payload))

    def fired(self, rec):
        return [v["rule"] for v in rec["verdicts"]]

    def test_two_agents_are_each_contained_to_their_own_repo(self):
        self.register("A", 1000, "/repo-a")
        self.register("B", 2000, "/repo-b")
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("process.exec", pid=2001, ppid=2000, exe="/usr/bin/python"))
        # Each writes inside its OWN repo: neither should fire.
        self.feed(event("file.write", pid=1001, path="/repo-a/src/main.py"))
        self.feed(event("file.write", pid=2001, path="/repo-b/src/main.py"))
        # B reaches into A's repo: that should fire.
        self.feed(event("file.write", pid=2001, path="/repo-a/src/evil.py"))

        recs = self.records()
        self.assertEqual(self.fired(recs[-3]), [], "A writing in /repo-a is contained")
        self.assertEqual(self.fired(recs[-2]), [], "B writing in /repo-b is contained")
        self.assertEqual(self.fired(recs[-1]), ["fs.outside_session_workspace"],
                         "B writing into A's repo is a containment breach")

    def test_extra_roots_are_still_allowlisted(self):
        self.register("A", 1000, "/repo-a")
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("file.write", pid=1001, path="/tmp/scratch.txt"))
        self.assertEqual(self.fired(self.records()[-1]), [])

    def test_an_unattributed_write_does_not_fire(self):
        # The deliberate hole from DESIGN.md 5A.4. It is why
        # attribution_health() exists.
        self.feed(event("file.write", pid=9999, path="/etc/passwd"))
        self.assertEqual(self.fired(self.records()[-1]), [])

    def test_the_private_workspace_key_is_never_stored(self):
        self.register("A", 1000, "/repo-a")
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("file.write", pid=1001, path="/repo-a/x.py"))
        for rec in self.records():
            self.assertNotIn("_workspace", rec)
            self.assertNotIn("_workspace", rec["data"])


class TestSessionTools(PipelineCase):
    """list_sessions / list_agents / attribution_health, read from the status file."""

    def register(self, session, pid, cwd="/repo"):
        from gm.collectors import IngestServer
        payload = hook_payload(session=session, agent_pid=pid)
        payload["cwd"] = cwd
        self.feed(IngestServer._to_canonical(payload))

    def test_list_sessions_reports_a_registered_agent(self):
        self.register("A", os.getpid(), cwd="/repo-a")
        self.publish()
        out = self.server.list_sessions()
        self.assertEqual(out["count"], 1)
        row = out["sessions"][0]
        self.assertEqual(row["session_id"], "A")
        self.assertEqual(row["cwd"], "/repo-a")
        self.assertTrue(row["alive"])
        self.assertIn("surface", row)
        self.assertIn("tracked_pids", out)

    def test_sessions_are_invisible_until_the_monitor_publishes_them(self):
        # The server shares no memory with the monitor. Until a status file
        # exists it must say the monitor is not running, not report "no agents".
        self.register("A", os.getpid())
        out = self.server.list_sessions()
        self.assertEqual(out["count"], 0)
        self.assertFalse(out["monitor"]["running"])
        self.assertIn("no status file", out["monitor"]["reason"])

    def test_list_sessions_hides_dead_agents_by_default(self):
        self.register("gone", 999_999_999)
        self.publish()
        self.assertEqual(self.server.list_sessions()["count"], 0)
        self.assertEqual(self.server.list_sessions(include_dead=True)["count"], 1)

    def test_list_agents_shape(self):
        self.publish()
        out = self.server.list_agents()
        for key in ("count", "agents", "without_hook_coverage", "note", "monitor"):
            self.assertIn(key, out)
        for row in out["agents"]:
            self.assertIn("hooks_registered", row)

    def test_list_agents_says_when_the_monitor_is_down(self):
        out = self.server.list_agents()
        self.assertIn("not running", out["note"])

    def test_attribution_health_is_perfect_when_everything_resolves(self):
        self.register("A", 1000)
        self.feed(event("process.exec", pid=1001, ppid=1000, exe="/usr/bin/python"))
        self.feed(event("file.open", pid=1001, path="/repo/x"))
        h = self.server.attribution_health()
        self.assertEqual(h["unattributed"], 0)
        self.assertEqual(h["unknown_rate"], 0.0)
        self.assertTrue(h["healthy"])

    def test_attribution_health_surfaces_a_broken_bridge(self):
        # No hook ever registered, so nothing resolves. This is the state that
        # otherwise reads as "the agent did nothing".
        for pid in (5001, 5002, 5003):
            self.feed(event("process.exec", pid=pid, ppid=4000, exe="/usr/bin/curl"))
        h = self.server.attribution_health()
        self.assertEqual(h["unattributed"], 3)
        self.assertEqual(h["unknown_rate"], 1.0)
        self.assertFalse(h["healthy"])
        self.assertEqual(h["by_kind"], {"process.exec": 3})

    def test_attribution_health_ignores_monitor_bookkeeping(self):
        # probe.start, enforce.* and monitor.* are ours, not the agent's;
        # counting them as unattributed would make the metric permanently
        # unhealthy.
        self.monitor.store.append(src="probe", kind="probe.start", session="gm-probe")
        self.monitor.store.append(src="gm", kind="monitor.start")
        self.monitor.store.append(src="gm", kind="monitor.collector_died")
        h = self.server.attribution_health()
        self.assertEqual(h["os_events"], 0)
        self.assertTrue(h["healthy"])

    def test_attribution_health_on_an_empty_log(self):
        h = self.server.attribution_health()
        self.assertEqual(h["unknown_rate"], 0.0)
        self.assertTrue(h["healthy"])


class TestSessionAttribution(PipelineCase):
    """DESIGN.md 6.1, end to end through the real funnel."""

    AGENT, BASH, PY, STRANGER = 1000, 1001, 1002, 7777
    SESSION = "sess-abc123"

    def run_scenario(self):
        from gm.collectors import IngestServer
        self.feed(IngestServer._to_canonical(hook_payload(
            tool_name="Bash", command="python helper.py",
            session=self.SESSION, agent_pid=self.AGENT)))
        self.feed(event("process.exec", pid=self.BASH, ppid=self.AGENT,
                        comm="bash", exe="/bin/bash", argv=["/bin/bash"]))
        self.feed(event("process.exec", pid=self.PY, ppid=self.BASH,
                        comm="python", exe="/usr/bin/python", argv=["python", "helper.py"]))
        self.feed(event("file.open", pid=self.PY, ppid=self.BASH,
                        path="/home/agent/.ssh/id_rsa"))
        self.feed(event("file.open", pid=self.STRANGER, ppid=6666, path="/etc/motd"))

    def test_the_agents_process_tree_shares_one_session(self):
        self.run_scenario()
        sessions = [r["session"] for r in self.records()]
        self.assertEqual(sessions[:4], [self.SESSION] * 4)

    def test_an_unrelated_process_is_not_attributed(self):
        self.run_scenario()
        self.assertEqual(self.records()[4]["session"], "unknown")

    def test_session_summary_sees_the_kernel_half(self):
        self.run_scenario()
        s = self.server.session_summary(self.SESSION)
        self.assertTrue(s["found"])
        self.assertEqual(s["events"], 4)
        self.assertEqual(sorted(s["binaries"]), ["bash", "python"])
        self.assertEqual(s["rules_tripped"], {"cred.read": 1})
        self.assertIn("process.exec", s["by_kind"])

    def test_session_summary_names_windows_binaries_on_any_host(self):
        self.feed(event("process.exec", session="W", pid=1,
                        exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
        self.assertEqual(self.server.session_summary("W")["binaries"], ["powershell.exe"])

    def test_session_summary_for_an_unknown_session(self):
        self.assertFalse(self.server.session_summary("no-such-session")["found"])

    def test_find_blind_spots_reports_only_the_real_gap(self):
        self.run_scenario()
        b = self.server.find_blind_spots(self.SESSION)
        self.assertEqual(b["hook_events"], 1)
        self.assertEqual(b["os_effect_events"], 3)
        self.assertEqual([e["data"]["path"] for e in b["undeclared"]],
                         ["/home/agent/.ssh/id_rsa"],
                         "the two execs are explained by the Bash call; the key read is not")

    def test_blind_spot_results_are_truncated_for_the_transport(self):
        from gm.collectors import IngestServer
        self.feed(IngestServer._to_canonical(hook_payload(
            command="python x.py", session="big", agent_pid=1)))
        for i in range(80):
            self.feed(event("file.open", pid=1, path="/etc/f%d" % i))
        b = self.server.find_blind_spots("big")
        self.assertEqual(len(b["undeclared"]), 50)


class TestQueryTools(PipelineCase):
    def setUp(self):
        super().setUp()
        self.feed(event("file.read", session="S", pid=1, path="/home/agent/.ssh/id_rsa"))
        self.feed(event("net.connect", session="S", pid=1, host="evil.example", port=443))
        self.feed(event("file.read", session="S", pid=1, path="/home/agent/project/ok.py"))

    def test_query_events_filters_by_kind(self):
        res = self.server.query_events(kinds=["net.connect"])
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["events"][0]["data"]["host"], "evil.example")

    def test_query_events_only_flagged(self):
        self.assertEqual(self.server.query_events(only_flagged=True)["count"], 2)

    def advance_clock(self, seconds):
        """Make the server believe `seconds` have passed.

        Not `minutes=0`: that makes `since` exactly now, and the coarse
        wall-clock on some platforms (~15ms on Windows) puts the just-written
        events in the same tick, so `ts < since` is false and they are
        included. That made the assertion depend on how fast setUp ran.
        """
        import time as real_time
        server = self.server
        original = server.time
        offset = seconds

        class _Shifted:
            def __getattr__(self, name):
                return getattr(real_time, name)

            @staticmethod
            def time():
                return real_time.time() + offset

        server.time = _Shifted()
        self.addCleanup(setattr, server, "time", original)

    def test_query_events_respects_the_time_window(self):
        self.assertEqual(self.server.query_events(minutes=60)["count"], 3)
        self.advance_clock(3600)          # an hour later
        self.assertEqual(self.server.query_events(minutes=1)["count"], 0,
                         "events older than the window must be excluded")
        self.assertEqual(self.server.query_events(minutes=120)["count"], 3,
                         "a window wide enough to reach them includes them again")

    def test_list_violations_applies_a_severity_floor(self):
        self.assertEqual(self.server.list_violations(min_severity="low")["count"], 2)
        self.assertEqual(self.server.list_violations(min_severity="critical")["count"], 1)

    def test_list_violations_shape(self):
        v = self.server.list_violations()["violations"][0]
        for key in ("seq", "ts", "kind", "src", "pid", "data", "verdicts"):
            self.assertIn(key, v)

    def test_verify_log_integrity(self):
        res = self.server.verify_log_integrity()
        self.assertTrue(res["ok"])
        self.assertEqual(res["checked"], 3)

    def test_verify_log_integrity_detects_tampering(self):
        p = self.path("events.jsonl")
        lines = p.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[1])
        rec["data"]["host"] = "innocent.example"
        lines[1] = json.dumps(rec)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = self.server.verify_log_integrity()
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "hash_mismatch")

    def test_control_coverage_splits_fired_from_never_fired(self):
        cov = self.server.control_coverage()
        self.assertEqual(cov["fired"], {"cred.read": 1, "net.egress_allowlist": 1})
        self.assertEqual(cov["never_fired"], ["exec.privilege"])
        for key in ("tracked_pids", "collectors_running", "monitor"):
            self.assertIn(key, cov)

    def test_control_coverage_window(self):
        self.assertEqual(self.server.control_coverage(days=7)["fired"],
                         {"cred.read": 1, "net.egress_allowlist": 1})
        self.advance_clock(3 * 86400)     # three days later
        self.assertEqual(self.server.control_coverage(days=1)["fired"], {},
                         "a rule that last fired outside the window is not 'firing'")
        self.assertEqual(sorted(self.server.control_coverage(days=1)["never_fired"]),
                         ["cred.read", "exec.privilege", "net.egress_allowlist"])


class TestMonitorHealthAcrossTheSplit(PipelineCase):
    """What the server can tell about a monitor it cannot see."""

    def add(self, label, alive=True, kernel=False):
        from gm.monitor import Collector
        self.monitor.collectors.append(Collector(label, FakeThread("gm-" + label, alive), kernel))

    def test_live_collectors_are_reported_running(self):
        self.add("sysmon", kernel=True)
        self.add("hook-ingest")
        self.monitor.check_health()
        cov = self.server.control_coverage()
        self.assertTrue(cov["monitor"]["running"])
        self.assertEqual(sorted(cov["collectors_running"]), ["hook-ingest", "sysmon"])
        self.assertTrue(cov["monitor"]["kernel_collector_alive"])

    def test_a_dead_collector_is_recorded_warned_and_not_reported_running(self):
        # The old check counted collectors that had been STARTED. A Sysmon
        # subscription that failed a millisecond later still satisfied it.
        self.add("sysmon", alive=False, kernel=True)
        self.add("hook-ingest")
        self.monitor.check_health()
        died = [r for r in self.records() if r["kind"] == "monitor.collector_died"]
        self.assertEqual([r["data"]["collector"] for r in died], ["sysmon"])
        self.assertIn("no kernel-level collector is running", self.err())
        cov = self.server.control_coverage()
        self.assertEqual(cov["collectors_running"], ["hook-ingest"])
        self.assertEqual(cov["monitor"]["dead_collectors"], ["sysmon"])
        self.assertFalse(cov["monitor"]["kernel_collector_alive"])

    def test_a_death_is_recorded_once_not_every_health_check(self):
        self.add("sysmon", alive=False, kernel=True)
        for _ in range(3):
            self.monitor.check_health()
        died = [r for r in self.records() if r["kind"] == "monitor.collector_died"]
        self.assertEqual(len(died), 1)
        self.assertEqual(self.err().count("no kernel-level collector"), 1)

    def test_a_stale_heartbeat_means_the_monitor_is_not_running(self):
        self.add("sysmon", kernel=True)
        self.monitor.check_health()
        status = json.loads(self.path("status.json").read_text(encoding="utf-8"))
        status["updated"] = time.time() - 3600
        self.path("status.json").write_text(json.dumps(status), encoding="utf-8")
        cov = self.server.control_coverage()
        self.assertFalse(cov["monitor"]["running"])
        self.assertIn("stale", cov["monitor"]["reason"])
        self.assertEqual(cov["collectors_running"], [],
                         "a frozen snapshot must not be presented as live collectors")

    def test_a_stopped_monitor_says_so(self):
        self.add("sysmon", kernel=True)
        self.monitor.stop()
        cov = self.server.control_coverage()
        self.assertFalse(cov["monitor"]["running"])
        self.assertIn("stopped", cov["monitor"]["reason"])
        self.assertEqual(self.records()[-1]["kind"], "monitor.stop")

    def test_an_unreadable_status_file_is_not_running(self):
        self.path("status.json").write_text("{not json", encoding="utf-8")
        self.assertFalse(self.server.control_coverage()["monitor"]["running"])


@requires_yaml
class TestProbeSuiteThroughTheServer(TempDirCase):
    def test_probe_results_carry_the_monitor_state(self):
        # Every probe FAILs when the monitor is down; the result must say so
        # instead of reading like four dead controls.
        policy = self.write_policy({
            "vars": {"agent_home": str(self.tmp), "workspace": str(self.path("project")),
                     "canary_dir": str(self.path(".gm-canaries"))},
            "rules": [{"id": "canary.file", "kind": ["file.read"], "severity": "low",
                       "verdict": "warn", "match": {"path_glob": ["**/fake_id_rsa"]}}],
        })
        server = load_server(self.tmp, policy)
        self.addCleanup(server._context().store.close)
        res = server.run_probe_suite(settle_seconds=0.0)
        self.assertFalse(res["monitor"]["running"])
        self.assertEqual(res["passed"], 0)
        starts = [r for r in server._context().store.scan() if r["kind"] == "probe.start"]
        self.assertEqual(len(starts), res["total"], "markers are still recorded")


@requires_yaml
class TestNoMutatingTools(TempDirCase):
    def test_the_server_exposes_no_way_to_mute_or_delete(self):
        # DESIGN.md 5.3: "There is deliberately no tool to mute a rule, delete
        # an event, or stop a collector."
        server = load_server(self.tmp, self.write_policy(minimal_policy()))
        banned = ("delete", "mute", "disable", "stop", "clear", "purge", "remove")
        exported = [n for n in dir(server) if not n.startswith("_")]
        for name in exported:
            if any(b in name.lower() for b in banned):
                self.fail("gm.server exposes %r, which looks like a mutating tool" % name)

    def test_the_documented_tool_set_is_what_exists(self):
        server = load_server(self.tmp, self.write_policy(minimal_policy()))
        for tool in ("query_events", "list_violations", "session_summary",
                     "find_blind_spots", "verify_log_integrity", "run_probe_suite",
                     "control_coverage", "list_sessions", "list_agents",
                     "attribution_health"):
            self.assertTrue(callable(getattr(server, tool, None)), "missing tool %s" % tool)

    def test_the_server_starts_no_collectors(self):
        server = load_server(self.tmp, self.write_policy(minimal_policy()))
        for name in ("start_collectors", "ingest", "_collectors", "IngestServer"):
            self.assertFalse(hasattr(server, name),
                             "gm.server has %r: sensors belong in gm.monitor, which does "
                             "not die when an MCP client disconnects" % name)


if __name__ == "__main__":
    unittest.main()
