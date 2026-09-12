"""SessionRegistry: the bridge from process tree to agent session.

If this is wrong, find_blind_spots and session_summary silently return the hook
half of the picture and nothing else -- which reads as "the agent did nothing
unusual" rather than as a broken monitor. Three failure directions matter:
losing a real descendant, inventing a session for a process we never saw spawn,
and -- the subtle one -- letting a recycled PID inherit a dead session.
"""

import os
import threading
import time
import unittest

from tests.support import event, requires_psutil


class RegistryCase(unittest.TestCase):
    def setUp(self):
        from gm.sessions import SessionRegistry
        self.r = SessionRegistry()


class TestRegisterResolve(RegistryCase):
    def test_register_then_resolve(self):
        self.r.register("S1", 100)
        self.assertEqual(self.r.resolve(100), "S1")

    def test_register_is_idempotent(self):
        a = self.r.register("S1", 100, cwd="/repo")
        b = self.r.register("S1", 100)
        self.assertIs(a, b)
        self.assertEqual(b.cwd, "/repo", "a later call without cwd must not erase it")

    def test_register_updates_cwd(self):
        self.r.register("S1", 100, cwd="/repo")
        self.r.register("S1", 100, cwd="/other")
        self.assertEqual(self.r.workspace("S1"), "/other")

    def test_agent_restart_under_the_same_session_id(self):
        self.r.register("S1", 100)
        self.r.register("S1", 200)
        self.assertEqual(self.r.resolve(200), "S1")

    def test_unknown_pid_resolves_to_unknown(self):
        self.assertEqual(self.r.resolve(999), "unknown")

    def test_none_and_zero_pids_are_ignored(self):
        # pid 0 is the swapper (Linux) / System Idle Process (Windows); it is
        # never a process we are attributing, and treating it as a real key
        # would let a normalizer that failed to parse a pid bind everything.
        self.r.bind(None, "S1")
        self.r.bind(0, "S1")
        self.assertEqual(self.r.resolve(None), "unknown")
        self.assertEqual(self.r.resolve(0), "unknown")
        self.assertEqual(self.r.tracked(), 0)

    def test_binding_the_unknown_session_is_a_no_op(self):
        self.r.bind(100, "unknown")
        self.r.bind(101, None)
        self.assertEqual(self.r.tracked(), 0)

    def test_forget(self):
        self.r.register("S1", 100)
        self.r.forget(100)
        self.assertEqual(self.r.resolve(100), "unknown")
        self.r.forget(100)      # idempotent
        self.r.forget(None)

    def test_child_inherits_from_a_known_parent(self):
        self.r.register("S1", 100)
        self.assertEqual(self.r.resolve(200, ppid=100), "S1")

    def test_inheritance_is_memoized(self):
        self.r.register("S1", 100)
        self.r.resolve(200, ppid=100)
        self.assertEqual(self.r.resolve(200), "S1",
                         "a resolved pid must not need its ppid again")

    def test_descent_through_a_grandchild(self):
        self.r.register("S1", 100)
        self.r.resolve(200, ppid=100)
        self.assertEqual(self.r.resolve(300, ppid=200), "S1")

    def test_an_orphan_is_not_guessed_at(self):
        self.r.register("S1", 100)
        self.assertEqual(self.r.resolve(500, ppid=499), "unknown",
                         "a wrong attribution puts one agent's actions in "
                         "another's summary -- worse than a visible gap")

    def test_two_sessions_do_not_bleed(self):
        self.r.register("A", 10)
        self.r.register("B", 20)
        self.assertEqual(self.r.resolve(11, ppid=10), "A")
        self.assertEqual(self.r.resolve(21, ppid=20), "B")

    def test_pid_table_is_bounded(self):
        from gm.sessions import SessionRegistry
        r = SessionRegistry(max_pids=4)
        r.register("S", 1)
        for pid in range(2, 10):
            r.bind(pid, "S")
        self.assertLessEqual(r.tracked(), 4,
                             "the pid table must not grow without bound between reaps")


class TestPidReuse(RegistryCase):
    """The bug create-time guards against.

    A recycled PID that silently inherits a dead session's attribution makes
    the audit trail actively misleading, which is worse than an empty one.
    """

    def test_a_recycled_pid_is_not_attributed_to_the_dead_session(self):
        from gm import sessions as S
        self.r.register("S1", 100)
        # Force a recorded create-time, then claim the live process is newer.
        with self.r._lock:
            self.r._pid_map[100] = ("S1", 1000.0)

        real = S._create_time
        S._create_time = lambda pid: 9999.0          # a different process now
        try:
            self.assertEqual(self.r.resolve(100), "unknown")
        finally:
            S._create_time = real

    def test_a_matching_create_time_still_resolves(self):
        from gm import sessions as S
        with self.r._lock:
            self.r._sessions["S1"] = S.Session(session_id="S1", root_pid=100)
            self.r._pid_map[100] = ("S1", 1000.0)

        real = S._create_time
        S._create_time = lambda pid: 1000.0
        try:
            self.assertEqual(self.r.resolve(100), "S1")
        finally:
            S._create_time = real

    def test_unverifiable_create_time_accepts_rather_than_drops(self):
        # On a host without psutil we cannot check. Dropping every attribution
        # would be worse than the rare mis-attribution we are guarding against.
        from gm import sessions as S
        self.assertTrue(S._same_process(1, None))

    def test_a_stale_binding_is_removed_not_just_ignored(self):
        from gm import sessions as S
        self.r.register("S1", 100)
        with self.r._lock:
            self.r._pid_map[100] = ("S1", 1000.0)
        real = S._create_time
        S._create_time = lambda pid: 9999.0
        try:
            self.r.resolve(100)
        finally:
            S._create_time = real
        self.assertNotIn(100, self.r._pid_map)


@requires_psutil
class TestAncestryWalk(RegistryCase):
    """Cold start: the monitor came up mid-session and missed the execs."""

    def test_a_live_descendant_resolves_through_its_ancestors(self):
        # This test process is the "agent"; a real child of it must resolve
        # even though the registry never saw the exec.
        import subprocess
        import sys
        self.r.register("S1", os.getpid())
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        self.assertEqual(self.r.resolve(child.pid), "S1",
                         "ancestry walk should find the registered root")

    def test_the_walk_result_is_memoized(self):
        import subprocess
        import sys
        self.r.register("S1", os.getpid())
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        self.r.resolve(child.pid)
        self.assertIn(child.pid, self.r._pid_map)

    def test_an_unrelated_process_does_not_resolve(self):
        self.assertEqual(self.r.resolve(os.getpid()), "unknown",
                         "nothing is registered, so nothing should resolve")


class TestAnnotate(RegistryCase):
    def hook(self, session="S1", pid=100, cwd="/repo"):
        return self.r.annotate(event("tool.pre", src="hook", session=session,
                                     pid=pid, agent_pid=pid, cwd=cwd))

    def test_hook_event_registers_the_session(self):
        self.hook()
        self.assertEqual(self.r.resolve(100), "S1")
        self.assertEqual(self.r.workspace("S1"), "/repo")

    def test_hook_event_keeps_its_own_session(self):
        self.assertEqual(self.hook()["session"], "S1")

    def test_gm_prefixed_field_is_also_accepted(self):
        # A shim from another build of this project uses gm_agent_pid.
        self.r.annotate(event("tool.pre", src="hook", session="S9", gm_agent_pid=555))
        self.assertEqual(self.r.resolve(555), "S9")

    def test_exec_inherits_from_parent(self):
        self.hook()
        self.assertEqual(
            self.r.annotate(event("process.exec", session="unknown", pid=200, ppid=100))["session"],
            "S1")

    def test_non_exec_event_resolves_by_its_own_pid(self):
        self.hook()
        self.r.annotate(event("process.exec", session="unknown", pid=200, ppid=100))
        ev = self.r.annotate(event("file.open", session="unknown", pid=200,
                                   path="/home/agent/.ssh/id_rsa"))
        self.assertEqual(ev["session"], "S1")

    def test_unrelated_process_is_not_guessed_at(self):
        self.hook()
        ev = self.r.annotate(event("file.open", session="unknown", pid=7777,
                                   ppid=6666, path="/etc/motd"))
        self.assertEqual(ev["session"], "unknown")

    def test_a_collector_that_already_knows_stays_authoritative(self):
        ev = self.r.annotate(event("process.exec", session="S-known", pid=42, ppid=1))
        self.assertEqual(ev["session"], "S-known")
        self.assertEqual(self.r.resolve(42), "S-known")

    def test_event_without_pid_survives(self):
        self.assertEqual(
            self.r.annotate(event("net.connect", session="unknown", host="x"))["session"],
            "unknown")

    def test_event_without_a_data_key_survives(self):
        ev = self.r.annotate({"kind": "process.exec", "session": "unknown",
                              "pid": 1, "ppid": 2, "src": "auditd"})
        self.assertEqual(ev["session"], "unknown")

    def test_hook_event_with_a_bad_pid_does_not_raise(self):
        self.r.annotate(event("tool.pre", src="hook", session="S", agent_pid="not-a-pid"))

    def test_annotate_returns_the_same_object(self):
        ev = event("file.open", session="unknown", pid=1)
        self.assertIs(self.r.annotate(ev), ev)


class TestIntrospection(RegistryCase):
    def test_sessions_lists_live_sessions(self):
        self.r.register("S1", os.getpid(), cwd="/repo")
        listed = self.r.sessions()
        self.assertEqual(len(listed), 1)
        row = listed[0]
        for key in ("session_id", "agent", "surface", "root_pid", "cwd",
                    "alive", "tracked_pids", "first_seen", "last_seen"):
            self.assertIn(key, row)
        self.assertEqual(row["cwd"], "/repo")

    def test_dead_sessions_are_hidden_unless_asked_for(self):
        self.r.register("dead", 999_999_999)
        self.assertEqual(self.r.sessions(), [])
        self.assertEqual(len(self.r.sessions(include_dead=True)), 1)
        self.assertFalse(self.r.sessions(include_dead=True)[0]["alive"])

    def test_workspace_of_an_unknown_session_is_none(self):
        self.assertIsNone(self.r.workspace("nope"))
        self.assertIsNone(self.r.workspace("unknown"))
        self.assertIsNone(self.r.workspace(None))

    def test_reap_drops_dead_stale_sessions_and_their_pids(self):
        from gm import sessions as S
        self.r.register("dead", 999_999_999)
        self.r.bind(4242, "dead")
        with self.r._lock:
            self.r._sessions["dead"].last_seen = time.time() - S.STALE_AFTER - 1
        self.assertEqual(self.r.reap(), 1)
        self.assertEqual(self.r.sessions(include_dead=True), [])
        self.assertEqual(self.r.resolve(4242), "unknown")

    def test_reap_keeps_recently_dead_sessions(self):
        # A session that just ended is still interesting for a final report.
        self.r.register("recent", 999_999_999)
        self.assertEqual(self.r.reap(), 0)

    def test_reap_keeps_live_sessions(self):
        self.r.register("live", os.getpid())
        self.assertEqual(self.r.reap(), 0)


class TestReaper(unittest.TestCase):
    def test_the_reaper_runs_and_stops(self):
        from gm.sessions import SessionRegistry, SessionReaper
        r = SessionRegistry()
        reaper = SessionReaper(r, interval=0.05)
        reaper.start()
        self.addCleanup(reaper.stop)
        time.sleep(0.2)
        self.assertTrue(reaper.is_alive())
        reaper.stop()
        reaper.join(timeout=5)
        self.assertFalse(reaper.is_alive(),
                         "reap() exists but nothing called it before this thread")


@requires_psutil
class TestClassifyAndDiscover(unittest.TestCase):
    def test_classify_returns_a_pair(self):
        from gm.sessions import classify
        agent, surface = classify(os.getpid())
        self.assertIsInstance(agent, str)
        self.assertIsInstance(surface, str)

    def test_classify_survives_a_dead_pid(self):
        from gm.sessions import classify
        self.assertEqual(classify(999_999_999), ("unknown", "unknown"))

    def test_discover_agents_returns_a_list_of_the_documented_shape(self):
        from gm.sessions import discover_agents
        found = discover_agents()
        self.assertIsInstance(found, list)
        for row in found:
            for key in ("pid", "agent", "surface", "cwd", "cmdline", "started"):
                self.assertIn(key, row)

    def test_agent_patterns_match_the_names_they_claim_to(self):
        from gm.sessions import AGENT_PATTERNS
        def label(name):
            for pat, lbl in AGENT_PATTERNS:
                if pat.search(name):
                    return lbl
            return None
        self.assertEqual(label("/usr/local/bin/claude"), "claude-code")
        self.assertEqual(label(r"C:\Program Files\claude.exe"), "claude-code")
        self.assertEqual(label("claude-code"), "claude-code")
        self.assertEqual(label("/usr/bin/aider"), "other-agent")
        self.assertIsNone(label("/usr/bin/python"))
        self.assertIsNone(label("/usr/bin/clang"))

    def test_surface_patterns_distinguish_the_launch_surfaces(self):
        from gm.sessions import SURFACE_PATTERNS
        def label(name):
            for pat, lbl in SURFACE_PATTERNS:
                if pat.search(name):
                    return lbl
            return None
        self.assertEqual(label("/usr/share/code/code"), "vscode")
        self.assertEqual(label("idea64.exe"), "jetbrains")
        self.assertEqual(label("/bin/bash"), "cli")
        self.assertEqual(label("/bin/zsh"), "cli")
        self.assertEqual(label(r"C:\Windows\System32\conhost.exe"), "cli")
        # "sh" must not match inside "sshd": an unanchored alternative checked
        # before the ssh pattern labelled every remote session "cli".
        self.assertEqual(label("sshd: agent@pts/0"), "ssh")
        self.assertEqual(label("/usr/sbin/sshd"), "ssh")
        self.assertIsNone(label("/usr/bin/flash"))
        self.assertIsNone(label("/usr/bin/python"))


class TestThreadSafety(unittest.TestCase):
    def test_concurrent_annotate_does_not_corrupt_the_registry(self):
        from gm.sessions import SessionRegistry
        r = SessionRegistry()
        r.register("S", 1)
        errors = []

        def worker(base):
            try:
                for i in range(200):
                    pid = base * 1000 + i
                    r.annotate(event("process.exec", session="unknown", pid=pid, ppid=1))
                    assert r.resolve(pid) == "S", "lost pid %d" % pid
            except Exception as exc:     # pragma: no cover - failure path
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(1, 5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(r.tracked(), 801)


if __name__ == "__main__":
    unittest.main()
