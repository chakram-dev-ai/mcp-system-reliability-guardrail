"""Functional: the collector threads themselves, running for real.

The normalizers are unit-tested elsewhere. What is exercised here is the part
that only shows up at runtime -- a thread that starts, delivers, survives bad
input, and stops. A collector that dies quietly is the failure this project
exists to detect, so "does not die" is the assertion that matters most.
"""

import json
import os
import subprocess
import sys
import time
import unittest

from tests.support import (HOOKS, TempDirCase, captured_output, requires_psutil,
                           requires_pywin32, posix_only)


def wait_for(predicate, timeout=10.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@requires_psutil
class TestProcTreeCollector(TempDirCase):
    """The portable poller. Dev fallback only, but it must not lie."""

    def spawn_child(self, seconds=10):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(%d)" % seconds],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self._reap, proc)
        return proc

    @staticmethod
    def _reap(proc):
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass

    def start(self, root_pid, session="unknown"):
        from gm.collectors import ProcTreeCollector
        seen = []
        c = ProcTreeCollector(root_pid, seen.append, session=session, interval=0.05)
        c.start()
        self.addCleanup(c.stop)
        return c, seen

    def test_it_reports_the_root_process(self):
        c, seen = self.start(os.getpid())
        self.assertTrue(wait_for(lambda: any(e["pid"] == os.getpid() for e in seen)),
                        "the root process was never reported")
        ev = [e for e in seen if e["pid"] == os.getpid()][0]
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual(ev["src"], "proc")
        self.assertIn("exe", ev["data"])

    def test_it_discovers_a_child(self):
        child = self.spawn_child()
        c, seen = self.start(os.getpid())
        self.assertTrue(wait_for(lambda: any(e["pid"] == child.pid for e in seen)),
                        "a child process was never observed")

    def test_each_pid_is_reported_once(self):
        c, seen = self.start(os.getpid())
        wait_for(lambda: len(seen) >= 1)
        time.sleep(0.3)                     # several more poll cycles
        pids = [e["pid"] for e in seen if e["kind"] == "process.exec"]
        self.assertEqual(len(pids), len(set(pids)), "the poller re-reported a pid")

    def test_it_carries_the_session_it_was_given(self):
        c, seen = self.start(os.getpid(), session="S-proc")
        self.assertTrue(wait_for(lambda: bool(seen)))
        self.assertEqual(seen[0]["session"], "S-proc")

    def test_an_absent_root_pid_exits_cleanly(self):
        c, seen = self.start(999_999_999)
        self.assertTrue(wait_for(lambda: not c.is_alive(), timeout=5),
                        "the collector should exit, not spin, on a missing root")
        self.assertEqual(seen, [])

    def test_stop_is_honoured(self):
        c, seen = self.start(os.getpid())
        wait_for(lambda: bool(seen))
        c.stop()
        self.assertTrue(wait_for(lambda: not c.is_alive(), timeout=5))

    def test_a_raising_emit_does_not_kill_the_thread(self):
        # The emit here is normally Monitor.ingest, which never raises -- but
        # the collector must not depend on that to stay alive.
        from gm.collectors import ProcTreeCollector
        calls = []

        def boom(ev):
            calls.append(ev)
            raise RuntimeError("downstream exploded")

        with captured_output() as _:
            c = ProcTreeCollector(os.getpid(), boom, interval=0.05)
            c.start()
            self.addCleanup(c.stop)
            self.assertTrue(wait_for(lambda: bool(calls)))
            time.sleep(0.2)
            alive = c.is_alive()
        self.assertTrue(alive, "the poll loop must survive a downstream failure")

    def test_uid_is_none_where_the_platform_has_no_uid(self):
        # psutil.Process has no uids() on Windows. The unguarded call raised
        # AttributeError on the first process and killed the whole thread
        # before a single event was emitted.
        c, seen = self.start(os.getpid())
        self.assertTrue(wait_for(lambda: bool(seen)))
        if sys.platform == "win32":
            self.assertIsNone(seen[0]["uid"])
        else:
            self.assertIsInstance(seen[0]["uid"], int)

    def test_is_alive_works_after_the_thread_ends(self):
        # threading.Thread._stop is a real method; shadowing it with an Event
        # made is_alive() and join() raise TypeError once the thread finished,
        # which broke control_coverage() exactly when a collector had died.
        c, seen = self.start(os.getpid())
        c.stop()
        self.assertTrue(wait_for(lambda: not c.is_alive(), timeout=5))
        c.join(timeout=5)          # must not raise either


class TestLineJSONCollector(TempDirCase):
    """The adapter that wraps eslogger / a tail of audit.log."""

    def start(self, script, normalizer):
        from gm.collectors import LineJSONCollector
        seen = []
        c = LineJSONCollector([sys.executable, "-u", "-c", script], normalizer, seen.append)
        c.start()
        self.addCleanup(c.stop)
        return c, seen

    def test_lines_are_normalized_and_emitted(self):
        from gm.collectors import canonical
        script = ("import sys\n"
                  "for i in range(3):\n"
                  "    sys.stdout.write('{\"i\": %d}\\n' % i)\n"
                  "sys.stdout.flush()\n"
                  "import time; time.sleep(5)\n")

        def norm(line):
            try:
                obj = json.loads(line)
            except ValueError:
                return
            yield canonical("test", "process.exec", pid=obj["i"])

        c, seen = self.start(script, norm)
        self.assertTrue(wait_for(lambda: len(seen) >= 3), "collector emitted %r" % seen)
        self.assertEqual([e["pid"] for e in seen[:3]], [0, 1, 2])

    def test_unparsable_lines_are_skipped_not_fatal(self):
        from gm.collectors import canonical
        script = ("import sys\n"
                  "sys.stdout.write('garbage\\n')\n"
                  "sys.stdout.write('{\"i\": 7}\\n')\n"
                  "sys.stdout.flush()\n"
                  "import time; time.sleep(5)\n")

        def norm(line):
            try:
                obj = json.loads(line)
            except ValueError:
                return
            yield canonical("test", "process.exec", pid=obj["i"])

        c, seen = self.start(script, norm)
        self.assertTrue(wait_for(lambda: bool(seen)))
        self.assertEqual(seen[0]["pid"], 7)

    def test_stop_terminates_the_tracer_process(self):
        script = "import time; time.sleep(30)"
        c, seen = self.start(script, lambda line: iter(()))
        self.assertTrue(wait_for(lambda: c.proc is not None))
        c.stop()
        self.assertTrue(wait_for(lambda: c.proc.poll() is not None, timeout=5),
                        "the external tracer must not outlive the monitor")

    def test_a_missing_tracer_binary_is_loud_but_not_fatal(self):
        from gm.collectors import LineJSONCollector
        seen = []
        c = LineJSONCollector(["gm-no-such-tracer-binary"], lambda l: iter(()), seen.append)
        with captured_output() as _:
            c.start()
            c.join(timeout=5)
        self.assertFalse(c.is_alive())
        self.assertEqual(seen, [])

    def test_stop_before_start_is_harmless(self):
        from gm.collectors import LineJSONCollector
        LineJSONCollector(["true"], lambda l: iter(()), lambda e: None).stop()

    def test_thread_is_named_after_the_tracer(self):
        from gm.collectors import LineJSONCollector
        c = LineJSONCollector(["eslogger", "exec"], lambda l: iter(()), lambda e: None)
        self.assertEqual(c.name, "gm-eslogger")


@posix_only
class TestIngestServerLifecycle(TempDirCase):
    def test_socket_is_replaced_if_a_stale_one_exists(self):
        from gm.collectors import IngestServer
        path = str(self.path("ingest.sock"))
        open(path, "w").close()                 # stale file from a crash
        srv = IngestServer(path, lambda e: None)
        srv.start()
        self.addCleanup(srv.stop)
        self.assertTrue(wait_for(lambda: os.path.exists(path)))

    def test_malformed_line_does_not_kill_the_connection_handler(self):
        import socket
        from gm.collectors import IngestServer
        path = str(self.path("ingest.sock"))
        seen = []
        srv = IngestServer(path, seen.append)
        srv.start()
        self.addCleanup(srv.stop)
        self.assertTrue(wait_for(lambda: os.path.exists(path)))

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        s.sendall(b"not json\n")
        s.sendall(b"\n")
        s.sendall(json.dumps({"hook_event_name": "PreToolUse",
                              "session_id": "S"}).encode() + b"\n")
        s.close()
        self.assertTrue(wait_for(lambda: bool(seen)), "the good line after a bad one was lost")
        self.assertEqual(seen[0]["session"], "S")


@requires_pywin32
class TestEventLogCollectorCallback(unittest.TestCase):
    """The EvtSubscribe callback, without needing a live event channel.

    A real subscription needs Sysmon installed and an event to occur. What can
    be tested anywhere is the contract that matters: the callback must ignore
    non-deliver actions, and must never let a bad event escape and tear down
    the subscription.
    """

    def make(self, normalizer, seen):
        from gm.collectors_win import EventLogCollector, SYSMON_CHANNEL, SYSMON_QUERY
        return EventLogCollector(SYSMON_CHANNEL, SYSMON_QUERY, normalizer,
                                 seen.append, name="gm-sysmon")

    def patch_render(self, xml):
        import win32evtlog
        original = win32evtlog.EvtRender
        win32evtlog.EvtRender = lambda handle, flag: xml
        self.addCleanup(setattr, win32evtlog, "EvtRender", original)

    def sysmon_xml(self):
        return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System><EventID>1</EventID>'
                '<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>'
                '<EventData><Data Name="ProcessId">99</Data>'
                '<Data Name="Image">C:\\x.exe</Data>'
                '<Data Name="CommandLine">x.exe</Data></EventData></Event>')

    def test_delivered_event_is_normalized_and_emitted(self):
        import win32evtlog
        from gm.collectors_win import sysmon_normalize
        self.patch_render(self.sysmon_xml())
        seen = []
        c = self.make(sysmon_normalize, seen)
        rc = c._callback(win32evtlog.EvtSubscribeActionDeliver, None, object())
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["pid"], 99)

    def test_non_deliver_action_is_ignored(self):
        from gm.collectors_win import sysmon_normalize
        self.patch_render(self.sysmon_xml())
        seen = []
        c = self.make(sysmon_normalize, seen)
        self.assertEqual(c._callback(0, None, object()), 0)
        self.assertEqual(seen, [])

    def test_a_malformed_event_does_not_kill_the_subscription(self):
        import win32evtlog
        from gm.collectors_win import sysmon_normalize
        self.patch_render("<Event><this is not valid")
        seen = []
        c = self.make(sysmon_normalize, seen)
        with captured_output() as _:
            rc = c._callback(win32evtlog.EvtSubscribeActionDeliver, None, object())
        self.assertEqual(rc, 0, "the callback must return, not raise, on a bad event")
        self.assertEqual(seen, [])

    def test_a_raising_emit_does_not_kill_the_subscription(self):
        import win32evtlog
        from gm.collectors_win import sysmon_normalize
        self.patch_render(self.sysmon_xml())

        def boom(ev):
            raise RuntimeError("downstream exploded")

        from gm.collectors_win import EventLogCollector, SYSMON_CHANNEL, SYSMON_QUERY
        c = EventLogCollector(SYSMON_CHANNEL, SYSMON_QUERY, sysmon_normalize, boom)
        with captured_output() as _:
            rc = c._callback(win32evtlog.EvtSubscribeActionDeliver, None, object())
        self.assertEqual(rc, 0)


@requires_pywin32
class TestNamedPipeLifecycle(TempDirCase):
    def start(self):
        from gm.collectors_win import NamedPipeIngest
        name = r"\\.\pipe\gm-lifecycle-%d" % os.getpid()
        seen = []
        srv = NamedPipeIngest(seen.append, pipe_name=name)
        srv.start()
        self.addCleanup(srv.stop)
        self.assertTrue(wait_for(lambda: self._connectable(name), timeout=5))
        return srv, name, seen

    @staticmethod
    def _connectable(name):
        try:
            open(name, "wb").close()
            return True
        except OSError:
            return False

    @staticmethod
    def open_pipe(name, timeout=5.0):
        """Open the pipe for raw writes, retrying like the shipped client does.

        A bare open() is not a fair test: there is a short window between one
        client disconnecting and the server creating the next instance, and
        every real client (gm_hook._send_pipe) retries through it.
        """
        deadline = time.time() + timeout
        while True:
            try:
                return open(name, "wb", buffering=0)
            except OSError:
                if time.time() >= deadline:
                    raise
                time.sleep(0.02)

    def send(self, name, payload):
        """Deliver via the REAL shipped client, not a reimplementation.

        gm_hook._send_pipe retries transient open failures, which is what
        covers the brief window between one client disconnecting and the
        server creating the next instance. Testing with a bare open() would be
        testing a client nobody ships.
        """
        sys.path.insert(0, str(HOOKS))
        import gm_hook
        original = gm_hook.PIPE
        gm_hook.PIPE = name
        try:
            gm_hook._send_pipe((json.dumps(payload) + "\n").encode("utf-8"))
        finally:
            gm_hook.PIPE = original

    def test_a_client_arriving_between_instances_still_gets_through(self):
        # After a client disconnects there is a brief window before the server
        # has created the next instance. Servicing connections inline made that
        # window as long as a full read + policy evaluation + fsync, and the
        # hook -- which only retried ERROR_PIPE_BUSY -- dropped the event and
        # failed open. Handing off to a worker thread, plus retrying every
        # transient error client-side, is what closes it.
        srv, name, seen = self.start()
        for i in range(8):
            self.send(name, {"hook_event_name": "PreToolUse", "session_id": "B%d" % i})
        self.assertTrue(wait_for(lambda: len(seen) >= 8, timeout=10),
                        "lost %d of 8 back-to-back events" % (8 - len(seen)))

    def test_more_than_one_client_in_a_row(self):
        # The regression this guards: only the FIRST CreateNamedPipe applies a
        # security descriptor, and later instances need FILE_CREATE_PIPE_INSTANCE
        # on the existing pipe. A DACL without the creating account got
        # ERROR_ACCESS_DENIED on the second connection, the thread died, and
        # every hook event after the first was silently lost.
        srv, name, seen = self.start()
        for i in range(4):
            self.send(name, {"hook_event_name": "PreToolUse", "session_id": "S%d" % i,
                             "agent_pid": 100 + i})
            self.assertTrue(wait_for(lambda: len(seen) >= i + 1, timeout=5),
                            "event %d never arrived; ingest thread alive=%s"
                            % (i, srv.is_alive()))
        self.assertEqual([e["session"] for e in seen], ["S0", "S1", "S2", "S3"])
        self.assertTrue(srv.is_alive())

    def test_malformed_line_is_skipped_and_the_thread_survives(self):
        srv, name, seen = self.start()
        with self.open_pipe(name) as fh:
            fh.write(b"garbage not json\n")
        self.assertTrue(wait_for(lambda: True, timeout=0.3))
        self.send(name, {"hook_event_name": "PreToolUse", "session_id": "after-bad"})
        self.assertTrue(wait_for(lambda: bool(seen), timeout=5))
        self.assertEqual(seen[0]["session"], "after-bad")

    def test_several_events_in_one_connection(self):
        srv, name, seen = self.start()
        with self.open_pipe(name) as fh:
            for i in range(3):
                fh.write((json.dumps({"hook_event_name": "PreToolUse",
                                      "session_id": "M%d" % i}) + "\n").encode())
        self.assertTrue(wait_for(lambda: len(seen) >= 3, timeout=5))
        self.assertEqual([e["session"] for e in seen[:3]], ["M0", "M1", "M2"])

    def test_stop_actually_stops_the_thread(self):
        srv, name, seen = self.start()
        srv.stop()
        self.assertTrue(wait_for(lambda: not srv.is_alive(), timeout=5),
                        "stop() must unblock ConnectNamedPipe, not leak the thread "
                        "and the claim on the pipe name")

    def test_the_dacl_names_the_creating_account(self):
        from gm.collectors_win import NamedPipeIngest
        sddl = NamedPipeIngest(lambda e: None).sddl
        self.assertIn("(A;;FA;;;S-1-", sddl,
                      "the creator needs FILE_ALL_ACCESS to make instance #2")
        self.assertIn("(A;;FW;;;WD)", sddl, "the agent gets write and nothing more")

    def test_an_explicit_sddl_overrides_the_default(self):
        from gm.collectors_win import NamedPipeIngest
        srv = NamedPipeIngest(lambda e: None, sddl="D:(A;;FA;;;WD)")
        self.assertEqual(srv.sddl, "D:(A;;FA;;;WD)")


if __name__ == "__main__":
    unittest.main()
