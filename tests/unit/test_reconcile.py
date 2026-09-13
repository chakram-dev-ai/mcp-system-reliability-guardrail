"""Reconciler: declared intent vs observed effect.

The number that matters is `undeclared` -- an OS effect no hook announced. It
is the project's reason to exist, so these tests pin both directions: a real
gap must be reported, and ordinary covered activity must not be, or the signal
drowns in its own noise.
"""

import time
import unittest

from tests.support import stored


class ReconcileCase(unittest.TestCase):
    def setUp(self):
        from gm import reconcile
        self.R = reconcile
        self.t = 1_000_000.0

    def hook(self, seq, dt=0.0, tool="Bash", **data):
        return stored("tool.pre", seq=seq, ts=self.t + dt, src="hook",
                      session="S", tool_name=tool, **data)

    def eff(self, kind, seq, dt=1.0, src="auditd", **data):
        return stored(kind, seq=seq, ts=self.t + dt, src=src, session="S", **data)


class TestCovers(ReconcileCase):
    def test_bash_command_covers_the_binary_it_names(self):
        h = self.hook(1, command="python helper.py")
        e = self.eff("process.exec", 2, exe="/usr/bin/python", argv=["python", "helper.py"])
        self.assertTrue(self.R._covers(h, e))

    def test_bash_command_does_not_cover_an_unrelated_binary(self):
        h = self.hook(1, command="python helper.py")
        e = self.eff("process.exec", 2, exe="/usr/bin/nc", argv=["nc", "-e"])
        self.assertFalse(self.R._covers(h, e))

    def test_shell_tool_covers_the_shell_process_itself(self):
        # Bash("python x.py") execs /bin/bash first; without this the shell
        # shows up as undeclared on every single tool call.
        h = self.hook(1, command="python helper.py")
        self.assertTrue(self.R._covers(h, self.eff("process.exec", 2, exe="/bin/bash")))
        self.assertTrue(self.R._covers(h, self.eff("process.exec", 2, exe="/bin/sh")))

    def test_a_non_shell_tool_does_not_cover_the_shell(self):
        h = self.hook(1, tool="Read", command=None, path="/x")
        self.assertFalse(self.R._covers(h, self.eff("process.exec", 2, exe="/bin/bash")))

    def test_windows_shell_binaries_are_recognised(self):
        h = self.hook(1, command="Get-ChildItem")
        for exe in (r"C:\Windows\System32\cmd.exe",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
            self.assertTrue(self.R._covers(h, self.eff("process.exec", 2, exe=exe)), exe)

    def test_a_windows_exe_is_explained_by_its_name_without_the_extension(self):
        # Found building the hosted demo: Sysmon's Image is C:\...\python.exe,
        # the Bash command says "python", and the exec was reported undeclared.
        h = self.hook(1, command="python -m pytest tests")
        e = self.eff("process.exec", 2, exe=r"C:\Python312\python.exe",
                     argv=["python -m pytest tests"])
        self.assertTrue(self.R._covers(h, e))
        other = self.eff("process.exec", 2, exe=r"C:\Windows\System32\certutil.exe")
        self.assertFalse(self.R._covers(h, other))

    def test_exec_with_no_binary_name_is_not_covered(self):
        h = self.hook(1, command="python helper.py")
        self.assertFalse(self.R._covers(h, self.eff("process.exec", 2)))

    def test_write_covers_the_exact_path(self):
        h = self.hook(1, tool="Write", command=None, path="/home/agent/project/a.py")
        e = self.eff("file.write", 2, path="/home/agent/project/a.py")
        self.assertTrue(self.R._covers(h, e))

    def test_write_does_not_cover_a_different_path(self):
        h = self.hook(1, tool="Write", command=None, path="/home/agent/project/a.py")
        e = self.eff("file.write", 2, path="/home/agent/.ssh/id_rsa")
        self.assertFalse(self.R._covers(h, e))

    def test_read_credits_files_under_its_cwd(self):
        h = self.hook(1, tool="Read", command=None, cwd="/home/agent/project")
        e = self.eff("file.open", 2, path="/home/agent/project/deep/x.py")
        self.assertTrue(self.R._covers(h, e))

    def test_read_does_not_credit_files_outside_its_cwd(self):
        h = self.hook(1, tool="Read", command=None, cwd="/home/agent/project")
        e = self.eff("file.open", 2, path="/home/agent/.ssh/id_rsa")
        self.assertFalse(self.R._covers(h, e))

    def test_webfetch_covers_its_own_host(self):
        h = self.hook(1, tool="WebFetch", command=None, url="https://api.example.com/x")
        self.assertTrue(self.R._covers(h, self.eff("net.connect", 2, host="api.example.com")))
        self.assertFalse(self.R._covers(h, self.eff("net.connect", 2, host="evil.com")))

    def test_bash_credits_any_egress_in_its_window(self):
        # Documented as deliberately permissive (README "Tuning you will need
        # to do"). Pinned so tightening it is a conscious change, not a
        # surprise regression in undeclared_rate.
        h = self.hook(1, command="curl https://pypi.org")
        self.assertTrue(self.R._covers(h, self.eff("net.connect", 2, host="anything.example")))

    def test_unknown_effect_kind_is_not_covered(self):
        self.assertFalse(self.R._covers(self.hook(1), self.eff("registry.write", 2, path="HKLM")))


class TestReconcile(ReconcileCase):
    def test_the_motivating_case(self):
        # DESIGN.md 6.1: Bash("python helper.py") is declared; the exec it
        # causes is covered, the credential read it performs is not.
        events = [
            self.hook(1, command="python helper.py"),
            self.eff("process.exec", 2, dt=1, exe="/usr/bin/python", argv=["python"]),
            self.eff("file.open", 3, dt=2, path="/home/agent/.ssh/id_rsa"),
        ]
        res = self.R.reconcile(events)
        self.assertEqual(res["hook_events"], 1)
        self.assertEqual(res["os_effect_events"], 2)
        self.assertEqual([e["seq"] for e in res["undeclared"]], [3])
        self.assertEqual(res["undeclared_rate"], 0.5)

    def test_hook_sourced_effects_are_not_counted_as_os_effects(self):
        # A tool.pre carrying a path must not be reconciled against itself.
        events = [stored("file.write", seq=1, ts=self.t, src="hook", session="S",
                         path="/x")]
        res = self.R.reconcile(events)
        self.assertEqual(res["os_effect_events"], 0)

    def test_effect_before_the_hook_is_undeclared(self):
        events = [self.hook(2, dt=5, command="python x.py"),
                  self.eff("process.exec", 1, dt=0, exe="/usr/bin/python")]
        res = self.R.reconcile(events)
        self.assertEqual(len(res["undeclared"]), 1, "a hook cannot explain the past")

    def test_effect_beyond_the_window_is_undeclared(self):
        events = [self.hook(1, dt=0, command="python x.py"),
                  self.eff("process.exec", 2, dt=31, exe="/usr/bin/python")]
        self.assertEqual(len(self.R.reconcile(events, window=30.0)["undeclared"]), 1)

    def test_effect_exactly_at_the_window_edge_is_covered(self):
        events = [self.hook(1, dt=0, command="python x.py"),
                  self.eff("process.exec", 2, dt=30, exe="/usr/bin/python")]
        self.assertEqual(self.R.reconcile(events, window=30.0)["undeclared"], [])

    def test_a_wider_window_can_rescue_a_long_build(self):
        events = [self.hook(1, dt=0, command="make all"),
                  self.eff("process.exec", 2, dt=120, exe="/usr/bin/make")]
        self.assertEqual(len(self.R.reconcile(events, window=30.0)["undeclared"]), 1)
        self.assertEqual(self.R.reconcile(events, window=300.0)["undeclared"], [])

    def test_unobserved_reports_a_declared_tool_with_no_effect(self):
        # The hook said Write; the kernel never saw it. Blocked, or the
        # collector dropped it -- either way it is worth surfacing.
        events = [self.hook(1, tool="Write", command=None, path="/home/agent/project/a.py")]
        res = self.R.reconcile(events)
        self.assertEqual([e["seq"] for e in res["unobserved"]], [1])

    def test_unobserved_ignores_tools_with_no_expected_footprint(self):
        events = [self.hook(1, tool="Read", command=None, path="/x")]
        self.assertEqual(self.R.reconcile(events)["unobserved"], [])

    def test_unobserved_ignores_tool_post(self):
        events = [stored("tool.post", seq=1, ts=self.t, src="hook", session="S",
                         tool_name="Bash", command="ls")]
        self.assertEqual(self.R.reconcile(events)["unobserved"], [])

    def test_empty_input(self):
        res = self.R.reconcile([])
        self.assertEqual(res["undeclared_rate"], 0.0)
        self.assertEqual((res["hook_events"], res["os_effect_events"]), (0, 0))

    def test_all_effects_undeclared_gives_rate_one(self):
        events = [self.eff("file.open", 1, path="/x"), self.eff("file.open", 2, path="/y")]
        self.assertEqual(self.R.reconcile(events)["undeclared_rate"], 1.0)

    def test_rate_is_rounded_not_truncated(self):
        events = [self.hook(1, command="python a.py"),
                  self.eff("process.exec", 2, exe="/usr/bin/python"),
                  self.eff("file.open", 3, path="/etc/shadow"),
                  self.eff("file.open", 4, path="/etc/passwd")]
        self.assertAlmostEqual(self.R.reconcile(events)["undeclared_rate"], 0.6667, places=4)


if __name__ == "__main__":
    unittest.main()
