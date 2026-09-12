"""Functional: collectors/setup-windows.ps1 refuses a broken setup BEFORE changing anything.

Only the preflight is exercised: -ValidateOnly, and one real run that must be
refused for lack of elevation. The elevated path changes machine-wide audit
policy, so these tests skip entirely when run as an administrator rather than
risk doing it.
"""

import os
import subprocess
import unittest

from tests.support import COLLECTORS, IS_WINDOWS

SCRIPT = COLLECTORS / "setup-windows.ps1"


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True          # cannot tell: behave as if elevated, and skip


@unittest.skipUnless(IS_WINDOWS, "Windows-only behaviour")
@unittest.skipIf(IS_WINDOWS and _is_admin(),
                 "elevated: a mistake here would change machine-wide audit policy")
class TestSetupPreflight(unittest.TestCase):
    def run_script(self, *args):
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(SCRIPT)] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")

    def test_the_script_parses(self):
        cmd = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               "'%s', [ref]$null, [ref]$e); exit $e.Count" % SCRIPT)
        rc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                            timeout=120).returncode
        self.assertEqual(rc, 0)

    def test_an_account_that_does_not_exist_is_refused_before_any_change(self):
        rc, out = self.run_script("-AgentAccount", "%s\\gm-no-such-user" % os.environ["COMPUTERNAME"],
                                  "-SkipSysmon", "-ValidateOnly")
        self.assertEqual(rc, 1, out)
        self.assertIn("does not resolve", out)
        self.assertIn("Nothing was changed", out)

    def test_the_monitor_cannot_run_as_the_agent(self):
        me = "%s\\%s" % (os.environ["USERDOMAIN"], os.environ["USERNAME"])
        rc, out = self.run_script("-AgentAccount", me, "-SkipSysmon", "-ValidateOnly")
        self.assertEqual(rc, 1, out)
        self.assertIn("separate account", out)

    def test_a_missing_sysmon_binary_is_refused_before_any_change(self):
        rc, out = self.run_script("-AgentAccount", "NT AUTHORITY\\LOCAL SERVICE",
                                  "-SysmonPath", "C:\\gm-nope\\sysmon64.exe", "-ValidateOnly")
        self.assertEqual(rc, 1, out)
        self.assertIn("does not exist", out)

    def test_the_agent_profile_is_resolved_not_hardcoded(self):
        rc, out = self.run_script("-AgentAccount", "NT AUTHORITY\\LOCAL SERVICE",
                                  "-SkipSysmon", "-ValidateOnly")
        self.assertEqual(rc, 0, out)
        self.assertIn("Preflight passed", out)
        self.assertIn("ServiceProfiles\\LocalService", out,
                      "the profile must come from the account, not C:\\Users\\agent")

    def test_a_workspace_the_policy_disagrees_with_is_warned_about(self):
        rc, out = self.run_script("-AgentAccount", "NT AUTHORITY\\LOCAL SERVICE",
                                  "-Workspace", "C:\\gm-elsewhere", "-SkipSysmon", "-ValidateOnly")
        self.assertEqual(rc, 0, out)
        self.assertIn("will disagree", out)

    def test_a_real_run_is_refused_without_elevation(self):
        rc, out = self.run_script("-AgentAccount", "NT AUTHORITY\\LOCAL SERVICE", "-SkipSysmon")
        self.assertEqual(rc, 1, out)
        self.assertIn("Not elevated", out)
        self.assertIn("Nothing was changed", out)


if __name__ == "__main__":
    unittest.main()
