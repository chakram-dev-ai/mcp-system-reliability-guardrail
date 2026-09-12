"""Paths are judged by their own shape, not by the host the monitor runs on.

A Windows policy evaluated on a POSIX host used os.path, which does not split
on backslashes: containment inverted (every write inside the workspace was
"outside") and C:\\Windows\\System32\\cmd.exe had no basename, so the reconciler
reported the shell of every PowerShell call as undeclared.
"""

import ntpath
import os
import unittest

from tests.support import event, posix_only


class TestFlavor(unittest.TestCase):
    def setUp(self):
        from gm import paths
        self.paths = paths

    def test_windows_shaped_paths_use_ntpath_on_any_host(self):
        for p in (r"C:\Windows\System32\cmd.exe", "C:/Users/agent/project",
                  r"\\server\share\file", r"relative\dir\file"):
            self.assertIs(self.paths.flavor(p), ntpath, p)

    def test_other_paths_use_the_host_module(self):
        self.assertIs(self.paths.flavor("/usr/bin/python"), os.path)
        self.assertIs(self.paths.flavor("python"), os.path)
        self.assertIs(self.paths.flavor(""), os.path)

    def test_basename_of_a_windows_binary_on_any_host(self):
        self.assertEqual(self.paths.basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe")
        self.assertEqual(self.paths.basename("/usr/bin/python3"), "python3")

    def test_windows_norm_ignores_case_and_separator_style(self):
        self.assertEqual(self.paths.norm(r"C:/Users/Agent\Project"),
                         self.paths.norm(r"c:\users\agent\project"))

    @posix_only
    def test_posix_norm_stays_case_sensitive(self):
        self.assertNotEqual(self.paths.norm("/srv/App"), self.paths.norm("/srv/app"))

    def test_sep_follows_the_path(self):
        self.assertEqual(self.paths.sep_for(r"C:\x"), "\\")
        self.assertEqual(self.paths.sep_for("/x"), os.sep)


class TestPolicyOnAnyHost(unittest.TestCase):
    def setUp(self):
        from gm import policy
        self.P = policy

    def test_windows_containment_is_evaluated_as_windows_everywhere(self):
        roots = [r"C:\Users\agent\project"]
        for p in (r"C:\Users\agent\project\src\a.py",
                  r"c:\users\AGENT\Project\src\a.py",
                  r"C:/Users/agent/project/src/a.py"):
            self.assertFalse(self.P._p_path_not_under(event("file.write", path=p), roots),
                             "%s is inside the workspace: containment inverted" % p)
        self.assertTrue(self.P._p_path_not_under(
            event("file.write", path=r"C:\Users\agent\Desktop\x"), roots))
        self.assertTrue(self.P._p_path_not_under(
            event("file.write", path=r"C:\Users\agent\project2\x"), roots),
            "a sibling sharing the prefix is outside")

    def test_a_posix_path_is_outside_a_windows_workspace(self):
        self.assertTrue(self.P._p_path_not_under(
            event("file.write", path="/etc/cron.d/x"), [r"C:\Users\agent\project"]))

    def test_windows_drive_root_as_a_root(self):
        self.assertFalse(self.P._p_path_not_under(
            event("file.write", path=r"C:\anything"), ["C:\\"]))

    def test_exe_not_in_splits_windows_paths_everywhere(self):
        e = event("process.exec", exe=r"C:\Windows\System32\certutil.exe")
        self.assertFalse(self.P._p_exe_not_in(e, ["certutil.exe"]))
        self.assertTrue(self.P._p_exe_not_in(e, ["git.exe"]))

    def test_windows_glob_is_case_insensitive_everywhere(self):
        e = event("file.read", path=r"C:\Users\Agent\.SSH\id_rsa")
        self.assertTrue(self.P._p_path_glob(e, [r"C:\Users\*\.ssh\*"]))


if __name__ == "__main__":
    unittest.main()
