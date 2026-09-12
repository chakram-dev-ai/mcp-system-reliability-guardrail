"""The hook's agent-PID walk: past shells, and not one step further.

The old walk climbed up to 8 levels looking for "claude" or "node" anywhere in
a process name. Run the test suite from inside a Claude Code session and the
shim anchored itself to claude.exe four levels above the real parent; put an
npm script between an agent and a hook and the session anchored to npm. Both
are wrong attributions, which DESIGN.md 5A.3 ranks worse than a visible gap.
"""

import sys
import unittest

from tests.support import HOOKS


class Proc(object):
    def __init__(self, pid, name, parent=None):
        self.pid = pid
        self._name = name
        self._parent = parent

    def name(self):
        return self._name

    def parent(self):
        return self._parent


def chain(*names):
    """Build a process chain from the oldest ancestor down; return the youngest."""
    proc = None
    for i, name in enumerate(names):
        proc = Proc(100 + i, name, proc)
    return proc


class TestAgentPidWalk(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(HOOKS))
        import gm_hook
        self.hook = gm_hook

    def walk(self, *names):
        found = self.hook._first_non_shell(chain(*names))
        return found.name() if found else None

    def test_an_intermediate_shell_is_walked_past(self):
        self.assertEqual(self.walk("claude.exe", "bash.exe"), "claude.exe")

    def test_several_shells_are_walked_past(self):
        self.assertEqual(self.walk("claude", "cmd.exe", "powershell.exe", "bash"), "claude")

    def test_a_non_shell_parent_is_the_answer_even_with_an_agent_above_it(self):
        # The suite run from a Claude Code session: claude -> bash -> python.
        self.assertEqual(self.walk("claude.exe", "bash.exe", "python.exe"), "python.exe")

    def test_an_npm_process_is_not_skipped_to_reach_node_further_up(self):
        self.assertEqual(self.walk("node", "bash", "npm"), "npm")

    def test_the_immediate_parent_wins_when_it_is_not_a_shell(self):
        self.assertEqual(self.walk("node"), "node")

    def test_nothing_but_shells_returns_none(self):
        self.assertIsNone(self.walk("sh", "bash"))

    def test_the_walk_is_bounded(self):
        self.assertIsNone(self.walk("claude", *(["bash"] * 12)))

    def test_shell_names_are_case_insensitive_and_exe_agnostic(self):
        for name in ("BASH.EXE", "Pwsh.exe", "cmd", "zsh"):
            self.assertTrue(self.hook._is_shell(name), name)
        for name in ("claude.exe", "node", "python.exe", "bash-helper", ""):
            self.assertFalse(self.hook._is_shell(name), name)


if __name__ == "__main__":
    unittest.main()
