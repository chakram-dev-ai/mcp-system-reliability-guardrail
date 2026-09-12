"""Smoke: everything else that ships must be well-formed and self-consistent.

The hook settings, the Sysmon config and the audit rules are all files a human
copies into place once and then never looks at again. A key that the consuming
program silently ignores -- a hook `args` array, a Sysmon event the collector
never subscribes to, an auditd key the normalizer does not recognise -- costs
you the signal without ever producing an error.
"""

import json
import re
import unittest
import xml.etree.ElementTree as ET

from tests.support import COLLECTORS, HOOKS, REPO

HOOK_SETTINGS = ["settings.example.json", "settings.windows.example.json"]

# The only keys Claude Code recognises inside a hook entry. `args`, `async` and
# `if` are not hook keys; entries using them do not run as intended.
HOOK_ENTRY_KEYS = {"type", "command", "timeout"}


class TestHookSettings(unittest.TestCase):
    def docs(self):
        for name in HOOK_SETTINGS:
            with self.subTest(file=name):
                yield name, json.loads((HOOKS / name).read_text(encoding="utf-8"))

    def test_valid_json(self):
        for name, doc in self.docs():
            self.assertIn("hooks", doc, name)

    def test_entries_use_only_real_hook_keys(self):
        for name, doc in self.docs():
            for event, groups in doc["hooks"].items():
                for group in groups:
                    for entry in group["hooks"]:
                        extra = set(entry) - HOOK_ENTRY_KEYS
                        self.assertEqual(extra, set(),
                                         "%s/%s uses non-existent hook keys %s"
                                         % (name, event, sorted(extra)))

    def test_command_is_a_single_string_that_runs_the_shim(self):
        for name, doc in self.docs():
            for event, groups in doc["hooks"].items():
                for group in groups:
                    for entry in group["hooks"]:
                        self.assertEqual(entry.get("type"), "command")
                        cmd = entry.get("command")
                        self.assertIsInstance(cmd, str, "%s/%s" % (name, event))
                        self.assertIn("gm_hook.py", cmd,
                                      "%s/%s runs an interpreter with no script, which "
                                      "would feed it the hook payload as source code"
                                      % (name, event))

    def test_tool_matchers_are_wildcards(self):
        # DESIGN.md 5.1: "Use matcher '*' -- narrow matchers are how blind
        # spots get in."
        for name, doc in self.docs():
            for event in ("PreToolUse", "PostToolUse"):
                for group in doc["hooks"].get(event, []):
                    self.assertEqual(group.get("matcher"), "*",
                                     "%s/%s narrows its matcher" % (name, event))

    def test_both_pre_and_post_are_wired(self):
        for name, doc in self.docs():
            for event in ("PreToolUse", "PostToolUse"):
                self.assertIn(event, doc["hooks"], "%s is missing %s" % (name, event))

    def test_the_shim_is_not_run_from_inside_the_project(self):
        # $CLAUDE_PROJECT_DIR/hooks/gm_hook.py is a shim the agent can edit --
        # and %CLAUDE_PROJECT_DIR% only expands under cmd, not the Bash that
        # Claude Code may run hook commands through on Windows.
        for name, doc in self.docs():
            for event, groups in doc["hooks"].items():
                for group in groups:
                    for entry in group["hooks"]:
                        cmd = entry["command"]
                        self.assertNotIn("CLAUDE_PROJECT_DIR", cmd, "%s/%s" % (name, event))
                        self.assertNotIn("%", cmd, "%s/%s expands a cmd-only variable"
                                         % (name, event))

    def test_windows_variant_uses_quoted_absolute_forward_slash_paths(self):
        doc = json.loads((HOOKS / "settings.windows.example.json").read_text(encoding="utf-8"))
        cmd = doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertNotIn("python3", cmd, "python3 is not the usual name on Windows")
        self.assertNotIn("\\", cmd, "a backslash is an escape character under Bash")
        self.assertRegex(cmd, r'^"[A-Za-z]:/[^"]*python\.exe" "[A-Za-z]:/[^"]*gm_hook\.py"$',
                         "both the interpreter and the shim must be absolute and quoted")

    def test_posix_variant_uses_an_absolute_shim_path(self):
        doc = json.loads((HOOKS / "settings.example.json").read_text(encoding="utf-8"))
        cmd = doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertRegex(cmd, r"^python3 /\S+/gm_hook\.py$")

    def test_every_entry_sets_a_timeout(self):
        # An un-timed hook that blocks stalls the agent's tool call.
        for name, doc in self.docs():
            for event, groups in doc["hooks"].items():
                for group in groups:
                    for entry in group["hooks"]:
                        self.assertIn("timeout", entry, "%s/%s" % (name, event))


class TestSysmonConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = COLLECTORS / "sysmon-config.xml"
        cls.tree = ET.parse(str(cls.path))

    def test_parses_and_has_a_schema_version(self):
        root = self.tree.getroot()
        self.assertEqual(root.tag, "Sysmon")
        self.assertIn("schemaversion", root.attrib)

    def test_collected_event_types_are_subscribed_to(self):
        # Sysmon element name -> event id the collector subscribes to.
        subscribed = self._subscribed_ids()
        element_to_id = {"ProcessCreate": 1, "NetworkConnect": 3, "FileCreate": 11,
                         "RegistryEvent": 12, "DnsQuery": 22, "FileDelete": 23}
        configured = {el.tag for group in self.tree.getroot().iter("RuleGroup")
                      for el in group}
        for element in configured:
            if element in element_to_id:
                self.assertIn(element_to_id[element], subscribed,
                              "%s is configured but SYSMON_QUERY does not subscribe "
                              "to event %d -- pure log volume, never ingested"
                              % (element, element_to_id[element]))

    def test_unsubscribed_event_types_are_called_out(self):
        # ProcessAccess (10) and CreateRemoteThread (8) are deliberately
        # collected but not yet mapped; WINDOWS.md lists them as "worth
        # adding". Pin it so the gap is visible rather than forgotten.
        configured = {el.tag for group in self.tree.getroot().iter("RuleGroup") for el in group}
        self.assertEqual(configured & {"ProcessAccess", "CreateRemoteThread"},
                         {"ProcessAccess", "CreateRemoteThread"},
                         "these are collected but unmapped; see WINDOWS.md")

    def _subscribed_ids(self):
        from gm.collectors_win import SYSMON_QUERY
        return {int(n) for n in re.findall(r"EventID=(\d+)", SYSMON_QUERY)}

    def test_canary_coverage_is_present_and_not_account_scoped(self):
        # The probe suite runs as the monitor, so a User-scoped include filters
        # it out and reports FAIL for a working control.
        text = self.path.read_text(encoding="utf-8")
        for marker in ("gm-canary-exec", ".gm-canaries-escape", "192.0.2.1"):
            self.assertIn(marker, text, "sysmon config has no canary coverage for %s" % marker)

    def test_registry_canary_key_is_watched(self):
        self.assertIn("GmCanary", self.path.read_text(encoding="utf-8"))

    def test_every_rulegroup_has_a_relation(self):
        for group in self.tree.getroot().iter("RuleGroup"):
            self.assertEqual(group.get("groupRelation"), "or")


class TestAuditRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = [l.strip() for l in
                     (COLLECTORS / "audit.rules").read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.strip().startswith("#")]

    def test_every_rule_declares_a_key(self):
        for line in self.lines:
            self.assertIn(" -k ", line, "audit rule without -k is unroutable: %r" % line)

    def test_keys_are_ones_the_normalizer_understands(self):
        # auditd_normalize dispatches on the key prefix; a key it does not
        # recognise produces no event at all.
        prefixes = ("gm-exec", "gm-file", "gm-net")
        for line in self.lines:
            key = line.rsplit(" -k ", 1)[1].strip()
            self.assertTrue(key.startswith(prefixes),
                            "key %r is not dispatched by auditd_normalize" % key)

    def test_canary_paths_are_watched(self):
        text = " ".join(self.lines)
        self.assertIn(".gm-canaries", text,
                      "without a canary watch, canary.file can only report FAIL")
        self.assertIn("gm-canary-exec", text)
        self.assertIn(".gm-canaries-escape", text)

    def test_credential_stores_are_watched(self):
        text = " ".join(self.lines)
        for store in (".ssh", ".aws", "gcloud"):
            self.assertIn(store, text)

    def test_the_monitors_own_log_is_watched(self):
        self.assertIn("/var/log/gm/", " ".join(self.lines))

    def test_syscall_rules_specify_an_architecture(self):
        for line in self.lines:
            if line.startswith("-a "):
                self.assertIn("-F arch=", line, "syscall rule without arch: %r" % line)

    def test_immutable_flag_is_present_but_commented(self):
        # -e 2 must not be active in the shipped file: it would lock the rules
        # before the operator has tested them and require a reboot to undo.
        text = (COLLECTORS / "audit.rules").read_text(encoding="utf-8")
        self.assertIn("-e 2", text)
        self.assertNotIn("\n-e 2", text, "-e 2 must stay commented out")


class TestRepoLayout(unittest.TestCase):
    def test_documented_files_exist(self):
        for rel in ("policy.yaml", "policy.windows.yaml", "README.md", "DESIGN.md",
                    "WINDOWS.md", "gm/server.py", "gm/monitor.py", "gm/paths.py",
                    "gm/filelock.py", "gm/config.py", "gm/store.py", "gm/policy.py",
                    "gm/sessions.py", "gm/probes.py", "gm/reconcile.py",
                    "gm/collectors.py", "gm/collectors_win.py", "hooks/gm_hook.py",
                    "collectors/audit.rules", "collectors/sysmon-config.xml",
                    "collectors/setup-windows.ps1"):
            self.assertTrue((REPO / rel).is_file(), "missing %s" % rel)

    def test_no_python_source_uses_crlf(self):
        # git normalises on commit, but a stray CRLF in a shipped shell-invoked
        # script is a real runtime failure on POSIX.
        for path in list(REPO.glob("gm/*.py")) + list(REPO.glob("hooks/*.py")):
            self.assertNotIn(b"\r\n", path.read_bytes(), "%s has CRLF endings" % path.name)

    def test_env_vars_used_by_the_code_are_documented(self):
        import re as _re
        documented = (REPO / "DESIGN.md").read_text(encoding="utf-8")
        used = set()
        for path in list(REPO.glob("gm/*.py")) + list(REPO.glob("hooks/*.py")):
            used |= set(_re.findall(r'environ\.get\(\s*"(GM_[A-Z_]+)"',
                                    path.read_text(encoding="utf-8")))
        missing = {v for v in used if v not in documented}
        self.assertEqual(missing, set(),
                         "env vars read by the code but absent from DESIGN.md 4.4: %s"
                         % sorted(missing))


if __name__ == "__main__":
    unittest.main()
