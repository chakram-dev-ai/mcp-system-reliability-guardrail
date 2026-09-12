"""Smoke: the policy files that actually ship must load and be coherent.

Run this before every release. It is the cheapest possible answer to "did the
last edit leave a rule that can never match, or a probe with no rule behind
it" -- both of which present as a quiet log rather than an error.
"""

import re
import unittest

from tests.support import REPO, requires_yaml

POLICIES = {"posix": REPO / "policy.yaml", "windows": REPO / "policy.windows.yaml"}

SEVERITIES = {"low", "medium", "high", "critical"}
VERDICTS = {"allow", "warn", "violation"}
ACTIONS = {"log", "alert", "kill"}

# Kinds any collector in this repo can actually emit. A rule keyed on anything
# else is dead by construction.
EMITTED_KINDS = {
    "tool.pre", "tool.post", "tool.other",
    "process.exec", "file.open", "file.read", "file.write", "file.create",
    "file.unlink", "net.connect", "net.dns", "registry.write",
    "probe.start", "monitor.start", "monitor.stop", "monitor.collector_died",
    "enforce.kill", "enforce.failed", "enforce.refused",
}

SOURCES = {"hook", "auditd", "eslogger", "proc", "sysmon", "winsec", "pwsh", "gm", "probe"}


class ShippedPolicyChecks(object):
    """Checks applied to every shipped policy.

    A plain mixin, not a TestCase: subclassing TestCase here would make the
    base class itself collectable and report a permanent skip on every run,
    which is exactly the kind of always-there noise that trains people to stop
    reading the output.
    """

    policy_key = None

    @classmethod
    def setUpClass(cls):
        from gm.policy import Policy
        import yaml
        cls.path = POLICIES[cls.policy_key]
        cls.raw = yaml.safe_load(cls.path.read_text(encoding="utf-8"))
        cls.pol = Policy.load(cls.path)

    def test_loads(self):
        self.assertTrue(self.pol.rules, "%s defines no rules" % self.path.name)

    def test_rule_ids_are_unique(self):
        ids = self.pol.rule_ids()
        dupes = {i for i in ids if ids.count(i) > 1}
        self.assertEqual(dupes, set(), "duplicate rule ids: later rules silently "
                                       "shadow nothing but confuse control_coverage")

    def test_enum_fields_are_valid(self):
        for r in self.pol.rules:
            self.assertIn(r.severity, SEVERITIES, r.id)
            self.assertIn(r.verdict, VERDICTS, r.id)
            self.assertIn(r.action, ACTIONS, r.id)

    def test_kinds_are_emitted_by_some_collector(self):
        for r in self.pol.rules:
            for k in r.kind:
                self.assertIn(k, EMITTED_KINDS,
                              "rule %s keys on '%s', which nothing emits" % (r.id, k))

    def test_src_filters_name_real_sources(self):
        for r in self.pol.rules:
            for s in r.src:
                self.assertIn(s, SOURCES, "rule %s restricts to unknown src '%s'" % (r.id, s))

    def test_every_rule_has_at_least_one_predicate(self):
        for r in self.pol.rules:
            self.assertTrue(r.match,
                            "rule %s has an empty match block and fires on every "
                            "event of its kind" % r.id)

    def test_every_regex_compiles(self):
        for r in self.pol.rules:
            for key in ("argv_regex", "tool_name_regex", "content_regex"):
                for pat in r.match.get(key, []):
                    try:
                        re.compile(pat)
                    except re.error as exc:
                        self.fail("rule %s: %s %r does not compile: %s" % (r.id, key, pat, exc))

    def test_no_unexpanded_variables_survive(self):
        for r in self.pol.rules:
            for key, val in r.match.items():
                for v in (val if isinstance(val, list) else [val]):
                    if isinstance(v, str):
                        self.assertNotIn("${", v,
                                         "rule %s: %s kept an unexpanded var: %r"
                                         % (r.id, key, v))

    def test_no_tilde_survives_expansion(self):
        # A '~' left in a compiled rule means it will be matched literally and
        # the rule is dead. agent_home is what prevents this.
        for r in self.pol.rules:
            for key in ("path_glob", "path_under", "path_not_under"):
                for v in r.match.get(key, []):
                    self.assertFalse(v.startswith("~"),
                                     "rule %s: %s still starts with ~: %r" % (r.id, key, v))

    def test_kill_actions_are_deliberate(self):
        # DESIGN.md 7.3: "Start with action: alert ... earn your way to kill."
        # This does not forbid kill, it just makes the set explicit so adding
        # one is a reviewed change rather than a copy-paste.
        expected = {
            "posix": {"fs.agent_config_write", "exec.privilege"},
            "windows": {"fs.agent_config_write", "cred.hive_access",
                        "reg.defender_tamper", "exec.privilege", "exec.log_tamper"},
        }[self.policy_key]
        actual = {r.id for r in self.pol.rules if r.action == "kill"}
        self.assertEqual(actual, expected,
                         "the set of killing rules changed; confirm that is intended")


@requires_yaml
class TestPosixPolicy(ShippedPolicyChecks, unittest.TestCase):
    policy_key = "posix"

    def test_agent_home_is_declared(self):
        self.assertIn("agent_home", self.pol.vars,
                      "without agent_home every ~ rule resolves to the MONITOR's "
                      "home and matches nothing")

    def test_credential_rule_matches_an_agent_key(self):
        from tests.support import event
        home = self.pol.vars["agent_home"]
        hits = [h["rule"] for h in self.pol.evaluate(
            event("file.read", path="%s/.ssh/id_rsa" % home))]
        self.assertIn("cred.read", hits)

    def test_workspace_containment_does_not_fire_inside_the_workspace(self):
        from tests.support import event
        ws = self.pol.vars["workspace"]
        hits = [h["rule"] for h in self.pol.evaluate(
            event("file.write", path="%s/src/main.py" % ws))]
        self.assertNotIn("fs.write_outside_workspace", hits,
                         "containment inverted: this would alert on every normal write")

    def test_workspace_containment_fires_outside(self):
        from tests.support import event
        hits = [h["rule"] for h in self.pol.evaluate(
            event("file.write", path="/etc/cron.d/evil"))]
        self.assertIn("fs.write_outside_workspace", hits)


@requires_yaml
class TestWindowsPolicy(ShippedPolicyChecks, unittest.TestCase):
    policy_key = "windows"

    def test_command_regexes_are_case_insensitive(self):
        # WINDOWS.md 6: "reg save HKLM\\SAM did not match a rule written for
        # lowercase sam. A rule that only catches one casing is worse than no
        # rule, because it looks covered."
        for r in self.pol.rules:
            for pat in r.match.get("argv_regex", []):
                self.assertTrue(pat.startswith("(?i)") or "(?i)" in pat,
                                "rule %s: %r needs (?i) on Windows" % (r.id, pat))

    def test_workspace_containment_does_not_fire_inside_the_workspace(self):
        from tests.support import event
        ws = self.pol.vars["workspace"]
        hits = [h["rule"] for h in self.pol.evaluate(
            event("file.write", path=ws + "\\src\\main.py"))]
        self.assertNotIn("fs.write_outside_workspace", hits)

    def test_registry_persistence_rules_match_real_keys(self):
        from tests.support import event
        for key, rule in [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil", "reg.run_key"),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
             "reg.defender_tamper"),
        ]:
            hits = [h["rule"] for h in self.pol.evaluate(event("registry.write", path=key))]
            self.assertIn(rule, hits, key)


@requires_yaml
class TestProbesAndPoliciesAgree(unittest.TestCase):
    """Every probe must have a rule, on every platform it can run on.

    This is the check that would have caught canary.net being absent from
    policy.windows.yaml -- a probe that could only ever report FAIL, which
    DESIGN.md 6.2 says you must treat as a dead control.
    """

    def test_every_probe_rule_exists_in_every_policy(self):
        from gm.policy import Policy
        from gm.probes import DEFAULT_PROBES
        expected = {p.expects_rule for p in DEFAULT_PROBES}
        for key, path in POLICIES.items():
            ids = set(Policy.load(path).rule_ids())
            missing = expected - ids
            self.assertEqual(missing, set(),
                             "%s has no rule for probe(s) %s -- those probes can "
                             "only ever report FAIL" % (path.name, sorted(missing)))

    def test_probe_ids_are_unique(self):
        from gm.probes import DEFAULT_PROBES
        ids = [p.id for p in DEFAULT_PROBES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_canary_rules_are_low_severity_warnings(self):
        # A canary firing is normal operation, not an incident. If it pages,
        # people mute it and the probe suite stops meaning anything.
        from gm.policy import Policy
        for key, path in POLICIES.items():
            for r in Policy.load(path).rules:
                if r.id.startswith("canary."):
                    self.assertEqual(r.severity, "low", "%s: %s" % (path.name, r.id))
                    self.assertEqual(r.verdict, "warn", "%s: %s" % (path.name, r.id))
                    self.assertNotEqual(r.action, "kill", "%s: %s" % (path.name, r.id))

    def test_rules_with_no_probe_are_listed_deliberately(self):
        # DESIGN.md 7.3: "Every rule needs a probe." Not all of them have one
        # yet; this pins the gap so it shrinks on purpose rather than growing
        # unnoticed.
        from gm.policy import Policy
        from gm.probes import DEFAULT_PROBES
        probed = {p.expects_rule for p in DEFAULT_PROBES}
        known_unprobed = {
            "posix": {"cred.read", "cred.dotenv", "fs.agent_config_write",
                      "exec.pipe_to_shell", "exec.privilege", "exec.history_tamper",
                      "net.egress_allowlist", "net.odd_port", "src.secret_committed"},
            "windows": {"cred.read", "cred.hive_access", "fs.startup_folder",
                        "fs.agent_config_write", "reg.run_key", "reg.defender_tamper",
                        "exec.lolbin_download", "exec.pipe_to_shell",
                        "exec.encoded_command", "exec.privilege", "exec.log_tamper",
                        "net.egress_allowlist", "canary.registry"},
        }
        for key, path in POLICIES.items():
            unprobed = {r.id for r in Policy.load(path).rules} - probed
            self.assertEqual(unprobed, known_unprobed[key],
                             "%s: the set of rules without a probe changed. Add a "
                             "probe, or update this list to acknowledge the gap."
                             % path.name)


if __name__ == "__main__":
    unittest.main()
