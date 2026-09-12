"""run_suite when the prober may read the log but not write it.

The MCP server now runs the probe suite as the supervisor, which setup can
grant read-only access to the log. A PermissionError on the probe.start marker
used to escape and abort the whole suite -- the 0/0 outcome probes.py exists to
prevent.
"""

from tests.support import TempDirCase


class ReadOnlyStore(object):
    def __init__(self, store):
        self.store = store

    def append(self, **kw):
        raise PermissionError(13, "Access is denied")

    def query(self, **kw):
        return self.store.query(**kw)


class TestUnwritableLog(TempDirCase):
    def test_the_suite_still_runs_and_reports_the_missing_marker(self):
        from gm.probes import Probe, run_suite
        store = ReadOnlyStore(self.new_store())
        probes = [Probe("a", "canary.file", "d", lambda d: None, lambda d: None),
                  Probe("b", "canary.exec", "d", lambda d: None, lambda d: None)]
        res = run_suite(store, str(self.path("c")), probes=probes, settle=0.0)
        self.assertEqual(res["total"], 2, "the remaining probes must still run")
        for r in res["results"]:
            self.assertEqual(r["status"], "FAIL")
            self.assertIn("probe.start not recorded", r["marker_error"])

    def test_a_writable_log_reports_no_marker_error(self):
        from gm.probes import Probe, run_suite
        probes = [Probe("a", "canary.file", "d", lambda d: None, lambda d: None)]
        res = run_suite(self.new_store(), str(self.path("c")), probes=probes, settle=0.0)
        self.assertIsNone(res["results"][0]["marker_error"])
