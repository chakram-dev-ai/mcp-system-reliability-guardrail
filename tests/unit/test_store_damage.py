"""EventStore with a second writer, a reader mid-write, and a crash mid-record.

The monitor and the MCP server are separate processes on one log. A cached tip
forked the chain as soon as the second one appended; a reader that parsed a
half-written last line raised; a writer that appended after a crashed partial
record glued its record onto the fragment.
"""

import json
import os
import unittest

from tests.support import TempDirCase


class TestDamageAndConcurrency(TempDirCase):
    def log(self):
        return self.path("events.jsonl")

    def test_constructing_a_store_touches_nothing_on_disk(self):
        from gm.store import EventStore
        p = self.path("not", "yet", "events.jsonl")
        s = EventStore(p)
        self.assertEqual(list(s.scan()), [])
        self.assertTrue(s.verify()["ok"])
        self.assertFalse(p.parent.exists(),
                         "a read-only query process must not need to create the log")

    def test_two_stores_on_one_file_keep_one_chain(self):
        from gm.store import EventStore
        a = self.new_store()
        b = EventStore(self.log())
        self.addCleanup(b.close)
        for i in range(10):
            (a if i % 2 == 0 else b).append(src="gm", kind="e", data={"i": i})
        res = a.verify()
        self.assertTrue(res["ok"], res)
        self.assertEqual([r["seq"] for r in a.scan()], list(range(1, 11)))

    def test_a_partial_last_line_is_an_in_progress_write_not_damage(self):
        s = self.new_store()
        s.append(src="gm", kind="a")
        with open(str(self.log()), "a", encoding="utf-8", newline="") as fh:
            fh.write('{"seq": 2, "half-written')
        self.assertEqual([r["kind"] for r in s.scan()], ["a"])
        self.assertEqual(s.verify(), {"ok": True, "checked": 1, "tip": s.verify()["tip"]})

    def test_a_malformed_complete_line_is_skipped_by_queries_and_reported_by_verify(self):
        s = self.new_store()
        s.append(src="gm", kind="a")
        with open(str(self.log()), "a", encoding="utf-8", newline="") as fh:
            fh.write("this is not a record\n")
        self.assertEqual(len(s.query()), 1)
        res = s.verify()
        self.assertFalse(res["ok"])
        self.assertEqual((res["reason"], res["at_line"]), ("malformed", 2))

    def test_an_append_after_a_torn_record_starts_on_its_own_line(self):
        from gm.store import EventStore
        s = self.new_store()
        s.append(src="gm", kind="a")
        with open(str(self.log()), "a", encoding="utf-8", newline="") as fh:
            fh.write('{"seq": 2, "torn by a crash')
        after = EventStore(self.log())            # a restarted monitor
        self.addCleanup(after.close)
        rec = after.append(src="gm", kind="b")
        self.assertEqual(rec["seq"], 2, "the torn record never consumed a seq")
        self.assertEqual([r["kind"] for r in after.scan()], ["a", "b"])
        res = after.verify()
        self.assertEqual(res["reason"], "malformed",
                         "the fragment is still evidence of a crash, and verify says so")
        lines = self.log().read_text(encoding="utf-8").splitlines()
        self.assertEqual(json.loads(lines[-1])["kind"], "b")

    def test_writes_use_lf_on_every_platform(self):
        s = self.new_store()
        s.append(src="gm", kind="a")
        self.assertNotIn(b"\r\n", self.log().read_bytes())


if __name__ == "__main__":
    unittest.main()
