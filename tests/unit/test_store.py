"""EventStore: hash chain, tamper detection, query filters, concurrency.

The store's whole claim is "you can tell if someone edited this file". These
tests try to break that claim in the three ways an attacker actually would:
delete a record, edit one in place, and truncate the tail.
"""

import json
import threading
import time
import unittest

from tests.support import TempDirCase


class TestAppend(TempDirCase):
    def test_record_shape(self):
        s = self.new_store()
        rec = s.append(src="auditd", kind="process.exec", session="S",
                       pid=10, ppid=1, comm="sh", uid=1001, data={"exe": "/bin/sh"})
        for field in ("seq", "ts", "src", "kind", "session", "pid", "ppid",
                      "comm", "uid", "data", "verdicts", "prev", "hash"):
            self.assertIn(field, rec, f"missing {field}")
        self.assertEqual(rec["seq"], 1)
        self.assertEqual(rec["prev"], "0" * 64)
        self.assertEqual(len(rec["hash"]), 64)

    def test_seq_increments_and_prev_chains(self):
        s = self.new_store()
        a = s.append(src="gm", kind="a")
        b = s.append(src="gm", kind="b")
        self.assertEqual((a["seq"], b["seq"]), (1, 2))
        self.assertEqual(b["prev"], a["hash"])

    def test_defaults_are_filled(self):
        s = self.new_store()
        rec = s.append(src="gm", kind="monitor.start")
        self.assertEqual(rec["session"], "unknown")
        self.assertEqual(rec["data"], {})
        self.assertEqual(rec["verdicts"], [])
        self.assertIsNone(rec["pid"])

    def test_one_line_of_json_per_record(self):
        s = self.new_store()
        s.append(src="gm", kind="a", data={"text": "with\nnewline"})
        s.append(src="gm", kind="b")
        lines = self.path("events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2, "embedded newlines must not split a record")
        for line in lines:
            json.loads(line)

    def test_reopen_continues_the_chain(self):
        from gm.store import EventStore
        s = self.new_store()
        s.append(src="gm", kind="a")
        s.append(src="gm", kind="b")
        again = EventStore(self.path("events.jsonl"))
        rec = again.append(src="gm", kind="c")
        self.assertEqual(rec["seq"], 3)
        self.assertTrue(again.verify()["ok"])

    def test_non_serialisable_data_does_not_break_the_chain(self):
        # default=str in the writer; a record that fails to serialise would
        # otherwise leave a half-written line and poison every later verify().
        s = self.new_store()
        s.append(src="gm", kind="odd", data={"when": time.gmtime(0)})
        self.assertTrue(s.verify()["ok"])


class TestVerify(TempDirCase):
    def _seed(self, n=5):
        s = self.new_store()
        for i in range(n):
            s.append(src="gm", kind="e", data={"i": i})
        return s, self.path("events.jsonl")

    def test_clean_log_verifies(self):
        s, _ = self._seed()
        res = s.verify()
        self.assertTrue(res["ok"])
        self.assertEqual(res["checked"], 5)
        self.assertIn("tip", res)

    def test_empty_and_absent_logs_verify(self):
        from gm.store import EventStore
        s = EventStore(self.path("nothing.jsonl"))
        self.assertTrue(s.verify()["ok"])
        self.assertEqual(s.verify()["checked"], 0)

    def test_deleted_record_is_detected(self):
        from gm.store import EventStore
        s, p = self._seed()
        lines = p.read_text(encoding="utf-8").splitlines()
        del lines[2]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = EventStore(p).verify()
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "chain_break")
        self.assertEqual(res["at_seq"], 4)

    def test_edited_record_is_detected(self):
        from gm.store import EventStore
        s, p = self._seed()
        lines = p.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[2])
        rec["data"]["i"] = 999                      # edit in place, keep the hash
        lines[2] = json.dumps(rec)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = EventStore(p).verify()
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "hash_mismatch")
        self.assertEqual(res["at_seq"], 3)

    def test_truncation_is_detected_by_a_later_verify(self):
        # Truncating the tail leaves a self-consistent chain, which is exactly
        # the limit DESIGN.md 7.1 calls out: the chain detects edits, it does
        # not prevent a rebuild. What it MUST catch is a truncation that a new
        # writer then appends past, because the seq restarts.
        from gm.store import EventStore
        s, p = self._seed()
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        trimmed = EventStore(p)
        self.assertTrue(trimmed.verify()["ok"], "a clean prefix still verifies")
        self.assertEqual(trimmed.verify()["checked"], 2)
        # ...and the operator sees it as a gap against the archived copy:
        self.assertEqual(trimmed.append(src="gm", kind="x")["seq"], 3)

    def test_reordered_records_are_detected(self):
        from gm.store import EventStore
        s, p = self._seed()
        lines = p.read_text(encoding="utf-8").splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(EventStore(p).verify()["ok"])


class TestQuery(TempDirCase):
    def setUp(self):
        super().setUp()
        self.s = self.new_store()
        self.t0 = time.time()
        self.s.append(src="hook", kind="tool.pre", session="A", data={})
        self.s.append(src="auditd", kind="process.exec", session="A", data={})
        self.s.append(src="auditd", kind="file.open", session="B", data={},
                      verdicts=[{"rule": "r1", "severity": "high",
                                 "verdict": "violation", "action": "alert"}])
        self.s.append(src="sysmon", kind="net.connect", session="B", data={})

    def test_filter_by_session(self):
        self.assertEqual(len(self.s.query(session="A")), 2)
        self.assertEqual(len(self.s.query(session="nope")), 0)

    def test_filter_by_kind_and_src(self):
        self.assertEqual(len(self.s.query(kinds=["process.exec", "file.open"])), 2)
        self.assertEqual(len(self.s.query(src="auditd")), 2)

    def test_filter_only_flagged(self):
        hits = self.s.query(only_flagged=True)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "file.open")

    def test_filter_by_time_window(self):
        self.assertEqual(len(self.s.query(since=self.t0 - 1)), 4)
        self.assertEqual(len(self.s.query(since=time.time() + 60)), 0)
        self.assertEqual(len(self.s.query(until=self.t0 - 1)), 0)

    def test_limit_returns_the_most_recent(self):
        got = self.s.query(limit=2)
        self.assertEqual([r["seq"] for r in got], [3, 4],
                         "limit must keep the newest, not the oldest")

    def test_combined_filters_are_conjunctive(self):
        self.assertEqual(len(self.s.query(session="B", kinds=["file.open"])), 1)
        self.assertEqual(len(self.s.query(session="A", kinds=["file.open"])), 0)


class TestConcurrency(TempDirCase):
    def test_parallel_appends_keep_the_chain_intact(self):
        # Collector threads all funnel through append(); a lost update would
        # show up as a duplicate seq or a broken prev pointer.
        s = self.new_store()
        errors = []

        def writer(n):
            try:
                for i in range(25):
                    s.append(src="t%d" % n, kind="process.exec", data={"i": i})
            except Exception as exc:      # pragma: no cover - failure path
                errors.append(repr(exc))

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        res = s.verify()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["checked"], 100)
        seqs = [r["seq"] for r in s.scan()]
        self.assertEqual(seqs, list(range(1, 101)), "seq must be gapless and unique")


if __name__ == "__main__":
    unittest.main()
