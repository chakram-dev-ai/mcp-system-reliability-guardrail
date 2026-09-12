"""Functional: several real processes appending to one log.

The monitor and the MCP server (probe markers) are separate processes on one
file. Before append() took a cross-process lock and re-read the tip, each kept
its own cached seq/hash and the second writer forked the chain: duplicate seqs,
broken prev pointers, and a verify_log_integrity() that reported tampering
nobody did.
"""

import subprocess
import sys
import unittest

from tests.support import REPO, TempDirCase

WRITER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from gm.store import EventStore\n"
    "s = EventStore(sys.argv[2])\n"
    "for i in range(int(sys.argv[4])):\n"
    "    s.append(src='w' + sys.argv[3], kind='e', data={'i': i})\n"
    "s.close()\n"
)


class TestConcurrentWriters(TempDirCase):
    WRITERS = 3
    EACH = 60

    def test_concurrent_processes_keep_one_gapless_chain(self):
        log = str(self.path("events.jsonl"))
        procs = [subprocess.Popen([sys.executable, "-c", WRITER, str(REPO), log, str(n),
                                   str(self.EACH)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for n in range(self.WRITERS)]
        for p in procs:
            out, err = p.communicate(timeout=180)
            self.assertEqual(p.returncode, 0, err.decode("utf-8", "replace"))

        store = self.new_store()
        total = self.WRITERS * self.EACH
        res = store.verify()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["checked"], total)
        self.assertEqual([r["seq"] for r in store.scan()], list(range(1, total + 1)),
                         "seq must be gapless and unique across processes")
        per_writer = {}
        for r in store.scan():
            per_writer[r["src"]] = per_writer.get(r["src"], 0) + 1
        self.assertEqual(sorted(per_writer.values()), [self.EACH] * self.WRITERS,
                         "no writer's records may be lost")


if __name__ == "__main__":
    unittest.main()
