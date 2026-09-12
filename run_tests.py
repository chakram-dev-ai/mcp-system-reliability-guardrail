#!/usr/bin/env python3
"""Test runner and release gate for guardrail-monitor.

    python run_tests.py                 # smoke + unit + functional, with coverage
    python run_tests.py smoke           # fast pre-release check (~1s)
    python run_tests.py unit
    python run_tests.py functional      # real sockets, pipes, subprocesses
    python run_tests.py --no-coverage   # skip measurement
    python run_tests.py --fail-under 75 # gate on coverage as well as on tests

Tiers:

  smoke       Does the shipped configuration still load and agree with itself?
              No side effects. This is the one to run before every release,
              and the one to run first when something looks wrong in the field.
  unit        Pure logic, one module at a time.
  functional  Several components together, and real syscalls: a unix socket or
              named pipe round trip, a subprocess exec, an outbound connect.

Coverage uses coverage.py when it is installed and falls back to the stdlib
`trace` module when it is not, so the gate works on a bare interpreter.
"""

from __future__ import annotations

import argparse
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

TIERS = ("smoke", "unit", "functional")

# What we measure. The runner itself and the tests are not the subject.
MEASURED = [str(REPO / "gm")]
OMIT = ["*/tests/*", "*/run_tests.py", "*/__pycache__/*"]


def build_suite(tiers) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for tier in tiers:
        start = REPO / "tests" / tier
        if not start.is_dir():
            raise SystemExit("no such tier: %s" % tier)
        suite.addTests(loader.discover(str(start), pattern="test_*.py",
                                       top_level_dir=str(REPO)))
    return suite


def run(tiers, verbosity) -> unittest.TestResult:
    return unittest.TextTestRunner(verbosity=verbosity, buffer=False).run(build_suite(tiers))


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def with_coverage_py(tiers, verbosity, html):
    import coverage

    cov = coverage.Coverage(source=MEASURED, omit=OMIT, branch=True)
    cov.start()
    try:
        result = run(tiers, verbosity)
    finally:
        cov.stop()
        cov.save()

    print("\n" + "=" * 78)
    print("COVERAGE (coverage.py, branch mode)")
    print("=" * 78)
    total = cov.report(show_missing=True, skip_empty=True, file=sys.stdout)
    if html:
        out = REPO / "htmlcov"
        cov.html_report(directory=str(out))
        print("\nHTML report: %s" % (out / "index.html"))
    return result, total


def with_trace(tiers, verbosity):
    """stdlib fallback: statement counts only, no branch coverage."""
    import trace as trace_mod

    tracer = trace_mod.Trace(count=1, trace=0, ignoremods=("unittest",))
    holder = {}
    tracer.runfunc(lambda: holder.setdefault("r", run(tiers, verbosity)))
    counts = tracer.results().counts

    print("\n" + "=" * 78)
    print("COVERAGE (stdlib trace -- statement counts; install coverage.py for branches)")
    print("=" * 78)
    executed = {}
    for (filename, lineno) in counts:
        p = Path(filename)
        if p.parent.name == "gm" and p.suffix == ".py":
            executed.setdefault(p.name, set()).add(lineno)

    total_stmts = total_hit = 0
    print("%-24s %8s %8s %7s" % ("File", "Stmts", "Hit", "Cover"))
    print("-" * 52)
    for path in sorted((REPO / "gm").glob("*.py")):
        stmts = _statement_lines(path)
        hit = len(stmts & executed.get(path.name, set()))
        total_stmts += len(stmts)
        total_hit += hit
        pct = (100.0 * hit / len(stmts)) if stmts else 100.0
        print("%-24s %8d %8d %6.1f%%" % (path.name, len(stmts), hit, pct))
    print("-" * 52)
    pct = (100.0 * total_hit / total_stmts) if total_stmts else 100.0
    print("%-24s %8d %8d %6.1f%%" % ("TOTAL", total_stmts, total_hit, pct))
    return holder["r"], pct


def _statement_lines(path: Path) -> set:
    """Line numbers that can be executed, approximated without coverage.py."""
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and not isinstance(
                node, (ast.Import, ast.ImportFrom)):
            lines.add(node.lineno)
    return lines


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tiers", nargs="*", choices=list(TIERS) + [[]], default=[],
                    help="which tiers to run (default: all)")
    ap.add_argument("--no-coverage", action="store_true")
    ap.add_argument("--html", action="store_true", help="also write htmlcov/")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="exit non-zero if total coverage is below this percentage")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    tiers = args.tiers or list(TIERS)
    verbosity = 2 if args.verbose else (0 if args.quiet else 1)

    print("guardrail-monitor test suite")
    print("  python   %s" % sys.version.split()[0])
    print("  platform %s" % sys.platform)
    print("  tiers    %s" % ", ".join(tiers))
    for mod in ("yaml", "psutil", "win32pipe", "mcp", "coverage"):
        try:
            __import__(mod)
            state = "present"
        except Exception:
            state = "MISSING (dependent tests will skip)"
        print("  %-9s %s" % (mod, state))
    # unittest writes to stderr, which is unbuffered; without this the header
    # lands after the results whenever the run is piped to a file or a CI log.
    print(flush=True)

    total = None
    if args.no_coverage:
        result = run(tiers, verbosity)
    else:
        try:
            import coverage  # noqa: F401
            result, total = with_coverage_py(tiers, verbosity, args.html)
        except ImportError:
            result, total = with_trace(tiers, verbosity)

    print()
    ok = result.wasSuccessful()
    print("TESTS: %d run, %d failures, %d errors, %d skipped -> %s"
          % (result.testsRun, len(result.failures), len(result.errors),
             len(result.skipped), "PASS" if ok else "FAIL"))
    if total is not None:
        print("COVERAGE: %.1f%%" % total)
        if args.fail_under is not None and total < args.fail_under:
            print("COVERAGE GATE: %.1f%% < %.1f%% -> FAIL" % (total, args.fail_under))
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
