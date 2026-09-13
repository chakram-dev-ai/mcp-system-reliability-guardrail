# Testing and the release gate

```bash
pip install -r requirements-dev.txt

python run_tests.py                  # everything, with coverage
python run_tests.py smoke            # ~1s: run this before every release
python run_tests.py unit functional
python run_tests.py --fail-under 85  # gate on coverage too
python run_tests.py --html           # writes htmlcov/index.html
```

The suite is stdlib `unittest`, so it runs on a bare interpreter with nothing
installed. `pytest tests` works too, and `python -m unittest discover tests`
is always available as a fallback.

---

## The three tiers

| Tier | What it answers | Side effects | Time |
|---|---|---|---|
| `smoke` | Does the shipped configuration load and agree with itself? | none | ~1s |
| `unit` | Is each module's logic correct in isolation? | temp files | ~2s |
| `functional` | Do the parts work *together*, over real transports? | sockets, named pipes, subprocesses, one outbound connect | ~20s |

**Before a release, run all three.** If you only have a second, run `smoke`:
it is the tier that catches a rule that can never match, a probe with no rule
behind it, and a hook config key that the harness silently ignores — the class
of failure that produces a *quiet log* rather than an error, which is precisely
what this project exists to detect and therefore what it must never itself do.

### What `smoke` actually checks

- both policy files load through the real loader, with unique ids, valid
  enums, kinds some collector actually emits, and regexes that compile
- **every probe has a rule in every policy** — a probe without one can only
  ever report FAIL, which DESIGN.md §6.2 says to treat as a dead control
- no `${var}` or `~` survives expansion (either means a dead rule)
- containment rules do *not* fire inside the workspace, and do fire outside
- Windows command regexes carry `(?i)` (WINDOWS.md §6)
- the set of `action: kill` rules is exactly what is expected, so adding one
  is a reviewed change
- hook settings use only real hook keys (`type`, `command`, `timeout`) and
  invoke the shim, with `matcher: "*"`
- the Sysmon config only collects event IDs the collector subscribes to
- audit rule keys are ones `auditd_normalize` dispatches on, and the canary
  paths are watched
- every `GM_*` env var the code reads is documented in DESIGN.md §4.4
- nothing in `gm/` prints to stdout (AST-checked): stdout was the MCP stdio
  stream, and the client silently dropped every alert written there
- importing `gm.server` touches no files, and `mcp` is pinned below 2
- hook commands run the shim from an absolute path outside the project, with
  no `%VAR%` that only cmd expands

### What `functional` actually exercises

Real syscalls, not mocks:

- the hook shim as a **subprocess** fed JSON on stdin, delivering over a real
  unix socket (POSIX) or named pipe (Windows), including back-to-back events
- fail-open and fail-closed behaviour with no monitor listening
- the probe suite's canaries: a decoy file read, a canary binary exec, an
  outbound `connect()` to TEST-NET-1, a write outside the workspace
- `ProcTreeCollector` polling a real process tree
- `LineJSONCollector` wrapping a real subprocess
- the whole ingest funnel in `gm.monitor`, then the MCP tools' real
  implementations reading only the files the monitor wrote
- `python -m gm.monitor` as a real process with **no stdin**: it keeps running,
  heartbeats, accepts a hook event from the real shim, refuses a second
  instance on the same log, and never writes to stdout
- several processes appending to one log without forking the hash chain
- `setup-windows.ps1` refusing a broken configuration before changing anything
  (Windows, non-elevated only — the tests skip rather than risk an elevated run)

---

## Skips are expected, and they are not passes

`run_tests.py` prints which optional dependencies are present before it starts.
A skip means a test could not run here, not that it passed:

| Missing | What stops being tested |
|---|---|
| `pyyaml` | every policy-file test |
| `psutil` | `ProcTreeCollector` |
| `pywin32` (or non-Windows) | named-pipe ingest, event-log callback |
| non-POSIX | unix-socket ingest, exec-bit handling |
| `mcp` | nothing — a minimal `FastMCP` stands in so the tool functions stay testable. `mcp` needs Python 3.10+ |
| `fastapi` / `uvicorn` / `defusedxml` / `httpx` | the hosted demo in `web/` (`requirements-web.txt`, Python 3.10+) |

**Coverage is platform-dependent for exactly this reason.** `gm/collectors.py`
reports lower on Windows because `IngestServer`'s socket loop cannot run there,
and `gm/collectors_win.py` reports lower on POSIX. Run the gate on both
platforms before a release, or accept that one sensor path is unmeasured.

---

## Adding tests

- Put it in the tier that matches its cost, not its subject.
- `tests/support.py` holds the fixtures: `TempDirCase` (per-test temp dir,
  `write_policy`, `new_store`), the `event()` / `stored()` / `hook_payload()`
  builders, `make_monitor()` and `load_server()` for a monitor and a query
  server bound to the same throwaway files, and `captured_output()` for tests
  that deliberately trip a logging path.
- Assert on *behaviour an operator depends on*, and say why in the message.
  A test named `test_workspace_containment_does_not_fire_inside_the_workspace`
  with the message "containment inverted: this would alert on every normal
  write" tells the next person what broke and why it matters; `assert x == y`
  does not.
- When a test documents a deliberate limitation (the reconciler crediting any
  egress to a Bash call, the rules that have no probe yet), pin it rather than
  skipping it, so narrowing the gap is a visible change.
