# guardrail-monitor — session handoff

Working record of a Claude Code session on `D:\develop\mcp-system-reliability-guardrail`.
Written so a fresh session can pick the work up without re-deriving anything.

**Date:** 2026-09-07 → 2026-09-08
**State at handoff:** 361 tests passing, 0 failures, 88.4% branch coverage, working
tree clean of build artefacts.

---

## 1. What the project is

An MCP server that verifies the security guardrails around an AI coding agent are
actually working — by watching what the agent's process tree does at the OS level and
diffing it against what the agent's tool layer *said* it was doing.

The load-bearing idea: **an MCP server is a tool the agent calls, so it must not be the
sensor.** Anything the agent does without invoking it would be invisible — and that
includes every subprocess spawned from `Bash`, which is where the interesting activity
lives. So the MCP server is a read-only query surface over sensors that run out-of-band
in a process the agent cannot reach.

Three signals:

| Signal | Source | Weakness |
|---|---|---|
| **Intent** | `PreToolUse`/`PostToolUse` hooks | In-band; blind to subprocesses |
| **Effect** | auditd / Endpoint Security / Sysmon | No semantics |
| **Divergence** | `reconcile.py` | Needs per-workload tuning |

The third row is the reason the project exists. A recurring theme throughout this
session: **a guardrail that stopped working looks exactly like an agent that behaved
well.** Every fix below is judged against that.

---

## 2. Environment facts that shaped the work

These matter — several decisions only make sense given them.

- **Python 3.7.3, 32-bit, win32.** This is old. `mcp` requires 3.10+, so `gm.server`
  cannot import here; tests substitute a minimal `FastMCP` (see `tests/support.py`).
- Installed during the session: `pyyaml`, `coverage`, `psutil`, `pywin32`.
  Still absent: `mcp`, `pytest`.
- **Coverage is platform-dependent.** `gm/collectors.py` sits at ~68% on Windows
  because `IngestServer`'s unix-socket loop cannot run; `collectors_win.py` would
  drop on POSIX. **Run the gate on both platforms before a release.**
- **Git tracks only `.gitignore` and `README.md`.** Everything else is untracked.
  The `README.md` modification predates this session (initial commit had a stub).
  Nothing has been committed during this session.

### Two gotchas that cost time — avoid repeating them

1. **Bash heredocs in this harness mangle backslashes and backticks.** `\\n` became a
   real newline, `\v` became a 0x0B byte, and backticks triggered command substitution
   inside a quoted `<<'PY'` heredoc. **Use the `Write`/`Edit` tools for any content with
   backslashes, regex escapes, or backticks.** A scratch helper
   (`patch.py` with `sub(path, old, new)`) was used for safe exact-match edits.
2. **Writing files with Python's default text mode on Windows introduced CRLF** into
   five source files. Always `open(..., newline="\n")`. A smoke test now asserts no
   Python source uses CRLF.

---

## 3. What happened, in order

### Phase 1 — Design + implementation review (no code changes)

Read `DESIGN.md` and all implementation, ran the pure-logic parts to confirm findings
rather than eyeballing them. Verdict: architecture sound, code clean and well-commented,
but **not runnable-correct** — nothing failed to compile; the problems were logic bugs,
several of which silently disabled the exact controls the design is built around.

### Phase 2 — Fixed 8 blocking issues, one at a time, verifying after each

### Phase 3 — Built a test suite (was zero tests) and ran coverage

### Phase 4 — Ported session improvements from a newer branch

---

## 4. Every bug found and fixed

Grouped by phase. The *why it mattered* column is the point — a fresh session should not
"simplify" any of these back.

### Phase 2 — the 8 blocking fixes

| # | Bug | Why it mattered |
|---|---|---|
| 1 | `path_not_under` appended `"/"` to an already-backslashed root (`gm/policy.py`) | **Inverted on Windows.** `fs.write_outside_workspace` fired on *every* write inside the workspace. Also fixed an invalid `"\/"` escape (a future `SyntaxError`). |
| 2 | `signal.SIGKILL` doesn't exist on Windows (`gm/server.py`) | `AttributeError` uncaught by `(ProcessLookupError, PermissionError)`; in `NamedPipeIngest` it killed the ingest thread permanently. Now `getattr(signal,"SIGKILL",signal.SIGTERM)`, `except OSError`, and `ingest()` never raises. Added refusal to signal the monitor's own pid. |
| 3 | **No pid→session correlation existed at all** | Kernel events always carried `session="unknown"`, so `find_blind_spots`/`session_summary` returned only the hook half — i.e. "all clear" regardless of what happened. The flagship feature did not work. Created `gm/sessions.py`; hook now ships `agent_pid`; added `ppid` parsing to auditd/eslogger; pulled `System/Execution/@ProcessID` for 4104. |
| 4 | Hook was `socket.AF_UNIX`-only (`hooks/gm_hook.py`) | Doesn't exist on Windows → `AttributeError`, not caught by `except OSError`. The entire intent signal was missing on Windows. Added named-pipe transport via builtin `open()` (deliberately **not** pywin32 — the shim runs as the agent account). |
| 5 | Both hook settings files used a non-existent schema | `args`, `async`, `if` are not hook keys. `"command": "python3"` alone would feed the payload to Python as source. Rewrote to `{type, command, timeout}` with `matcher: "*"`. |
| 6 | The probe suite could not pass | `gm-canary.invalid` fails in `getaddrinfo` → **no `connect()` ever issued**; `#!/bin/sh` canary is not executable on Windows; containment canary wrote to `/` (unwritable); `canary.net` missing from the Windows policy; sensor configs are account-scoped but probes run as the monitor. |
| 7 | `~` in policy globs expanded to the **monitor's** home | With the design's own `gmmonitor` account, `cred.read` — the most important rule in the file — matched nothing while still appearing as "never fired". Added `agent_home` var; removed `expanduser` from `_norm`. Also added load-time validation (missing `id`/`kind`, typo'd keys, empty file). |
| 8 | All Windows collector threads were named `gm-operational` | Derived from the channel's last path segment, so Sysmon and PowerShell collided — and `server.py`'s health check keys on `"gm-sysmon"`, so it printed "no kernel-level collector started" on **every** Windows run. |

### Phase 3 — bugs the tests found

| Bug | Why it mattered |
|---|---|
| `_covers` compared the effect's `exe` against the effect's **own** `argv` (`reconcile.py`) | Tautologically true for essentially every exec. One Bash hook in the window marked **every** concurrent process as declared, so `undeclared_rate` sat near 0 no matter what the agent ran. Now: a tool call explains binaries it names, plus the shell it runs through (`SHELL_TOOLS`/`SHELL_BINARIES`). |
| **All five collector classes shadowed `threading.Thread._stop`** with an `Event` | `is_alive()` and `join()` raise `TypeError` once a thread ends — and `control_coverage()` calls `is_alive()`, so the health tool crashed precisely when a collector had died. Renamed to `_stopping` everywhere. |
| `p.uids()` doesn't exist on Windows (`ProcTreeCollector`) | `AttributeError` on the first process killed `gm-proctree` before it emitted anything. The psutil fallback was 100% dead on Windows, silently. |
| Named-pipe DACL locked the monitor out of its own pipe | Only the *first* `CreateNamedPipe` applies a security descriptor; later instances need `FILE_CREATE_PIPE_INSTANCE`, which `FW` doesn't grant. A monitor as its own non-admin account (the layout `WINDOWS.md` recommends) got `ACCESS_DENIED` after the first hook event and the thread died. Creator SID now gets `FA`; agent still write-only. |
| **Events dropped between pipe connections** | The next instance was only created *after* the previous message was fully processed, leaving a window with nothing listening; the client only retried `ERROR_PIPE_BUSY`, and Windows reports this as bare `EINVAL`. Back-to-back tool calls are the *normal* case. Fixed both ends: server hands off to a worker and re-listens immediately; client retries any transient error. |
| Fail-open skipped the shim's own deny rule | `sys.exit(0)` fired *before* the in-band check — so when the monitor was down (and out-of-band policy therefore evaluating nothing), the last remaining control was skipped too. |
| `canary.exec` in the Windows policy lacked `(?i)` | Violated the rule `WINDOWS.md` §6 itself states. |
| Four `GM_*` env vars undocumented | `GM_HOOK_TIMEOUT`, `GM_PIPE`, `GM_CANARY_IP`, `GM_CANARY_PORT`. A smoke test now enforces this. |
| `LineJSONCollector.stop()` left a zombie + unclosed pipe | Slow FD leak in a process meant to run for weeks. |
| `.gitignore` was a **Rust** template | No `__pycache__`, and it would have committed `events.jsonl` — which is *evidence*. |

### Phase 4 — session port from `guardrail-monitor-new`

Source: `E:\docs\personal\chakri\Anthropic\guardrail-monitor\guardrail-monitor-new`

**Critical:** that copy is branched from the **original**, before Phase 2/3. It still
contains the `_stop` shadowing, `SIGKILL`, the `path_not_under` bug, the AF_UNIX-only
hook, and `p.uids()`. **Do not copy `gm/` wholesale from it** — cherry-pick only.

Adopted (its session model is genuinely better):

1. **PID-reuse guard via process create-time.** The old `SessionMap` keyed on pid alone,
   so a recycled PID inherited a dead session's attribution — an audit trail that is
   *actively misleading*, worse than an empty one.
2. **Ancestry walk for cold starts** — a monitor restarted mid-session used to return
   `unknown` forever; now walks live parents via psutil, then memoizes.
3. **Rich `Session` objects** — cwd, launch surface (cli/vscode/jetbrains/ssh), agent
   kind, alive, first/last seen, tracked pids.
4. **`outside_session_workspace` predicate** — per-agent containment against the
   session's own cwd, closing the "policy is global" limitation.
5. **Three MCP tools** — `list_sessions`, `list_agents`, `attribution_health`.
6. **Hook walks up past an intermediate shell** to find the real agent PID.

`list_agents` cross-referenced against `list_sessions` is the strongest idea in the new
design: **a discovered agent process with no registered session is an agent running
unmonitored**, and that gap was previously invisible.

Three bugs found *in the new code* and fixed while porting:

| Bug | Fix |
|---|---|
| `reap()` defined but **never called anywhere** → `_pid_map` grows unbounded | Added `SessionReaper` thread started by `start_collectors()`, plus a `MAX_TRACKED_PIDS` ceiling |
| `evaluate()` stashes `_workspace` on the event, pops at end → a raising predicate leaks it into the stored record | `try/finally`, with a test that patches a predicate to raise |
| `sh` unanchored in `SURFACE_PATTERNS` **and** CLI checked before SSH → `sshd` matched CLI, so **every SSH session was labelled `cli`** | Anchored to path separators, reordered ssh first |

Not adopted: the new `policy.yaml` doesn't actually use `outside_session_workspace`.
Kept the global rule as the shipped default (correct for single-agent) and added a
commented drop-in replacement showing the multi-agent form and its trade-off.

---

## 5. How agent detection actually works

Asked and answered during the session; now documented in `DESIGN.md` §5A.

**Nothing scans for the agent by default.** Three independent mechanisms:

| Mechanism | Scopes by | Decides |
|---|---|---|
| `audit.rules` (`-F auid=1001`) / Sysmon (`<User contains agent>`) | **account** | what is captured at all |
| Hook self-registration + ppid inheritance | **process tree** | which agent an event belongs to |
| `GM_AGENT_PID` → `ProcTreeCollector` | one pid subtree | psutil dev fallback only |

The hook runs as a child of the agent, walks up past any intermediate shell, and reports
the agent PID with the session id. Every `process.exec` carries a ppid, so attribution
flows down the tree. A PID first seen mid-session is resolved by walking live ancestry.

**Multiple agents are supported** and verified by tests: separate sessions, per-agent
violation attribution, per-agent blind spots, no cross-contamination, recycled pids
rebind correctly.

Still global (reasons to prefer **one monitor per agent** — `GM_LOG`, `GM_POLICY`,
`GM_SOCK`/`GM_PIPE` are all env vars, so N monitors costs nothing structurally):
the rule set, the sensor account filters, `GM_AGENT_PID`, and the three monitor-wide
tools. `control_coverage` in particular aggregates across agents, so a rule that fired
for A but never for B reports as "fired".

### The deliberate hole

`outside_session_workspace` **cannot fire on an event it cannot attribute** — firing
would flood the operator with false violations. `attribution_health()` is the
compensating control: a broken PID bridge and a well-behaved agent produce the identical
empty `session_summary`. Same failure shape as a dead collector; same treatment —
**alert on the health metric, not just on violations.** (`DESIGN.md` §5A.4)

---

## 6. Current state

### Files

```
gm/sessions.py        414   pid→session registry, discovery, surface classification
gm/collectors_win.py  474   Sysmon / Security 4663 / PowerShell 4104 / named pipe
gm/collectors.py      390   hook socket, eslogger/auditd adapters, psutil fallback
gm/server.py          353   MCP tools + the single ingest funnel
gm/policy.py          317   rule engine, 11 predicates
gm/probes.py          236   canary suite
gm/store.py           140   hash-chained append-only JSONL
gm/reconcile.py       112   intent-vs-effect diff
gm/__init__.py         38
                     ----
                     2474

tests/                       12 files, ~3400 lines
run_tests.py           187   runner + release gate
```

Docs: `README.md`, `DESIGN.md`, `WINDOWS.md`, `TESTING.md`, this file.
Config: `policy.yaml`, `policy.windows.yaml`, `hooks/settings*.json`,
`collectors/{audit.rules,sysmon-config.xml,setup-windows.ps1}`,
`requirements.txt`, `requirements-dev.txt`.

### Tests

| Tier | Tests | Time | Purpose |
|---|---|---|---|
| `smoke` | 65 | 1.2s | Does the shipped config load and agree with itself? |
| `unit` | 180 | 10.3s | Per-module logic |
| `functional` | 116 | 31.1s | Real sockets, named pipes, subprocesses, canaries |
| **total** | **361** | ~35s | 88.4% branch coverage |

```bash
pip install -r requirements-dev.txt
python run_tests.py                  # all tiers + coverage
python run_tests.py smoke            # ~1s pre-release check
python run_tests.py --fail-under 85  # gate on coverage too
python run_tests.py --html           # htmlcov/index.html
```

Stdlib `unittest` throughout — runs on a bare interpreter. `pytest tests` also works.
7 skips are expected here (POSIX-only socket tests, `mcp` absent). **A skip is not a
pass** — the runner prints which optional deps are present before it starts.

Per-module coverage at handoff: `reconcile` 100%, `sessions` 95%, `policy` 95%,
`store` 96%, `probes` 91%, `server` 86%, `collectors_win` 86%, `collectors` 68%
(platform-gated), `__init__` 88%.

---

## 7. Open items

None blocking. In rough priority order:

1. **Run the suite on Linux/macOS.** The POSIX sensor path is entirely unmeasured here
   — `IngestServer`'s socket loop, the auditd tail, eslogger. This is the single
   biggest gap in confidence.
2. **`store.scan()` has no error handling for a torn JSON line.** MCP queries run
   concurrently with collector appends; a partial line raises. `verify()` should return
   `{"ok": False, "reason": "malformed"}` rather than propagate, and `EventStore.__init__`
   currently cannot open a log whose last line was truncated by a crash.
3. **auditd fidelity**: `name=` is often a *relative* path (needs joining with the `cwd=`
   record, or most path rules silently miss), and `saddr` is raw hex so
   `net.egress_allowlist` flags 100% of connections while `port_in` is dead.
4. **`reconcile._norm` lacks `normcase`** — hook-vs-effect path comparison is
   case-sensitive on Windows.
5. **Unmapped Sysmon events 8 and 10** — collected by the config, dropped by the
   collector. `sysmon-config.xml`'s own comment calls event 10 (ProcessAccess targeting
   the monitor) "the highest-signal event in this whole system".
6. **`canary.registry` has no probe** — violates `DESIGN.md` §7.3's own rule. The smoke
   suite pins the current set of unprobed rules so the gap can only shrink deliberately.
7. **Duplicate root `__init__.py`** — byte-identical to `gm/__init__.py`, makes the repo
   root a package. Almost certainly accidental.
8. **Nothing is committed.** `git log` shows only the initial commit.

---

## 8. Conventions to preserve

Things a fresh session should not undo:

- **`ingest()` never raises.** It runs on collector threads and the Windows EvtSubscribe
  callback; an escaping exception silently kills the sensor.
- **Attribution never guesses.** An unattributable event stays `unknown`. A wrong
  attribution puts one agent's actions in another's summary — worse than a visible gap.
- **`_stopping`, never `_stop`,** for thread stop flags.
- **No mutating MCP tools.** No way to mute a rule, delete an event, or stop a collector
  — those are config-file operations done out of band. A smoke test enforces this.
- **Tests assert on operator-visible behaviour and say why in the message.** e.g.
  "containment inverted: this would alert on every normal write". When a test documents
  a deliberate limitation, it is *pinned* rather than skipped, so narrowing the gap is a
  visible change.
- **Canaries touch nothing real**: decoy file, decoy binary, TEST-NET-1 (`192.0.2.1`).
  The canary target must stay an **address**, not a name — an unresolvable hostname
  fails in `getaddrinfo`, so no `connect()` is issued and the probe reports a permanent
  FAIL indistinguishable from a dead control.

---

## 9. Prompt to resume in a new session

> I'm continuing work on `guardrail-monitor` (`D:\develop\mcp-system-reliability-guardrail`),
> an MCP server that verifies the guardrails around an AI coding agent are actually working.
> `HANDOFF.md` in the repo root has the full context: what it is, every bug fixed and why,
> current state (361 tests, 88.4% coverage), and open items in §7.
>
> Read `HANDOFF.md` first, then `DESIGN.md` and `TESTING.md`.
> Verify with `python run_tests.py` before changing anything.
>
> Next task: <pick from §7, e.g. "harden store.scan() against torn lines (§7.2)">

Note for a Claude UI (non-Code) session: it has no access to this filesystem, so attach
or paste this file, plus whichever source files the task touches. `HANDOFF.md` is written
to be usable standalone.

---

## 10. Session 2 — 2026-09-12 (Claude Code desktop app)

**This section supersedes §6 and extends §8.** Where §1–§9 say `python -m gm.server`
starts the collectors, that is no longer true.

### What changed, and the problem each change fixes

| Change | Problem it fixes (verified, not inferred) |
|---|---|
| **Split into two processes.** `gm/monitor.py` (`python -m gm.monitor`) runs the collectors, policy, kill, alerts and a heartbeat. `gm/server.py` is now a read-only MCP query process over the files the monitor writes (`GM_LOG`, `GM_ALERT_LOG`, `GM_STATUS`) | A stdio MCP server exits as soon as its stdin closes. Measured with mcp 1.30.0: `mcp.run()` returned after 0.05 s and every daemon collector thread died with it. So the monitor could not run as a service. |
| **Every `print` in `gm/` goes to stderr** (AST smoke test). Alerts also go to `GM_ALERT_LOG` as JSON lines | stdout carried the JSON-RPC stream. A real mcp client logged `Failed to parse JSONRPC message` for each alert and dropped it; the startup warning met the same fate. |
| **`mcp>=1.0,<2`** | mcp 2.x renamed `FastMCP`, so an unpinned install could not import `gm.server`. |
| **No import-time side effects**: `gm/config.py` reads settings at call time; building an `EventStore` touches no disk | `import gm.server` raised `PermissionError: '/var/log/gm'` on Linux. |
| **Store is safe with more than one process**: `gm/filelock.py` locks each append and the tip is re-read from disk. A partial trailing line is skipped; a malformed line makes `verify()` return `reason: "malformed"`; an append after a torn tail starts on a new line | The server's probe markers and the monitor's events are now written by two processes. Without the lock and re-read, the chain forks. |
| **One monitor per log** (`events.jsonl.monitor.lock`; a second instance exits with code 2) | Two monitors would split hook events between them and fork the chain. |
| **`gm/paths.py`** picks the path handling from the path's shape (`ntpath` for drive letters and backslashes), not from the host OS | 2 failures on Linux: the Windows policy's containment inverted, and `C:\...\cmd.exe` had no basename. |
| **The hook's `agent_pid()` walks past shells only** | The old walk matched the substring `claude`/`node` anywhere in the ancestry. Inside Claude Code it returned claude.exe instead of the test process, and an `npm` process in the chain became the "agent". |
| **Health checks use `is_alive()`**. A dead collector writes a `monitor.collector_died` event; an `EvtSubscribe` failure is caught and logged | The warning checked which collectors had been *started*, so a Sysmon subscription that failed right after starting still counted as running. |
| **`setup-windows.ps1` preflight** (`-ValidateOnly`, needs no elevation): the profile is resolved from the account SID. It refuses a nonexistent agent account, a monitor running as the agent, and a missing Sysmon binary *before changing anything*. It cross-checks the policy vars and adds `-ReaderAccount`, `-SkipSysmon` and `-SysmonPath` | Credential-store paths were hardcoded to `C:\Users\agent`; `-Workspace` was ignored. If the agent and monitor shared an account, block 6's Deny ACE locked the monitor out of its own log. A nonexistent account failed only after blocks 1–5 had already changed the machine. |
| **Hook settings use absolute, quoted, forward-slash paths outside the project** | `%CLAUDE_PROJECT_DIR%` expands only under cmd, and a shim inside the project can be edited by the agent. |

### State at the end of session 2

| Platform | Tests | Failures | Skips | Coverage |
|---|---|---|---|---|
| Windows, Python 3.7.3 (mcp stubbed) | 422 | 0 | 9 | 85.8% |
| Linux: WSL1 Ubuntu 26.04, Python 3.14.4, **real mcp 1.30.0** | 422 | 0 | 28 | 81.8% |

Coverage dropped from 88.4%, mostly because `gm.monitor.main()` is exercised only by subprocess tests, which coverage does not measure. The documented `--fail-under 85` gate passes on Windows but not on Linux (Linux was already at 83.3% before this session). The suite now passes when run inside a Claude Code session; no detached launch is needed.

New test files: `unit/test_paths.py`, `unit/test_hook_ancestry.py`, `unit/test_store_damage.py`, `unit/test_probe_markers.py`, `functional/test_monitor_process.py` (runs the monitor with no stdin, real shim → log, second instance refused, stdout empty, clean SIGTERM on POSIX), `functional/test_store_multiprocess.py`, `functional/test_setup_windows.py` (preflight only; skips when elevated). `test_pipeline.py` and `smoke/test_package.py` were rewritten around `make_monitor()` + `load_server(tmp, policy)`.

### Conventions added to §8

- **Nothing in `gm/` writes to stdout.**
- **`gm.server` never starts collectors**, and it has no `ingest`. Anything that must keep running belongs in `gm.monitor`.
- **Exactly one monitor writes a given log**, and every append goes through `EventStore.append`, which takes the lock.
- **Event and rule paths go through `gm.paths`**, never through bare `os.path`.
- **`agent_pid()` never walks past a non-shell process.**

### Still open

- §7.1 is only partly closed. Linux now runs the unix-socket ingest and the POSIX branches, but live auditd capture cannot run on WSL1 (`NETLINK_AUDIT` fails with "Protocol not supported"), and eslogger is macOS-only.
- §7.3, §7.5 and §7.6 are unchanged. §7.4 (`reconcile._norm` lacks normcase) is also unchanged.
- §7.2 is partly addressed by the store changes above.
- §7.7: the root `__init__.py` was identical to `gm/__init__.py` and is now also out of date.
- §7.8: **nothing is committed.**
- No combined cross-platform coverage number is computed.
- Alerts go only to a file (and stderr); there is no syslog or Windows Event Log sink.
- Untested: the scheduled-task commands in WINDOWS.md step 5, and the `claude mcp add` examples.
- WSL scratch left from this session: `~/gm-build`, `~/mcp1-venv`, `~/stdio-test`.
