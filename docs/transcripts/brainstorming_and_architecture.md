# guardrail-monitor — Conversation Transcript

A build log for the guardrail-monitor project, captured as it was designed.

**Date:** 12 September 2026
**Scope:** initial design → Windows port → packaging → design doc → multi-agent attribution

> **Note on completeness.** User messages are verbatim. Assistant responses are
> reproduced in full. Tool calls are summarized with their significant results
> rather than raw output. Source code is **not** inlined — it ships in the
> repository alongside this file. Where a turn produced or changed a file, the
> path is named so you can read the artifact itself.

---

## Turn 1 — Initial request

**User:**

> want to develop mcp server that monitors system activity of AI coding agent to make sure the security guard rails placed are working fine.

**Work performed:** consulted the product-self-knowledge skill; searched and
fetched the Claude Code hooks reference to get the `PreToolUse` payload shape
and `permissionDecision` semantics correct.

**Assistant response:**

Opened with the design trap that sinks most projects of this shape:

> An MCP server is a tool the agent calls. If your monitor is an MCP server, a
> misbehaving or compromised agent simply doesn't call it — and anything it
> does through `Bash` never touches MCP at all. **The MCP server cannot be the
> sensor.** It has to be the *query surface* over sensors that live outside the
> agent's reach.

Laid out the three-layer shape:

| Layer | What it gives you | Can the agent skip it? |
|---|---|---|
| **Hooks** (`PreToolUse`/`PostToolUse`) | Declared intent — tool name, args, session id | Yes, for anything inside a spawned subprocess |
| **OS telemetry** (eBPF / auditd / ES) | Ground truth — every `execve`, `open`, `connect` | No |
| **Reconciler** | The *diff* between the two | No |

On why the third layer matters:

> If the kernel saw a write to `~/.aws/credentials` and no hook announced it,
> you've found either an evasion or a blind spot in your guardrails. That diff
> is the strongest single signal you can build here, and almost nobody
> instruments it.

**Files created (11):** `README.md`, `policy.yaml`, `gm/__init__.py`,
`gm/store.py`, `gm/policy.py`, `gm/collectors.py`, `gm/reconcile.py`,
`gm/probes.py`, `gm/server.py`, `hooks/gm_hook.py`,
`hooks/settings.example.json`, `collectors/audit.rules`

**Smoke test result:** the `npm` exec was correctly credited to the `Bash` hook
that announced it, while the `~/.ssh/id_rsa` read appeared with no declaring
hook. Deleting one record from the log broke the hash chain at exactly the
right sequence number.

**Closing points raised:**

1. The MCP server must not be attached to the monitored agent — an agent that
   can call `find_blind_spots` learns which of its actions were invisible.
2. The hook shim is signal, not control; it runs as the agent's uid.
3. A dead guardrail and a well-behaved agent produce identical logs. Only the
   canary probes distinguish them.
4. `_covers()` in the reconciler needs workload-specific tuning.

Two open questions posed: whether `action: kill` is wanted at all (it converts
a monitoring failure into an availability incident), and whether the agent runs
in a container with a logging egress proxy.

---

## Turn 2 — Windows

**User:**

> is the above design centered around Linux OS? what about Windows?

**Assistant response:**

Confirmed the ground-truth layer was Linux + macOS only, but that the damage
was contained: of eight modules, only `collectors.py` is platform-specific.

Platform mapping table:

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Process exec | auditd `execve` / eBPF | ES `NOTIFY_EXEC` | **Sysmon Event 1** |
| Network connect | auditd `connect` | ES `NOTIFY_CONNECT` | **Sysmon 3** (+ hostname, free) |
| DNS | — | — | **Sysmon 22** |
| File create/write | auditd `-w` watches | ES `NOTIFY_WRITE` | **Sysmon 11 / 23 / 26** |
| **File read** | auditd `-p r` | ES `NOTIFY_OPEN` | **SACL + Security log 4663** — not Sysmon |
| Persistence | crontab/systemd paths | launchd paths | **Registry (Sysmon 12–14), WMI (19–21)** |
| Script content | — | — | **PowerShell 4104** — deobfuscated |
| Hook transport | unix socket | unix socket | **named pipe** or HTTP hook |
| Containment | cgroup + uid | uid | **Job Object + separate local account** |

Two rows flagged as the ones that actually bite:

> **File reads are the real gap.** Sysmon has no file-read event, at all. The
> `cred.read` rule — arguably the single most important rule in the policy —
> has no Sysmon implementation.

> **PowerShell script block logging is a capability Linux doesn't have.** Event
> 4104 gives you the fully deobfuscated script text after all the string
> concatenation and base64 unwrapping.

**Two live bugs found during the port:**

1. `path_not_under` used `startswith`, which is case-sensitive. On NTFS,
   `C:\Users\Agent\project` and `c:\users\agent\project` are the same
   directory, so every containment rule was one capital letter from being
   bypassed. Fixed with `os.path.normcase` (a no-op on POSIX).
2. Command-line regexes lacked `(?i)`. `reg save HKLM\SAM` did not match a rule
   written for lowercase `sam`.

On why the second is the more instructive failure:

> A rule that matches one casing still appears green on your control-coverage
> list while catching nothing.

Also added a `key_glob` predicate, because running `HKLM\Software\...` through
`normpath`/`expanduser` is meaningless — registry keys are not filesystem paths.

**Files created (6):** `gm/collectors_win.py`, `policy.windows.yaml`,
`WINDOWS.md`, `collectors/setup-windows.ps1`, `collectors/sysmon-config.xml`,
`hooks/settings.windows.example.json`
**Files modified (1):** `gm/policy.py`

**Verification:** all 16 Windows rules fire correctly across case variations;
benign activity (`npm.cmd test`, an ordinary registry write) stays clean.

---

## Turn 3 — Scope confirmation

**User:**

> So the overall project includes the files in the first iteration plus the second one above?

**Assistant response:**

Confirmed yes, with a manifest table, and flagged three things that made it not
a plain union:

1. **`gm/policy.py` was modified, not just added to.** A round-1 copy carries
   the containment bypass.
2. **The two `policy.*.yaml` files are alternatives, not both loaded.**
3. **A gap was closed on the spot:** `start_collectors()` never reached the
   Windows collectors, and called `os.uname()`, which does not exist on
   Windows — so it would have crashed at startup rather than degrading.

**Files modified (1):** `gm/server.py` — dispatch on `sys.platform`,
platform-aware `GM_POLICY` default, and a loud warning when no kernel-level
collector starts.

---

## Turn 4 — Missing diagram

**User:**

> On the right side, I saw an architectural diagram before with all the details of the project. I don't see that anymore.. where is it?

**Assistant response:**

No artifact had gone missing — no standalone diagram was ever created. The
diagram was the ASCII block inside `README.md`. The side panel had switched
because `present_files` opens whichever file is listed first, and the previous
message had put `gm/server.py` at the front.

Re-presented `README.md` first, and offered to build a properly rendered
diagram if useful.

---

## Turn 5 — File count mismatch

**User:**

> You mentioned it as 18 files in total - when I combined all the files you attached I see only 17 files. See the attached screenshot.
> *(screenshot: Windows Explorer showing 17 files in a single flat folder)*

**Assistant response:**

The missing file was `gm/__init__.py` — empty, and zero-byte files often do not
survive a download.

But the screenshot showed a larger problem:

> **The directory structure was flattened.** Everything landed in one folder.
> The package uses relative imports (`from .store import EventStore`), so
> `python -m gm.server` will fail immediately with `ImportError: attempted
> relative import with no known parent package`.

Gave the correct tree, rewrote `__init__.py` with real content (a layer map
docstring plus lazy `__getattr__` exports, so it can never be dropped again and
so the pure-Python layers import without `psutil`/`pywin32`), and packaged
everything as a zip that preserves directories.

**Verification:** copied to a clean directory and imported — `gm.Policy`,
`gm.EventStore`, `gm.reconcile` all resolve; hash chain validates.

---

## Turn 6 — Design document

**User:**

> Can you give a brief description of how the guard-rails monitor works? Start with the architecture, all components of it, how many user and kernel components are there, how it is installed, uninstalled, and run. Then how it can be used to monitor an AI Agent. Also a complete sequence diagram of one or two use cases. How it can be configured to set rules and access controls. Save it as a MD file, too.

**Assistant response:**

Created `DESIGN.md` covering architecture, components, install/uninstall/run
per platform, the operating loop, two Mermaid sequence diagrams, and
configuration.

The component count answer:

> **The project ships zero kernel components.** Two user-space executables —
> the monitor daemon (one process, several collector threads) and a short-lived
> hook shim spawned per tool call. It borrows exactly one kernel facility per
> platform, none of them ours: `kauditd` on Linux, Endpoint Security on macOS,
> `SysmonDrv.sys` on Windows.

And the consequence, documented rather than glossed:

> **Enforcement is post-hoc.** By the time an `open()` event reaches the
> monitor and `action: kill` fires, the read already completed — a real TOCTOU
> gap of roughly 1–50ms. The only true pre-execution gate is the hook's
> `permissionDecision: "deny"`, and that runs in-band as the agent's own
> account. So use a sandbox for prevention and this monitor for *verification*
> that the sandbox held.

| Control | Prevents? | Notes |
|---|---|---|
| Hook `permissionDecision: "deny"` | **Yes** | The only true pre-execution gate. But in-band |
| Sandbox / container / ACL | **Yes** | Enforced by the OS, not by us |
| `action: kill` | No — **contains** | Stops continuation, not the act itself |
| `action: alert` | No — **detects** | The honest default |

Two sequence diagrams:

- **A:** the agent writes a helper script and runs it. The hook sees only
  `Bash("python helper.py")`; the kernel sees the actual key read. The
  reconciler flags it as undeclared — a *structural* gap, not one bad command.
- **B:** a `git clean` destroys a watched directory, the file-read control
  dies, and the log goes quiet while looking healthy. This failure produces no
  log entry, no error, no counter gap. Only a canary probe catches it.

**Files created (1):** `DESIGN.md`

---

## Turn 7 — Agent discovery and multi-agent

**User:**

> does it monitor coding agents? how does it know where is the coding agent (CLI/VSCODE) running? can it also monitor multiple agents?

**Assistant response:**

The question surfaced a genuine bug, not a missing feature.

> Kernel events arrive with a PID and no session id, and nothing was bridging
> the two — so every auditd and Sysmon event landed under `"unknown"`. That
> meant `find_blind_spots(session)` queried for a session, got back only hook
> events, found zero OS effects, and reported "nothing undeclared" no matter
> what happened. **The feature reported all-clear by construction.** My earlier
> smoke test hid it because I passed `session="s1"` by hand on every event.

Answers to the three questions:

**Agent-agnostic?** The OS layer watches a process subtree, so Cursor, Aider,
or homegrown agents all work. The hook layer is Claude Code-specific:

| Agent | Ground truth | Declared intent | Reconciliation |
|---|---|---|---|
| Claude Code (any surface) | yes | yes, via hooks | **yes** |
| Cursor / Aider / homegrown | yes | no hook API | **no** |

**Locating the agent?** It doesn't search — the agent self-registers. The hook
shim runs as a child of the agent process, so it walks its own parent chain and
reports the agent PID with the session id. CLI vs VS Code vs JetBrains needs no
separate handling because the binary is identical; only the ancestors differ:

```
CLI:        bash → claude                  → surface "cli"
VS Code:    code → extension-host → claude → surface "vscode"
JetBrains:  idea → claude                  → surface "jetbrains"
```

**Multiple agents?** Now yes. Two design choices called out:

> `resolve()` **never guesses.** An unattributable event stays `unknown` rather
> than getting assigned to whichever session is active. With one agent that
> distinction is invisible; with three, a wrong attribution puts one agent's
> credential read in another agent's summary, which is worse than a gap. PID
> reuse is guarded by create-time comparison for the same reason.

And the remaining trade, stated rather than buried:

> `outside_session_workspace` stays silent on unattributed events, so they
> escape workspace containment. `attribution_health()` is what surfaces it —
> and it belongs on your alerting alongside probe failures, because a broken
> PID bridge and a well-behaved agent produce identical quiet reports.

**Files created (1):** `gm/sessions.py`
**Files modified (4):** `gm/server.py` (registry wiring + `list_sessions`,
`list_agents`, `attribution_health` tools), `gm/policy.py`
(`outside_session_workspace` predicate), `hooks/gm_hook.py` (agent PID
self-reporting), `gm/collectors.py` (carry PID through canonicalization)
**Docs:** `DESIGN.md` §5A added

**Verification:** two live process trees; children resolved to the correct
sessions, an unrelated PID resolved to `unknown`, per-session containment
distinguished repo-a from repo-b correctly, and the reconciler — given properly
attributed events — surfaced the undeclared `~/.ssh/id_rsa` read.

---

## Turn 8 — This file

**User:**

> save all the conversation into an md file that I can download

---

## Recurring theme

One failure shape came up in four separate forms across the build, and it is
the thing worth carrying away from the whole exercise:

| Instance | Turn | Why it's invisible |
|---|---|---|
| Dead collector | 1 | Log goes quiet; looks like good behavior |
| Case-sensitive rule | 2 | Shows green on control coverage; catches nothing |
| Broken PID attribution | 7 | Per-session views return empty; report all-clear |
| SACL lost to `git clean` | 2 | No error, no gap in any counter |

**In every case the broken control and the well-behaved agent produce the same
output.** No amount of detection engineering distinguishes them. Only
deliberately tripping the control does — which is why `run_probe_suite` and
`attribution_health` belong on the same alerting path as actual violations, and
why a rule with no probe covering it should be treated as broken until proven
otherwise.

---

## Final state

20 files. Runs on Linux, macOS, and Windows.

```
guardrail-monitor/
├── README.md                  architecture overview
├── DESIGN.md                  full design + operations reference
├── WINDOWS.md                 Windows deployment guide
├── docs/
│   └── transcripts/
│       └── brainstorming_and_architecture.md   this file
├── policy.yaml                POSIX rules
├── policy.windows.yaml        Windows rules
├── gm/
│   ├── __init__.py            layer map, lazy exports
│   ├── store.py               hash-chained append-only log
│   ├── policy.py              rule engine
│   ├── sessions.py            PID → session attribution, agent discovery
│   ├── collectors.py          Linux + macOS sensors
│   ├── collectors_win.py      Windows sensors
│   ├── reconcile.py           intent vs effect diff
│   ├── probes.py              canary control-efficacy suite
│   └── server.py              MCP query surface
├── hooks/
│   ├── gm_hook.py
│   ├── settings.example.json
│   └── settings.windows.example.json
└── collectors/
    ├── audit.rules
    ├── sysmon-config.xml
    └── setup-windows.ps1
```

### Known open items

- `reconcile._covers()` does not know about the PowerShell tool. On Windows
  every PowerShell call reads as `unobserved`. One-line fix, left visible
  rather than guessed at.
- `_covers()` credits any egress within a `Bash` call's window — permissive,
  needs workload tuning.
- `store.query()` full-scans; move to SQLite past ~10⁵ events.
- The auditd parser is minimal; use `auparse` or a SIEM in production.
- Sysmon events 8, 10, 25, 7, 17/18 are unmapped. Event 10 with `TargetImage`
  pointing at the monitor process is the highest-value addition available.

---

## What came next

For the subsequent web demo implementation, containerization, Docker build
validation, and Render deployment execution, see
[`implementation_and_validation.md`](implementation_and_validation.md). The
design review, blocking fixes and test suite built in between, in a Claude Code
CLI session, are summarized in [`HANDOFF.md`](../../HANDOFF.md); several details
above changed along the way, and [`DESIGN.md`](../../DESIGN.md) is the current
reference.
