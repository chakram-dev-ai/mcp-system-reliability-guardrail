# guardrail-monitor

An MCP server that verifies the security guardrails around an AI coding agent
are actually working — by watching what the agent's process tree does at the
OS level and diffing it against what the agent's tool layer claimed it was doing.

## The design constraint everything else follows from

An MCP server is a tool the agent calls. If the monitor is something the agent
invokes, then anything the agent does *without* invoking it is invisible — and
that includes every subprocess spawned from `Bash`, which is where most of the
interesting activity lives.

So the MCP server here is **not the sensor**. It's the query surface over
sensors that run out-of-band, in a process the agent can't reach.

Nor does it host the sensors. A stdio MCP server exits when its client
disconnects, so the sensors run in their own long-lived process, `gm.monitor`,
and `gm.server` only reads what the monitor writes.

```
                    ┌──────────────────────────────┐
   agent uid  ──────│ Claude Code (or other agent) │
                    └──────┬────────────────┬──────┘
                           │ hooks          │ syscalls
                           │ (intent)       │ (ground truth)
       ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─┼─ ─ ─ ─ trust boundary
                           ▼                ▼
   monitor uid       unix socket      eslogger / auditd / eBPF
                           └───────┬────────┘
                                   ▼
                   gm.monitor: policy engine ──▶ alert / kill
                   (long-running service)    ──▶ alerts.jsonl
                                   ▼
                hash-chained append-only log + status.json
                                   ▼
                       ┌────────────────────────┐
                       │ gm.server (MCP, RO)    │──▶ supervisor session
                       └────────────────────────┘
```

## The three signals

| Signal | Source | Strength | Weakness |
|---|---|---|---|
| **Intent** | `PreToolUse` / `PostToolUse` hooks | Semantic — you know it was a `Write` to a named path | In-band. Runs as the agent's uid. Blind to subprocess activity |
| **Effect** | eBPF / auditd / Endpoint Security | Unskippable. Every `execve`, `open`, `connect` | No semantics. A write is a write; you don't know why |
| **Divergence** | `find_blind_spots()` | Catches what neither catches alone | Needs tuning per tool set |

The third one is the reason to build this rather than buy a generic EDR. When
the kernel observes an effect that no hook declared, you've found either an
evasion or a hole in your hook coverage. Both are findings. In steady state
`undeclared_rate` should sit near zero, so any drift is a signal.

## Layout

```
policy.yaml              declarative rules — paths, egress allowlist, exec patterns
gm/store.py              hash-chained append-only JSONL log + integrity check
gm/policy.py             rule engine (globs, prefixes, regexes, set membership)
gm/collectors.py         hook ingest socket, eslogger/auditd adapters, psutil fallback
gm/collectors_win.py     Sysmon / Security 4663 / PowerShell 4104 + named-pipe ingest
gm/sessions.py           process tree → agent session, so the two halves can be diffed
gm/reconcile.py          intent-vs-effect diff
gm/probes.py             canary suite that proves the controls still fire
gm/monitor.py            the long-running process: collectors, policy, alerts, heartbeat
gm/server.py             FastMCP server — the read-only query surface over the monitor's files
gm/config.py             GM_* settings, read at call time (nothing touches disk on import)
gm/paths.py              path handling by the path's own flavor, not the host's
gm/filelock.py           cross-process locks: one chain, one monitor per log
hooks/gm_hook.py         Claude Code hook shim
hooks/settings.example.json
collectors/audit.rules   Linux auditd ruleset
collectors/setup-windows.ps1  Windows sensors + ACLs, with a -ValidateOnly preflight
run_tests.py             test runner and release gate
tests/                   smoke / unit / functional
```

## Testing

```bash
pip install -r requirements-dev.txt
python run_tests.py            # all tiers, with coverage
python run_tests.py smoke      # ~1s pre-release check
```

Three tiers -- `smoke` (does the shipped config load and agree with itself),
`unit` (per-module logic), `functional` (real sockets, pipes, subprocesses and
canaries). Run all three before a release, on **both** platforms: the sensor
layer is the platform-specific part, so each OS leaves the other's collector
unmeasured. See [TESTING.md](TESTING.md).

## Running it

Two processes, started in this order. Windows has its own walkthrough in
[WINDOWS.md](WINDOWS.md).

**1. The monitor** — a long-running service under the monitor account. It needs
no terminal, reads no stdin and writes nothing to stdout.

```bash
pip install -r requirements.txt          # pins mcp<2: 2.x cannot import gm.server

# Linux ground truth
sudo auditctl -R collectors/audit.rules

# macOS 13+ ground truth (requires Full Disk Access) is picked up automatically

export GM_LOG=/var/log/gm/events.jsonl   # alerts.jsonl and status.json go beside it
export GM_SOCK=/run/gm/ingest.sock
export GM_AGENT_PID=$(pgrep -f claude)     # optional psutil fallback

python -m gm.monitor
```

Alerts go to stderr and, one JSON line each, to `alerts.jsonl` — tail that into
your pager. Only one monitor can write a given log; a second refuses to start.

**2. The agent's hooks** — copy `hooks/settings.example.json` into the monitored
project's `.claude/settings.json`, pointing at the shim in the monitor's install
(somewhere the agent can read but not write), never at a copy inside the project.

**3. The query server** — register `gm.server` with a client in a **different**
session from the one being monitored (see the trust notes below):

```bash
claude mcp add guardrail-monitor -e PYTHONPATH=/opt/gm -- /opt/gm/venv/bin/python -m gm.server
```

It runs no collectors and exits with its client. Every tool that reports on
collectors or sessions includes a `monitor` block that says whether the
monitor's heartbeat is current, stale, or stopped.

### MCP tools

| Tool | Answers |
|---|---|
| `query_events` | What happened, filtered by kind/session/time |
| `list_violations` | What tripped a rule, above a severity floor |
| `session_summary` | Profile of one session: binaries, hosts, files written, rules tripped |
| `find_blind_spots` | Where declared intent and observed effect diverge |
| `verify_log_integrity` | Has the log been edited or truncated |
| `run_probe_suite` | Are the controls still firing *right now* |
| `control_coverage` | Which rules fire, which have never fired |
| `list_sessions` | Which agents are registered, from where (cli/vscode/jetbrains), in which directory |
| `list_agents` | Which agent processes are running, and which are missing hook coverage |
| `attribution_health` | What fraction of OS events could not be tied to a session |

### Agents and sessions

**Nothing scans for the agent.** The hook shim runs as a child of the agent, so
it walks up past any intermediate shell and reports the agent's PID with the
session id — the agent self-registers on its first tool call, whether launched
from a terminal, VS Code, or JetBrains. Every `process.exec` carries a ppid, so
attribution then flows down the process tree; a PID first seen mid-session is
resolved by walking live ancestry.

Multiple agents are supported: each session is anchored to its own subtree, PID
reuse is guarded by process create-time, and `outside_session_workspace` gives
each agent containment against **its own** working directory rather than one
global `${workspace}`.

Attribution never guesses — an unattributable event stays `unknown` rather than
being assigned to whichever session is active. That is honest but it is also a
hole: `outside_session_workspace` cannot fire for an event it cannot attribute.
**`attribution_health()` is the compensating control** — check `unknown_rate`
before you trust a quiet `session_summary`, exactly as you check the probe
suite before trusting a quiet log. See DESIGN.md §5A.

## Why the probe suite is not optional

Detection rots quietly. A collector dies, an eBPF program fails to load, a
policy path stops matching after someone reorganizes the repo — and the log
just gets quieter. **A guardrail that stopped working looks exactly like an
agent that behaved well.** There is no way to tell them apart from the log.

`run_probe_suite()` trips each control on purpose using canaries: a decoy key
file, a decoy binary, a `connect()` to TEST-NET-1 (`192.0.2.1`, reserved and
never routed), and a write outside the workspace. Nothing touches a real secret
or a real host, and nothing is an evasion technique — the probe's only job is
to answer "did the control fire, and how fast." Run it on a cron, not on
demand, and alert on FAIL as loudly as you alert on a violation.

Note the canary target is an **address**, not a name: an unresolvable hostname
fails in `getaddrinfo`, so no `connect()` is ever issued and a connect-based
collector sees nothing — a permanent FAIL indistinguishable from a dead
control.

## Trust boundary notes

These are the things that quietly undo a monitor like this:

1. **Don't attach this MCP server to the agent you're monitoring.** An agent
   that can query its own monitor can also learn which of its actions were
   invisible. Attach it to a supervisor session, a CI job, or your own client.
2. **Run the monitor as a different uid** than the agent, and put the agent in
   its own cgroup or container. If the agent can `kill` the collector, the
   collector is decorative.
3. **Ship events off-box immediately.** The hash chain detects tampering; it
   doesn't prevent someone with write access from truncating and rebuilding.
   Syslog, S3 with object lock, whatever — just not only local disk.
4. **The hook shim is not a control.** It runs inside the blast radius. Use it
   for signal; put real enforcement in `policy.yaml` where the agent can't
   reach it. `gm_hook.py` fails open by design; flip `GM_FAIL_OPEN=0` if you'd
   rather stall the agent than run it unmonitored.
5. **Watch your own config.** `fs.agent_config_write` fires if anything writes
   to `.claude/settings.json`, `.mcp.json`, or `policy.yaml`. An agent editing
   its own guardrails is the highest-signal event in the whole system.

## Tuning you will need to do

- **`_covers()` in `reconcile.py` is deliberately permissive for `Bash`
  egress.** A Bash tool call credits any network connection in its window,
  because a shell genuinely can connect anywhere. Tighten it once you know
  your workload, or you'll under-report egress. Exec is *not* permissive: a
  tool call explains only the binaries it names, plus the shell it runs
  through.
- **The auditd parser is minimal.** It's there so the pipeline runs end to
  end. For production use `auparse`, or better, ship straight to a SIEM and
  point the collector at that.
- **`store.query()` scans the file.** Fine to a few hundred thousand events.
  Past that, move to SQLite with an index on `(session, ts, kind)` and keep the
  JSONL as the tamper-evident record.
- **Severity floors matter more than rule count.** Thirteen rules that page
  correctly beat a hundred that get muted after week two.

## What this doesn't do

It doesn't inspect model reasoning, evaluate prompt-injection resistance, or
judge whether a code change was a good idea. It's a systems-level control:
what did the process actually touch, and did the guardrail notice. Pair it with
transcript-level review for the semantic half.
