# Windows deployment

The core design is unchanged. Only the sensor layer is platform-specific:
`gm/collectors_win.py` emits the same canonical events as `gm/collectors.py`,
so `store.py`, `policy.py`, `reconcile.py`, `probes.py` and `server.py` run
untouched.

```
gm/monitor.py          the long-running process (all platforms)
gm/collectors.py       Linux (auditd) + macOS (eslogger)
gm/collectors_win.py   Windows (Sysmon + Security log + PowerShell 4104)
policy.yaml            POSIX rules
policy.windows.yaml    Windows rules
collectors/setup-windows.ps1
```

## Setup

Run steps 1-5 from an **elevated** PowerShell. Three accounts are involved and
two of them must differ: the **agent** (runs Claude Code), the **monitor**
(runs `gm.monitor`; SYSTEM is fine), and the **supervisor** (runs the MCP
client that launches `gm.server`).

**1. A separate agent account**, signed in once so its profile exists:

```powershell
New-LocalUser -Name agent
```

**2. Python for all users** — the hook runs as the agent, which cannot read a
per-user Python under someone else's profile. `mcp` needs 3.10+.

```powershell
winget install -e --id Python.Python.3.12 --scope machine
```

**3. Install where the agent cannot write.** A non-system drive commonly grants
Authenticated Users *Modify*, which would let the agent edit the monitor's
code, policy and hook shim.

```powershell
robocopy D:\path\to\repo "C:\Program Files\gm" /E /XD .git __pycache__ htmlcov tests
& "C:\Program Files\Python312\python.exe" -m venv "C:\Program Files\gm\venv"
& "C:\Program Files\gm\venv\Scripts\python.exe" -m pip install -r "C:\Program Files\gm\requirements.txt"
```

Check `vars` in `C:\Program Files\gm\policy.windows.yaml` matches the agent's
profile (`workspace`, `canary_dir`).

**4. Sensors and ACLs.** Preflight first; it needs no elevation and changes
nothing. It refuses an agent account that does not exist, a monitor that would
run as the agent (the log's Deny ACE would lock it out), and a missing Sysmon
binary, and it warns when the policy's paths disagree with the SACLs it would
set. The profile paths come from the account, not a hardcoded `C:\Users\agent`.

```powershell
cd "C:\Program Files\gm"
.\collectors\setup-windows.ps1 -AgentAccount "$env:COMPUTERNAME\agent" -SysmonPath C:\Tools\Sysmon\sysmon64.exe -ValidateOnly
.\collectors\setup-windows.ps1 -AgentAccount "$env:COMPUTERNAME\agent" -SysmonPath C:\Tools\Sysmon\sysmon64.exe
```

Add `-ReaderAccount` to let a non-administrator supervisor read the log.

**5. The monitor, as a boot-time task** — not in a console someone can close.
`GM_LOG` defaults to `%ProgramData%\gm\events.jsonl` and `GM_POLICY` to the
policy beside the package. (Example commands; this repository's tests do not
register tasks.)

```powershell
$action   = New-ScheduledTaskAction -Execute "C:\Program Files\gm\venv\Scripts\python.exe" -Argument "-m gm.monitor" -WorkingDirectory "C:\Program Files\gm"
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName guardrail-monitor -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest
Start-ScheduledTask -TaskName guardrail-monitor
```

**6. The agent's hooks.** Copy `hooks\settings.windows.example.json` into the
agent project's `.claude\settings.json`. Its commands use quoted, absolute,
forward-slash paths, which work whether the hook runs through cmd or Git Bash.

**7. The query server**, registered in a supervisor session:

```powershell
claude mcp add guardrail-monitor -e "PYTHONPATH=C:\Program Files\gm" -- "C:\Program Files\gm\venv\Scripts\python.exe" -m gm.server
```

**8. Verify before trusting it:** `control_coverage` (its `monitor` block must
say `running: true`, and `collectors_running` must include `gm-sysmon`),
`list_agents`, `attribution_health`, then `run_probe_suite`.

## What is genuinely different

### 1. File reads are not covered by Sysmon

Sysmon has no file-read event. None. The `cred.read` rule — arguably the most
important rule in the whole policy — has no Sysmon implementation.

Getting it requires object-access auditing plus a SACL on each watched
directory, which routes through the **Security** channel as Event 4663. That
means a second collector, a second event schema, and much higher volume. Two
consequences worth planning for:

- **Scope SACLs tightly.** A SACL on a build directory will bury the Security
  log in minutes and you will lose the events you built this for. The setup
  script raises the channel to 1 GB; that is a mitigation, not a fix.
- **This is the most likely thing to be silently broken.** `auditpol` settings
  get reverted by Group Policy refresh. A SACL does not survive a directory
  being deleted and recreated — which is exactly what a `git clean` does. Run
  `canary.file` on a schedule and mean it.

### 2. You get hostnames for free

Sysmon Event 3 populates `DestinationHostname`, and Event 22 gives you the DNS
query outright, both attributed to a PID. On Linux, syscall-level `connect`
tracing gives you an IP and you have to correlate DNS separately. So egress
allowlisting by name is *easier* on Windows, not harder.

### 3. PowerShell script block logging has no Linux equivalent

Event 4104 gives you script text after PowerShell has deobfuscated it — post
concatenation, post base64. There is no `bash` analogue that gives you
post-expansion command text. `collectors_win.powershell_normalize` emits these
as `process.exec` so existing `argv_regex` rules apply directly.

Caveat: long scripts arrive **split across multiple 4104 events**, with
`MessageNumber`/`MessageTotal` telling you the sequence. A regex that spans the
split point will not match. Reassemble by `ScriptBlockId` before matching if
you care about long scripts; the normalizer surfaces both fields for this.

### 4. Persistence lives in the registry, not in files

There is no crontab to watch. `reg.run_key`, `fs.startup_folder`, and the WMI
event IDs (Sysmon 19–21) cover ground that has no entry in `policy.yaml` at
all. If you port the Linux policy directly you will have a large blind spot
here.

### 5. Isolation is a different mechanism

| Linux | Windows |
|---|---|
| Separate uid | Separate local account |
| cgroup | Job Object, or AppContainer for a real boundary |
| `-e 2` immutable audit rules | ACL the Sysmon service + config; sign the config |
| File mode on the log | ACL with an explicit **Deny** for the agent account |

The named pipe DACL in `NamedPipeIngest` is the equivalent of the unix socket's
permission bits: grant the agent `FILE_WRITE_DATA` and nothing else, so it can
append events but cannot read, enumerate, or delete them. **Do not use a NULL
DACL to make it work** — that is the Windows version of `chmod 777` on the
socket and it hands the agent full control of its own audit trail.

### 6. Case sensitivity will bite you

Two bugs found while porting, both fixed in `policy.py`, both worth
understanding because they will recur in any rule you add:

- `path_not_under` used `startswith`, which is case-sensitive. On NTFS,
  `C:\Users\Agent\project` and `c:\users\agent\project` are the same directory,
  so every containment rule was one capital letter from being bypassed. Fixed
  with `os.path.normcase` (a no-op on POSIX).
- Command-line regexes need `(?i)`. `reg save HKLM\SAM` did not match a rule
  written for lowercase `sam`. A credential-dump rule that only catches one
  casing is worse than no rule, because it appears "covered" on your control
  list while catching nothing.

Registry keys get their own `key_glob` predicate rather than reusing
`path_glob` — running `HKLM\Software\...` through `normpath`/`expanduser` is
meaningless, and the registry is case-insensitive on every Windows version.

## Reconciler note

`_covers()` matches `tool_name` against `{"bash", ...}`. Claude Code exposes a
separate **PowerShell** tool on Windows, so add it to those sets or every
PowerShell call will show up as `unobserved` and every effect it causes as
`undeclared`, drowning the signal you built the reconciler for.

Hook matchers should be `"Bash|PowerShell"`, and `if` conditions use the
PowerShell form: `"PowerShell(Remove-Item *)"` rather than `"Bash(rm *)"`.

## What Windows gives you that is worth adding

Sysmon events not currently mapped, in rough order of value for an agent
context:

| ID | Event | Why it matters |
|---|---|---|
| 8 | CreateRemoteThread | Injection. Should never happen from a coding agent |
| 10 | ProcessAccess | Reading another process's memory — credential theft |
| 25 | Process tampering | Hollowing / herpaderping |
| 7 | Image loaded | Unsigned DLL loads from the workspace |
| 17/18 | Named pipe | Includes attempts to talk to the monitor's own pipe |

Event 10 with `TargetImage` pointing at the monitor process is about as
high-signal as anything in this system. Add it before you add anything else.
