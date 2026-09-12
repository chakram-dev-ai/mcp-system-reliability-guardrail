#!/usr/bin/env python3
"""Claude Code hook shim: forward the event to the monitor, optionally deny.

Wire it up for PreToolUse and PostToolUse (see settings.example.json).

Two design points that matter:

1. This runs as the agent's uid and is therefore in the agent's blast radius.
   It is an intent signal, not a control. Never let it be the only thing
   standing between the agent and a credential.

2. It fails OPEN on transport errors -- if the monitor endpoint is gone (the
   unix socket on POSIX, the named pipe on Windows), the
   tool call still proceeds. That is the right default for a shim whose job is
   observation, but it means "no events" and "monitor down" look the same from
   the outside. That is exactly what verify_log_integrity() and the probe
   suite exist to disambiguate. If you want fail-closed, flip FAIL_OPEN and
   accept that a monitor restart will stall the agent.

Blocking uses PreToolUse decision control: exit 0 and print
hookSpecificOutput.permissionDecision = "deny". Note that exit code 2 also
blocks, and blocks even when JSON says allow.
"""

import json
import os
import socket
import sys
import time

IS_WINDOWS = sys.platform == "win32"

SOCK = os.environ.get("GM_SOCK", "/run/gm/ingest.sock")
PIPE = os.environ.get("GM_PIPE", r"\\.\pipe\gm-ingest")
FAIL_OPEN = os.environ.get("GM_FAIL_OPEN", "1") == "1"
TIMEOUT = float(os.environ.get("GM_HOOK_TIMEOUT", "1.5"))


def _send_socket(blob: bytes) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect(SOCK)
        s.sendall(blob)
    finally:
        s.close()


def _send_pipe(blob: bytes) -> None:
    """Windows has no AF_UNIX, so the monitor listens on a named pipe.

    Opened with the builtin open() rather than win32file on purpose: this shim
    runs as the AGENT account, and requiring pywin32 in the agent's interpreter
    is a dependency the monitor cannot verify and the agent could remove. A
    named pipe is openable as an ordinary file handle.

    A failed open is usually transient, not "the monitor is down": between one
    client disconnecting and the server creating the next instance there is a
    brief moment with no instance listening, and Windows reports it as
    ERROR_PIPE_BUSY, ERROR_FILE_NOT_FOUND, or -- through Python's errno
    mapping, with winerror lost -- a bare EINVAL. Keying the retry on
    winerror == ERROR_PIPE_BUSY alone therefore dropped events whenever tool
    calls came back to back, which for an agent is most of the time.

    So: retry every transient open failure until the deadline, and only then
    report the monitor unreachable.
    """
    deadline = time.time() + TIMEOUT
    while True:
        try:
            with open(PIPE, "wb", buffering=0) as fh:
                fh.write(blob)
            return
        except OSError:
            if time.time() >= deadline:
                raise
            time.sleep(0.02)


def send(payload: dict) -> None:
    blob = (json.dumps(payload) + "\n").encode("utf-8")
    if IS_WINDOWS:
        _send_pipe(blob)
    else:
        _send_socket(blob)


# The only processes walked past on the way up. Claude Code may run the hook
# through one of these; anything else above the shim is taken to be the agent.
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "powershell", "pwsh"}


def _is_shell(name: str) -> bool:
    name = (name or "").lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name in SHELLS


def _first_non_shell(proc, max_depth: int = 8):
    """Walk up from `proc` past shells. None if no non-shell ancestor is found."""
    p = proc
    for _ in range(max_depth):
        if not _is_shell(p.name()):
            return p
        p = p.parent()
        if p is None:
            return None
    return None


def agent_pid() -> int:
    """The PID of the agent that spawned us.

    Claude Code may invoke the hook through a shell, so getppid() can be that
    shell rather than the agent itself. Walk up past SHELLS only, and return
    the first process that is not one; fall back to the immediate parent.

    It used to walk up to 8 levels looking for "claude" or "node" anywhere in a
    process name. That skipped straight past the real parent whenever an
    agent-looking process sat further up: a test runner started from a Claude
    Code session anchored itself to claude.exe, and an npm script between an
    agent and a hook anchored the session to npm. Attribution must not guess;
    stopping at the first non-shell is the rule that cannot overshoot.

    This is how the monitor learns where the agent is running without any
    configuration: the agent self-registers on its first tool call, whether it
    was launched from a terminal, VS Code, or JetBrains. Attributing to the
    shell instead would still work -- everything the agent spawns descends
    from it either way -- but it would anchor the session one level too low
    and lose the launch surface, which is read from the agent's ancestors.

    psutil is optional here on purpose: this runs as the AGENT account, and
    the shim must not require anything the agent's interpreter may not have.
    """
    ppid = os.getppid()
    try:
        import psutil

        found = _first_non_shell(psutil.Process(ppid))
        if found is not None:
            return found.pid
    except Exception:
        pass
    return ppid


def deny(reason: str) -> None:
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, sys.stdout)
    sys.exit(0)


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # never wedge the agent on a malformed payload

    # The monitor cannot correlate kernel events with this session unless it
    # knows which pid the session belongs to. This process is a direct child of
    # the agent, so our parent IS the agent process; everything the agent spawns
    # descends from it and inherits the session by ppid. Without this the
    # reconciler only ever sees the hook half. See gm/sessions.py.
    payload["agent_pid"] = agent_pid()
    payload["hook_pid"] = os.getpid()

    try:
        send(payload)
    except OSError as exc:
        if not FAIL_OPEN:
            deny("Guardrail monitor is unreachable; refusing to proceed unmonitored.")
        # Fail open on the TRANSPORT only, and fall through to the local
        # checks below rather than exiting here. An unreachable monitor means
        # the out-of-band policy is not evaluating anything either, so this is
        # precisely the moment the in-band check is the only control left --
        # exiting early made the two failures compound silently.
        print(f"gm: monitor unreachable ({exc})", file=sys.stderr)

    # Optional in-band enforcement for the highest-severity cases. Keep this
    # list short and obvious -- the authoritative policy lives in policy.yaml
    # and is enforced out-of-band where the agent cannot reach it.
    if payload.get("hook_event_name") == "PreToolUse":
        cmd = (payload.get("tool_input") or {}).get("command", "")
        if "curl" in cmd and "| sh" in cmd.replace("|sh", "| sh"):
            deny("Piping remote content into a shell is blocked by policy.")

    sys.exit(0)


if __name__ == "__main__":
    main()
