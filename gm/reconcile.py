"""Reconcile declared intent (hooks) against observed effects (OS telemetry).

This is the part that catches what neither layer catches alone.

  undeclared  - the kernel observed an effect that no hook announced.
                Either the agent acted outside its tool layer (a subprocess
                spawned by a script it wrote, an MCP server acting on its
                behalf), or your hook matchers have a gap. Both are findings.

  unobserved  - a hook announced an effect the kernel never saw. Usually means
                the guardrail blocked it (good, and you should be able to point
                at the deny event), or your collector dropped it (bad).

Neither result is a verdict on its own. The value is that the number should be
near zero in steady state, so any drift is worth a look.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from . import paths

HOOK_KINDS = {"tool.pre", "tool.post"}
EFFECT_KINDS = {"process.exec", "file.open", "file.read", "file.write", "file.create", "net.connect"}

# How long after a hook fires we still credit it for an observed effect.
WINDOW_SECONDS = 30.0

# Tools that run a command through a shell, and the interpreters they reach it
# through. A shell tool call inherently execs the shell itself, over and above
# whatever binary the command names, so the shell process must be credited or
# every Bash call contributes a spurious `undeclared` exec.
SHELL_TOOLS = {"bash", "powershell", "pwsh"}
SHELL_BINARIES = {"sh", "bash", "dash", "zsh", "ksh", "cmd",
                  "powershell", "pwsh", "conhost"}


def _norm(p: str | None) -> str | None:
    return paths.normpath(os.path.expanduser(p)) if p else None


def _covers(hook: dict, effect: dict) -> bool:
    """Does this declared tool call plausibly explain this observed effect?"""
    hd, ed = hook["data"], effect["data"]
    tool = (hd.get("tool_name") or "").lower()

    if effect["kind"] == "process.exec":
        cmd = hd.get("command") or ""
        # paths.basename, not os.path.basename: on a POSIX host the latter
        # does not split C:\\Windows\\System32\\cmd.exe at all.
        exe = paths.basename(ed.get("exe") or ed.get("comm") or "")
        if not exe:
            return False
        # A tool call explains any exec whose binary name it names -- with or
        # without its extension. Sysmon reports C:\...\python.exe for a Bash
        # call that says "python x.py"; matching only "python.exe" left every
        # Windows exec undeclared.
        stem = os.path.splitext(exe)[0]
        if exe in cmd or (stem and stem in cmd):
            return True
        # ...and a shell tool call additionally explains the shell it runs
        # through. It must NOT explain anything else in the window: an earlier
        # version tested the effect's exe against the effect's OWN argv, which
        # is true for essentially every exec, so a single Bash hook marked
        # every concurrent process as declared and undeclared_rate sat at ~0
        # no matter what the agent ran.
        return tool in SHELL_TOOLS and os.path.splitext(exe)[0].lower() in SHELL_BINARIES

    if effect["kind"].startswith("file."):
        hp, ep = _norm(hd.get("path")), _norm(ed.get("path"))
        if hp and ep and hp == ep:
            return True
        # Read/Grep/Glob touch many files under cwd; credit them loosely.
        return bool(ep) and tool in {"read", "grep", "glob"} and bool(hd.get("cwd")) \
            and ep.startswith(_norm(hd["cwd"]))

    if effect["kind"] == "net.connect":
        url = hd.get("url")
        host = ed.get("host")
        if url and host:
            return urlparse(url).hostname == host
        return tool in {"websearch", "webfetch", "bash"}

    return False


def reconcile(events: list[dict], window: float = WINDOW_SECONDS) -> dict:
    hooks = [e for e in events if e["kind"] in HOOK_KINDS]
    effects = [e for e in events if e["kind"] in EFFECT_KINDS and e["src"] != "hook"]

    undeclared, matched_hooks = [], set()
    for eff in effects:
        hit = None
        for h in hooks:
            if not (0 <= eff["ts"] - h["ts"] <= window):
                continue
            if _covers(h, eff):
                hit = h
                break
        if hit is None:
            undeclared.append(eff)
        else:
            matched_hooks.add(hit["seq"])

    unobserved = [
        h for h in hooks
        if h["seq"] not in matched_hooks
        and h["kind"] == "tool.pre"
        and (h["data"].get("tool_name") or "") in {"Bash", "Write", "Edit", "WebFetch"}
    ]

    return {
        "hook_events": len(hooks),
        "os_effect_events": len(effects),
        "undeclared": undeclared,
        "unobserved": unobserved,
        "undeclared_rate": round(len(undeclared) / len(effects), 4) if effects else 0.0,
    }
