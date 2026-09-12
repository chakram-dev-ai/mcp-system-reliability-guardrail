"""Declarative policy over canonical events.

A rule fires when every predicate in its `match` block is true. Rules are
evaluated in file order; all matching rules contribute a verdict, so one event
can trip several controls.

Deliberately boring matchers: globs, prefixes, regexes, set membership. If you
find yourself wanting a general expression language here, that is a signal the
rule belongs in a collector filter instead.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from . import paths

Severity = str  # low | medium | high | critical
Verdict = str  # allow | warn | violation


@dataclass
class Rule:
    id: str
    kind: list[str]
    match: dict[str, Any]
    verdict: Verdict = "violation"
    severity: Severity = "medium"
    action: str = "log"  # log | alert | kill
    description: str = ""
    src: list[str] = field(default_factory=list)


def _expand_home(value: str, agent_home: str | None) -> str:
    """Resolve a leading `~` against the AGENT's home, never the monitor's.

    os.path.expanduser() answers "whose home?" with "the home of the account
    running this process" -- and in the recommended layout that is the monitor
    account (gmmonitor), not the agent. So "~/.ssh/**" in policy.yaml silently
    became "/home/gmmonitor/.ssh/**", and cred.read -- the single most
    important rule in the file -- matched nothing at all while still appearing
    in control_coverage as a rule that simply had not fired yet.

    Set `agent_home` in the policy's vars block. The expanduser fallback is
    kept only for the single-account development case, and complains.
    """
    if not value.startswith("~"):
        return value
    if agent_home:
        rest = value[1:]
        if not rest.strip("\\/"):
            return agent_home
        # Keep the separator the policy author wrote rather than os.sep: a
        # POSIX policy read on any host should stay "/home/agent/.ssh/**", not
        # become the mixed "/home/agent\.ssh/**" that os.path.join produces.
        sep = rest[0] if rest[0] in "\\/" else os.sep
        return agent_home.rstrip("\\/") + sep + rest.lstrip("\\/")
    if not _expand_home.warned:
        print("[gm] WARNING: policy uses '~' but no `agent_home` var is set; "
              "falling back to this process's home "
              f"({os.path.expanduser('~')}). If the monitor runs as its own "
              "account, every ~-anchored rule is matching the wrong home "
              "directory and is effectively dead.", file=sys.stderr, flush=True)
        _expand_home.warned = True
    return os.path.expanduser(value)


_expand_home.warned = False


def _expand(value: Any, vars: dict[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in vars.items():
            value = value.replace("${" + k + "}", v)
        return _expand_home(value, vars.get("agent_home"))
    if isinstance(value, list):
        return [_expand(v, vars) for v in value]
    return value


def _norm(p: str) -> str:
    # normcase is identity on POSIX, but on Windows it lowercases and converts
    # forward slashes to backslashes. Without it, path_not_under's startswith
    # is case-sensitive and every containment rule is one capital letter away
    # from being bypassed on NTFS.
    #
    # No expanduser here: `~` is resolved once at load time against agent_home
    # (see _expand_home). Doing it again at match time would reintroduce the
    # monitor's home for any `~` that slipped through.
    #
    # The flavor comes from the path, not the host (gm.paths): a Windows policy
    # evaluated on a POSIX host must still split on backslashes and ignore case.
    return paths.norm(p)


# --- predicates -------------------------------------------------------------
# Each takes (event, argument) and returns True when the condition holds.

def _p_path_glob(ev, arg) -> bool:
    path = ev["data"].get("path")
    if not path:
        return False
    path = _norm(path)
    return any(fnmatch.fnmatch(path, _norm(g)) for g in arg)


def _is_under(path: str, root: str) -> bool:
    """True when an already-normalized `path` is `root` or lives inside it.

    The separator must be the ROOT's own, not a hardcoded "/" and not os.sep:
    _norm runs normcase, which rewrites a Windows path's separators to
    backslashes. An earlier version appended "/" to a backslashed root, so the
    prefix test never matched and every containment rule reported "outside"
    for paths that were plainly inside; os.sep made the same mistake for a
    Windows policy on a POSIX host. Boundary-anchored so /srv/app2 is not
    "under" /srv/app.
    """
    root = _norm(root).rstrip("\\/")
    sep = paths.sep_for(root) if root else os.sep
    if not root:
        root = sep
    if path == root:
        return True
    return path.startswith(root if root.endswith(sep) else root + sep)


def _p_path_not_under(ev, arg) -> bool:
    path = ev["data"].get("path")
    if not path:
        return False
    path = _norm(path)
    return not any(_is_under(path, r) for r in arg)


def _p_path_under(ev, arg) -> bool:
    return not _p_path_not_under(ev, arg) and ev["data"].get("path") is not None


def _p_argv_regex(ev, arg) -> bool:
    argv = ev["data"].get("argv")
    line = " ".join(argv) if isinstance(argv, list) else (argv or "")
    line = line or ev["data"].get("command", "")
    return any(re.search(pat, line) for pat in arg)


def _p_exe_not_in(ev, arg) -> bool:
    exe = ev["data"].get("exe") or ev["data"].get("comm")
    if not exe:
        return False
    base = paths.basename(exe)
    return base not in arg and exe not in arg


def _p_host_not_in(ev, arg) -> bool:
    host = ev["data"].get("host")
    if not host:
        return False
    for allowed in arg:
        if host == allowed or host.endswith("." + allowed.lstrip(".")):
            return False
    return True


def _p_port_in(ev, arg) -> bool:
    return ev["data"].get("port") in set(arg)


def _p_tool_name_regex(ev, arg) -> bool:
    name = ev["data"].get("tool_name", "")
    return any(re.search(pat, name) for pat in arg)


def _p_key_glob(ev, arg) -> bool:
    """Registry keys, not filesystem paths.

    Deliberately does NOT go through _norm: normpath/expanduser on
    'HKLM\\Software\\...' is meaningless, and on POSIX (where you may well be
    running tests) it would not even collapse the separators. The registry is
    case-insensitive on every Windows version, so both sides are lowercased
    regardless of the host OS.
    """
    key = ev["data"].get("path")
    if not key:
        return False
    key = key.replace("/", "\\").lower()
    return any(fnmatch.fnmatchcase(key, g.replace("/", "\\").lower()) for g in arg)


def _p_content_regex(ev, arg) -> bool:
    blob = ev["data"].get("content") or ev["data"].get("new_string") or ""
    return any(re.search(pat, blob) for pat in arg)


def _p_outside_session_workspace(ev, arg) -> bool:
    """Path is outside THIS session's workspace, plus any listed extra roots.

    A single global ${workspace} breaks the moment you monitor two agents in
    two repos: whichever one is not in policy.yaml has every write flagged.
    This predicate reads the workspace from the session that produced the
    event, so containment is per-agent.

    If the session's workspace is unknown, the predicate does NOT fire --
    unattributed events would otherwise produce a flood of false violations.
    That is a real hole, deliberately chosen: it is why attribution_health()
    exists, and why you check unknown_rate before trusting a quiet report.
    """
    ws = ev.get("_workspace")
    if not ws:
        return False
    return _p_path_not_under(ev, [ws, *(arg or [])])


PREDICATES: dict[str, Callable[[dict, Any], bool]] = {
    "outside_session_workspace": _p_outside_session_workspace,
    "path_glob": _p_path_glob,
    "key_glob": _p_key_glob,
    "path_not_under": _p_path_not_under,
    "path_under": _p_path_under,
    "argv_regex": _p_argv_regex,
    "exe_not_in": _p_exe_not_in,
    "host_not_in": _p_host_not_in,
    "port_in": _p_port_in,
    "tool_name_regex": _p_tool_name_regex,
    "content_regex": _p_content_regex,
}


class Policy:
    def __init__(self, rules: list[Rule], vars: dict[str, str]):
        self.rules = rules
        self.vars = vars

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw_vars = {k: str(v) for k, v in (raw.get("vars") or {}).items()}

        # agent_home is resolved first and on its own terms: everything else
        # expands against it, so it cannot itself contain a '~'.
        agent_home = raw_vars.get("agent_home")
        if agent_home and agent_home.startswith("~"):
            raise ValueError(
                "policy var `agent_home` must be an absolute path -- it is the "
                "answer to 'whose home?', so it cannot be written as '~'"
            )
        vars: dict[str, str] = {}
        if agent_home:
            vars["agent_home"] = agent_home
        for k, v in raw_vars.items():
            if k != "agent_home":
                vars[k] = _expand(v, vars)

        rules = []
        for i, r in enumerate(raw.get("rules") or []):
            if "id" not in r:
                raise ValueError(f"rule #{i + 1} in {path} has no `id`")
            if "kind" not in r:
                raise ValueError(f"rule {r['id']}: no `kind`")
            unknown = set(r.get("match") or {}) - set(PREDICATES)
            if unknown:
                raise ValueError(f"rule {r['id']}: unknown matchers {sorted(unknown)}")
            unknown_keys = set(r) - {"id", "kind", "match", "verdict", "severity",
                                     "action", "description", "src"}
            if unknown_keys:
                # A typo'd `sevrity:` would otherwise default to medium and
                # quietly page at the wrong threshold forever.
                raise ValueError(f"rule {r['id']}: unknown keys {sorted(unknown_keys)}")
            kind = r["kind"]
            src = r.get("src", [])
            rules.append(
                Rule(
                    id=r["id"],
                    kind=[kind] if isinstance(kind, str) else kind,
                    src=[src] if isinstance(src, str) else src,
                    match={k: _expand(v, vars) for k, v in (r.get("match") or {}).items()},
                    verdict=r.get("verdict", "violation"),
                    severity=r.get("severity", "medium"),
                    action=r.get("action", "log"),
                    description=r.get("description", ""),
                )
            )
        return cls(rules, vars)

    def evaluate(self, ev: dict, workspace: str | None = None) -> list[dict]:
        """Evaluate every rule against one event.

        `workspace` is this session's own cwd, supplied by the caller from the
        session registry. It is stashed under a private key so predicates can
        reach it without widening every predicate signature -- and removed in a
        finally block, because a predicate that raises would otherwise leave
        `_workspace` on the event and the store would persist it as if it were
        collected telemetry.
        """
        ev["_workspace"] = workspace
        try:
            hits = []
            for rule in self.rules:
                if rule.kind and ev["kind"] not in rule.kind:
                    continue
                if rule.src and ev["src"] not in rule.src:
                    continue
                if not all(PREDICATES[k](ev, v) for k, v in rule.match.items()):
                    continue
                hits.append(
                    {
                        "rule": rule.id,
                        "verdict": rule.verdict,
                        "severity": rule.severity,
                        "action": rule.action,
                        "description": rule.description,
                    }
                )
            return hits
        finally:
            ev.pop("_workspace", None)

    def rule_ids(self) -> list[str]:
        return [r.id for r in self.rules]
