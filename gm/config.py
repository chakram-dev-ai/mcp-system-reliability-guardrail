"""Paths and intervals shared by the monitor and the MCP server.

Read from the environment at call time, not import time: importing a module
must never touch the filesystem or depend on who is running it. The previous
server built its EventStore at import, so on a POSIX host `import gm.server`
raised PermissionError for any user who could not create /var/log/gm.

Defaults are per platform. `/var/log/gm/events.jsonl` on Windows resolves to
`\\var\\log\\gm` on whatever drive the process happens to start on, and a
relative `./policy.yaml` resolves against whatever directory an MCP client
chose to launch the server from -- neither is a default anyone wants.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = sys.platform == "win32"


def default_log_dir() -> str:
    if IS_WINDOWS:
        base = os.environ.get("ProgramData") or r"C:\ProgramData"
        return os.path.join(base, "gm")
    return "/var/log/gm"


@dataclass
class Settings:
    log: str
    policy: str
    sock: str
    alert_log: str
    status: str
    status_interval: float

    @classmethod
    def from_env(cls) -> "Settings":
        log = os.environ.get("GM_LOG") or os.path.join(default_log_dir(), "events.jsonl")
        log_dir = os.path.dirname(os.path.abspath(log))
        policy = os.environ.get("GM_POLICY") or str(
            REPO_ROOT / ("policy.windows.yaml" if IS_WINDOWS else "policy.yaml"))
        return cls(
            log=log,
            policy=policy,
            sock=os.environ.get("GM_SOCK", "/run/gm/ingest.sock"),
            alert_log=os.environ.get("GM_ALERT_LOG") or os.path.join(log_dir, "alerts.jsonl"),
            status=os.environ.get("GM_STATUS") or os.path.join(log_dir, "status.json"),
            status_interval=float(os.environ.get("GM_STATUS_INTERVAL", "5")),
        )
