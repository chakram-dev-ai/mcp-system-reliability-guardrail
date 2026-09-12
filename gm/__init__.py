"""guardrail-monitor: verify the security guardrails around an AI coding agent.

Layer map -- only the collectors are platform-specific:

    store           hash-chained append-only event log
    policy          declarative rules over canonical events
    collectors      Linux (auditd) + macOS (eslogger) sensors
    collectors_win  Windows (Sysmon + Security 4663 + PowerShell 4104) sensors
    sessions        process tree -> agent session, so kernel events and hook
                    events can be compared at all
    reconcile       declared intent vs observed effect
    probes          canary suite proving the controls still fire
    paths           path handling by the path's flavor, not the host's
    filelock        cross-process locks for the log and the single monitor
    config          shared settings, read from the environment at call time

Two processes:

    monitor         python -m gm.monitor -- collectors, policy, enforcement,
                    alerts, heartbeat. Long-running; needs no stdin.
    server          python -m gm.server -- read-only MCP query surface over
                    what the monitor writes. Lives as long as its client.

Do not attach the MCP server to the agent being monitored. See README.md.
"""

__version__ = "0.1.0"

__all__ = ["EventStore", "Policy", "reconcile", "run_suite"]


def __getattr__(name):
    # Lazy, so importing the package on a host without psutil or pywin32 still
    # works for the pure-Python layers.
    if name == "EventStore":
        from .store import EventStore
        return EventStore
    if name == "Policy":
        from .policy import Policy
        return Policy
    if name == "reconcile":
        from .reconcile import reconcile
        return reconcile
    if name == "run_suite":
        from .probes import run_suite
        return run_suite
    raise AttributeError(name)
