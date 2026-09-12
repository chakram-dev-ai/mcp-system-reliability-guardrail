"""Windows sensors. Drop-in replacement for the auditd/eslogger adapters in
collectors.py -- emits the same canonical events, so store.py, policy.py,
reconcile.py, probes.py and server.py are unchanged.

Three sources, because no single Windows channel covers what auditd covers:

  SysmonCollector      Microsoft-Windows-Sysmon/Operational
                       exec, network, DNS, file create/delete, registry, WMI.
                       This is the workhorse. Requires the Sysmon driver.

  SecurityLogCollector Security channel, Event 4663.
                       The ONLY practical way to see file READS. Requires
                       object-access auditing enabled AND a SACL on each
                       watched directory. Noisy -- scope the SACLs tightly.

  PowerShellCollector  Microsoft-Windows-PowerShell/Operational, Event 4104.
                       Deobfuscated script block text. No Linux equivalent.
                       If the agent uses the PowerShell tool, this is your
                       best semantic source.

Requires pywin32. The agent account must NOT have read access to these
channels -- see WINDOWS.md for the ACL story.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
from typing import Callable, Iterable

from .collectors import Emit, canonical

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
PWSH_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

# Only subscribe to what we map. Every extra ID is volume you pay for forever.
SYSMON_QUERY = (
    "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=12 or "
    "EventID=13 or EventID=22 or EventID=23 or EventID=26)]]"
)
SECURITY_QUERY = "*[System[(EventID=4663)]]"
PWSH_QUERY = "*[System[(EventID=4104)]]"


def _fields(xml: str) -> tuple[dict, dict]:
    """Return (system_fields, event_data) from a rendered event XML."""
    root = ET.fromstring(xml)
    sys_el = root.find("e:System", NS)
    exec_el = sys_el.find("e:Execution", NS)
    system = {
        "event_id": int(sys_el.findtext("e:EventID", default="0", namespaces=NS)),
        "channel": sys_el.findtext("e:Channel", namespaces=NS),
        # System/Execution/@ProcessID is the writing process. For 4104 it is the
        # only pid available -- EventData has none -- and without a pid the
        # event cannot be attributed to a session. See gm/sessions.py.
        "process_id": _int(exec_el.get("ProcessID")) if exec_el is not None else None,
    }
    data = {}
    for node in root.iterfind(".//e:EventData/e:Data", NS):
        name = node.get("Name")
        if name:
            data[name] = node.text
    return system, data


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------

def sysmon_normalize(xml: str) -> Iterable[dict]:
    system, d = _fields(xml)
    eid = system["event_id"]
    base = {
        "pid": _int(d.get("ProcessId")),
        "comm": d.get("Image"),
        # Sysmon has no idea what an agent session is, and there is no
        # "gm_session" field in any Sysmon schema -- an earlier version read
        # one and so every Windows event was permanently "unknown". The session
        # is attached downstream by gm.sessions, from the process tree.
        "session": "unknown",
    }

    if eid == 1:  # process creation
        yield canonical(
            "sysmon", "process.exec",
            ppid=_int(d.get("ParentProcessId")),
            exe=d.get("Image"),
            # Sysmon gives one command line string, not an argv vector. The
            # argv_regex predicate joins with spaces, so a 1-element list is
            # equivalent for matching purposes.
            argv=[d.get("CommandLine") or ""],
            parent_exe=d.get("ParentImage"),
            parent_command=d.get("ParentCommandLine"),
            user=d.get("User"),
            integrity=d.get("IntegrityLevel"),
            sha256=(d.get("Hashes") or ""),
            **base,
        )

    elif eid == 3:  # network connection
        yield canonical(
            "sysmon", "net.connect",
            # DestinationHostname is often populated -- free hostname
            # attribution that Linux syscall tracing does not give you.
            host=d.get("DestinationHostname") or d.get("DestinationIp"),
            ip=d.get("DestinationIp"),
            port=_int(d.get("DestinationPort")),
            proto=d.get("Protocol"),
            **base,
        )

    elif eid == 22:  # DNS query
        yield canonical(
            "sysmon", "net.dns",
            host=d.get("QueryName"), results=d.get("QueryResults"), **base
        )

    elif eid == 11:  # file created
        yield canonical("sysmon", "file.write", path=d.get("TargetFilename"), **base)

    elif eid in (23, 26):  # file deleted
        yield canonical("sysmon", "file.unlink", path=d.get("TargetFilename"), **base)

    elif eid in (12, 13, 14):  # registry
        yield canonical(
            "sysmon", "registry.write",
            path=d.get("TargetObject"), value=d.get("Details"), **base
        )


# 4663 AccessMask bits we care about. 0x1 = ReadData/ListDirectory.
_READ_MASK = 0x1
_WRITE_MASK = 0x2 | 0x4 | 0x10  # WriteData | AppendData | WriteEA


def security_normalize(xml: str) -> Iterable[dict]:
    """Event 4663: an object access attempt that matched a SACL."""
    system, d = _fields(xml)
    if system["event_id"] != 4663:
        return
    path = d.get("ObjectName")
    if not path:
        return
    mask = _int((d.get("AccessMask") or "0x0").strip(), ) if not (d.get("AccessMask") or "").startswith("0x") \
        else int(d["AccessMask"], 16)
    base = {
        "pid": _int(d.get("ProcessId"), ) if not (d.get("ProcessId") or "").startswith("0x")
        else int(d["ProcessId"], 16),
        "comm": d.get("ProcessName"),
        "session": "unknown",
    }
    if mask and mask & _WRITE_MASK:
        yield canonical("winsec", "file.write", path=path, access_mask=hex(mask), **base)
    elif mask and mask & _READ_MASK:
        yield canonical("winsec", "file.read", path=path, access_mask=hex(mask), **base)


_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def powershell_normalize(xml: str) -> Iterable[dict]:
    """Event 4104: script block text, after PowerShell has deobfuscated it.

    Emitted as process.exec so existing argv_regex rules apply to it without
    duplication -- a `sudo`-equivalent pattern written for Bash catches the
    PowerShell form too if you add the alternation to the rule.
    """
    system, d = _fields(xml)
    if system["event_id"] != 4104:
        return
    text = d.get("ScriptBlockText") or ""
    yield canonical(
        "pwsh", "process.exec",
        pid=system["process_id"],
        exe="powershell.exe",
        argv=[text],
        script_id=d.get("ScriptBlockId"),
        script_path=d.get("Path"),
        part=f"{d.get('MessageNumber')}/{d.get('MessageTotal')}",
        # A long base64 blob inside a script block is worth surfacing on its
        # own -- policy can match on it without regexing the whole body.
        has_b64_blob=bool(_B64_BLOB.search(text)),
        session="unknown",
    )


# ---------------------------------------------------------------------------
# Event Log subscription
# ---------------------------------------------------------------------------

class EventLogCollector(threading.Thread):
    """Push subscription to a Windows event channel via EvtSubscribe.

    Push, not poll: the callback fires as events are written, so you do not
    inherit a polling window the way ProcTreeCollector does.
    """

    daemon = True

    def __init__(self, channel: str, query: str, normalizer: Callable[[str], Iterable[dict]],
                 emit: Emit, name: str | None = None):
        # The name is explicit, not derived from the channel. Deriving it gave
        # both "Microsoft-Windows-Sysmon/Operational" and
        # ".../PowerShell/Operational" the name "gm-operational" -- two threads
        # with the same name, and, worse, the monitor's health check looks for
        # "gm-sysmon" to decide whether a kernel-level collector came up, so it
        # printed "no kernel-level collector started" on every Windows run.
        # DESIGN.md 3.1 names these threads; keep them in sync with it.
        super().__init__(name=name or f"gm-{channel.rsplit('/', 1)[0].rsplit('-', 1)[-1].lower()}")
        self.channel = channel
        self.query = query
        self.normalizer = normalizer
        self.emit = emit
        # NOT self._stop: threading.Thread already defines a private _stop()
        # method and uses it from _wait_for_tstate_lock(). Shadowing it with an
        # Event makes is_alive() and join() raise TypeError once the thread has
        # finished -- so server.control_coverage(), which calls is_alive() on
        # every collector, blew up exactly when a collector had died, which is
        # the one moment it has something important to report.
        self._stopping = threading.Event()
        self._sub = None

    def _callback(self, action, context, event_handle):
        import win32evtlog

        if action != win32evtlog.EvtSubscribeActionDeliver:
            return 0
        try:
            xml = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            for ev in self.normalizer(xml):
                self.emit(ev)
        except Exception as exc:  # never let a bad event kill the subscription
            print(f"[gm] {self.channel} render failed: {exc!r}", file=sys.stderr, flush=True)
        return 0

    def run(self) -> None:
        import win32evtlog

        try:
            self._sub = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                None,
                Callback=self._callback,
                Context=None,
                Query=self.query,
            )
        except Exception as exc:
            # Sysmon not installed, the channel disabled, or no right to read
            # it (Security needs admin or Event Log Readers). The thread ends
            # here and gm.monitor's health check records it as dead. The old
            # startup check counted collectors that had been STARTED, so a
            # subscription that failed a millisecond later still satisfied
            # "a kernel-level collector is running".
            print(f"[gm] ERROR cannot subscribe to {self.channel}: {exc!r}",
                  file=sys.stderr, flush=True)
            return
        self._stopping.wait()  # subscription lives on the callback thread

    def stop(self) -> None:
        self._stopping.set()
        self._sub = None


# ---------------------------------------------------------------------------
# Named pipe ingest (Python has no AF_UNIX on Windows)
# ---------------------------------------------------------------------------

# Must match hooks/gm_hook.py's PIPE. Both read GM_PIPE so a non-default
# deployment cannot end up with the two halves talking past each other.
PIPE_NAME = os.environ.get("GM_PIPE", r"\\.\pipe\gm-ingest")


class NamedPipeIngest(threading.Thread):
    """Windows equivalent of IngestServer.

    The DACL is the whole security story here. Grant the agent account
    FILE_WRITE_DATA and nothing else: it can append events, and cannot read,
    enumerate, or delete them. Do not use a NULL DACL just to make it work.
    """

    daemon = True

    def __init__(self, emit: Emit, pipe_name: str = PIPE_NAME, sddl: str | None = None):
        super().__init__(name="gm-ingest")
        self.emit = emit
        self.pipe_name = pipe_name
        self._sddl = sddl
        # NOT self._stop: threading.Thread already defines a private _stop()
        # method and uses it from _wait_for_tstate_lock(). Shadowing it with an
        # Event makes is_alive() and join() raise TypeError once the thread has
        # finished -- so server.control_coverage(), which calls is_alive() on
        # every collector, blew up exactly when a collector had died, which is
        # the one moment it has something important to report.
        self._stopping = threading.Event()

    @staticmethod
    def _own_sid() -> str:
        """SID of the account this monitor runs as."""
        import win32api
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        try:
            sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
            return win32security.ConvertSidToStringSid(sid)
        finally:
            win32api.CloseHandle(token)

    @property
    def sddl(self) -> str:
        """DACL for the pipe.

        The creating account needs FILE_ALL_ACCESS, and that is not a nicety.
        Only the FIRST CreateNamedPipe call for a name applies a security
        descriptor; every later instance is authorised against the existing
        pipe and needs FILE_CREATE_PIPE_INSTANCE on it. FILE_GENERIC_WRITE
        (SDDL "FW") does not include that bit, so a DACL of only
        FW-for-Everyone plus SYSTEM and Administrators left a monitor running
        as its own non-admin account -- the layout WINDOWS.md recommends --
        unable to create the second instance. It got ERROR_ACCESS_DENIED after
        the first hook event, the ingest thread died, and every later hook
        event was silently lost while the monitor still looked healthy.

        The agent still gets FW and nothing more: it can append events and
        cannot read, enumerate, delete, or impersonate through them.
        """
        if self._sddl:
            return self._sddl
        try:
            own = self._own_sid()
        except Exception:                                   # pragma: no cover
            own = None
        creator = f"(A;;FA;;;{own})" if own else ""
        return f"D:{creator}(A;;FW;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)"

    def _security_attributes(self):
        import win32security

        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            self.sddl, win32security.SDDL_REVISION_1
        )
        return sa

    def run(self) -> None:
        """Accept loop.

        The connected pipe is handed to a worker thread and the next instance
        is created IMMEDIATELY, rather than after the current message has been
        read, normalized, policy-evaluated and fsynced. Servicing inline left a
        window in which no instance was listening at all, and a hook that
        connected during it got ERROR_PIPE_BUSY/EINVAL, gave up, and failed
        open -- so the event was silently lost. Back-to-back tool calls are the
        normal case for an agent, so that window was hit constantly.
        """
        import win32pipe

        while not self._stopping.is_set():
            try:
                pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    0, 65536, 0,
                    self._security_attributes(),
                )
            except Exception as exc:
                # Never let this thread die: a dead ingest thread is invisible
                # from the outside and looks exactly like an idle agent.
                print(f"[gm] ERROR CreateNamedPipe({self.pipe_name}) failed: {exc!r}",
                      file=sys.stderr, flush=True)
                self._stopping.wait(1.0)
                continue

            try:
                win32pipe.ConnectNamedPipe(pipe, None)
            except Exception as exc:
                # stop() wakes this call by connecting to our own pipe, so an
                # error here during shutdown is the normal path, not a fault.
                if not self._stopping.is_set():
                    print(f"[gm] ERROR ConnectNamedPipe: {exc!r}", file=sys.stderr, flush=True)
                self._close(pipe)
                continue

            if self._stopping.is_set():
                self._close(pipe)
                break

            threading.Thread(target=self._serve, args=(pipe,), daemon=True,
                             name="gm-ingest-conn").start()

    def _serve(self, pipe) -> None:
        """Drain one connection and emit whatever complete lines it carried."""
        import json

        import pywintypes
        import win32file

        from .collectors import IngestServer

        try:
            buf = b""
            while True:
                try:
                    _, chunk = win32file.ReadFile(pipe, 65536)
                except pywintypes.error:
                    break
                if not chunk:
                    break
                buf += chunk
            for line in buf.decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.emit(IngestServer._to_canonical(payload))
        except Exception as exc:
            print(f"[gm] ERROR pipe ingest: {exc!r}", file=sys.stderr, flush=True)
        finally:
            self._close(pipe)

    @staticmethod
    def _close(pipe) -> None:
        import win32file
        import win32pipe

        try:
            win32pipe.DisconnectNamedPipe(pipe)
        except Exception:
            pass
        try:
            win32file.CloseHandle(pipe)
        except Exception:
            pass

    def stop(self) -> None:
        # Setting the flag is not enough: the thread is parked inside a
        # blocking ConnectNamedPipe and will not look at it again until a
        # client arrives. Connect to our own pipe once to wake it, so the
        # collector is actually stoppable and does not leak a handle and a
        # claim on the pipe name for the life of the process.
        self._stopping.set()
        try:
            with open(self.pipe_name, "wb", buffering=0):
                pass
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def start_windows_collectors(emit: Emit, *, security_log: bool = True, powershell: bool = True) -> list:
    """Returns started collector threads. Caller keeps the references alive."""
    started = [
        EventLogCollector(SYSMON_CHANNEL, SYSMON_QUERY, sysmon_normalize, emit, name="gm-sysmon"),
        NamedPipeIngest(emit),
    ]
    if security_log:
        started.append(EventLogCollector(SECURITY_CHANNEL, SECURITY_QUERY, security_normalize,
                                         emit, name="gm-winsec"))
    if powershell:
        started.append(EventLogCollector(PWSH_CHANNEL, PWSH_QUERY, powershell_normalize,
                                         emit, name="gm-pwsh"))
    for c in started:
        c.start()
    return started
