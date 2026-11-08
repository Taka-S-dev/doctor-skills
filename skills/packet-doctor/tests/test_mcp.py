from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from packet_doctor.mcp_server import CaptureManager, call_tool, handle, parse_interfaces, resolve_interface, serve, tool_definitions
from packet_doctor.models import InvestigationError
from test_expert import scenario_silent_syn, write_pcap

LISTING = "1. \\Device\\NPF_{A} (イーサネット)\n2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n3. eth0\n"
ROOT = Path(__file__).resolve().parents[1]


class FakeProcess:
    """Stands in for dumpcap: start() writes a sealed file and an active one."""

    def __init__(self, command, **_):
        self.output, self.code = Path(command[command.index("-w") + 1]), None
        self.directory = self.output.parent
        self.write(1)
        self.write(2)

    def write(self, number):
        write_pcap(self.directory / f"capture_{number:05d}_x.pcapng", scenario_silent_syn())

    def poll(self):
        return self.code

    @property
    def returncode(self):
        return self.code

    def terminate(self):
        self.code = 1

    def wait(self, timeout=None):
        return self.code

    kill = terminate


class Protocol(unittest.TestCase):
    def call(self, method, params=None):
        return handle(None, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def test_initialize_negotiates_version(self):
        self.assertEqual(self.call("initialize", {"protocolVersion": "2025-03-26"})["result"]["protocolVersion"], "2025-03-26")
        result = self.call("initialize", {"protocolVersion": "1999-01-01"})["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertIn("tools", result["capabilities"])

    def test_notifications_get_no_reply_and_errors_are_reported(self):
        self.assertIsNone(handle(None, {"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(self.call("nope")["error"]["code"], -32601)
        self.assertEqual(self.call("tools/call", {"name": "shell"})["error"]["code"], -32602)
        self.assertEqual(handle(None, [1])["error"]["code"], -32600)
        self.assertEqual(self.call("ping")["result"], {})

    def test_tools_are_described_and_listing_is_read_only(self):
        tools = {t["name"]: t for t in self.call("tools/list")["result"]["tools"]}
        self.assertEqual(set(tools), {"list_interfaces", "start_capture", "capture_status", "capture_peek", "capture_stop"})
        self.assertTrue(tools["list_interfaces"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["start_capture"]["annotations"]["readOnlyHint"])
        self.assertEqual(set(tools["start_capture"]["inputSchema"]["required"]), {"case", "interface", "duration_seconds", "observation"})
        self.assertTrue(all(t["inputSchema"]["additionalProperties"] is False for t in tool_definitions()))

    def test_stream_contains_only_protocol_messages(self):
        lines = [b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', b"\n", b"not json\n", b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n']
        output = BytesIO()
        with tempfile.TemporaryDirectory() as d:
            serve(d, stdin=BytesIO(b"".join(lines)), stdout=output)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r.get("result", r.get("error", {}).get("code")) for r in replies], [{}, -32700])

    def test_cli_runs_as_a_stdio_server(self):
        message = b'{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n'
        with tempfile.TemporaryDirectory() as d:
            done = subprocess.run([sys.executable, "-m", "packet_doctor", "mcp", "--cases-root", d], input=message, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout.splitlines()[0])["id"], 7)
        self.assertEqual(len(done.stdout.splitlines()), 1)


class Interfaces(unittest.TestCase):
    def test_listing_and_exact_resolution(self):
        items = parse_interfaces(LISTING)
        self.assertEqual([(i["index"], i["name"]) for i in items][:2], [(1, "イーサネット"), (2, "Adapter for loopback traffic capture")])
        self.assertEqual(items[2]["device"], "eth0")
        for value in ("1", "\\Device\\NPF_{A}", "イーサネット"):
            self.assertEqual(resolve_interface(value, items)["index"], 1)

    def test_unlisted_values_are_rejected(self):
        for value in ("-Z", "rpcap://192.0.2.1/eth0", "9", "", "イーサ"):
            with self.subTest(value=value), self.assertRaises(InvestigationError):
                resolve_interface(value, parse_interfaces(LISTING))


class Lifecycle(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "cases"
        self.manager = CaptureManager(self.root, backend="builtin")
        for target, value in (("packet_doctor.mcp_server.find_tool", "fake-dumpcap"),
                              ("packet_doctor.mcp_server.interfaces", {"interfaces": LISTING})):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("packet_doctor.mcp_server.subprocess.Popen", FakeProcess)
        self.popen = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("packet_doctor.mcp_server.START_GRACE", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, **overrides):
        return self.manager.start_capture(**{"case": "device", "interface": "1", "duration_seconds": 60, "observation": "ミラーポート", **overrides})

    def test_peek_then_stop_saves_to_case(self):
        session = self.start(target="192.0.2.20", port=502, symptom="接続できない")["session"]
        peek = self.manager.capture_peek(session)
        self.assertEqual(peek["sealed_files"], 1)  # The active file is excluded.
        self.assertEqual(peek["state"], "running")
        self.assertIn("途中経過", peek["partial"])
        self.assertIn("tcp_no_reply", [f["code"] for f in peek["summary"]["findings"]])
        self.assertFalse((self.root / "device" / "case.json").exists())  # Peeking leaves the case alone.
        self.manager.sessions[session]["chunk"] = 0
        with patch("packet_doctor.mcp_server.STOP_MARGIN", 0):
            result = self.manager.capture_stop(session)
        self.assertEqual(result["state"], "complete")
        self.assertTrue((self.root / "device" / "case.json").is_file())
        self.assertIn("next_checks", result["summary"])
        self.assertIs(self.manager.capture_stop(session), result)
        self.assertFalse((self.manager.sessions[session]["directory"] / "peek").exists())

    def test_identical_idle_chunks_do_not_break_analysis(self):
        session = self.start()["session"]
        process = self.manager.sessions[session]["process"]
        process.write(3)
        process.write(4)
        self.assertEqual(self.manager.capture_peek(session)["sealed_files"], 1)
        self.manager.sessions[session]["chunk"] = 0
        with patch("packet_doctor.mcp_server.STOP_MARGIN", 0):
            self.assertEqual(self.manager.capture_stop(session)["state"], "complete")
        self.assertTrue((self.root / "device" / "case.json").is_file())

    def test_cases_stay_under_the_root(self):
        for case in ("../outside", "..", "", str(Path(self.root).parent / "x")):
            with self.subTest(case=case), self.assertRaises(InvestigationError):
                self.start(case=case)
        self.assertFalse((self.root.parent / "outside").exists())

    def test_limits_and_single_session(self):
        for overrides in ({"duration_seconds": 0}, {"duration_seconds": 3601}, {"observation": " "}, {"capture_filter": "a\nb"}, {"protocol": "other"}, {"interface": "-Z"}):
            with self.subTest(overrides=overrides), self.assertRaises(InvestigationError):
                self.start(**overrides)
        self.start()
        with self.assertRaises(InvestigationError):
            self.start()

    def test_long_captures_fit_the_file_limit(self):
        session = self.start(duration_seconds=3600)["session"]
        self.assertEqual(self.manager.sessions[session]["chunk"], 60)

    def test_shutdown_stops_running_capture(self):
        session = self.start()["session"]
        self.manager.shutdown()
        self.assertIsNotNone(self.manager.sessions[session]["process"].poll())

    def test_tool_errors_do_not_raise(self):
        result = call_tool(self.manager, "capture_status", {"session": "missing"})
        self.assertTrue(result["isError"])
        for arguments in ({}, {"session": 1}, {"session": "x", "extra": 1}):
            self.assertTrue(call_tool(self.manager, "capture_status", arguments)["isError"])
        bad_type = call_tool(self.manager, "start_capture", {"case": "c", "interface": "1", "duration_seconds": True, "observation": "x"})
        self.assertTrue(bad_type["isError"])


if __name__ == "__main__":
    unittest.main()
