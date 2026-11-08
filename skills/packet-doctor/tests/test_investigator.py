import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from packet_doctor.capture import TSHARK_FIELDS, load_capture, load_tshark
from packet_doctor.connections import analyze_connections, reconnect_measurements
from packet_doctor.demo import demo_records, write_pcap, write_pcapng
from packet_doctor.investigation import analyze, latest, update_hypotheses, case_lock
from packet_doctor.live import build_command, capture_live, closed_files
from packet_doctor.models import InvestigationError, read_json, write_json
from packet_doctor.protocol import load_protocol, check_protocol, validate_rules

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "protocols/example-device/protocol.md"


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "test.pcap"
        write_pcap(self.capture, demo_records())
        self.protocol = load_protocol(SPEC)

    def tearDown(self):
        self.temp.cleanup()

    def packets(self):
        return load_capture(self.capture, "builtin")[0]

    def test_pcap_pcapng_equivalent(self):
        other = self.root / "test.pcapng"
        write_pcapng(other, demo_records())
        packets, meta = load_capture(other, "builtin")
        original = self.packets()
        self.assertEqual(meta["packet_count"], 10)
        self.assertEqual([(p.time_ns, p.seq, p.payload) for p in packets], [(p.time_ns, p.seq, p.payload) for p in original])

    def test_exact_expected_reconnect(self):
        connections = analyze_connections(self.packets())
        values, candidates = reconnect_measurements(connections)
        self.assertEqual(len(connections), 2)
        self.assertEqual([m["value_ms"] for m in values], [20, 20, 5000])
        self.assertEqual(candidates[0]["status"], "candidate")

    def test_segmented_protocol_response(self):
        result = check_protocol(analyze_connections(self.packets()), self.protocol)
        check = result["checks"][0]
        self.assertEqual(check["elapsed_ms"], 620)
        self.assertEqual(check["status"], "observed_late")
        self.assertEqual(len(check["evidence_ids"]), 3)

    def test_normal_protocol_response(self):
        write_pcap(self.capture, demo_records(200, 100))
        result = check_protocol(analyze_connections(self.packets()), self.protocol)
        self.assertEqual(result["checks"][0]["status"], "observed_within_limit")

    def test_missing_response_not_timeout(self):
        write_pcap(self.capture, demo_records()[:-1])
        result = check_protocol(analyze_connections(self.packets()), self.protocol)
        self.assertEqual(result["checks"][0]["status"], "unobserved")
        self.assertIsNone(result["checks"][0]["elapsed_ms"])

    def test_missing_segment_does_not_invent_message(self):
        packets = self.packets()
        packets = [p for p in packets if p.frame != 8]
        result = check_protocol(analyze_connections(packets), self.protocol)
        self.assertEqual(result["checks"], [])
        self.assertTrue(any("欠落" in w for w in result["warnings"]))

    def test_midstream_no_handshake_no_protocol_claim(self):
        packets = self.packets()[7:]
        connections = analyze_connections(packets)
        self.assertIsNone(connections[0]["start"])
        self.assertEqual(reconnect_measurements(connections)[0], [])
        self.assertEqual(check_protocol(connections, self.protocol)["checks"], [])

    def test_repeated_syn_is_same_attempt(self):
        packets = self.packets()
        repeated = copy.copy(packets[0])
        repeated.frame, repeated.time_ns = 11, repeated.time_ns + 1_000_000
        connections = analyze_connections(packets + [repeated])
        self.assertEqual(len(connections), 2)
        self.assertEqual(connections[0]["syn_repeats"], 1)

    def test_invalid_ack_does_not_establish(self):
        packets = self.packets()[:3]
        packets[2].ack += 5
        self.assertIsNone(analyze_connections(packets)[0]["established"])

    def test_parallel_connections_ambiguous(self):
        packets = self.packets()
        parallel = copy.copy(packets[0])
        parallel.frame, parallel.sport, parallel.time_ns = 11, 49000, parallel.time_ns + 1_000_000
        measurements, candidates = reconnect_measurements(analyze_connections(packets + [parallel]))
        self.assertFalse(any(m["name"].startswith("observed_gap") for m in measurements))
        self.assertTrue(any(c["status"] == "ambiguous" for c in candidates))

    def test_no_end_no_invented_gap(self):
        packets = [p for p in self.packets() if not p.flags & 4]
        measurements, _ = reconnect_measurements(analyze_connections(packets))
        self.assertFalse(any(m["name"].startswith("observed_gap") for m in measurements))

    def test_identical_retransmission_deduplicated(self):
        packets = self.packets()
        repeat = copy.copy(packets[7])
        repeat.frame, repeat.time_ns = 11, repeat.time_ns + 500_000
        result = check_protocol(analyze_connections(packets + [repeat]), self.protocol)
        self.assertEqual(len(result["checks"]), 1)
        self.assertEqual(result["checks"][0]["elapsed_ms"], 620)

    def test_conflicting_retransmission_rejected(self):
        packets = self.packets()
        repeat = copy.copy(packets[7])
        repeat.frame, repeat.payload, repeat.time_ns = 11, b"\x00\x08\x01", repeat.time_ns + 500_000
        result = check_protocol(analyze_connections(packets + [repeat]), self.protocol)
        self.assertEqual(result["checks"], [])
        self.assertTrue(any("異なる" in w for w in result["warnings"]))

    def test_out_of_order_uses_completion_time(self):
        packets = self.packets()
        packets[7].time_ns = packets[8].time_ns + 10_000_000
        result = check_protocol(analyze_connections(packets), self.protocol)
        self.assertEqual(result["checks"][0]["elapsed_ms"], 610)

    def test_id_reuse_ambiguous(self):
        packets = self.packets()
        repeated = copy.copy(packets[8])
        repeated.frame, repeated.seq, repeated.payload = 11, 207, b"\x00\x06\x01\x07\xaa\xbb"
        repeated.time_ns += 1_000_000
        result = check_protocol(analyze_connections(packets + [repeated]), self.protocol)
        self.assertEqual([c["status"] for c in result["checks"]], ["ambiguous", "ambiguous"])

    def test_plain_markdown_context_only(self):
        path = self.root / "spec.md"
        path.write_text("# 私の仕様\n応答は500ms以内", encoding="utf-8")
        protocol = load_protocol(path)
        result = check_protocol(analyze_connections(self.packets()), protocol)
        self.assertEqual(result["status"], "context_only")
        self.assertEqual(result["checks"], [])

    def test_invalid_rules_fail(self):
        rules = copy.deepcopy(self.protocol["rules"])
        rules["command"]["size"] = 3
        with self.assertRaises(InvestigationError):
            validate_rules(rules)

    def test_truncated_capture_error(self):
        data = self.capture.read_bytes()
        self.capture.write_bytes(data[:-1])
        with self.assertRaises(InvestigationError):
            load_capture(self.capture, "builtin")

    def test_invalid_pcapng_block_error(self):
        path = self.root / "bad.pcapng"
        write_pcapng(path, demo_records())
        data = bytearray(path.read_bytes())
        data[24:28] = b"\0" * 4
        path.write_bytes(data)
        with self.assertRaises(InvestigationError):
            load_capture(path, "builtin")

    def test_big_endian_nanosecond_pcap(self):
        ns, data = demo_records()[0]
        ns += 123
        sec, frac = divmod(ns, 1_000_000_000)
        self.capture.write_bytes(struct.pack(">IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 1)
                                 + struct.pack(">IIII", sec, frac, len(data), len(data)) + data)
        self.assertEqual(self.packets()[0].time_ns, ns)

    def test_fragment_skipped(self):
        ns, data = demo_records()[0]
        altered = bytearray(data)
        altered[20:22] = b"\x20\x00"
        write_pcap(self.capture, [(ns, altered)])
        packets, meta = load_capture(self.capture, "builtin")
        self.assertEqual(packets, [])
        self.assertTrue(any("断片" in w for w in meta["warnings"]))

    def test_file_boundary_preserves_connection(self):
        one, two = self.root / "one.pcapng", self.root / "two.pcapng"
        write_pcapng(one, demo_records()[:8])
        write_pcapng(two, demo_records()[8:])
        result = analyze(self.root / "case", [one, two], protocol_path=SPEC, backend="builtin")
        self.assertEqual(result["protocol"]["checks"][0]["elapsed_ms"], 620)
        self.assertEqual(result["connections"], 2)

    def test_evidence_and_report_and_update(self):
        root = self.root / "case"
        result = analyze(root, [self.capture], symptom="<script>alert(1)</script>", protocol_path=SPEC, backend="builtin")
        html = Path(result["reports"]["html"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        _, run, _, analysis = latest(root)
        evidence = {json.loads(line)["id"] for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines()}
        for measurement in analysis["measurements"]:
            self.assertTrue(set(measurement["evidence_ids"]) <= evidence)
            for ref in measurement["evidence_ids"]:
                self.assertIn(f"href='#{ref}'", html)
                self.assertIn(f"id='{ref}'", html)
        hypotheses = read_json(run / "hypotheses.json")
        hypotheses[0]["statement"] = "追加確認が必要"
        path = self.root / "update.json"
        write_json(path, hypotheses)
        update_hypotheses(root, path)
        self.assertEqual(read_json(run / "hypotheses.json")[0]["statement"], "追加確認が必要")
        hypotheses[0]["evidence_ids"] = ["invented"]
        write_json(path, hypotheses)
        with self.assertRaises(InvestigationError):
            update_hypotheses(root, path)

    def test_verification_requires_details(self):
        root = self.root / "case"
        analyze(root, [self.capture], backend="builtin")
        _, run, _, _ = latest(root)
        hypotheses = read_json(run / "hypotheses.json")
        hypotheses[0]["status"] = "verified"
        path = self.root / "update.json"
        write_json(path, hypotheses)
        with self.assertRaises(InvestigationError):
            update_hypotheses(root, path)

    def test_failed_run_keeps_previous(self):
        root = self.root / "case"
        first = analyze(root, [self.capture], backend="builtin")
        with self.assertRaises(InvestigationError):
            analyze(root, [self.root / "missing"], backend="builtin")
        self.assertEqual(latest(root)[3]["run_id"], first["run_id"])
        self.assertFalse((root / ".write.lock").exists())

    def test_case_lock(self):
        root = self.root / "case"
        with case_lock(root):
            with self.assertRaises(InvestigationError):
                analyze(root, [self.capture], backend="builtin")

    def test_interrupted_run_is_recorded_and_unlocks(self):
        root = self.root / "interrupted"
        with patch("packet_doctor.investigation.load_capture", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                analyze(root, [self.capture], backend="builtin")
        manifest = next((root / "runs").glob("*/manifest.json"))
        self.assertEqual(read_json(manifest)["status"], "interrupted")
        self.assertFalse((root / ".write.lock").exists())

    def test_no_target_returns_insufficient_data(self):
        result = analyze(self.root / "case", [self.capture], target="192.0.2.99", backend="builtin")
        self.assertEqual(result["connections"], 0)
        self.assertTrue(any("一致" in w for w in result["warnings"]))

    def test_cli_end_to_end(self):
        result = subprocess.run([sys.executable, "-m", "packet_doctor", "analyze", "--case", str(self.root / "cli-case"),
                                 "--capture", str(self.capture), "--backend", "builtin", "--protocol", str(SPEC)],
                                cwd=ROOT, capture_output=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        response = json.loads(result.stdout)
        self.assertTrue(Path(response["data"]["reports"]["html"]).exists())

    def test_cli_missing_file_error(self):
        result = subprocess.run([sys.executable, "-m", "packet_doctor", "inspect", "--capture", "missing.pcap"],
                                cwd=ROOT, capture_output=True, encoding="utf-8")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_tshark_adapter_contract(self):
        values = {"frame.number": "1", "frame.time_epoch": "1700000000.123456789", "ip.src": "192.0.2.10", "ip.dst": "192.0.2.20",
                  "tcp.srcport": "42000", "tcp.dstport": "5000", "tcp.seq_raw": "100", "tcp.ack_raw": "0", "tcp.flags": "0x0002",
                  "tcp.window_size_value": "8192", "tcp.len": "0", "frame.interface_id": "0", "frame.cap_len": "54", "frame.len": "54"}
        row = [values.get(name, "") for name in TSHARK_FIELDS]

        def run(args, stdout, stderr, timeout):
            stdout.write(("\t".join(row) + "\n").encode())
            return subprocess.CompletedProcess(args, 0)

        with patch("packet_doctor.capture.subprocess.run", side_effect=run):
            packets, count, _, _, _ = load_tshark(self.capture, "cap-test", "fake-tshark", set())
        self.assertEqual(count, 1)
        self.assertEqual(packets[0].time_ns, 1700000000123456789)
        self.assertEqual(packets[0].flags, 2)

    def test_live_command_no_overwrite_and_filter_argument(self):
        command = build_command("dumpcap", "2", "capture.pcapng", 60, 5, 24, "tcp port 5000")
        self.assertIn("files:24", command)
        self.assertEqual(command[command.index("files:24") - 1], "-a")
        self.assertEqual(command[-1], "tcp port 5000")
        self.assertNotIn("-b files:24", command)

    def test_live_excludes_active_file(self):
        for i in (1, 2, 3):
            (self.root / f"capture_{i:05d}.pcapng").touch()
        self.assertEqual(len(closed_files(self.root)), 2)
        self.assertEqual(len(closed_files(self.root, True)), 3)

    def test_live_fake_capture_end_to_end(self):
        class FakeProcess:
            def __init__(self, command, **kwargs):
                directory = Path(command[command.index("-w") + 1]).parent
                write_pcapng(directory / "capture_00001.pcapng", demo_records()[:8])
                write_pcapng(directory / "capture_00002.pcapng", demo_records()[8:])
                self.returncode = 0

            def poll(self):
                return self.returncode

        with patch("packet_doctor.live.find_tool", return_value="fake-dumpcap"), patch("packet_doctor.live.subprocess.Popen", FakeProcess):
            result = capture_live(self.root / "case", "test", backend="builtin", protocol_path=SPEC)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["analysis"]["protocol"]["checks"][0]["elapsed_ms"], 620)


if __name__ == "__main__":
    unittest.main()
