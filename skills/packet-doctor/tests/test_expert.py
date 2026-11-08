"""Known-cause scenarios and the investigation workflow, on both analysis backends."""
import json
from pathlib import Path
import ssl
import struct
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from packet_doctor.capture import find_tool, load_capture, truthy
from packet_doctor.demo import checksum, frame, write_pcap
from packet_doctor.external import add_evidence, match_log, parse_flow
from packet_doctor.investigation import analyze, latest, record_check, set_state, update_hypotheses
from packet_doctor.models import InvestigationError, read_json, write_json
from packet_doctor.protocol import load_protocol, validate_rules
from packet_doctor.reasoning import ACCESS, CHECKS, classify_symptom
from packet_doctor.summary import query, render_handoff, summarize
from packet_doctor.twopoint import two_point

from test_generic import CERT, CLIENT, ORIGIN, SERVER, dns_frame, handshake, hello, icmp_frame, ip_frame, record, tcp_flow

ROOT = Path(__file__).resolve().parents[1]
MODBUS = ROOT / "protocols/modbus-tcp/protocol.md"
ETHERNET_IP = ROOT / "protocols/ethernet-ip/protocol.md"
MS = 1_000_000
SECOND = 1_000 * MS
TSHARK = find_tool("tshark")


def open_causes_of(result):
    return [h["cause"] for h in result["summary"]["hypotheses"] if h.get("cause") and not h["contradicted"]]


def rewrite_ip(data, ttl=None, ip_id=None):
    data = bytearray(data)
    if ttl is not None:
        data[22] = ttl
    if ip_id is not None:
        data[18:20] = ip_id.to_bytes(2, "big")
    data[24:26] = b"\0\0"
    data[24:26] = struct.pack("!H", checksum(bytes(data[14:34])))
    return bytes(data)


def c2s(sport, port, seq, ack, flags, payload=b"", ip_id=None):
    built = frame(CLIENT, SERVER, sport, port, seq, ack, flags, payload)
    return rewrite_ip(built, ip_id=ip_id) if ip_id else built


def s2c(sport, port, seq, ack, flags, payload=b"", window=8192, ttl=None, ip_id=None):
    built = frame(SERVER, CLIENT, port, sport, seq, ack, flags, payload, window)
    return rewrite_ip(built, ttl, ip_id) if ttl or ip_id else built


def handshake_records(port=502, sport=42000, origin=ORIGIN):
    return [(origin, c2s(sport, port, 100, 0, 2)), (origin + 5 * MS, s2c(sport, port, 900, 101, 18)),
            (origin + 10 * MS, c2s(sport, port, 101, 901, 16))]


def scenario_refused():
    return [(ORIGIN, c2s(42000, 502, 100, 0, 2)), (ORIGIN + MS, s2c(42000, 502, 0, 101, 20))]


def scenario_silent_syn():
    return [(ORIGIN + delay * SECOND, c2s(42000, 502, 100, 0, 2)) for delay in (0, 1, 3, 7)]


def scenario_injected_reset():
    records = handshake_records(443)
    records += [(ORIGIN + 20 * MS, c2s(42000, 443, 101, 901, 24, b"request")), (ORIGIN + 25 * MS, s2c(42000, 443, 901, 108, 24, b"reply")),
                (ORIGIN + 40 * MS, s2c(42000, 443, 906, 108, 20, ttl=120))]
    return records


def scenario_admin_prohibited():
    return [(ORIGIN, c2s(42000, 21, 100, 0, 2)), (ORIGIN + MS, icmp_frame())]


def scenario_expired_certificate():
    der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
    chain = len(der).to_bytes(3, "big") + der
    return tcp_flow(record(22, hello()), record(22, hello(True) + handshake(11, len(chain).to_bytes(3, "big") + chain)))


def scenario_zero_window():
    records = handshake_records()
    records += [(ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"x" * 100)), (ORIGIN + 25 * MS, s2c(42000, 502, 901, 201, 16, window=0)),
                (ORIGIN + 2 * SECOND, s2c(42000, 502, 901, 201, 16, window=8192))]
    return records


def scenario_loss():
    records = handshake_records()
    records += [(ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"x" * 100)), (ORIGIN + 320 * MS, c2s(42000, 502, 101, 901, 24, b"x" * 100, ip_id=77)),
                (ORIGIN + 325 * MS, s2c(42000, 502, 901, 201, 16))]
    return records


def scenario_mtu():
    records = handshake_records()
    records += [(ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"s" * 100)), (ORIGIN + 25 * MS, s2c(42000, 502, 901, 201, 16)),
                (ORIGIN + 30 * MS, c2s(42000, 502, 201, 901, 24, b"L" * 1400))]
    for index, delay in enumerate((230, 630, 1430), 1):
        records.append((ORIGIN + delay * MS, c2s(42000, 502, 201, 901, 24, b"L" * 1400, ip_id=100 + index)))
    return records


def scenario_slow_server():
    records = handshake_records(8080)
    records += [(ORIGIN + 20 * MS, c2s(42000, 8080, 101, 901, 24, b"GET / HTTP/1.1\r\n\r\n")), (ORIGIN + 25 * MS, s2c(42000, 8080, 901, 119, 16)),
                (ORIGIN + 1800 * MS, s2c(42000, 8080, 901, 119, 24, b"HTTP/1.1 200 OK\r\n\r\n"))]
    return records


def scenario_reconnect_wait():
    records = handshake_records(sport=42000) + [(ORIGIN + SECOND, s2c(42000, 502, 901, 101, 20))]
    return records + handshake_records(sport=42001, origin=ORIGIN + 6 * SECOND)


def scenario_peer_vanishes():
    records = handshake_records()
    records.append((ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"x" * 100)))
    for index, delay in enumerate((220, 620, 1420), 1):
        records.append((ORIGIN + delay * MS, c2s(42000, 502, 101, 901, 24, b"x" * 100, ip_id=50 + index)))
    return records


def scenario_peer_vanishes_sender_gives_up():
    records = scenario_peer_vanishes()
    records.append((ORIGIN + 3 * SECOND, c2s(42000, 502, 201, 901, 20)))
    return records


def scenario_linear_syn_retry():
    return [(ORIGIN + delay * SECOND, c2s(42000, 502, 100, 0, 2)) for delay in (0, 1, 2, 3, 4, 5)]


def scenario_idle_timeout():
    records = handshake_records()
    records += [(ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"a" * 10)), (ORIGIN + 25 * MS, s2c(42000, 502, 901, 111, 16)),
                (ORIGIN + 70 * SECOND, c2s(42000, 502, 111, 901, 24, b"b" * 10)), (ORIGIN + 70 * SECOND + 2 * MS, s2c(42000, 502, 901, 121, 20))]
    return records


def arp_frame(opcode, sender_ip, sender_mac, target_ip):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode) + bytes.fromhex(sender_mac) + socket.inet_aton(sender_ip) + b"\0" * 6 + socket.inet_aton(target_ip)
    return bytes.fromhex("ffffffffffff") + bytes.fromhex(sender_mac) + b"\x08\x06" + body


def scenario_duplicate_ip():
    return [(ORIGIN, arp_frame(2, SERVER, "020000000020", CLIENT)), (ORIGIN + SECOND, arp_frame(2, SERVER, "02000000aa20", CLIENT))]


def scenario_arp_unanswered():
    return [(ORIGIN + i * SECOND, arp_frame(1, CLIENT, "020000000010", SERVER)) for i in range(3)]


SCENARIOS = {
    "refused": (scenario_refused, {"symptom": "機器に接続できない", "target": SERVER, "port": 502}, {"no_listener"}, {"silent_drop", "peer_down"}, {"tcp_refused"}),
    "silent_syn": (scenario_silent_syn, {"symptom": "接続できない", "target": SERVER, "port": 502}, {"silent_drop", "peer_down"}, {"no_listener"}, {"tcp_no_reply", "tcp_syn_retry_pattern"}),
    "injected_reset": (scenario_injected_reset, {"symptom": "途中で切れる", "target": SERVER, "port": 443}, {"active_reject", "session_abort"}, set(), {"tcp_reset", "tcp_rst_ttl_anomaly"}),
    "admin_prohibited": (scenario_admin_prohibited, {"symptom": "接続できない", "target": SERVER, "port": 21}, {"active_reject"}, {"no_listener"}, {"administratively_prohibited"}),
    "expired_certificate": (scenario_expired_certificate, {"symptom": "接続できない", "target": SERVER, "port": 443}, {"tls_certificate"}, set(), {"certificate_expired"}),
    "zero_window": (scenario_zero_window, {"symptom": "遅い", "target": SERVER, "port": 502}, {"receiver_stall"}, set(), {"tcp_zero_window"}),
    "loss": (scenario_loss, {"symptom": "遅い", "target": SERVER, "port": 502}, {"path_loss"}, {"receiver_stall"}, {"tcp_repeated_data"}),
    "mtu": (scenario_mtu, {"symptom": "たまに止まる", "target": SERVER, "port": 502}, {"mtu_blackhole"}, set(), {"tcp_large_segment_loss"}),
    "slow_server": (scenario_slow_server, {"symptom": "応答が遅い", "target": SERVER, "port": 8080}, {"server_app_delay"}, {"path_loss"}, {"app_response_slow"}),
    "reconnect_wait": (scenario_reconnect_wait, {"symptom": "再接続が遅い", "target": SERVER, "port": 502}, {"application_restart_wait"}, set(), set()),
    "peer_vanishes": (scenario_peer_vanishes, {"symptom": "突然切れる", "target": SERVER, "port": 502}, {"peer_down"}, set(), {"tcp_unanswered_tail", "tcp_rto_backoff"}),
    "peer_vanishes_gives_up": (scenario_peer_vanishes_sender_gives_up, {"symptom": "突然切れる", "target": SERVER, "port": 502}, {"peer_down"}, {"session_abort"}, {"tcp_unanswered_tail"}),
    "linear_syn_retry": (scenario_linear_syn_retry, {"symptom": "接続できない", "target": SERVER, "port": 502}, {"silent_drop"}, {"no_listener"}, {"tcp_syn_retry_pattern"}),
    "idle_timeout": (scenario_idle_timeout, {"symptom": "放置すると切れる", "target": SERVER, "port": 502}, {"session_timeout"}, set(), {"tcp_failure_after_idle"}),
    "duplicate_ip": (scenario_duplicate_ip, {"symptom": "たまにつながらない", "target": SERVER}, {"l2_address_problem"}, set(), {"arp_duplicate_ip"}),
    "arp_unanswered": (scenario_arp_unanswered, {"symptom": "接続できない", "target": SERVER}, {"l2_address_problem"}, set(), {"arp_no_reply"}),
}


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture.pcap"

    def tearDown(self):
        self.temp.cleanup()

    def run_case(self, records, backend="builtin", name="case", **options):
        write_pcap(self.capture, records)
        result = analyze(self.root / name, [self.capture], backend=backend, **options)
        _, run, case, analysis = latest(self.root / name)
        return result, run, case, analysis, read_json(run / "hypotheses.json")


class ScenarioTests(Base):
    def verify(self, backend):
        for name, (build, options, expected, forbidden, codes) in SCENARIOS.items():
            with self.subTest(name=name, backend=backend):
                _, _, _, analysis, hypotheses = self.run_case(build(), backend, name=f"{backend}-{name}", **options)
                causes = {h.get("cause") for h in hypotheses}
                self.assertLessEqual(expected, causes)
                self.assertFalse(forbidden & causes, causes)
                found = {f["code"] for f in analysis["diagnostics"]["findings"]}
                self.assertLessEqual(codes, found)
                self.assertTrue(all(h["status"] == "candidate" for h in hypotheses))

    def test_builtin_backend(self):
        self.verify("builtin")

    @unittest.skipUnless(TSHARK, "tsharkが必要です")
    def test_tshark_backend(self):
        self.verify("tshark")

    @unittest.skipUnless(TSHARK, "tsharkが必要です")
    def test_backends_report_same_findings(self):
        for name, (build, options, *_rest) in SCENARIOS.items():
            with self.subTest(name=name):
                builtin = self.run_case(build(), "builtin", name=f"b-{name}", **options)[3]
                tshark = self.run_case(build(), "tshark", name=f"t-{name}", **options)[3]
                self.assertEqual({f["code"] for f in builtin["diagnostics"]["findings"]}, {f["code"] for f in tshark["diagnostics"]["findings"]})

    def test_symptom_order_puts_relevant_cause_first(self):
        records = scenario_loss() + scenario_slow_server()
        records.sort(key=lambda r: r[0])
        _, _, _, _, hypotheses = self.run_case(records, symptom="再送が多くて遅い", target=SERVER)
        self.assertIn(hypotheses[0]["cause"], ("server_app_delay", "path_loss"))

    def test_symptom_classification(self):
        self.assertEqual(classify_symptom("機器に接続できない"), "no_connect")
        self.assertEqual(classify_symptom("再接続が遅い"), "no_recovery")
        self.assertEqual(classify_symptom("応答が遅い"), "slow")
        self.assertEqual(classify_symptom("突然通信が切れます"), "drops")
        self.assertEqual(classify_symptom("何か変"), "unknown")


class EvidenceQualityTests(Base):
    def test_one_way_is_not_reported_as_no_reply(self):
        records = [r for r in tcp_flow(b"a" * 50, b"b" * 50) if r[1][26:30] == socket.inet_aton(CLIENT)]
        _, _, _, analysis, _ = self.run_case(records)
        self.assertFalse([f for f in analysis["diagnostics"]["findings"] if f["code"] == "tcp_no_reply"])
        self.assertEqual(analysis["quality"]["status"], "blocked")
        self.assertEqual(analysis["quality"]["issues"][0]["code"], "one_way_capture")

    def test_incident_outside_capture(self):
        _, _, _, analysis, _ = self.run_case(scenario_refused(), incident_time="2099-01-01T00:00:00+09:00")
        self.assertIn("incident_outside_capture", {i["code"] for i in analysis["quality"]["issues"]})

    def test_target_absent(self):
        _, _, _, analysis, hypotheses = self.run_case(scenario_refused(), target="192.0.2.99")
        self.assertEqual(analysis["quality"]["status"], "blocked")
        self.assertEqual(hypotheses[0]["cause"], "capture_limitation")

    def test_mirror_duplicate_is_not_retransmission(self):
        records = handshake_records()
        records += [(ORIGIN + 20 * MS, c2s(42000, 502, 101, 901, 24, b"x" * 10)), (ORIGIN + 20 * MS + 100_000, c2s(42000, 502, 101, 901, 24, b"x" * 10))]
        _, _, _, analysis, _ = self.run_case(records)
        self.assertNotIn("tcp_repeated_data", {f["code"] for f in analysis["diagnostics"]["findings"]})
        self.assertIn("mirror_duplicates", {i["code"] for i in analysis["quality"]["issues"]})

    def test_snaplen_keeps_tcp_headers(self):
        records = tcp_flow(b"x" * 300, b"y" * 300)
        with self.capture.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 96, 1))
            for ns, data in records:
                sec, rem = divmod(ns, 1_000_000_000)
                stream.write(struct.pack("<IIII", sec, rem // 1000, min(len(data), 96), len(data)) + data[:96])
        packets, meta = load_capture(self.capture, "builtin")
        self.assertEqual(len(packets), len(records))
        self.assertEqual(max(p.segment_length for p in packets), 300)
        self.assertGreater(meta["truncated_frames"], 0)

    def test_large_stream_keeps_certificate_analysis(self):
        records = scenario_expired_certificate()
        seq = 901 + (len(records[-1][1]) + len(records[-2][1]) - 2 * 54)
        for index in range(1500):
            records.append((ORIGIN + 50 * MS + index * 1000, s2c(42000, 443, seq + index * 1400, 200, 24, b"z" * 1400)))
        _, _, _, analysis, _ = self.run_case(records)
        self.assertIn("certificate_expired", {f["code"] for f in analysis["diagnostics"]["findings"]})

    def test_interface_statistics_drops(self):
        def block(kind, data):
            data += b"\0" * (-len(data) % 4)
            size = len(data) + 12
            return struct.pack("<II", kind, size) + data + struct.pack("<I", size)
        path = self.root / "drops.pcapng"
        statistics = struct.pack("<III", 0, 0, 0) + struct.pack("<HHQ", 5, 8, 7) + struct.pack("<HH", 0, 0)
        path.write_bytes(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535)) + block(5, statistics))
        _, meta = load_capture(path, "builtin")
        self.assertEqual(meta["interface_statistics"]["dropped_by_interface"], 7)


class DecodingTests(Base):
    def ipv6_frame(self, next_header, payload):
        header = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 60) + socket.inet_pton(socket.AF_INET6, "2001:db8::10") + socket.inet_pton(socket.AF_INET6, "2001:db8::20")
        return bytes.fromhex("02000000000202000000000186dd") + header + payload

    def test_tshark_boolean_forms(self):
        self.assertTrue(truthy("True") and truthy("1"))
        self.assertFalse(truthy("False") or truthy("0") or truthy(""))

    def test_builtin_ipv6_tcp(self):
        tcp = struct.pack("!HHIIBBHHH", 42000, 502, 100, 0, 5 << 4, 2, 8192, 0, 0)
        write_pcap(self.capture, [(ORIGIN, self.ipv6_frame(6, tcp))])
        packets, _ = load_capture(self.capture, "builtin")
        self.assertEqual((packets[0].src, packets[0].dst, packets[0].ttl), ("2001:db8::10", "2001:db8::20", 60))

    def test_linux_cooked_capture(self):
        packet = frame(CLIENT, SERVER, 42000, 502, 100, 0, 2)
        cooked = struct.pack("!HHH", 0, 1, 6) + b"\x02\0\0\0\0\x01\0\0" + b"\x08\x00" + packet[14:]
        with self.capture.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
            stream.write(struct.pack("<IIII", 100, 0, len(cooked), len(cooked)) + cooked)
        self.assertEqual(load_capture(self.capture, "builtin")[0][0].dst, SERVER)

    def test_dns_answer_links_finding_to_target(self):
        answer = struct.pack("!6H", 7, 0x8180, 1, 1, 0, 0) + b"\x03ftp\x07example\x00\x00\x01\x00\x01" + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(SERVER)
        failing = struct.pack("!6H", 8, 0x8182, 1, 0, 0, 0) + b"\x03ftp\x07example\x00\x00\x1c\x00\x01"

        def udp_frame(message):
            return ip_frame("192.0.2.53", CLIENT, 17, struct.pack("!4H", 53, 53000, len(message) + 8, 0) + message)

        _, _, _, analysis, _ = self.run_case([(ORIGIN, udp_frame(answer)), (ORIGIN + MS, udp_frame(failing))] + scenario_refused(), target=SERVER)
        finding = next(f for f in analysis["diagnostics"]["findings"] if f["code"] == "dns_error")
        self.assertEqual(finding["scope"], "selected")

    def test_search_suffix_nxdomain_is_downgraded(self):
        def make(name, rcode, answers):
            encoded = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
            body = struct.pack("!6H", 9, 0x8180 | rcode, 1, len(answers), 0, 0) + encoded + b"\0\x01\0\x01"
            for address in answers:
                body += b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04" + socket.inet_aton(address)
            return ip_frame("192.0.2.53", CLIENT, 17, struct.pack("!4H", 53, 53000, len(body) + 8, 0) + body)

        _, _, _, analysis, _ = self.run_case([(ORIGIN, make("device.local", 0, [SERVER])), (ORIGIN + MS, make("device.local.corp.example", 3, []))])
        self.assertEqual(next(f for f in analysis["diagnostics"]["findings"] if f["code"] == "dns_error")["severity"], "info")

    def test_certificate_name_mismatch_from_sni(self):
        def client_hello(name):
            encoded = name.encode()
            server_name = struct.pack("!HBH", len(encoded) + 3, 0, len(encoded)) + encoded
            extension = struct.pack("!HH", 0, len(server_name)) + server_name
            body = b"\x03\x03" + b"\0" * 32 + b"\0" + b"\x00\x02\x00\x2f\x01\x00" + struct.pack("!H", len(extension)) + extension
            return handshake(1, body)

        der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
        chain = len(der).to_bytes(3, "big") + der
        records = tcp_flow(record(22, client_hello("wrong.example")), record(22, hello(True) + handshake(11, len(chain).to_bytes(3, "big") + chain)))
        _, _, _, analysis, _ = self.run_case(records, target=SERVER)
        finding = next(f for f in analysis["diagnostics"]["findings"] if f["code"] == "certificate_name_mismatch")
        self.assertEqual(finding["details"]["requested"], "wrong.example")

    def test_pasv_private_address_mismatch(self):
        records = tcp_flow(b"PASV\r\n", b"220 FTP ready\r\n227 Passive (10,0,0,5,195,80)\r\n", port=21)
        _, _, _, analysis, hypotheses = self.run_case(records, target=SERVER, port=21)
        finding = next(f for f in analysis["diagnostics"]["findings"] if f["code"] == "ftp_pasv_address_mismatch")
        self.assertTrue(finding["details"]["announced_is_private"])
        self.assertIn("ftp_data_path", {h["cause"] for h in hypotheses})

    def test_all_http_errors_on_keepalive_connection(self):
        records = tcp_flow(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n", port=8080)
        _, _, _, analysis, _ = self.run_case(records)
        self.assertEqual(next(f for f in analysis["diagnostics"]["findings"] if f["code"] == "http_error")["details"]["status_code"], 503)


class ProtocolPresetTests(Base):
    @staticmethod
    def modbus(transaction, function, data):
        return struct.pack("!HHHB", transaction, 0, len(data) + 2, 1) + bytes([function]) + data

    def exchange(self, pairs):
        records, seq_c, seq_s, now = handshake_records(), 101, 901, ORIGIN + 20 * MS
        for request, response, delay_ms in pairs:
            records.append((now, c2s(42000, 502, seq_c, seq_s, 24, request)))
            seq_c += len(request)
            now += delay_ms * MS
            if response:
                records.append((now, s2c(42000, 502, seq_s, seq_c, 24, response)))
                seq_s += len(response)
            now += 10 * MS
        return records

    def test_modbus_late_error_and_reused_transaction(self):
        request = self.modbus(0, 3, b"\0\0\0\1")
        ok = self.modbus(0, 3, b"\2\0\0")
        exception = self.modbus(0, 131, b"\2")
        _, _, _, analysis, _ = self.run_case(self.exchange([(request, ok, 10), (request, ok, 900), (request, exception, 10), (request, None, 0)]),
                                             protocol_path=MODBUS, symptom="応答が遅い")
        self.assertEqual([c["status"] for c in analysis["protocol"]["checks"]], ["observed_within_limit", "observed_late", "observed_error", "unobserved"])
        codes = {f["code"] for f in analysis["diagnostics"]["findings"]}
        self.assertLessEqual({"protocol_response_late", "protocol_error_response"}, codes)

    @unittest.skipUnless(TSHARK, "tsharkが必要です")
    def test_modbus_frames_are_valid_for_wireshark(self):
        write_pcap(self.capture, self.exchange([(self.modbus(7, 3, b"\0\0\0\1"), self.modbus(7, 3, b"\2\0\0"), 10)]))
        output = subprocess.run([TSHARK, "-r", str(self.capture), "-Y", "modbus", "-T", "fields", "-e", "mbtcp.trans_id", "-e", "modbus.func_code"],
                                capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(output, ["7", "3", "7", "3"])

    def test_presets_validate(self):
        for path in (MODBUS, ETHERNET_IP):
            self.assertEqual(load_protocol(path)["status"], "validated_rules")

    def test_adjust_required_when_length_excludes_header(self):
        rules = load_protocol(MODBUS)["rules"]
        del rules["length"]["adjust"]
        with self.assertRaises(InvestigationError):
            validate_rules(rules)


class WorkflowTests(Base):
    def busy_records(self):
        records, now = [], ORIGIN
        for index in range(2000):
            records += [(now, c2s(20000 + index, 443, 100, 0, 2)), (now + MS, s2c(20000 + index, 443, 0, 101, 20))]
            now += 2 * MS
        for index in range(2000):
            records += [(now, dns_frame(False, 0, index)), (now + MS, dns_frame(True, 3, index))]
            now += 2 * MS
        return records

    def cli(self, *arguments):
        result = subprocess.run([sys.executable, "-m", "packet_doctor", *map(str, arguments)], cwd=ROOT, capture_output=True, encoding="utf-8")
        return result.stdout, result.returncode

    def test_output_is_bounded_on_a_busy_capture(self):
        write_pcap(self.capture, self.busy_records())
        output, code = self.cli("analyze", "--case", self.root / "busy", "--capture", self.capture, "--backend", "builtin", "--target", SERVER, "--port", 443, "--symptom", "接続できない")
        self.assertEqual(code, 0)
        self.assertLess(len(output), 20_000)
        summary = json.loads(output)["data"]["summary"]
        self.assertEqual(next(f for f in summary["findings"] if f["code"] == "tcp_refused")["count"], 2000)
        self.assertEqual(summary["hypotheses"][0]["cause"], "no_listener")
        output, _ = self.cli("inspect", "--capture", self.capture, "--backend", "builtin")
        self.assertLess(len(output), 20_000)
        output, _ = self.cli("connections", "--capture", self.capture, "--backend", "builtin", "--limit", 5)
        self.assertEqual(len(json.loads(output)["data"]["connections"]), 5)

    def test_unrelated_dns_does_not_become_a_hypothesis(self):
        records = scenario_refused() + [(ORIGIN + 5 * MS, dns_frame(True, 3))]
        _, _, _, _, hypotheses = self.run_case(records, target=SERVER, port=502)
        self.assertNotIn("dns_failure", {h["cause"] for h in hypotheses})

    def test_hypotheses_are_causes_not_observations(self):
        _, _, _, analysis, hypotheses = self.run_case(scenario_refused(), target=SERVER, port=502)
        titles = {f["title"] for f in analysis["diagnostics"]["findings"]}
        self.assertFalse(titles & {h["statement"] for h in hypotheses})

    def test_contrary_evidence_and_verification_reach_report(self):
        _, run, _, _, hypotheses = self.run_case(scenario_injected_reset(), target=SERVER, port=443)
        hypotheses[0].update(status="verified", verification="両端取得で確認した", contrary_evidence_ids=hypotheses[0]["evidence_ids"][:1])
        write_json(self.root / "update.json", hypotheses)
        update_hypotheses(self.root / "case", self.root / "update.json")
        for name in ("report.md", "report.html"):
            text = (run / name).read_text(encoding="utf-8")
            self.assertIn("両端取得で確認した", text)
            self.assertIn("反する証拠", text)

    def test_external_evidence_can_be_cited(self):
        _, run, _, _, hypotheses = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        entry = add_evidence(self.root / "case", "firewall_log", "DROPの記録", source="fw.log", line=120)
        hypotheses[0].update(status="supported", evidence_ids=[entry["id"]])
        write_json(self.root / "update.json", hypotheses)
        update_hypotheses(self.root / "case", self.root / "update.json")
        self.assertIn(entry["id"], (run / "report.md").read_text(encoding="utf-8"))

    def test_agent_hypothesis_survives_reanalysis(self):
        _, _, _, _, hypotheses = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        hypotheses[0].update(status="supported", statement="FW Aが破棄している")
        write_json(self.root / "update.json", hypotheses)
        update_hypotheses(self.root / "case", self.root / "update.json")
        analyze(self.root / "case", [self.capture], backend="builtin", target=SERVER, port=502, symptom="接続できない")
        _, run, _, _ = latest(self.root / "case")
        current = read_json(run / "hypotheses.json")
        kept = next(h for h in current if h["statement"] == "FW Aが破棄している")
        self.assertEqual(kept["status"], "supported")
        self.assertEqual(len({h["cause"] for h in current}), len(current))
        write_json(self.root / "update.json", current)
        update_hypotheses(self.root / "case", self.root / "update.json")

    def test_recorded_check_leaves_the_plan(self):
        result, run, case, analysis, hypotheses = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        first = result["summary"]["next_checks"][0]["check_id"]
        record_check(self.root / "case", first, "実施した")
        root, run, case, analysis = latest(self.root / "case")
        self.assertNotIn(first, [c["check_id"] for c in summarize(root, case, analysis, hypotheses)["next_checks"]])
        with self.assertRaises(InvestigationError):
            record_check(self.root / "case", "not-a-check", "x")

    def test_arp_reply_contradicts_peer_down_and_keeps_two_point(self):
        records = [(ORIGIN - MS, arp_frame(2, SERVER, "020000000020", CLIENT))] + scenario_silent_syn()
        result, _, _, _, hypotheses = self.run_case(records, target=SERVER, port=502)
        peer = next(h for h in hypotheses if h["cause"] == "peer_down")
        self.assertTrue(peer["contradicted"] and peer["contrary_evidence_ids"])
        self.assertIn("two_point", [c["check_id"] for c in result["summary"]["next_checks"]])
        self.assertTrue(Path(result["summary"]["files"]["hypotheses"]).is_file())

    def test_arp_before_the_failure_is_not_evidence_the_peer_survived(self):
        before = [(ORIGIN - MS, arp_frame(2, SERVER, "020000000020", CLIENT))] + scenario_peer_vanishes()
        _, _, _, _, hypotheses = self.run_case(before, name="before", target=SERVER, port=502)
        self.assertFalse(next(h for h in hypotheses if h["cause"] == "peer_down")["contradicted"])
        during = scenario_peer_vanishes() + [(ORIGIN + 300 * MS, arp_frame(1, SERVER, "020000000020", CLIENT))]
        during.sort(key=lambda r: r[0])
        _, _, _, _, hypotheses = self.run_case(during, name="during", target=SERVER, port=502)
        self.assertTrue(next(h for h in hypotheses if h["cause"] == "peer_down")["contradicted"])

    def test_plan_prefers_check_that_separates_candidates(self):
        result, *_ = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        self.assertGreaterEqual(result["summary"]["next_checks"][0]["separates"], 2)
        self.assertIn("observation_not_specified", {i["code"] for i in result["summary"]["quality"]["issues"]})

    def test_verified_state_requires_verified_hypothesis(self):
        self.run_case(scenario_refused(), target=SERVER, port=502)
        with self.assertRaises(InvestigationError):
            set_state(self.root / "case", "verified", "確認した")
        self.assertEqual(set_state(self.root / "case", "handed_off", "担当へ")["state"], "handed_off")

    def test_query_views(self):
        _, run, _, analysis, _ = self.run_case(scenario_loss(), target=SERVER, port=502)
        view = query(run, analysis, conn="conn-0001", limit=2)
        self.assertEqual((view["total"], len(view["rows"])), (6, 2))
        finding = analysis["diagnostics"]["findings"][0]
        self.assertTrue(query(run, analysis, finding=finding["id"])["rows"])
        center = view["rows"][1]["id"]
        around = query(run, analysis, around=center, before=1, after=1)
        self.assertEqual(around["total"], 3)

    def test_log_match_prefers_address_and_time(self):
        _, _, _, analysis, _ = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        from datetime import datetime, timedelta, timezone
        stamp = datetime.fromtimestamp(ORIGIN / 1e9, timezone(timedelta(hours=9))).replace(tzinfo=None)
        text = f"{stamp.isoformat(sep=' ')} DROP src={CLIENT} dst={SERVER}\n{stamp.isoformat(sep=' ')} unrelated\n2000-01-01 00:00:00 DROP {SERVER}\nno time here\n"
        log = self.root / "fw.log"
        log.write_text(text, encoding="utf-8")
        result = match_log(analysis, log, "+09:00")
        self.assertEqual([m["line"] for m in result["matches"]], [1])
        self.assertEqual([m["line"] for m in result["time_only"]], [2])

    def match_lines(self, make_lines):
        _, _, _, analysis, _ = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        from datetime import datetime, timedelta, timezone
        stamp = datetime.fromtimestamp(ORIGIN / 1e9, timezone(timedelta(hours=9))).replace(tzinfo=None).isoformat(sep=" ")
        log = self.root / "fw.log"
        log.write_text("\n".join(make_lines(stamp)) + "\n", encoding="utf-8")
        return match_log(analysis, log, "+09:00")

    def test_firewall_formats_link_to_the_same_connection(self):
        flow = f"{CLIENT} {SERVER} 42000 502"
        samples = {
            "netfilter": lambda t: [f"{t} kernel: FW-DROP: IN=eth0 OUT= SRC={CLIENT} DST={SERVER} LEN=60 PROTO=TCP SPT=42000 DPT=502 SYN"],
            "key_value": lambda t: [f'{t} devname="fg" srcip={CLIENT} srcport=42000 dstip={SERVER} dstport=502 proto=6 action="deny"'],
            "asa": lambda t: [f"{t} %ASA-4-106023: Deny tcp src inside:{CLIENT}/42000 dst dmz:{SERVER}/502 by access-group \"X\" [0x0, 0x0]"],
            "asa_inbound": lambda t: [f"{t} %ASA-2-106001: Inbound TCP connection denied from {CLIENT}/42000 to {SERVER}/502 flags SYN on interface outside"],
            "windows": lambda t: ["#Fields: date time action protocol src-ip dst-ip src-port dst-port size", f"{t} DROP TCP {flow} 60"],
        }
        for name, lines in samples.items():
            with self.subTest(name=name):
                result = self.match_lines(lines)
                self.assertEqual([(e["relation"], e["assessment"], e["block"]) for e in result["flow_evidence"]], [("same_flow", "block_logged", 1)], result)
                self.assertTrue(result["matches"][0]["flow"]["connection"].startswith("conn-"))

    def test_allow_and_mixed_records_are_distinguished(self):
        allow = f"action=accept src={CLIENT} spt=42000 dst={SERVER} dpt=502"
        block = f"action=deny src={CLIENT} spt=42000 dst={SERVER} dpt=502"
        self.assertEqual(self.match_lines(lambda t: [f"{t} {allow}"])["flow_evidence"][0]["assessment"], "allow_logged")
        self.assertEqual(self.match_lines(lambda t: [f"{t} {allow}", f"{t} {block}"])["flow_evidence"][0]["assessment"], "mixed")

    def test_other_flows_are_not_evidence_for_this_connection(self):
        different_port = lambda t: [f"{t} DROP src={CLIENT} spt=42000 dst={SERVER} dpt=443"]
        other_client_port = lambda t: [f"{t} DROP src={CLIENT} spt=50000 dst={SERVER} dpt=502"]
        udp = lambda t: [f"{t} DROP proto=udp src={CLIENT} spt=42000 dst={SERVER} dpt=502"]
        for lines in (different_port, other_client_port, udp):
            result = self.match_lines(lines)
            self.assertEqual((result["flow_evidence"], result["matches"], result["flows_not_in_capture"]), ([], [], 1))
        nat = self.match_lines(lambda t: [f"{t} DROP src=198.51.100.7 spt=42000 dst={SERVER} dpt=502"])
        self.assertEqual(nat["flow_evidence"][0]["assessment"], "other_client_or_nat")

    def test_every_check_states_what_it_needs(self):
        self.assertEqual(set(ACCESS), set(CHECKS))
        self.assertTrue(all(a["needs"] and a["provide"] and "direct_access" in a for a in ACCESS.values()))
        self.assertIsNone(ACCESS["keepalive_test"]["direct_access"])

    def test_next_checks_say_what_would_narrow_the_causes(self):
        result, _, _, _, _ = self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        check = next(c for c in result["summary"]["next_checks"] if c["check_id"] == "firewall_log")
        self.assertIn("ログ", check["needs"])
        self.assertIn("log-match", check["provide"])
        self.assertEqual(set(check["narrows"]) | set(check["leaves_open"]), set(open_causes_of(result)))
        self.assertTrue(set(check["narrows"]))

    def test_report_and_handoff_state_what_is_needed(self):
        self.run_case(scenario_silent_syn(), target=SERVER, port=502)
        root, run, case, analysis = latest(self.root / "case")
        hypotheses = read_json(run / "hypotheses.json")
        for path in (run / "report.md", run / "report.html", Path(render_handoff(root, case, analysis, hypotheses))):
            text = path.read_text(encoding="utf-8")
            self.assertIn("必要なもの", text, path.name)
            self.assertIn("絞れる候補", text, path.name)

    def test_malformed_log_lines_do_not_stop_matching(self):
        good = f"action=deny src={CLIENT} spt=42000 dst={SERVER} dpt=502"
        poison = [f"src={CLIENT} dst={SERVER} dpt=²", f"src={CLIENT} dst={SERVER} dpt=" + "1" * 5000]
        lines = lambda t: [f"{t} {p}" for p in poison] + ["0001-01-01 00:00:00 +09:00 x", "2026-01-01 00:00:00 +99:00 x", f"{t} {good}"]
        self.assertEqual(self.match_lines(lines)["flow_evidence"][0]["assessment"], "block_logged")

    def test_long_hyphen_line_is_bounded(self):
        started = time.perf_counter()
        self.assertIsNone(parse_flow("a-" * 500_000))
        self.assertLess(time.perf_counter() - started, 2)

    def test_conflicting_fields_do_not_make_a_flow(self):
        base = f"action=deny src={CLIENT} spt=42000 dst={SERVER} dpt=502"
        for line in (base + " msg=x src=198.51.100.9", base + " saddr=198.51.100.9", base + ' msg="unbalanced'):
            self.assertIsNone(parse_flow(line), line)
        self.assertEqual(parse_flow(base + f" src={CLIENT}")["src"], CLIENT)

    def test_quoted_regions_cannot_start_keys_or_device_tags(self):
        real = f"src={CLIENT} dst={SERVER} dpt=502"
        escaped = parse_flow(f'msg="a\\" src=198.51.100.9 dst=198.51.100.8 dpt=1" {real}')
        self.assertEqual((escaped["src"], escaped["dport"]), (CLIENT, 502))
        self.assertIsNone(parse_flow(f'"x src={CLIENT} dst={SERVER} dpt=502"'))
        self.assertIsNone(parse_flow(f'src={CLIENT}" dst={SERVER} dpt=502'))
        deny = f"%ASA-4-106023: Deny tcp src in:{CLIENT}/42000 dst out:{SERVER}/502 by access-group"
        self.assertIsNone(parse_flow(f'host msg="{deny}"'))
        self.assertIsNone(parse_flow(f"user=x {deny}"))
        self.assertIsNone(parse_flow(f"%ASA-6-302013: Built note {deny}"))
        self.assertEqual(parse_flow(f"2100-01-01 00:00:00 fw {deny}")["action"], "block")
        for header in ("", "fw01 ", "Nov  8 12:00:00 fw01 : ", "<166>Nov 8 12:00:00 fw01 ", "<166>", "2100-01-01T00:00:00+09:00 fw01 ", "Nov 08 2100 12:00:00: "):
            self.assertEqual(parse_flow(header + deny)["action"], "block", header)
        for header in ("note about this ", "2100-01-01 00:00:00 fw said "):
            self.assertIsNone(parse_flow(header + deny), header)

    def test_overlong_lines_are_not_parsed_from_a_prefix(self):
        base = f"action=deny src={CLIENT} spt=42000 dst={SERVER} dpt=502"
        self.assertIsNotNone(parse_flow(base))
        self.assertIsNone(parse_flow(base + " " + "x" * 9000 + " src=198.51.100.9"))

    def test_windows_action_comes_only_from_its_column(self):
        fields = "date time action protocol src-ip dst-ip src-port dst-port info".split()
        row = f"2100-01-01 00:00:00 %s TCP {CLIENT} {SERVER} 42000 502 %s"
        self.assertEqual(parse_flow(row % ("ALLOW", "DROP"), fields)["action"], "allow")
        self.assertIsNone(parse_flow(row % ("-", "DROP"), fields)["action"])

    def test_quoted_and_trailing_text_cannot_set_flow_or_action(self):
        self.assertIsNone(parse_flow(f'msg="src={CLIENT} dst={SERVER} dpt=502"'))
        unknown = f"src={CLIENT} dst={SERVER} dpt=502 note=x allowed by admin"
        self.assertIsNone(parse_flow(unknown)["action"])
        self.assertEqual(parse_flow(f"FW-DROP: src={CLIENT} dst={SERVER} dpt=502 note=x allowed")["action"], "block")

    def test_evidence_hex_masks_ftp_password(self):
        self.run_case(tcp_flow(b"USER test\r\nPASS private-password\r\n", b"220 FTP ready\r\n", port=21))
        _, run, _, analysis = latest(self.root / "case")
        row = next(json.loads(line) for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines() if json.loads(line).get("payload_length", 0) > 10)
        output, code = self.cli("evidence", "--case", self.root / "case", "--id", row["id"], "--hex")
        self.assertEqual(code, 0)
        self.assertNotIn("private-password", output)
        self.assertIn("PASS ****", output)

    def test_handoff_and_anonymized_export(self):
        self.run_case(scenario_refused(), symptom="接続できない", target=SERVER, port=502)
        root, run, case, analysis = latest(self.root / "case")
        handoff = Path(render_handoff(root, case, analysis, read_json(run / "hypotheses.json"))).read_text(encoding="utf-8")
        self.assertIn("次にお願いしたい確認", handoff)
        output, code = self.cli("export", "--case", self.root / "case", "--out", self.root / "export", "--anonymize")
        self.assertEqual(code, 0, output)
        for name in ("summary.json", "handoff.md", "report.md"):
            text = (self.root / "export" / name).read_text(encoding="utf-8")
            self.assertNotIn(SERVER, text)
            self.assertNotIn(CLIENT, text)
            self.assertNotIn(str(self.root), text)
        self.assertFalse((self.root / "export" / "anonymize-map.json").exists())


class TwoPointTests(Base):
    OFFSET = 3 * SECOND

    def write(self, name, records):
        path = self.root / name
        write_pcap(path, records)
        return path

    def shifted(self, records):
        return [(ns + self.OFFSET + 2 * MS, data) for ns, data in records]

    def base(self):
        return handshake_records(443)

    def analyze_pair(self, near_client, near_server, backend="builtin"):
        return two_point(self.write("a.pcap", near_client), self.write("b.pcap", near_server), backend=backend)

    def test_clean_path_with_clock_offset(self):
        records = self.base()
        forward = [(ns + self.OFFSET + 2 * MS, d) for ns, d in records if d[26:30] == socket.inet_aton(CLIENT)]
        backward = [(ns + self.OFFSET - 2 * MS, d) for ns, d in records if d[26:30] == socket.inet_aton(SERVER)]
        result = self.analyze_pair(records, sorted(forward + backward, key=lambda r: r[0]))
        self.assertEqual(result["findings"], [])
        self.assertAlmostEqual(result["clock_offset_ms"], 3000, delta=0.01)
        self.assertAlmostEqual(result["one_way_delay_ms"]["median"], 2, delta=0.01)

    def test_loss_between_points(self):
        near_client = self.base() + [(ORIGIN + 20 * MS, c2s(42000, 443, 101, 901, 24, b"x" * 20))]
        near_server = self.shifted(self.base()) + [(ORIGIN + self.OFFSET + 30 * MS, c2s(42000, 443, 121, 901, 24, b"y" * 20))]
        near_client.append((ORIGIN + 28 * MS, c2s(42000, 443, 121, 901, 24, b"y" * 20)))
        result = self.analyze_pair(near_client, near_server)
        finding = next(f for f in result["findings"] if f["code"] == "lost_between_points")
        self.assertEqual((finding["direction"], finding["count"]), ("client_to_server", 1))

    def test_reset_generated_between_points(self):
        near_client = self.base() + [(ORIGIN + 40 * MS, s2c(42000, 443, 901, 101, 20))]
        near_server = self.shifted(self.base())
        near_server.append((ORIGIN + self.OFFSET + 50 * MS, c2s(42000, 443, 101, 901, 16)))
        result = self.analyze_pair(near_client, near_server)
        self.assertIn("generated_between_points", {f["code"] for f in result["findings"]})

    def test_nat_does_not_break_matching(self):
        near_client = self.base()
        near_server = []
        for ns, data in self.base():
            changed = bytearray(data)
            if data[26:30] == socket.inet_aton(CLIENT):
                changed[26:30] = socket.inet_aton("198.51.100.7")
            else:
                changed[30:34] = socket.inet_aton("198.51.100.7")
            near_server.append((ns + 2 * MS, bytes(changed)))
        result = self.analyze_pair(near_client, near_server)
        self.assertEqual((result["flows_matched"], result["findings"]), (1, []))

    def test_unrelated_captures_are_reported(self):
        other = handshake_records(443, 43000, ORIGIN + 500 * SECOND)
        other = [(ns, bytearray(d)) for ns, d in other]
        for _, data in other:
            data[38:42] = b"\x11\x22\x33\x44"
        result = self.analyze_pair(self.base(), [(ns, bytes(d)) for ns, d in other])
        self.assertEqual(result["flows_matched"], 0)
        self.assertTrue(result["warnings"])

    @unittest.skipUnless(TSHARK, "tsharkが必要です")
    def test_tshark_backend_matches(self):
        near_client = self.base() + [(ORIGIN + 20 * MS, c2s(42000, 443, 101, 901, 24, b"x" * 20)), (ORIGIN + 28 * MS, c2s(42000, 443, 121, 901, 24, b"y" * 20))]
        near_server = self.shifted(self.base()) + [(ORIGIN + self.OFFSET + 30 * MS, c2s(42000, 443, 121, 901, 24, b"y" * 20))]
        result = self.analyze_pair(near_client, near_server, "tshark")
        self.assertIn("lost_between_points", {f["code"] for f in result["findings"]})


if __name__ == "__main__":
    unittest.main()
