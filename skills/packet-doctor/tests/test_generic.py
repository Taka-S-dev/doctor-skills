from datetime import datetime
import json
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from packet_doctor.capture import load_capture
from packet_doctor.connections import analyze_connections
from packet_doctor.demo import frame, checksum, write_pcap
from packet_doctor.diagnostics import diagnose
from packet_doctor.investigation import analyze, latest
from packet_doctor.models import InvestigationError
from packet_doctor.network import decode_dns
from packet_doctor.probe import probe
from packet_doctor.tls import certificate_validity, read_certificate

ROOT = Path(__file__).resolve().parents[1]
CERT = Path(__file__).parent / "fixtures/localhost-cert.pem"
ORIGIN = 4_102_444_800_000_000_000  # 2100-01-01 UTC, independent of test execution time
CLIENT, SERVER = "192.0.2.10", "192.0.2.20"


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(kind, body):
    return bytes([kind, 3, 3]) + len(body).to_bytes(2, "big") + body


def hello(server=False, tls13=False):
    body = b"\x03\x03" + b"\0" * 32 + b"\0"
    body += b"\x00\x2f\x00" if server else b"\x00\x02\x00\x2f\x01\x00"
    if server and tls13:
        body += b"\x00\x06\x00\x2b\x00\x02\x03\x04"
    return handshake(2 if server else 1, body)


def tcp_flow(client_data=b"", server_data=b"", port=443, origin=ORIGIN, client_port=42000):
    values = [(origin, frame(CLIENT, SERVER, client_port, port, 100, 0, 2)),
              (origin + 10_000_000, frame(SERVER, CLIENT, port, client_port, 900, 101, 18)),
              (origin + 20_000_000, frame(CLIENT, SERVER, client_port, port, 101, 901, 16))]
    if client_data:
        values.append((origin + 30_000_000, frame(CLIENT, SERVER, client_port, port, 101, 901, 24, client_data)))
    if server_data:
        half = len(server_data) // 2
        values.append((origin + 40_000_000, frame(SERVER, CLIENT, port, client_port, 901, 101 + len(client_data), 24, server_data[:half])))
        values.append((origin + 41_000_000, frame(SERVER, CLIENT, port, client_port, 901 + half, 101 + len(client_data), 24, server_data[half:])))
    return values


def ip_frame(src, dst, protocol, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + payload


def dns_message(response=False, rcode=0, ident=123):
    flags = (0x8180 if response else 0x0100) | rcode
    return struct.pack("!6H", ident, flags, 1, 0, 0, 0) + b"\x03ftp\x07example\x00\x00\x01\x00\x01"


def dns_frame(response=False, rcode=0, ident=123):
    payload = dns_message(response, rcode, ident)
    sport, dport = (53, 53000) if response else (53000, 53)
    udp = struct.pack("!4H", sport, dport, len(payload) + 8, 0) + payload
    return ip_frame("192.0.2.53" if response else CLIENT, CLIENT if response else "192.0.2.53", 17, udp)


def icmp_frame(code=13, quoted=None):
    quoted = quoted or frame(CLIENT, SERVER, 42000, 21, 100, 0, 2)[14:42]
    message = bytes([3, code, 0, 0, 0, 0, 0, 0]) + quoted
    message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
    return ip_frame("192.0.2.1", CLIENT, 1, message)


class GenericTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture.pcap"

    def tearDown(self):
        self.temp.cleanup()

    def diagnosis(self, records, **options):
        write_pcap(self.capture, records)
        packets, metadata = load_capture(self.capture, "builtin")
        return diagnose(analyze_connections(packets), metadata["network_events"], **options)

    def test_dns_nxdomain_without_spec(self):
        result = self.diagnosis([(ORIGIN, dns_frame()), (ORIGIN + 10_000_000, dns_frame(True, 3))])
        self.assertEqual(result["findings"][0]["code"], "dns_error")
        self.assertIn("NXDOMAIN", result["findings"][0]["title"])
        self.assertFalse(any(f["code"] == "dns_no_observed_response" for f in result["findings"]))

    def test_dns_response_matching_checks_transaction(self):
        result = self.diagnosis([(ORIGIN, dns_frame()), (ORIGIN + 10_000_000, dns_frame(True, 0, 999))])
        self.assertTrue(any(f["code"] == "dns_no_observed_response" for f in result["findings"]))

    def test_dns_empty_success_is_not_named_failure(self):
        result = self.diagnosis([(ORIGIN, dns_frame()), (ORIGIN + 10_000_000, dns_frame(True))])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["coverage"]["dns"], "observed")

    def test_dns_pointer_cycle_rejected(self):
        message = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0) + b"\xc0\x0c\0\x01\0\x01"
        with self.assertRaises(ValueError):
            decode_dns(message)

    def test_icmp_admin_prohibition_target_quoted(self):
        result = self.diagnosis([(ORIGIN, icmp_frame())], target=SERVER, port=21)
        self.assertEqual(result["findings"][0]["code"], "administratively_prohibited")
        self.assertEqual(result["findings"][0]["details"]["quoted_destination"], SERVER)

    def test_icmp_unrelated_target_excluded(self):
        result = self.diagnosis([(ORIGIN, icmp_frame())], target="192.0.2.99")
        self.assertEqual(result["findings"], [])

    def test_no_syn_response_does_not_confirm_firewall(self):
        result = self.diagnosis(tcp_flow()[:1])
        finding = result["findings"][0]
        self.assertEqual(finding["code"], "tcp_no_reply")
        self.assertGreater(len(finding["candidates"]), 1)
        self.assertFalse(any(f["code"] == "administratively_prohibited" for f in result["findings"]))

    def test_real_certificate_dates_against_known_dates(self):
        der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
        expired = certificate_validity(der, ORIGIN)
        self.assertEqual(expired["status"], "expired")
        before = datetime.fromisoformat(expired["not_before"])
        after = datetime.fromisoformat(expired["not_after"])
        middle = int(((before.timestamp() + after.timestamp()) / 2) * 1e9)
        self.assertEqual(certificate_validity(der, middle)["status"], "within_dates")
        self.assertEqual(certificate_validity(der, 0)["status"], "not_yet_valid")
        self.assertEqual(read_certificate(CERT.read_bytes(), ORIGIN), expired)

    def test_tls12_expired_certificate_from_split_packets(self):
        der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
        chain = len(der).to_bytes(3, "big") + der
        cert = handshake(11, len(chain).to_bytes(3, "big") + chain)
        result = self.diagnosis(tcp_flow(record(22, hello()), record(22, hello(True) + cert)))
        finding = next(f for f in result["findings"] if f["code"] == "certificate_expired")
        self.assertEqual(finding["details"]["status"], "expired")
        self.assertEqual(len(finding["evidence_ids"]), 2)
        self.assertEqual(result["coverage"]["certificate"], "observed")

    def test_tls13_encrypted_cert_is_unknown(self):
        server = record(22, hello(True, True)) + record(23, b"encrypted bytes")
        result = self.diagnosis(tcp_flow(record(22, hello()), server))
        self.assertEqual(result["coverage"]["certificate"], "not_observed")
        self.assertTrue(any(f["code"] == "tls_certificate_unavailable" for f in result["findings"]))
        self.assertFalse(any(f["code"] == "certificate_expired" for f in result["findings"]))

    def test_tls_plaintext_expired_alert(self):
        result = self.diagnosis(tcp_flow(record(22, hello()), record(21, b"\x02\x2d")))
        finding = next(f for f in result["findings"] if f["code"] == "tls_alert")
        self.assertEqual(finding["details"]["alert"], 45)

    def test_encrypted_alert_not_decoded(self):
        result = self.diagnosis(tcp_flow(record(22, hello()), record(20, b"\x01") + record(21, b"\x02\x2d")))
        self.assertFalse(any(f["code"] == "tls_alert" for f in result["findings"]))

    def test_http_status_without_custom_rules(self):
        result = self.diagnosis(tcp_flow(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", port=8080))
        self.assertEqual(next(f for f in result["findings"] if f["code"] == "http_error")["details"]["status_code"], 403)

    def test_ftp_error_never_persists_password(self):
        records = tcp_flow(b"USER test\r\nPASS private-password\r\n", b"220 FTP ready\r\n530 Login incorrect\r\n", port=21)
        write_pcap(self.capture, records)
        result = analyze(self.root / "case", [self.capture], backend="builtin")
        self.assertTrue(any(f["code"] == "ftp_error" for f in result["diagnostics"]["findings"]))
        for path in (self.root / "case").rglob("*"):
            if path.is_file():
                self.assertNotIn(b"private-password", path.read_bytes())

    def test_ftp_passive_data_failure_survives_control_port_filter(self):
        records = tcp_flow(b"PASV\r\n", b"220 FTP ready\r\n227 Passive (192,0,2,20,195,80)\r\n", port=21)
        records += tcp_flow(port=50000, origin=ORIGIN + 100_000_000, client_port=42001)[:1]
        write_pcap(self.capture, records)
        result = analyze(self.root / "case", [self.capture], backend="builtin", target=SERVER, port=21)
        self.assertTrue(any(f["code"] == "ftp_data_connection_failed" for f in result["diagnostics"]["findings"]))

    def test_ftp_starttls_passive_certificate(self):
        der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
        chain = len(der).to_bytes(3, "big") + der
        client = b"AUTH TLS\r\n" + record(22, hello())
        server = b"220 FTP ready\r\n234 Proceed\r\n" + record(22, hello(True) + handshake(11, len(chain).to_bytes(3, "big") + chain))
        result = self.diagnosis(tcp_flow(client, server, port=21))
        self.assertTrue(any(f["code"] == "certificate_expired" for f in result["findings"]))

    def test_standard_findings_saved_and_linked_without_spec(self):
        records = [(ORIGIN, dns_frame()), (ORIGIN + 10_000_000, dns_frame(True, 2)), (ORIGIN + 20_000_000, icmp_frame())]
        write_pcap(self.capture, records)
        result = analyze(self.root / "case", [self.capture], backend="builtin")
        self.assertIsNone(result["protocol"])
        _, run, _, analysis = latest(self.root / "case")
        evidence = {json.loads(line)["id"] for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines()}
        report = (run / "report.html").read_text(encoding="utf-8")
        for finding in analysis["diagnostics"]["findings"]:
            self.assertTrue(set(finding["evidence_ids"]) <= evidence)
            self.assertIn(finding["title"], report)
        self.assertEqual(analysis["diagnostics"]["coverage"]["tls"], "not_observed")

    def test_dns_probe_failure_no_tcp_attempt(self):
        with patch("packet_doctor.probe.socket.getaddrinfo", side_effect=socket.gaierror("unknown")), patch("packet_doctor.probe.socket.socket") as connect:
            result = probe("unknown.invalid", 443, "direct")
        self.assertEqual(result["findings"][0]["code"], "dns_resolution_failed")
        connect.assert_not_called()

    def test_probe_expired_error_classification(self):
        class DummySocket:
            def settimeout(self, value): pass
            def connect(self, address): pass
            def close(self): pass

        error = ssl.SSLCertVerificationError(1, "certificate expired")
        error.verify_code, error.verify_message = 10, "certificate has expired"
        with patch("packet_doctor.probe.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]), \
             patch("packet_doctor.probe.socket.socket", return_value=DummySocket()), \
             patch("packet_doctor.probe.ssl.create_default_context") as context:
            context.return_value.wrap_socket.side_effect = error
            result = probe("localhost", 443, "direct")
        self.assertIn("期限切れ", result["findings"][0]["title"])
        self.assertEqual(result["steps"][-1]["verify_code"], 10)

    def test_probe_bad_ca_fails_before_network(self):
        with patch("packet_doctor.probe.socket.getaddrinfo") as resolve:
            with self.assertRaises(InvestigationError):
                probe("localhost", 443, "direct", cafile=str(self.root / "missing.pem"))
        resolve.assert_not_called()

    def test_certificate_cli_requires_timezone(self):
        result = subprocess.run([sys.executable, "-m", "packet_doctor", "certificate", str(CERT), "--at", "2100-01-01"], cwd=ROOT, capture_output=True, encoding="utf-8")
        self.assertEqual(result.returncode, 2)


class LocalTLSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred = "C:/Program Files/Git/usr/bin/openssl.exe"
        cls.openssl = preferred if Path(preferred).is_file() else shutil.which("openssl") or "missing-openssl"
        if not Path(cls.openssl).is_file():
            raise unittest.SkipTest("Local TLS integration test requires openssl")
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
        subprocess.run([cls.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key),
                        "-out", str(cls.cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def local_probe(self, name, ftps=False):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        received = []

        def serve():
            try:
                connection, _ = server.accept()
                with connection:
                    if ftps:
                        connection.sendall(b"220-test\r\n220 Ready\r\n")
                        command = b""
                        while not command.endswith(b"\r\n"):
                            command += connection.recv(1)
                        received.append(command)
                        connection.sendall(b"234 Proceed\r\n")
                    try:
                        with context.wrap_socket(connection, server_side=True) as tls:
                            tls.recv(1)
                    except (ssl.SSLError, ConnectionError):
                        pass
            finally:
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = probe("127.0.0.1", port, "ftp-starttls" if ftps else "direct", server_name=name, cafile=str(self.cert))
        thread.join(timeout=6)
        self.assertFalse(thread.is_alive())
        if ftps:
            self.assertEqual(received, [b"AUTH TLS\r\n"])
        return result

    def test_actual_tls_localhost_verified(self):
        result = self.local_probe("localhost")
        self.assertEqual(result["status"], "tls_verified")
        self.assertEqual(result["certificate"]["status"], "within_dates")

    def test_actual_tls_hostname_mismatch(self):
        result = self.local_probe("wrong.example")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["steps"][-1]["verify_code"], 62)

    def test_actual_ftp_starttls(self):
        self.assertEqual(self.local_probe("localhost", True)["status"], "tls_verified")


if __name__ == "__main__":
    unittest.main()
