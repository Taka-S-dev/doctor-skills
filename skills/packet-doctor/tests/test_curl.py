import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from packet_doctor.curl import check, compare_checks, metrics_from_output, outcome, tool_info, validate_url
from packet_doctor.investigation import analyze
from packet_doctor.models import InvestigationError
from test_expert import handshake_records, write_pcap


def metrics(code=200):
    return dict(time_namelookup=0.001, time_connect=0.002, time_appconnect=0.003,
                time_pretransfer=0.004, time_starttransfer=0.005, time_total=0.006,
                size_download=4, response_code=code, remote_port=80, ssl_verify_result=0, remote_ip='127.0.0.1')


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = self.root / 'case'
        capture = self.root / 'capture.pcap'
        write_pcap(capture, handshake_records())
        analyze(self.case, [capture], backend='builtin')


class CurlContract(Base):
    def test_rejects_unsafe_or_unsupported_urls(self):
        for url in ('file:///secret', 'http://user:pass@host/', 'http://host/%0aX', 'http://host:0/', 'http://host/a#b', 'http://host/\n'):
            with self.subTest(url=url), self.assertRaises(InvestigationError):
                validate_url(url, False)
        with self.assertRaises(InvestigationError):
            validate_url('https://host/', True)

    def test_auth_stays_out_of_arguments_artifacts_and_child_environment(self):
        info = dict(path='curl', version='8.21.0', protocols=['http', 'https', 'ftp', 'ftps'])
        secrets = {'CURL_TEST_USER': 'private-user', 'CURL_TEST_PASS': 'private-pass', 'SSLKEYLOGFILE': 'private-key-log'}
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(metrics()).encode(), stderr=b'private-pass')
        with patch.dict(os.environ, secrets), patch('packet_doctor.curl.tool_info', return_value=info), patch('packet_doctor.curl.subprocess.run', return_value=completed) as run:
            result = check(self.case, 'http://example.test/private-path?token=private-token', 'test', user_env='CURL_TEST_USER', password_env='CURL_TEST_PASS')
        command = run.call_args.args[0]
        self.assertEqual(command[1], '-q')
        self.assertIn(b'private-pass', run.call_args.kwargs['input'])
        self.assertNotIn('CURL_TEST_PASS', run.call_args.kwargs['env'])
        self.assertNotIn('SSLKEYLOGFILE', run.call_args.kwargs['env'])
        for secret in ('private-user', 'private-pass', 'private-token', 'private-path'):
            self.assertNotIn(secret, str(command))
            for path in self.case.rglob('*'):
                if path.is_file():
                    self.assertNotIn(secret.encode(), path.read_bytes(), str(path))
        self.assertEqual(result['status'], 'transfer_completed')

    def test_old_curl_and_missing_protocol_are_rejected(self):
        with patch('packet_doctor.curl.find_tool', return_value='curl'), patch('packet_doctor.curl.subprocess.run',
                   return_value=SimpleNamespace(returncode=0, stdout=b'curl 7.88.1\nProtocols: http https\n')):
            with self.assertRaises(InvestigationError):
                tool_info()
        with patch('packet_doctor.curl.tool_info', return_value=dict(path='curl', version='8.21.0', protocols=['http'])):
            with self.assertRaises(InvestigationError):
                check(self.case, 'ftp://example.test/file', 'test')

    def test_zero_response_and_invalid_metrics(self):
        data = {k: str(v) for k, v in metrics(0).items()}
        data['response_code'] = '000'
        self.assertEqual(metrics_from_output(json.dumps(data).encode())['response_code'], 0)
        data['time_total'] = 'NaN'
        self.assertIsNone(metrics_from_output(json.dumps(data).encode()))
        self.assertEqual(outcome(60, metrics(0), 'https'), 'certificate_verification_failed')
        self.assertEqual(outcome(67, metrics(530), 'ftp'), 'authentication_rejected')

    def test_timeout_is_recorded_as_incomplete_transfer(self):
        with patch('packet_doctor.curl.tool_info', return_value=dict(path='curl', version='8.21.0', protocols=['http'])), patch(
                'packet_doctor.curl.subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 1)):
            result = check(self.case, 'http://example.test/', 'test')
        self.assertEqual(result['status'], 'timeout')
        self.assertEqual(result['stages']['transfer'], 'not_completed')
        self.assertIsNone(result['metrics'])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/ok')
            self.end_headers()
            return
        if self.path == '/missing':
            self.send_error(404)
            return
        if self.path == '/auth':
            self.send_error(401)
            return
        self.send_response(200)
        if self.path != '/large':
            self.send_header('Content-Length', '4')
        self.end_headers()
        try:
            self.wfile.write(b'x' * (65536 if self.path == '/large' else 4))
        except (ConnectionError, OSError):
            pass


class CurlLocalHTTP(Base):
    def setUp(self):
        super().setUp()
        try:
            tool_info()
        except InvestigationError as exc:
            self.skipTest(str(exc))
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def test_real_http_and_comparison(self):
        before = check(self.case, self.url + '/missing', 'local')
        after = check(self.case, self.url + '/ok', 'local')
        self.assertEqual(before['status'], 'http_error')
        self.assertEqual(after['status'], 'transfer_completed')
        self.assertEqual(after['metrics']['size_download'], 4)
        result = compare_checks(self.case, before['evidence_id'], after['evidence_id'])
        self.assertTrue(result['selected_transfer_completed_after'])
        self.assertFalse(result['same_request_profile'])
        self.assertEqual(result['application_recovery'], 'not_verified')

    def test_real_redirect_and_auth_are_not_success(self):
        self.assertEqual(check(self.case, self.url + '/redirect', 'local')['status'], 'redirect_not_followed')
        self.assertEqual(check(self.case, self.url + '/auth', 'local')['status'], 'authentication_required_or_rejected')

    def test_real_unknown_size_download_is_limited(self):
        result = check(self.case, self.url + '/large', 'local', max_bytes=128)
        self.assertEqual(result['status'], 'size_limit')
        self.assertEqual(result['stages']['transfer'], 'not_completed')


class FTPHandler(socketserver.StreamRequestHandler):
    def enable_tls(self):
        self.rfile.close()
        self.wfile.close()
        self.connection = self.server.tls_context.wrap_socket(self.connection, server_side=True)
        self.rfile, self.wfile = self.connection.makefile('rb'), self.connection.makefile('wb')

    def reply(self, text):
        self.wfile.write(text.encode() + b'\r\n')
        self.wfile.flush()

    def handle(self):
        self.connection.settimeout(5)
        passive = None
        protected = False
        try:
            if getattr(self.server, 'implicit_tls', False):
                self.enable_tls()
            self.reply('220 Test server')
            while line := self.rfile.readline():
                verb = line.decode().strip().split(' ', 1)[0]
                if verb == 'AUTH' and self.server.tls_context:
                    self.reply('234 Proceed')
                    self.enable_tls()
                elif verb == 'USER':
                    self.reply('331 Password required')
                elif verb == 'PASS':
                    self.reply('530 Login rejected' if getattr(self.server, 'reject_login', False) else '230 Logged in')
                elif verb in ('PBSZ', 'TYPE'):
                    self.reply('200 OK')
                elif verb == 'PROT':
                    protected = True
                    self.reply('200 OK')
                elif verb == 'PWD':
                    self.reply('257 "/"')
                elif verb == 'EPSV':
                    passive = socket.socket()
                    passive.bind(('127.0.0.1', 0))
                    passive.listen(1)
                    passive.settimeout(5)
                    self.reply(f'229 Entering Extended Passive Mode (|||{passive.getsockname()[1]}|)')
                elif verb == 'SIZE':
                    self.reply('213 4')
                elif verb == 'RETR':
                    self.reply('150 Opening data connection')
                    data, _ = passive.accept()
                    if protected:
                        data = self.server.tls_context.wrap_socket(data, server_side=True)
                    with data:
                        data.sendall(b'test')
                        if protected:
                            try:
                                data.unwrap().close()
                            except (ssl.SSLError, OSError):
                                pass
                    self.reply('226 Transfer complete')
                elif verb == 'QUIT':
                    self.reply('221 Bye')
                    break
                else:
                    self.reply('502 Unsupported command')
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            if passive:
                passive.close()
            self.connection.close()


class CurlLocalTLSAndFTP(Base):
    @classmethod
    def setUpClass(cls):
        try:
            tool_info()
        except InvestigationError as exc:
            raise unittest.SkipTest(str(exc))
        openssl = 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not Path(openssl).is_file():
            openssl = shutil.which('openssl')
        if not openssl:
            raise unittest.SkipTest('openssl is required for temporary test certificates')
        cls.temp_cert = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_cert.cleanup)
        cls.cert, cls.key = Path(cls.temp_cert.name) / 'cert.pem', Path(cls.temp_cert.name) / 'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.key), '-out', str(cls.cert),
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True, timeout=30)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cls.cert, cls.key)

    def start_server(self, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_real_https_valid_and_untrusted_certificate(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.socket = self.context.wrap_socket(server.socket, server_side=True)
        port = self.start_server(server)
        url = f'https://localhost:{port}/ok'
        trusted = check(self.case, url, 'local TLS', cafile=str(self.cert))
        self.assertEqual(trusted['status'], 'transfer_completed')
        self.assertEqual(trusted['stages']['tls'], 'verified')
        untrusted = check(self.case, url, 'local TLS')
        self.assertEqual(untrusted['status'], 'certificate_verification_failed')

    def test_real_ftp_and_ftps_transfer(self):
        for mode in ('ftp', 'explicit', 'implicit'):
            with self.subTest(mode=mode):
                server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), FTPHandler)
                server.daemon_threads = True
                server.tls_context = self.context if mode != 'ftp' else None
                server.implicit_tls = mode == 'implicit'
                port = self.start_server(server)
                scheme = 'ftps' if mode == 'implicit' else 'ftp'
                result = check(self.case, f'{scheme}://localhost:{port}/file', 'local FTP', starttls=mode == 'explicit',
                               cafile=str(self.cert) if mode != 'ftp' else None)
                self.assertEqual(result['status'], 'transfer_completed', result)
                self.assertEqual(result['metrics']['size_download'], 4)

    def test_real_ftp_authentication_rejected(self):
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), FTPHandler)
        server.daemon_threads = True
        server.tls_context = None
        server.reject_login = True
        port = self.start_server(server)
        result = check(self.case, f'ftp://localhost:{port}/file', 'local FTP')
        self.assertEqual(result['status'], 'authentication_rejected')


if __name__ == '__main__':
    unittest.main()
