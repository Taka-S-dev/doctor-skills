import json
from pathlib import Path
import tempfile
import unittest

from packet_doctor.models import Packet
from packet_doctor.protocol import messages_for_direction
from packet_doctor.reasoning import build_hypotheses
from packet_doctor.stream import reassemble
from packet_doctor.summary import Anonymizer
from packet_doctor.summary import export_case
from packet_doctor.external import add_evidence
from packet_doctor.investigation import analyze, latest, refresh_report, set_state, update_hypotheses
from packet_doctor.models import InvestigationError, read_json, write_json
from packet_doctor.nmap import parse_xml
from packet_doctor.twopoint import two_point
from test_expert import handshake_records, c2s, s2c, MS, SECOND, ORIGIN, write_pcap
from test_expert import scenario_silent_syn, icmp_frame


class ReviewRegressions(unittest.TestCase):
    def hypotheses(self, support_connections, contrary_connections, total=None):
        def finding(code, connections, number):
            return dict(code=code, connections=connections, id=str(number), scope='selected',
                        severity='warning', count=1, evidence_ids=[str(number)], details={})
        support = finding('tcp_no_reply', support_connections, 1)
        if total is not None:
            support['connections_total'] = total
        return build_hypotheses([support, finding('tcp_refused', contrary_connections, 2)],
                                [], 'no_connect', {'status': 'no_issue_detected'}, False)

    def test_other_connection_does_not_refute_silent_drop(self):
        hypotheses, plan = self.hypotheses(['conn-1'], ['conn-2'])
        silent = next(h for h in hypotheses if h['cause'] == 'silent_drop')
        self.assertFalse(silent['contradicted'])
        self.assertEqual(silent['contrary_evidence_ids'], [])
        self.assertTrue(any('silent_drop' in c['expected'] for c in plan))

    def test_partial_and_truncated_aggregates_stay_open(self):
        for support, total in [(['conn-1', 'conn-2'], 2), (['conn-1'], 2)]:
            hypotheses, _ = self.hypotheses(support, ['conn-1'], total)
            self.assertFalse(next(h for h in hypotheses if h['cause'] == 'silent_drop')['contradicted'])

    def test_same_connection_can_refute(self):
        hypotheses, _ = self.hypotheses(['conn-1'], ['conn-1'])
        self.assertTrue(next(h for h in hypotheses if h['cause'] == 'silent_drop')['contradicted'])

    def test_conflicting_stream_trims_bytes_and_provenance(self):
        def packet(frame, seq, flags, data=b''):
            return Packet('cap', frame, frame, '192.0.2.1', '192.0.2.2', 40000, 443,
                          seq, 0, flags, 1000, data)
        packets = [packet(1, 100, 2), packet(2, 101, 24, b'\x08\x01\x01ABCDE'),
                   packet(3, 104, 24, b'AXX'), packet(4, 105, 24, b'BCDE')]
        raw, spans, warning = reassemble(packets)
        self.assertEqual(raw, b'\x08\x01\x01A')
        self.assertEqual(spans, [(0, 4, 2, 'cap:frame:2')])
        self.assertIsNotNone(warning)
        rules = dict(byte_order='big', length=dict(offset=0, size=1, includes_header=True),
                     command=dict(offset=1, size=1), request_id=dict(offset=2, size=1))
        self.assertEqual(messages_for_direction(packets, rules, set()), [])

    def test_capture_ends_before_missing_packet_both_clock_signs(self):
        for offset in (3 * SECOND, -3 * SECOND):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as d:
                a, b = Path(d) / 'a.pcap', Path(d) / 'b.pcap'
                base = handshake_records(443)
                write_pcap(a, base + [(ORIGIN + 100 * MS, c2s(42000, 443, 101, 901, 24, b'late'))])
                write_pcap(b, [(ns + offset, data) for ns, data in base])
                result = two_point(a, b, backend='builtin')
                self.assertEqual(result['clock_offset_ms'], offset / MS)
                self.assertEqual(result['findings'], [])

    def test_reverse_packet_outside_capture_is_not_loss(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'a.pcap', Path(d) / 'b.pcap'
            base = handshake_records(443)
            write_pcap(a, base)
            write_pcap(b, [(ns + 3 * SECOND, data) for ns, data in base] +
                       [(ORIGIN + 3 * SECOND + 100 * MS, s2c(42000, 443, 901, 101, 24, b'late'))])
            self.assertEqual(two_point(a, b, backend='builtin')['findings'], [])

    def test_paths_with_spaces_and_unix_paths_are_masked(self):
        paths = [r'C:\Users\Example User\SecretCustomer\trace.pcap',
                 '/home/Example User/SecretCustomer/trace.pcap',
                 r'\\fileserver\SecretCustomer\trace file.pcap']
        with tempfile.TemporaryDirectory() as d:
            anonymizer = Anonymizer(d)
            for path in paths:
                with self.subTest(path=path):
                    document = anonymizer.structured({'path': path, 'count': 4})
                    self.assertEqual(document['count'], 4)
                    self.assertRegex(document['path'], r'^path-\d+$')
                    text = anonymizer.text('Source: `' + path + '`\nNext line')
                    self.assertNotIn('SecretCustomer', text)
                    self.assertNotIn('Example User', text)
                    self.assertIn('Next line', text)
                    self.assertEqual(json.loads(json.dumps(document)), document)

    def test_icmp_only_refutes_its_quoted_flow(self):
        with tempfile.TemporaryDirectory() as d:
            capture = Path(d) / 'trace.pcap'
            records = scenario_silent_syn()
            records.append((ORIGIN + MS, icmp_frame(quoted=records[0][1][14:42])))
            write_pcap(capture, sorted(records))
            analyze(Path(d) / 'case', [capture], backend='builtin')
            _, run, _, _ = latest(Path(d) / 'case')
            hypotheses = read_json(run / 'hypotheses.json')
            self.assertTrue(next(h for h in hypotheses if h['cause'] == 'silent_drop')['contradicted'])

    def test_export_masks_paths_with_spaces_and_preserves_json(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 'Example User' / 'SecretCustomer'
            folder.mkdir(parents=True)
            capture = folder / 'trace file.pcap'
            write_pcap(capture, handshake_records(443))
            analyze(folder / 'case', [capture], backend='builtin')
            root, run, case, analysis = latest(folder / 'case')
            out = Path(d) / 'export'
            export_case(root, run, case, analysis, read_json(run / 'hypotheses.json'), out, anonymize=True)
            for name in ('summary.json', 'report.md', 'handoff.md'):
                text = (out / name).read_text(encoding='utf-8')
                self.assertNotIn('SecretCustomer', text)
                self.assertNotIn('Example User', text)
            summary = json.loads((out / 'summary.json').read_text(encoding='utf-8'))
            self.assertRegex(summary['files']['hypotheses'], r'^path-\d+$')

    def test_slash_separators_in_prose_are_not_paths(self):
        with tempfile.TemporaryDirectory() as d:
            anonymizer = Anonymizer(d)
            text = anonymizer.text('解析 run-1 / conn-1: 192.0.2.1:5 → 192.0.2.2:80 / 受信 / 送信 TCP/IP')
            self.assertIn('解析 run-1 / conn-1:', text)
            self.assertIn('/ 受信 / 送信 TCP/IP', text)
            self.assertNotIn('192.0.2.1', text)
            self.assertNotIn('path-', text)
            masked = anonymizer.text(r'元 C:\Users\Example\trace.pcap / 次の項目')
            self.assertNotIn('Example', masked)
            self.assertIn('/ 次の項目', masked)

    def test_known_path_with_spaces_is_masked_without_delimiters(self):
        path = r'C:\Cases\Secret Customer\trace file.pcap'
        with tempfile.TemporaryDirectory() as d:
            text = Anonymizer(d, paths=[path]).text('取得: ' + path + ' / 次')
            self.assertNotIn('Secret', text)
            self.assertNotIn('file.pcap', text)
            self.assertIn('/ 次', text)

    def test_export_masks_names_and_labels_from_added_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            capture = Path(d) / 'trace.pcap'
            write_pcap(capture, handshake_records(443))
            root = Path(d) / 'case'
            analyze(root, [capture], backend='builtin', observation='観測点B-3')
            root, run, case, analysis = latest(root)
            add_evidence(root, 'curl', 'curl https ftp.secret.example:443: transfer_completed / 観測端末A',
                         details={'observation': '観測端末A', 'status': 'transfer_completed', 'started_at': 'unknown',
                                  'request': {'scheme': 'https', 'host': 'ftp.secret.example', 'port': 443},
                                  'execution': {'scanner_identity': 'SECRET-LAPTOP'}})
            add_evidence(root, 'host_snapshot', '端末状態 HOST-SECRET-01 / client / complete',
                         details={'host': {'hostname': 'HOST-SECRET-01', 'platform': 'Windows'}})
            refresh_report(root)
            out = Path(d) / 'export'
            export_case(root, run, case, analysis, read_json(run / 'hypotheses.json'), out, anonymize=True)
            for name in ('summary.json', 'report.md', 'handoff.md'):
                text = (out / name).read_text(encoding='utf-8')
                for secret in ('ftp.secret.example', 'HOST-SECRET-01', '観測端末A', '観測点B-3'):
                    self.assertNotIn(secret, text, (name, secret))

    def lost_retransmissions(self, directory, client_sends):
        a, b = Path(directory) / 'a.pcap', Path(directory) / 'b.pcap'
        base = handshake_records(443)
        base.append((ORIGIN + 20 * MS, c2s(42000, 443, 101, 901, 24, b'ok')))
        base.append((ORIGIN + 25 * MS, s2c(42000, 443, 901, 103, 24, b'ok')))
        later = (ORIGIN + 9 * SECOND, s2c(42000, 443, 903, 103, 24, b'later'))
        data = c2s(42000, 443, 103, 903, 24, b'never-arrives')
        write_pcap(a, base + [(ORIGIN + n * SECOND, data) for n in client_sends] + [later])
        write_pcap(b, base + [later])
        return two_point(a, b, backend='builtin')

    def test_retransmissions_never_seen_downstream_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.lost_retransmissions(d, (1, 2, 4, 8))
            lost = [f for f in result['findings'] if f['code'] == 'lost_between_points']
            self.assertEqual([(f['direction'], f['count']) for f in lost], [('client_to_server', 4)])
            self.assertEqual(result['packets_not_comparable'], 0)

    def test_carried_verdict_cannot_be_cleared_by_omitting_the_flag(self):
        with tempfile.TemporaryDirectory() as d:
            capture, root, update = Path(d) / 'a.pcap', Path(d) / 'case', Path(d) / 'update.json'
            write_pcap(capture, scenario_silent_syn())
            analyze(root, [capture], backend='builtin', port=502)
            _, run, _, _ = latest(root)
            hypotheses = read_json(run / 'hypotheses.json')
            hypotheses[0].update(status='verified', verification='FW管理者がログで確認')
            write_json(update, hypotheses)
            update_hypotheses(root, update)
            analyze(root, [capture], backend='builtin', port=503)
            _, run, _, analysis = latest(root)
            hypotheses = read_json(run / 'hypotheses.json')
            stale = next(h for h in hypotheses if h.get('needs_revalidation'))
            stale.pop('needs_revalidation')
            write_json(update, hypotheses)
            update_hypotheses(root, update)
            with self.assertRaises(InvestigationError):
                set_state(root, 'verified', '古い判断のみ')
            _, run, _, _ = latest(root)
            hypotheses = read_json(run / 'hypotheses.json')
            stale = next(h for h in hypotheses if h.get('needs_revalidation'))
            stale['revalidation'] = '今回の取得でも同じ破棄をFWログで確認'
            write_json(update, hypotheses)
            update_hypotheses(root, update)
            set_state(root, 'verified', '今回の条件で再確認済み')
            _, run, _, _ = latest(root)
            current = next(h for h in read_json(run / 'hypotheses.json') if h.get('revalidation'))
            self.assertNotIn('needs_revalidation', current)
            self.assertEqual(current['revalidated_in_run'], analysis['run_id'])

    def test_connectionless_support_is_refuted_only_by_same_peer(self):
        def finding(code, number, peer, connections=()):
            return dict(code=code, connections=list(connections), id=str(number), scope='selected', peer=peer,
                        severity='warning', count=1, evidence_ids=[str(number)], details={})
        for refused_peer, expected in (('192.0.2.20', True), ('192.0.2.99', False)):
            findings = [finding('arp_no_reply', 1, '192.0.2.20'), finding('tcp_refused', 2, refused_peer, ['conn-1'])]
            hypotheses, _ = build_hypotheses(findings, [], 'no_connect', {'status': 'no_issue_detected'}, False)
            self.assertEqual(next(h for h in hypotheses if h['cause'] == 'l2_address_problem')['contradicted'], expected)

    def test_full_range_nmap_import_keeps_aggregate(self):
        data = ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" args="nmap" start="1700000000">'
                '<scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>'
                '<host starttime="1700000000" endtime="1700000100"><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/>'
                '<ports><extraports state="closed" count="65534"><extrareasons reason="conn-refused" count="65534"/></extraports>'
                '<port protocol="tcp" portid="502"><state state="open" reason="syn-ack"/></port></ports></host>'
                '<runstats><finished time="1700000100" exit="success"/></runstats></nmaprun>').encode()
        result = parse_xml(data)
        self.assertEqual([(r['port'], r['state']) for r in result['observations']], [(502, 'open')])
        self.assertEqual(result['aggregated_ports'][0]['state'], 'closed')
        self.assertEqual(result['aggregated_ports'][0]['count'], 65534)
        self.assertEqual(result['status'], 'completed')


if __name__ == '__main__':
    unittest.main()
