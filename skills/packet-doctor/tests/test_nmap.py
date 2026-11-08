from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from packet_doctor.cli import parser
from packet_doctor.external import external_evidence
from packet_doctor.investigation import analyze, latest, update_hypotheses
from packet_doctor.models import InvestigationError, digest, read_json, write_json
from packet_doctor.nmap import compare_scans, import_scan, parse_xml, ports_from_text, scan
from test_expert import ORIGIN, SERVER, handshake_records, write_pcap


def xml(state='open', host=SERVER, body=None, finish=True):
    ports = body if body is not None else f'''<port protocol="tcp" portid="502">
      <state state="{state}" reason="syn-ack"/><service name="modbus" method="table" conf="3"/>
      <script id="example" output="&lt;script&gt;untrusted&lt;/script&gt;"/></port>'''
    return (f'''<?xml version="1.0"?><!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" version="7.95" args="nmap &lt;untrusted&gt;" start="{ORIGIN // 10**9}">
    <scaninfo type="connect" protocol="tcp" numservices="1" services="502"/>
    <host starttime="{ORIGIN // 10**9}" endtime="{ORIGIN // 10**9 + 5}">
    <status state="up"/><address addr="{host}" addrtype="ipv4"/><ports>{ports}</ports></host>
    ''' + ('<runstats><finished time="1700000005" exit="success"/></runstats>' if finish else '') + '</nmaprun>').encode()


class NmapParsing(unittest.TestCase):
    def test_states_and_untrusted_content_are_preserved(self):
        for state in ('open', 'closed', 'filtered', 'open|filtered', 'closed|filtered', 'unfiltered'):
            result = parse_xml(xml(state))
            row = result['observations'][0]
            self.assertEqual(row['state'], state)
            self.assertEqual(row['service']['method'], 'table')
            self.assertIn('<script>', row['scripts'][0]['output'])
            self.assertEqual(result['status'], 'completed')

    def test_uniform_aggregate_can_be_expanded(self):
        data = xml(body='<extraports state="closed" count="2"><extrareasons reason="resets" count="2"/></extraports>')
        data = data.replace(b'numservices="1" services="502"', b'numservices="2" services="21-22"')
        rows = parse_xml(data)['observations']
        self.assertEqual([(r['port'], r['state']) for r in rows], [(21, 'closed'), (22, 'closed')])
        self.assertTrue(all(r['origin'] == 'extraports' for r in rows))

    def test_ambiguous_aggregate_is_not_assigned_to_ports(self):
        data = xml(body='<extraports state="closed" count="1"/><extraports state="filtered" count="1"/>')
        data = data.replace(b'numservices="1" services="502"', b'numservices="2" services="21-22"')
        result = parse_xml(data)
        self.assertEqual(result['observations'], [])
        self.assertEqual(result['status'], 'incomplete')

    def test_incomplete_and_unknown_are_not_closed(self):
        self.assertEqual(parse_xml(xml(finish=False))['status'], 'incomplete')
        self.assertEqual(parse_xml(xml(body='<port protocol="tcp" portid="502"/>'))['observations'][0]['state'], 'unknown')
        self.assertEqual(parse_xml(xml(body=''))['observations'], [])

    def test_entities_bad_roots_and_truncated_xml_rejected(self):
        for data in (b'<root/>', xml()[:-10], b'<!DOCTYPE nmaprun SYSTEM "file:///private"><nmaprun scanner="nmap"/>',
                     b'<!DOCTYPE nmaprun [<!ENTITY secret "data">]><nmaprun scanner="nmap"/>',
                     xml().decode().encode('utf-16')):
            with self.subTest(data=data[:50]), self.assertRaises(InvestigationError):
                parse_xml(data)

    def test_limits_and_duplicate_rows(self):
        with self.assertRaises(InvestigationError):
            parse_xml(b' ' * (8 * 1024 * 1024 + 1))
        with self.assertRaises(InvestigationError):
            parse_xml(xml(body='<port protocol="tcp" portid="502"/><port protocol="tcp" portid="502"/>'))
        for text in ('1-65535', '-p80', '0', '65536', '21;whoami', ','.join(map(str, range(1, 34)))):
            with self.subTest(text=text), self.assertRaises(InvestigationError):
                ports_from_text(text)
        self.assertEqual(ports_from_text('443,21,443'), [21, 443])


class NmapWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = self.root / 'case'
        self.source = self.root / 'scan.xml'
        self.source.write_bytes(xml())
        capture = self.root / 'capture.pcap'
        write_pcap(capture, handshake_records())
        analyze(self.case, [capture], backend='builtin')

    def test_import_is_offline_copies_source_and_correlates(self):
        with patch('packet_doctor.nmap.subprocess.run') as execute:
            output = import_scan(self.case, self.source, 'client network')
            execute.assert_not_called()
        result = read_json(output['result_file'])
        saved = Path(result['artifacts']['scan.xml']['path'])
        self.assertEqual(saved.read_bytes(), xml())
        self.source.write_bytes(b'changed')
        self.assertEqual(digest(saved), result['artifacts']['scan.xml']['sha256'])
        self.assertEqual(result['correlations'][0]['relation'], 'same_endpoint_only')
        self.assertEqual(result['scanner_identity'], 'unknown')
        self.assertEqual(external_evidence(self.case)[0]['id'], output['evidence_id'])
        _, run, _, _ = latest(self.case)
        self.assertIn(output['evidence_id'], (run / 'report.md').read_text(encoding='utf-8'))
        self.assertNotIn('<script>untrusted', (run / 'report.html').read_text(encoding='utf-8'))
        # New evidence can be cited without changing hypotheses automatically.
        hypotheses = read_json(run / 'hypotheses.json')
        hypotheses[0].update(evidence_ids=[output['evidence_id']], statement='Additional observation')
        update = self.root / 'update.json'
        write_json(update, hypotheses)
        update_hypotheses(self.case, update)

    def test_other_endpoint_does_not_correlate(self):
        self.source.write_bytes(xml(host='192.0.2.200'))
        output = import_scan(self.case, self.source, 'other')
        self.assertEqual(output['correlations_total'], 0)

    def fake_process(self, command, **kwargs):
        Path(command[command.index('-oX') + 1]).write_bytes(xml())
        kwargs['stdout'].write(b'fake nmap stdout')
        return SimpleNamespace(returncode=0)

    def test_execution_is_bounded_and_audited(self):
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'), patch('packet_doctor.nmap.subprocess.run', side_effect=self.fake_process) as run:
            output = scan(self.case, SERVER, '502', 'client network', timeout=12)
        command = run.call_args.args[0]
        self.assertIn('-sT', command)
        self.assertIn('-Pn', command)
        self.assertIn('-n', command)
        self.assertNotIn('-A', command)
        self.assertNotIn('--script', command)
        self.assertEqual(command[-1], SERVER)
        self.assertEqual(command[command.index('--max-parallelism') + 1], '1')
        self.assertEqual(run.call_args.kwargs['timeout'], 17)
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        result = read_json(output['result_file'])
        self.assertTrue(result['requested_scope_complete'])
        self.assertEqual(result['execution']['command'], command)
        self.assertIn('execution.json', result['artifacts'])
        self.assertIn('stdout.txt', result['artifacts'])

    def test_timeout_and_process_failure_are_not_success(self):
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'):
            with patch('packet_doctor.nmap.subprocess.run', side_effect=subprocess.TimeoutExpired('nmap', 1)):
                result = scan(self.case, SERVER, '502', 'client')
            self.assertEqual(result['status'], 'timeout')
            self.assertEqual(result['observations_total'], 0)
            with patch('packet_doctor.nmap.subprocess.run', return_value=SimpleNamespace(returncode=2)):
                result = scan(self.case, SERVER, '502', 'client')
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(Path(result['result_file']).is_file())

    def test_missing_requested_port_is_incomplete(self):
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'), patch('packet_doctor.nmap.subprocess.run', side_effect=self.fake_process):
            result = scan(self.case, SERVER, '21,502', 'client')
        self.assertEqual(result['status'], 'incomplete')
        self.assertFalse(read_json(result['result_file'])['requested_scope_complete'])

    def test_malformed_success_output_is_incomplete_and_preserved(self):
        def fake(command, **kwargs):
            Path(command[command.index('-oX') + 1]).write_bytes(b'<nmaprun')
            return SimpleNamespace(returncode=0)
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'), patch('packet_doctor.nmap.subprocess.run', side_effect=fake):
            output = scan(self.case, SERVER, '502', 'client')
        self.assertEqual(output['status'], 'incomplete')
        result = read_json(output['result_file'])
        self.assertEqual(Path(result['artifacts']['scan.xml']['path']).read_bytes(), b'<nmaprun')

    def test_ipv6_command_and_result(self):
        def fake(command, **kwargs):
            data = xml(host='2001:db8::20').replace(b'addrtype="ipv4"', b'addrtype="ipv6"')
            Path(command[command.index('-oX') + 1]).write_bytes(data)
            return SimpleNamespace(returncode=0)
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'), patch('packet_doctor.nmap.subprocess.run', side_effect=fake) as run:
            output = scan(self.case, '2001:db8::20', '502', 'client')
        self.assertEqual(output['status'], 'completed')
        self.assertIn('-6', run.call_args.args[0])

    def test_compare_missing_observation_is_not_closed(self):
        before = import_scan(self.case, self.source, 'client')
        self.source.write_bytes(xml(body=''))
        after = import_scan(self.case, self.source, 'client')
        result = compare_scans(self.case, before['evidence_id'], after['evidence_id'])
        self.assertEqual(result['ports'][0]['after'], 'not_observed')
        self.assertEqual(result['after_status'], 'incomplete')

    def test_invalid_target_and_absent_case_do_not_execute(self):
        with patch('packet_doctor.nmap.find_tool', return_value='nmap'), patch('packet_doctor.nmap.subprocess.run') as run:
            for host in ('example.com', '192.0.2.0/24', '--script=all', '0.0.0.0', '224.0.0.1'):
                with self.assertRaises(InvestigationError):
                    scan(self.case, host, '502', 'client')
            with self.assertRaises((InvestigationError, FileNotFoundError)):
                scan(self.root / 'absent', SERVER, '502', 'client')
            run.assert_not_called()

    def test_compare_never_claims_application_recovery(self):
        self.source.write_bytes(xml('filtered'))
        before = import_scan(self.case, self.source, 'client')
        self.source.write_bytes(xml('open'))
        after = import_scan(self.case, self.source, 'server')
        comparison = compare_scans(self.case, before['evidence_id'], after['evidence_id'])
        self.assertEqual((comparison['ports'][0]['before'], comparison['ports'][0]['after']), ('filtered', 'open'))
        self.assertEqual(comparison['application_recovery'], 'not_verified')
        self.assertFalse(comparison['same_observation_label'])
        with self.assertRaises(InvestigationError):
            compare_scans(self.case, before['evidence_id'], before['evidence_id'])

    def test_cli_import_and_argument_contract(self):
        args = parser().parse_args(['nmap-scan', '--case', str(self.case), '--host', SERVER, '--ports', '502', '--observation', 'client'])
        self.assertEqual(args.timeout, 30)
        process = subprocess.run([sys.executable, '-m', 'packet_doctor', 'nmap-import', '--case', str(self.case),
                                  '--file', str(self.source), '--observation', 'client'], capture_output=True, encoding='utf-8')
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('evidence_id', process.stdout)


if __name__ == '__main__':
    unittest.main()
