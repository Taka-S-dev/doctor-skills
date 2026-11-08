import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from packet_doctor.external import external_evidence
from packet_doctor.host import (COUNTERS, SCHEMAS, collect_section, compare_snapshots, import_snapshot,
                                  load_snapshot, script_for, take_snapshot, validate_snapshot)
from packet_doctor.investigation import analyze, latest
from packet_doctor.models import InvestigationError, digest, write_json
from test_expert import handshake_records, write_pcap


def snapshot(day=1, counter=10):
    start, finish = f'2026-01-{day:02d}T00:00:00+00:00', f'2026-01-{day:02d}T00:00:05+00:00'
    sections = {name: dict(status='ok', truncated=False, rows=[], started_at=start, finished_at=finish) for name in SCHEMAS}
    sections['system']['rows'] = [{'boot_time': '2025-12-01T00:00:00+00:00'}]
    sections['adapters']['rows'] = [dict(if_index=1, guid='nic-guid', name='Ethernet', status='Up', link_speed='1 Gbps', mac='00-11-22-33-44-55')]
    sections['counters']['rows'] = [{'name': 'Ethernet', **{key: counter for key in COUNTERS}}]
    sections['tcp']['rows'] = [dict(local_address='0.0.0.0', local_port=21, remote_address='0.0.0.0', remote_port=0, state='Listen', pid=123)]
    return dict(schema_version=1, kind='host_snapshot', host=dict(hostname='test-host', platform='Windows'),
                started_at=start, finished_at=finish, sections=sections)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def compare(self, before, after):
        a, b = self.root / 'a.json', self.root / 'b.json'
        write_json(a, before)
        write_json(b, after)
        return compare_snapshots(a, b)

    def test_read_only_queries_and_encoded_execution(self):
        for name in SCHEMAS:
            script = script_for(name, 3)
            self.assertNotIn('Set-Net', script)
            self.assertNotIn('Remove-', script)
            self.assertNotIn('-ComputerName', script)
            self.assertIn('Select-Object -First 4', script)
        result = dict(status='permission_denied', rows=[], truncated=False)
        with patch('packet_doctor.host.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(result).encode(), stderr=b'')) as run:
            data = collect_section('powershell.exe', 'tcp', 3, 2)
        self.assertEqual(data['status'], 'permission_denied')
        command = run.call_args.args[0]
        self.assertIn('-NoProfile', command)
        self.assertIn('-NonInteractive', command)
        self.assertIn('-EncodedCommand', command)
        self.assertEqual(run.call_args.kwargs['timeout'], 2)

    def test_failed_timeout_oversized_and_invalid_output_are_distinct(self):
        with patch('packet_doctor.host.subprocess.run', side_effect=subprocess.TimeoutExpired('powershell', 1)):
            self.assertEqual(collect_section('powershell', 'tcp', 3, 1)['status'], 'timeout')
        for stdout, code, expected in [(b'not json', 0, 'failed'), (b'', 1, 'failed'), (b'x' * (1024 * 1024 + 1), 0, 'output_limit')]:
            with patch('packet_doctor.host.subprocess.run', return_value=SimpleNamespace(returncode=code, stdout=stdout, stderr=b'')):
                self.assertEqual(collect_section('powershell', 'tcp', 3, 1)['status'], expected)

    def test_successful_empty_is_not_failure(self):
        data = json.dumps(dict(status='ok', rows=[], truncated=False)).encode()
        with patch('packet_doctor.host.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=data, stderr=b'')):
            result = collect_section('powershell', 'tcp', 3, 1)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['rows'], [])

    def test_unsupported_platform_is_partial_and_no_overwrite(self):
        out = self.root / 'state.json'
        with patch('packet_doctor.host.platform.system', return_value='Linux'), patch('packet_doctor.host.subprocess.run') as run:
            result = take_snapshot(out)
            run.assert_not_called()
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(all(s['status'] == 'unsupported' for s in result['sections'].values()))
        original = out.read_bytes()
        with self.assertRaises(InvestigationError):
            take_snapshot(out)
        self.assertEqual(out.read_bytes(), original)

    def test_time_budget_exhaustion_is_recorded(self):
        with patch('packet_doctor.host.platform.system', return_value='Windows'), patch('packet_doctor.host.shutil.which', return_value='powershell'), patch(
                'packet_doctor.host.time.monotonic', side_effect=[0] + [2] * len(SCHEMAS)), patch('packet_doctor.host.subprocess.run') as run:
            result = take_snapshot(self.root / 'state.json', timeout=1)
        run.assert_not_called()
        self.assertTrue(all(s['status'] == 'timeout' for s in result['sections'].values()))

    def test_validation_rejects_bad_schema_values_and_timestamps(self):
        changes = [lambda s: s.update(schema_version=2),
                   lambda s: s['sections']['tcp']['rows'][0].update(pid='execute me'),
                   lambda s: s['sections']['tcp'].update(status='permission_denied'),
                   lambda s: s['sections']['system']['rows'][0].update(boot_time='not a timestamp'),
                   lambda s: s.update(finished_at='2025-01-01T00:00:00Z'),
                   lambda s: s['sections']['tcp'].update(started_at='2020-01-01T00:00:00Z')]
        for change in changes:
            sample = snapshot()
            change(sample)
            with self.assertRaises(InvestigationError):
                validate_snapshot(sample)

    def test_powershell_timestamp_precision_is_accepted(self):
        sample = snapshot()
        sample['sections']['system']['rows'][0]['boot_time'] = '2025-12-01T00:00:00.1234567Z'
        self.assertIs(validate_snapshot(sample), sample)

    def test_snapshot_file_size_limit(self):
        path = self.root / 'big.json'
        path.write_bytes(b' ' * (8 * 1024 * 1024 + 1))
        with self.assertRaises(InvestigationError):
            load_snapshot(path)

    def test_configuration_and_counter_differences(self):
        before, after = snapshot(), snapshot(2, 15)
        after['sections']['tcp']['rows'] = []
        result = self.compare(before, after)
        self.assertEqual(result['sections']['tcp']['removed_total'], 1)
        adapter = result['counters']['adapters'][0]
        self.assertEqual(adapter['status'], 'observed_delta')
        self.assertEqual(adapter['delta']['rx_errors'], 5)

    def test_partial_data_is_not_reported_as_removed(self):
        for status, truncated in [('timeout', False), ('permission_denied', False), ('ok', True)]:
            before, after = snapshot(), snapshot(2)
            after['sections']['tcp'].update(status=status, rows=[], truncated=truncated)
            result = self.compare(before, after)
            self.assertEqual(result['sections']['tcp']['status'], 'not_comparable')
            self.assertNotIn('removed', result['sections']['tcp'])

    def test_reboot_reset_unknown_and_changed_adapter_do_not_create_deltas(self):
        before, after = snapshot(), snapshot(2, 1)
        self.assertEqual(self.compare(before, after)['counters']['adapters'][0]['status'], 'reset_or_wrap')
        after['sections']['system']['rows'][0]['boot_time'] = '2026-01-02T00:00:00Z'
        self.assertEqual(self.compare(before, after)['counters']['reason'], 'reboot_or_different_host')
        after = snapshot(2, 20)
        after['sections']['system']['rows'] = []
        self.assertEqual(self.compare(before, after)['counters']['reason'], 'boot_time_unknown')
        after = snapshot(2, 20)
        after['sections']['adapters']['rows'][0]['guid'] = 'another-nic'
        self.assertTrue(all(r['status'] == 'not_comparable' for r in self.compare(before, after)['counters']['adapters']))

    def test_missing_counter_is_unknown_not_zero(self):
        before, after = snapshot(), snapshot(2, 20)
        before['sections']['counters']['rows'][0]['rx_errors'] = None
        self.assertIsNone(self.compare(before, after)['counters']['adapters'][0]['delta']['rx_errors'])

    def test_missing_adapter_identity_is_not_silently_ignored(self):
        before, after = snapshot(), snapshot(2, 20)
        after['sections']['adapters']['rows'][0]['guid'] = None
        result = self.compare(before, after)['counters']
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['unmatched_counter_rows'], 1)
        self.assertEqual(result['adapters'][0]['status'], 'not_comparable')

    def test_renamed_adapter_is_matched_by_guid(self):
        before, after = snapshot(), snapshot(2, 20)
        after['sections']['adapters']['rows'][0]['name'] = 'Renamed'
        after['sections']['counters']['rows'][0]['name'] = 'Renamed'
        result = self.compare(before, after)['counters']
        self.assertEqual(result['status'], 'compared')
        self.assertEqual(result['adapters'][0]['delta']['rx_errors'], 10)

    def test_different_host_and_nonchronological_data_are_not_compared(self):
        before, after = snapshot(), snapshot(2)
        after['host']['hostname'] = 'other'
        self.assertEqual(self.compare(before, after)['reason'], 'host_mismatch')
        self.assertEqual(self.compare(snapshot(2), snapshot())['reason'], 'time_order_or_overlap')
        self.assertEqual(self.compare(snapshot(), snapshot())['reason'], 'time_order_or_overlap')

    def test_import_copies_raw_file_and_adds_evidence_without_execution(self):
        case, capture, source = self.root / 'case', self.root / 'capture.pcap', self.root / 'source.json'
        write_pcap(capture, handshake_records())
        analyze(case, [capture], backend='builtin')
        write_json(source, snapshot())
        original = source.read_bytes()
        with patch('packet_doctor.host.subprocess.run') as run:
            result = import_snapshot(case, source, 'server')
            run.assert_not_called()
        source.write_text('{}')
        self.assertEqual(Path(result['source']).read_bytes(), original)
        evidence = external_evidence(case)[0]
        self.assertEqual(evidence['source_sha256'], digest(result['source']))
        self.assertEqual(evidence['details']['role'], 'server')
        _, run, _, _ = latest(case)
        self.assertIn(result['evidence_id'], (run / 'report.md').read_text(encoding='utf-8'))
        self.assertIn('test-host', (run / 'report.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
