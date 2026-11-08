from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from packet_doctor.investigation import analyze, latest, record_check, set_state, update_hypotheses
from packet_doctor.models import InvestigationError, Packet, read_json, write_json
from packet_doctor.summary import summarize, render_handoff
from packet_doctor.twopoint import compare_flow, match_flows, clock_offset, two_point
from test_expert import handshake_records, c2s, ORIGIN, MS, SECOND, write_pcap, scenario_silent_syn


def flow(port=40000, payload=b'abc'):
    def packet(frame, src, dst, sport, dport, seq, ack, flags, data=b''):
        return Packet('cap', frame, frame * MS, src, dst, sport, dport, seq, ack, flags, 1000, data)
    return dict(client=['192.0.2.1', port], start=True, packets=[
        packet(1, '192.0.2.1', '192.0.2.2', port, 443, 100, 0, 2),
        packet(2, '192.0.2.2', '192.0.2.1', 443, port, 900, 101, 18),
        packet(3, '192.0.2.1', '192.0.2.2', port, 443, 101, 901, 24, payload)])


class MatchingBoundaries(unittest.TestCase):
    def test_equal_candidates_and_many_to_one_are_unmatched(self):
        self.assertEqual(match_flows([flow()], [flow(41000), flow(42000)]), [])
        self.assertEqual(match_flows([flow(41000), flow(42000)], [flow()]), [])

    def test_repeated_syn_is_not_multiple_independent_matches(self):
        a, b = flow(), flow()
        a['packets'] = [a['packets'][0]] * 3
        b['packets'] = [b['packets'][0]] * 3
        self.assertEqual(match_flows([a], [b]), [])

    def test_payload_disambiguates_connections(self):
        a, b, other = flow(), flow(41000), flow(42000, b'xyz')
        self.assertEqual(match_flows([a], [other, b]), [(a, b)])

    def test_retransmission_is_not_assigned_to_wrong_attempt(self):
        a, b = flow(), flow()
        a['packets'].append(replace(a['packets'][-1], frame=4, time_ns=100 * MS))
        b['packets'][-1] = replace(b['packets'][-1], time_ns=101 * MS)
        matched, only_a, only_b = compare_flow(a, b)
        self.assertEqual(sum(map(len, matched.values())), 2)
        self.assertEqual(sum(map(len, only_a.values())), 0)
        self.assertEqual(sum(map(len, only_b.values())), 0)
        self.assertEqual(clock_offset([(matched, only_a, only_b, a)]), (0, 0))

    def test_truncation_and_conflicting_payload_do_not_invent_loss(self):
        for truncated in (False, True):
            a, b = flow(), flow()
            b['packets'][-1] = replace(b['packets'][-1], payload=b'x' if truncated else b'xyz', tcp_len=3)
            matched, only_a, only_b = compare_flow(a, b)
            self.assertEqual(sum(map(len, matched.values())), 2)
            self.assertFalse(any(only_a.values()) or any(only_b.values()))

    def test_same_packet_in_opposite_direction_does_not_match(self):
        a, b = flow(), flow()
        b['client'] = ['192.0.2.2', 443]
        matched, _, _ = compare_flow(a, b)
        self.assertFalse(any(matched.values()))

    def test_partial_retransmission_result_is_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'a.pcap', Path(d) / 'b.pcap'
            base = handshake_records(443)
            payload = c2s(42000, 443, 101, 901, 24, b'request')
            write_pcap(a, base + [(ORIGIN + 20 * MS, payload), (ORIGIN + 100 * MS, payload)])
            write_pcap(b, [(ns + 3 * SECOND, data) for ns, data in base] + [(ORIGIN + 3 * SECOND + 101 * MS, payload)])
            result = two_point(a, b, backend='builtin')
            self.assertEqual(result['matching_status'], 'partial')
            self.assertEqual(result['packets_not_comparable'], 3)
            self.assertEqual(result['findings'], [])
            self.assertTrue(result['warnings'])


class ReanalysisBoundaries(unittest.TestCase):
    def test_prior_verification_does_not_verify_new_capture(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'case'
            capture = Path(d) / 'a.pcap'
            write_pcap(capture, scenario_silent_syn())
            analyze(root, [capture], backend='builtin')
            _, run, _, _ = latest(root)
            previous_run = run.name
            hypotheses = read_json(run / 'hypotheses.json')
            previous = next(h for h in hypotheses if h['cause'] == 'silent_drop')
            previous.update(status='verified', verification='Confirmed in firewall log')
            update = Path(d) / 'update.json'
            write_json(update, hypotheses)
            update_hypotheses(root, update)
            record_check(root, 'firewall_log', 'Confirmed')
            # Same symptoms, different capture content and period.
            write_pcap(capture, [(ns + 60 * SECOND, data) for ns, data in scenario_silent_syn()])
            analyze(root, [capture], backend='builtin')
            _, run, case, analysis = latest(root)
            hypotheses = read_json(run / 'hypotheses.json')
            old = next(h for h in hypotheses if h['status'] == 'verified')
            self.assertTrue(old['needs_revalidation'])
            self.assertEqual(old['finding_ids'], [])
            self.assertEqual(old['prior_finding_ids']['run_id'], previous_run)
            self.assertEqual(old['scope']['run_id'], previous_run)
            current = next(h for h in hypotheses if h['cause'] == 'silent_drop' and h['status'] == 'candidate')
            self.assertEqual(current['scope']['run_id'], analysis['run_id'])
            self.assertEqual(current['scope']['connections'][0]['server'][1], 502)
            self.assertIn('firewall_log', {c['check_id'] for c in summarize(root, case, analysis, hypotheses)['next_checks']})
            with self.assertRaises(InvestigationError):
                set_state(root, 'verified', 'Old result alone is insufficient')
            for filename in ('report.md', 'report.html'):
                self.assertIn('再確認が必要', (run / filename).read_text(encoding='utf-8'))
                self.assertIn(previous_run, (run / filename).read_text(encoding='utf-8'))
            handoff = Path(render_handoff(root, case, analysis, hypotheses)).read_text(encoding='utf-8')
            self.assertIn(previous_run, handoff)
            self.assertIn('再確認が必要', handoff)


if __name__ == '__main__':
    unittest.main()
