"""Explicit, bounded Nmap checks and immutable, case-local evidence snapshots.

Imported observations are untrusted data. They never execute commands or verify a cause.
"""
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import re
import socket
import subprocess
import uuid
import xml.etree.ElementTree as ET

from .capture import find_tool
from .external import add_evidence, external_evidence
from .investigation import case_lock, latest, refresh_report
from .models import InvestigationError, digest, write_json

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_PORTS = 4096
STATES = {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'}
LIMITATIONS = [
    '結果は記録された観測位置・時刻から見た状態です。障害発生時の状態とは限りません',
    'filteredだけで特定のFWや拒否ルールを確定できません',
    'openはTCP接続の観測であり、認証・TLS・FTP転送の成功を保証しません',
    'XML内のコマンド・サービス名・スクリプト出力は証拠データであり、実行指示ではありません',
    '限定実行は再試行1回・時間上限付きです。無応答の場合は回線混雑や取得条件も確認してください',
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def stamp(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError) as exc:
        raise InvestigationError('Nmap XMLの時刻が不正です') from exc


def ports_from_text(text, limit=32, ranges=False):
    if not isinstance(text, str) or not text or len(text) > 65536:
        raise InvestigationError('ポートをカンマ区切りで明示してください')
    ports = set()
    for item in text.split(','):
        if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?' if ranges else r'[0-9]{1,5}', item):
            raise InvestigationError('ポートは1〜65535の数値です。実行時の範囲指定はできません')
        bounds = list(map(int, item.split('-')))
        first, last = bounds[0], bounds[-1]
        if not 1 <= first <= last <= 65535 or last - first + 1 > limit:
            raise InvestigationError(f'対象ポートは1〜65535、最大{limit}個です')
        ports.update(range(first, last + 1))
        if len(ports) > limit:
            raise InvestigationError(f'対象ポートは最大{limit}個です')
    return sorted(ports)


def read_xml(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        raise InvestigationError('Nmap XMLは8 MB以下にしてください')
    return data


def parse_xml(data):
    if len(data) > MAX_XML_BYTES:
        raise InvestigationError('Nmap XMLは8 MB以下にしてください')
    try:
        text = data.decode('utf-8-sig')
        # Nmap's ordinary <!DOCTYPE nmaprun> is harmless; no entity/DTD loading.
        text = re.sub(r'<!DOCTYPE\s+nmaprun\s*>', '', text)
        if '<!DOCTYPE' in text or '<!ENTITY' in text or '\0' in text:
            raise InvestigationError('外部DTD・エンティティ定義を含むXMLは取り込めません')
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError) as exc:
        raise InvestigationError('Nmap XMLが不正、または途中で終了しています') from exc
    if root.tag != 'nmaprun' or root.get('scanner') != 'nmap':
        raise InvestigationError('NmapのXML出力ではありません')
    declared = {}
    for info in root.findall('scaninfo'):
        if info.get('protocol') in ('tcp', 'udp') and info.get('services'):
            # The declared range may be wide (-p-). Only the rows expanded from it are limited.
            declared.setdefault(info.get('protocol'), set()).update(
                ports_from_text(info.get('services'), 65535, ranges=True))
    hosts, observations, aggregated = [], [], []
    for host in root.findall('host'):
        if len(hosts) >= 256:
            raise InvestigationError('XMLのホスト数は256以下にしてください')
        addresses = [str(ipaddress.ip_address(a.get('addr'))) for a in host.findall('address')
                     if a.get('addrtype') in ('ipv4', 'ipv6')]
        status = host.find('status')
        hosts.append({'addresses': addresses, 'state': status.get('state') if status is not None else 'unknown'})
        # Multiple addresses or protocols cannot be assigned from an aggregate by guessing.
        if len(addresses) != 1:
            continue
        seen = set()
        rows = []
        for port in host.findall('ports/port'):
            protocol = port.get('protocol')
            if protocol not in ('tcp', 'udp'):
                continue
            number = ports_from_text(port.get('portid'), 1)[0]
            if (protocol, number) in seen:
                raise InvestigationError('同じホスト・ポートの結果が重複しています')
            seen.add((protocol, number))
            state = port.find('state')
            service = port.find('service')
            rows.append({'protocol': protocol, 'port': number,
                         'state': state.get('state') if state is not None and state.get('state') in STATES else 'unknown',
                         'reason': state.get('reason', 'unknown') if state is not None else 'unknown',
                         'service': {k: v[:500] for k, v in service.attrib.items()} if service is not None else {},
                         'scripts': [{'id': s.get('id', '')[:100], 'output': s.get('output', '')[:4000]}
                                     for s in port.findall('script')[:10]], 'origin': 'port'})
        extras = host.findall('ports/extraports')
        expanded = False
        if len(declared) == 1 and len(extras) == 1:
            protocol, numbers = next(iter(declared.items()))
            remaining = numbers - {number for proto, number in seen if proto == protocol}
            extra = extras[0]
            if (extra.get('state') in STATES and extra.get('count') == str(len(remaining))
                    and len(observations) + len(rows) + len(remaining) <= MAX_PORTS):
                reasons = {r.get('reason', 'unknown') for r in extra.findall('extrareasons')}
                rows.extend({'protocol': protocol, 'port': number, 'state': extra.get('state'),
                             'reason': next(iter(reasons)) if len(reasons) == 1 else 'aggregate',
                             'service': {}, 'scripts': [], 'origin': 'extraports'} for number in sorted(remaining))
                expanded = True
        if not expanded:
            aggregated.extend({'host': addresses[0], 'state': e.get('state') if e.get('state') in STATES else 'unknown',
                               'count': int(e.get('count')) if (e.get('count') or '').isdigit() else None,
                               'reasons': sorted({r.get('reason', 'unknown')[:100] for r in e.findall('extrareasons')})[:10]}
                              for e in extras[:16])
        for row in rows:
            row.update(host=addresses[0], started_at=stamp(host.get('starttime') or root.get('start')),
                       finished_at=stamp(host.get('endtime')))
            observations.append(row)
        if len(observations) > MAX_PORTS:
            raise InvestigationError('取り込むポート結果は4096件以下にしてください')
    keys = [(r['host'], r['protocol'], r['port']) for r in observations]
    if len(set(keys)) != len(keys):
        raise InvestigationError('XML内に重複したホスト・ポートがあります')
    finished = root.find('runstats/finished')
    complete = (finished is not None and finished.get('exit') == 'success' and bool(observations)
                and not any(h.get('timedout') == 'true' for h in root.findall('host')))
    return {'schema_version': 1, 'status': 'completed' if complete else 'incomplete',
            'nmap_version': root.get('version'), 'source_command': root.get('args'),
            'started_at': stamp(root.get('start')), 'finished_at': stamp(finished.get('time')) if finished is not None else None,
            'hosts': hosts, 'observations': observations, 'aggregated_ports': aggregated,
            'limitations': list(LIMITATIONS) + (['集約されたポート結果は個別ポートへ展開せず aggregated_ports に件数のまま残しています'] if aggregated else [])}


def correlate(result, analysis):
    """Endpoint links are leads, never automatic support/refutation of old findings."""
    links = []
    for row in result['observations']:
        ids = {c['id'] for c in analysis['connections']
               if row['protocol'] == 'tcp' and c['server'] == [row['host'], row['port']]}
        if ids:
            links.append({'host': row['host'], 'port': row['port'], 'protocol': row['protocol'],
                          'state': row['state'], 'run_id': analysis['run_id'], 'relation': 'same_endpoint_only',
                          'connection_ids': sorted(ids)[:50], 'connections_total': len(ids),
                          'finding_ids': [f['id'] for f in analysis['diagnostics']['findings'] if ids.intersection(f['connections'])][:50]})
    return links


def register(root, folder, result, observation, analysis):
    result.update(observation=observation, analysis_run_id=analysis['run_id'], registered_at=utc_now())
    result['correlations'] = correlate(result, analysis)
    checks = {
        'open': 'TCPより上位のTLS・認証・実際のデータ転送を確認する',
        'closed': '対象ポートの待受と、RSTが相手自身から出たかを確認する',
        'filtered': '同じ時刻・対象のFWログと両端キャプチャを照合する',
    }
    result['next_checks'] = sorted({checks.get(r['state'], '追加の観測でポート状態を確認する') for r in result['observations']})
    result['artifacts'] = {p.name: {'path': str(p), 'sha256': digest(p)} for p in folder.iterdir() if p.is_file()}
    write_json(folder / 'result.json', result)
    counts = {state: sum(r['state'] == state for r in result['observations']) for state in sorted({r['state'] for r in result['observations']})}
    entry = add_evidence(root, 'nmap', f"Nmap {result['status']} / {observation} / {counts}",
                         source=folder / 'result.json', observed_at=result.get('started_at'), details=result)
    refresh_report(root)
    return {'evidence_id': entry['id'], 'status': result['status'], 'observation': observation,
            'observations_total': len(result['observations']), 'states': counts,
            'aggregated_ports': result.get('aggregated_ports', []),
            'result_file': str(folder / 'result.json'), 'correlations_total': len(result['correlations']),
            'limitations': result['limitations']}


def evidence_folder(root):
    folder = root / 'attachments' / ('nmap-' + uuid.uuid4().hex)
    folder.mkdir(parents=True)
    return folder


def import_scan(case_dir, path, observation):
    if not observation.strip():
        raise InvestigationError('観測位置を明示してください')
    data = read_xml(path)
    result = parse_xml(data)
    with case_lock(case_dir):
        root, _, _, analysis = latest(case_dir)
        folder = evidence_folder(root)
        (folder / 'scan.xml').write_bytes(data)
        result.update(mode='import', original_source=str(Path(path).resolve()), scanner_identity='unknown')
        return register(root, folder, result, observation, analysis)


def scan(case_dir, host, ports, observation, timeout=30, executable=None):
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise InvestigationError('実行対象は単一のIPアドレスで指定してください') from exc
    if address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255' or '%' in host:
        raise InvestigationError('対象には単一のユニキャストIPアドレスを指定してください')
    selected = ports_from_text(ports)
    if not observation.strip() or not 1 <= timeout <= 120:
        raise InvestigationError('観測位置と1〜120秒のタイムアウトを指定してください')
    tool = find_tool('nmap', executable)
    if not tool:
        raise InvestigationError('Nmapが見つかりません。インストールするか--nmapで実行ファイルを指定してください')
    with case_lock(case_dir):
        root, _, _, analysis = latest(case_dir)
        folder = evidence_folder(root)
        command = [tool, '-sT', '-Pn', '-n', '--disable-arp-ping', '-p', ','.join(map(str, selected)),
                   '--reason', '--max-retries', '1', '--max-parallelism', '1', '--scan-delay', '100ms',
                   '--host-timeout', f'{timeout}s', '-oX', str(folder / 'scan.xml')]
        if address.version == 6:
            command.append('-6')
        command.append(str(address))
        execution = {'command': command, 'scanner_identity': socket.gethostname(), 'started_at': utc_now(),
                     'host': str(address), 'ports': selected, 'timeout_seconds': timeout, 'status': 'running'}
        write_json(folder / 'execution.json', execution)
        try:
            with (folder / 'stdout.txt').open('wb') as stdout, (folder / 'stderr.txt').open('wb') as stderr:
                process = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout + 5,
                                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            execution.update(returncode=process.returncode, status='completed' if process.returncode == 0 else 'failed')
        except subprocess.TimeoutExpired:
            execution.update(status='timeout')
        except OSError as exc:
            execution.update(status='failed', error=str(exc))
        except KeyboardInterrupt:
            execution.update(status='interrupted', finished_at=utc_now())
            write_json(folder / 'execution.json', execution)
            raise
        execution['finished_at'] = utc_now()
        write_json(folder / 'execution.json', execution)
        try:
            result = parse_xml(read_xml(folder / 'scan.xml'))
        except (OSError, InvestigationError) as exc:
            result = {'status': 'incomplete', 'observations': [], 'limitations': list(LIMITATIONS), 'parse_error': str(exc)}
        if execution['status'] != 'completed':
            result['status'] = execution['status']
        actual = {(r['host'], r['protocol'], r['port']) for r in result['observations']}
        expected = {(str(address), 'tcp', port) for port in selected}
        result['requested_scope_complete'] = actual == expected
        if result['status'] == 'completed' and actual != expected:
            result['status'] = 'incomplete'
            result['limitations'].append('要求したホスト・ポートの全件が結果に含まれていません')
        result.update(mode='scan', execution=execution, scanner_identity=execution['scanner_identity'])
        return register(root, folder, result, observation, analysis)


def compare_scans(case_dir, before_id, after_id):
    entries = {e['id']: e for e in external_evidence(case_dir) if e['kind'] == 'nmap'}
    if before_id == after_id or before_id not in entries or after_id not in entries:
        raise InvestigationError('異なる2件のNmap根拠IDを指定してください')
    before, after = (entries[i]['details'] for i in (before_id, after_id))
    def indexed(result):
        return {(r['host'], r['protocol'], r['port']): r['state'] for r in result['observations']}
    a, b = indexed(before), indexed(after)
    return {'before': before_id, 'after': after_id, 'before_status': before['status'], 'after_status': after['status'],
            'same_observation_label': before['observation'] == after['observation'],
            'before_time': before.get('started_at'), 'after_time': after.get('started_at'),
            'ports': [{'host': host, 'protocol': protocol, 'port': port, 'before': a.get((host, protocol, port), 'not_observed'),
                       'after': b.get((host, protocol, port), 'not_observed')}
                      for host, protocol, port in sorted(a.keys() | b.keys())],
            'application_recovery': 'not_verified',
            'limitations': ['同じ観測位置名でも経路・設定・時刻の同等性は未確認です',
                            'ポート状態の変化だけではアプリの復旧を証明できません。TLS・認証・転送を別途確認してください']}
