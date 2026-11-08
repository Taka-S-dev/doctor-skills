"""Local, read-only Windows network snapshots and conservative offline comparisons."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import time
import uuid

from . import __version__
from .external import add_evidence
from .investigation import case_lock, latest, refresh_report
from .models import InvestigationError, digest

MAX_FILE = 8 * 1024 * 1024
MAX_SECTION = 1024 * 1024
STATUSES = {'ok', 'unsupported', 'permission_denied', 'failed', 'timeout', 'output_limit'}
COUNTERS = ('rx_bytes', 'tx_bytes', 'rx_errors', 'tx_errors', 'rx_discards', 'tx_discards')
SCHEMAS = {
    'system': {'boot_time': 'str'},
    'addresses': {'if_index': 'int', 'address': 'str', 'prefix_length': 'int', 'family': 'str'},
    'dns': {'if_index': 'int', 'family': 'str', 'servers': 'list'},
    'routes': {'if_index': 'int', 'destination': 'str', 'next_hop': 'str', 'route_metric': 'int'},
    'tcp': {'local_address': 'str', 'local_port': 'int', 'remote_address': 'str', 'remote_port': 'int', 'state': 'str', 'pid': 'int'},
    'adapters': {'if_index': 'int', 'guid': 'str', 'name': 'str', 'status': 'str', 'link_speed': 'str', 'mac': 'str'},
    'counters': {'name': 'str', **{key: 'int' for key in COUNTERS}},
}
# No user input is interpolated into these queries, and none modifies settings.
QUERIES = {
    'system': ('Get-CimInstance -ClassName Win32_OperatingSystem',
               "boot_time = $_.LastBootUpTime.ToUniversalTime().ToString('o')"),
    'addresses': ('Get-NetIPAddress',
                  'if_index = $_.InterfaceIndex; address = $_.IPAddress; prefix_length = $_.PrefixLength; family = [string]$_.AddressFamily'),
    'dns': ('Get-DnsClientServerAddress',
            'if_index = $_.InterfaceIndex; family = [string]$_.AddressFamily; servers = @($_.ServerAddresses)'),
    'routes': ('Get-NetRoute',
               'if_index = $_.InterfaceIndex; destination = $_.DestinationPrefix; next_hop = $_.NextHop; route_metric = $_.RouteMetric'),
    'tcp': ('Get-NetTCPConnection',
            'local_address = $_.LocalAddress; local_port = $_.LocalPort; remote_address = $_.RemoteAddress; remote_port = $_.RemotePort; state = [string]$_.State; pid = $_.OwningProcess'),
    'adapters': ('Get-NetAdapter',
                 'if_index = $_.ifIndex; guid = [string]$_.InterfaceGuid; name = $_.Name; status = [string]$_.Status; link_speed = [string]$_.LinkSpeed; mac = [string]$_.MacAddress'),
    'counters': ('Get-NetAdapterStatistics',
                 'name = $_.Name; rx_bytes = $_.ReceivedBytes; tx_bytes = $_.SentBytes; rx_errors = $_.ReceivedPacketErrors; tx_errors = $_.OutboundPacketErrors; rx_discards = $_.ReceivedDiscardedPackets; tx_discards = $_.OutboundDiscardedPackets'),
}
LIMITATIONS = [
    '採取した端末の、その時間帯の状態です。過去の障害時の状態や他の端末の状態ではありません',
    '項目は順番に採取するため、完全に同時刻の記録ではありません',
    '取得失敗・権限不足・打ち切りは、異常なし／接続なしを意味しません',
    'ホスト名・IP・MAC・接続先・PIDを含みます。共有前に内容を確認してください',
]


def now():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    try:
        # PowerShell's round-trip format has seven fractional digits; Python 3.10
        # accepts only three or six. Keep the original text in the evidence.
        normalized = re.sub(r'(\d{2}:\d{2}:\d{2})\.(\d{1,9})(?=Z|[+-])',
                            lambda m: m[1] + '.' + m[2][:6].ljust(6, '0'), value)
        parsed = datetime.fromisoformat(normalized.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvestigationError('スナップショットの時刻にはタイムゾーン付きISO 8601が必要です') from exc


def script_for(section, limit):
    query, fields = QUERIES[section]
    return r'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$result = @{status='ok'; rows=@(); truncated=$false; powershell_version=$PSVersionTable.PSVersion.ToString()}
try {
    $items = @(''' + query + f''' | Select-Object -First {limit + 1} | ForEach-Object {{ [PSCustomObject]@{{ {fields} }} }})
    $result.truncated = $items.Count -gt {limit}
    $result.rows = @($items | Select-Object -First {limit})
''' + r'''} catch {
    $result.status = 'failed'
    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { $result.status = 'unsupported' }
    if ($_.CategoryInfo.Category -in @('PermissionDenied','SecurityError') -or
        $_.Exception -is [System.UnauthorizedAccessException] -or
        $_.Exception.HResult -eq -2147024891 -or $_.Exception.NativeErrorCode -eq 5) {
        $result.status = 'permission_denied'
    }
    $result.error_type = $_.Exception.GetType().FullName
}
$json = ConvertTo-Json -InputObject $result -Depth 6 -Compress
if ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt 1048576) {
    $json = '{"status":"output_limit","rows":[],"truncated":true}'
}
[Console]::WriteLine($json)
'''


def empty_section(status):
    return {'status': status, 'rows': [], 'truncated': False}


def collect_section(tool, section, limit, timeout):
    script = script_for(section, limit)
    command = [tool, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode('ascii')]
    started = now()
    try:
        process = subprocess.run(command, capture_output=True, timeout=timeout, check=False,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if len(process.stdout) > MAX_SECTION or len(process.stderr) > MAX_SECTION:
            result = empty_section('output_limit')
        elif process.returncode:
            result = empty_section('failed')
        else:
            result = json.loads(process.stdout.decode('utf-8-sig'))
            validate_section(section, result)
    except subprocess.TimeoutExpired:
        result = empty_section('timeout')
    except (OSError, ValueError, UnicodeError, InvestigationError):
        result = empty_section('failed')
    result.update(started_at=started, finished_at=now(), source=QUERIES[section][0],
                  script_sha256=hashlib.sha256(script.encode('utf-8')).hexdigest())
    return result


def validate_section(name, section):
    if not isinstance(section, dict) or section.get('status') not in STATUSES or type(section.get('truncated')) is not bool:
        raise InvestigationError('採取項目の状態が不正です')
    rows = section.get('rows')
    if not isinstance(rows, list) or len(rows) > 5000 or (section['status'] != 'ok' and rows):
        raise InvestigationError('採取項目の行数・状態が不正です')
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(SCHEMAS[name]):
            raise InvestigationError(f'{name}の項目形式が不正です')
        for key, kind in SCHEMAS[name].items():
            value = row[key]
            if value is None:  # Unavailable properties must not silently become zero.
                continue
            valid = (kind == 'str' and isinstance(value, str) and len(value) <= 512
                     or kind == 'int' and type(value) is int and 0 <= value < 2**64
                     or kind == 'list' and isinstance(value, list) and len(value) <= 64
                     and all(isinstance(v, str) and len(v) <= 512 for v in value))
            if not valid:
                raise InvestigationError(f'{name}.{key}の値が不正です')


def validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get('schema_version') != 1 or snapshot.get('kind') != 'host_snapshot':
        raise InvestigationError('対応する端末スナップショットではありません')
    if timestamp(snapshot.get('finished_at')) < timestamp(snapshot.get('started_at')):
        raise InvestigationError('採取時刻の順序が不正です')
    host = snapshot.get('host')
    if not isinstance(host, dict) or any(not isinstance(host.get(k), str) or not host[k] or len(host[k]) > 512 for k in ('hostname', 'platform')):
        raise InvestigationError('端末識別情報が不正です')
    sections = snapshot.get('sections')
    if not isinstance(sections, dict) or set(sections) != set(SCHEMAS):
        raise InvestigationError('採取項目の一覧が不正です')
    for name, section in sections.items():
        validate_section(name, section)
        if name == 'system':
            for row in section['rows']:
                if row['boot_time']:
                    timestamp(row['boot_time'])
        start, end = timestamp(section.get('started_at')), timestamp(section.get('finished_at'))
        if end < start or start < timestamp(snapshot['started_at']) or end > timestamp(snapshot['finished_at']):
            raise InvestigationError('採取項目の時刻がスナップショット範囲外です')
    return snapshot


def load_snapshot(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise InvestigationError('スナップショットは8 MB以下にしてください')
    try:
        snapshot = json.loads(data.decode('utf-8-sig'))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvestigationError('スナップショットのJSONが不正です') from exc
    return validate_snapshot(snapshot), data


def snapshot_summary(snapshot):
    return {'host': snapshot['host'], 'started_at': snapshot['started_at'], 'finished_at': snapshot['finished_at'],
            'status': 'complete' if all(s['status'] == 'ok' and not s['truncated'] for s in snapshot['sections'].values()) else 'partial',
            'sections': {k: {'status': v['status'], 'rows': len(v['rows']), 'truncated': v['truncated']} for k, v in snapshot['sections'].items()}}


def take_snapshot(out, timeout=45, max_rows=500):
    if not 1 <= timeout <= 120 or not 1 <= max_rows <= 5000:
        raise InvestigationError('時間制限は1〜120秒、項目別の行数は1〜5000で指定してください')
    out = Path(out).resolve()
    if out.exists():
        raise InvestigationError('既存のスナップショットは上書きしません')
    started, deadline = now(), time.monotonic() + timeout
    tool = shutil.which('powershell.exe') if platform.system() == 'Windows' else None
    sections = {}
    for name in SCHEMAS:
        remaining = deadline - time.monotonic()
        if not tool or remaining <= 0:
            stamp = now()
            sections[name] = {**empty_section('unsupported' if not tool else 'timeout'), 'started_at': stamp, 'finished_at': stamp}
        else:
            sections[name] = collect_section(tool, name, max_rows, min(10, remaining))
    snapshot = {'schema_version': 1, 'kind': 'host_snapshot', 'started_at': started, 'finished_at': now(),
                'host': {'hostname': socket.gethostname(), 'platform': platform.system()},
                'collector': {'name': 'packet_doctor', 'version': __version__, 'powershell': tool,
                              'timeout_seconds': timeout, 'max_rows': max_rows},
                'sections': sections, 'limitations': list(LIMITATIONS)}
    validate_snapshot(snapshot)
    data = (json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(data) > MAX_FILE:
        raise InvestigationError('出力が8 MBを超えました。--max-rowsを減らしてください')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('xb') as stream:
        stream.write(data)
    return {**snapshot_summary(snapshot), 'file': str(out), 'sha256': digest(out), 'limitations': snapshot['limitations']}


def import_snapshot(case_dir, path, role):
    if role not in ('client', 'server', 'other'):
        raise InvestigationError('roleはclient/server/otherで指定してください')
    snapshot, data = load_snapshot(path)
    with case_lock(case_dir):
        root, _, _, analysis = latest(case_dir)
        folder = root / 'attachments' / ('host-' + uuid.uuid4().hex)
        folder.mkdir(parents=True)
        source = folder / 'snapshot.json'
        source.write_bytes(data)
        details = {**snapshot_summary(snapshot), 'role': role, 'analysis_run_id': analysis['run_id'],
                   'source': str(source), 'source_sha256': digest(source), 'snapshot': snapshot,
                   'limitations': list(LIMITATIONS)}
        entry = add_evidence(root, 'host_snapshot', f"端末状態 {snapshot['host']['hostname']} / {role} / {details['status']}",
                             source=source, observed_at=snapshot['started_at'], details=details)
        refresh_report(root)
        return {'evidence_id': entry['id'], 'source': str(source), 'role': role, **snapshot_summary(snapshot), 'limitations': list(LIMITATIONS)}


def complete(snapshot, name):
    section = snapshot['sections'][name]
    return section['status'] == 'ok' and not section['truncated']


def counter_deltas(before, after):
    if not all(complete(s, name) for s in (before, after) for name in ('system', 'adapters', 'counters')):
        return {'status': 'not_comparable', 'reason': 'missing_or_partial_identity_or_counters'}
    boot = [s['sections']['system']['rows'] for s in (before, after)]
    if any(len(rows) != 1 or not rows[0]['boot_time'] for rows in boot):
        return {'status': 'not_comparable', 'reason': 'boot_time_unknown'}
    if timestamp(boot[0][0]['boot_time']) != timestamp(boot[1][0]['boot_time']):
        return {'status': 'not_comparable', 'reason': 'reboot_or_different_host'}
    def indexed(snapshot):
        names = {}
        for adapter in snapshot['sections']['adapters']['rows']:
            names.setdefault(adapter['name'], []).append(adapter['guid'])
        result, unmatched = {}, 0
        for row in snapshot['sections']['counters']['rows']:
            guids = names.get(row['name'], [])
            if len(guids) == 1 and guids[0]:
                result.setdefault(guids[0], []).append(row)
            else:
                unmatched += 1
        return result, unmatched
    a, missing_a = indexed(before)
    b, missing_b = indexed(after)
    rows = []
    for guid in sorted(a.keys() | b.keys()):
        left, right = a.get(guid, []), b.get(guid, [])
        if len(left) != 1 or len(right) != 1:
            rows.append({'guid': guid, 'status': 'not_comparable', 'reason': 'adapter_missing_or_ambiguous'})
            continue
        left, right = left[0], right[0]
        reset = any(left[k] is not None and right[k] is not None and right[k] < left[k] for k in COUNTERS)
        known = any(left[k] is not None and right[k] is not None for k in COUNTERS)
        rows.append({'guid': guid, 'name': right['name'], 'status': 'reset_or_wrap' if reset else 'observed_delta' if known else 'not_comparable',
                     'delta': {k: right[k] - left[k] if not reset and left[k] is not None and right[k] is not None else None for k in COUNTERS}})
    return {'status': 'not_comparable' if not rows else 'partial' if missing_a or missing_b or any(r['status'] == 'not_comparable' for r in rows) else 'compared',
            'unmatched_counter_rows': missing_a + missing_b, 'adapters_total': len(rows), 'adapters': rows[:100],
            'limitation': '同名端末・同一起動時刻・同一NICを前提とした差分です。途中のカウンタ初期化をすべて検出できる保証はありません'}


def compare_snapshots(before_path, after_path):
    before, _ = load_snapshot(before_path)
    after, _ = load_snapshot(after_path)
    result = {'before_host': before['host'], 'after_host': after['host'], 'before_time': before['finished_at'],
              'after_time': after['finished_at'], 'limitations': list(LIMITATIONS)}
    if before['host'] != after['host']:
        return {**result, 'status': 'not_comparable', 'reason': 'host_mismatch'}
    if timestamp(after['started_at']) <= timestamp(before['finished_at']):
        return {**result, 'status': 'not_comparable', 'reason': 'time_order_or_overlap'}
    changes = {}
    for name in SCHEMAS:
        if name == 'counters':
            continue
        if not complete(before, name) or not complete(after, name):
            changes[name] = {'status': 'not_comparable', 'reason': 'unavailable_or_truncated'}
            continue
        sets = [{json.dumps(r, sort_keys=True, ensure_ascii=False) for r in s['sections'][name]['rows']} for s in (before, after)]
        added, removed = sorted(sets[1] - sets[0]), sorted(sets[0] - sets[1])
        changes[name] = {'status': 'compared', 'added_total': len(added), 'removed_total': len(removed),
                         'added': [json.loads(r) for r in added[:100]], 'removed': [json.loads(r) for r in removed[:100]]}
    return {**result, 'status': 'compared', 'sections': changes, 'counters': counter_deltas(before, after)}
