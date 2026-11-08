"""Bounded read-only HTTP/FTP transfers; credentials stay in process memory."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
from urllib.parse import urlsplit, unquote
import uuid

from .capture import find_tool
from .external import add_evidence, external_evidence
from .investigation import case_lock, latest, refresh_report
from .models import InvestigationError, digest, write_json

SCHEMES = {'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990}
TIMES = ('time_namelookup', 'time_connect', 'time_appconnect', 'time_pretransfer', 'time_starttransfer', 'time_total')
NUMBERS = (*TIMES, 'size_download', 'response_code', 'remote_port', 'ssl_verify_result')
WRITE_OUT = '{' + ','.join('"' + key + '":"%{' + key + '}"' for key in NUMBERS) + ',"remote_ip":"%{remote_ip}"}'
ERRORS = {5: 'proxy_resolution_failed', 6: 'dns_failed', 7: 'connect_failed', 9: 'access_denied',
          18: 'partial_transfer', 22: 'http_error', 28: 'timeout', 35: 'tls_handshake_failed',
          51: 'certificate_verification_failed', 60: 'certificate_verification_failed',
          63: 'size_limit', 64: 'tls_required_failed', 67: 'authentication_rejected',
          77: 'ca_file_error', 78: 'resource_not_found'}
LIMITATIONS = [
    'この確認は指定したURLの取得結果です。業務全体の復旧や内容の正しさは保証しません',
    'リダイレクトは追跡せず、プロキシ・ユーザーのcurl設定を使用しません。普段のアプリと経路・条件が異なる場合があります',
    'FTPはパッシブ方式です。PASVの通知IPは使わず制御接続と同じIPにデータ接続します',
    '時間はcurlが報告した開始からの累積値です。FTPでは制御とデータ接続があるため、単純な差分を段階別時間と断定しません',
    '取得内容・認証情報・URLのパスとクエリ・詳細エラーテキストは保存しません',
]


def now():
    return datetime.now(timezone.utc).isoformat()


def tool_info(explicit=None):
    tool = find_tool('curl', explicit)
    if not tool:
        raise InvestigationError('curlが見つかりません。インストールするか--curlで実行ファイルを指定してください')
    try:
        result = subprocess.run([tool, '-q', '--version'], capture_output=True, timeout=5,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InvestigationError('curlのバージョンを確認できません') from exc
    output = result.stdout.decode('utf-8', errors='replace')
    version = re.match(r'curl (\d+)\.(\d+)\.(\d+)', output)
    protocols = re.search(r'^Protocols:\s*(.*)$', output, re.M)
    if result.returncode or not version or not protocols:
        raise InvestigationError('curlのバージョン・対応プロトコルを確認できません')
    if tuple(map(int, version.groups())) < (8, 4, 0):
        raise InvestigationError('取得サイズの制限を保証するためcurl 8.4.0以降が必要です')
    return {'path': tool, 'version': '.'.join(version.groups()), 'protocols': protocols[1].split()}


def validate_url(url, starttls):
    if len(url) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in url) or '\\' in url:
        raise InvestigationError('URLに制御文字を含めず、8192文字以下で指定してください')
    try:
        parsed = urlsplit(url)
        port = parsed.port or SCHEMES.get(parsed.scheme)
    except ValueError as exc:
        raise InvestigationError('URLが不正です') from exc
    if parsed.scheme not in SCHEMES or not parsed.hostname or not port or parsed.port == 0:
        raise InvestigationError('HTTP/HTTPS/FTP/FTPSのURLを指定してください')
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise InvestigationError('URL内の認証情報・フラグメントは使えません。認証情報は環境変数で渡してください')
    if any(c in unquote(url) for c in '\r\n\0'):
        raise InvestigationError('URLにエンコードされた制御文字は使えません')
    if starttls and parsed.scheme != 'ftp':
        raise InvestigationError('--ftp-starttlsはftp://のURLと組み合わせてください')
    return parsed, port


def credentials(user_env, password_env):
    if bool(user_env) != bool(password_env):
        raise InvestigationError('--username-envと--password-envを両方指定してください')
    if not user_env:
        return None
    user, password = os.environ.get(user_env), os.environ.get(password_env)
    if user is None or password is None or not user or ':' in user:
        raise InvestigationError('認証用環境変数が未設定、またはユーザー名が不正です')
    if any(c in user + password for c in '\r\n\0'):
        raise InvestigationError('認証情報に改行・NULは使えません')
    return user + ':' + password


def config_value(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\t', '\\t') + '"'


def metrics_from_output(output):
    if len(output) > 16384:
        return None
    try:
        raw = json.loads(output)
        metrics = {}
        for key in NUMBERS:
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                return None
            value = float(value)
            if not math.isfinite(value) or value < 0:
                return None
            metrics[key] = value
        address = raw.get('remote_ip', '')
        metrics['remote_ip'] = str(ipaddress.ip_address(address)) if address else None
        return metrics
    except (ValueError, KeyError, TypeError):
        return None


def outcome(code, metrics, scheme):
    if metrics is None:
        return 'incomplete' if code == 0 else ERRORS.get(code, 'execution_failed')
    response = metrics['response_code']
    if code == 0:
        if scheme in ('http', 'https') and 300 <= response < 400:
            return 'redirect_not_followed'
        return 'transfer_completed' if 200 <= response < 300 else 'unexpected_response'
    if scheme in ('http', 'https') and response == 401:
        return 'authentication_required_or_rejected'
    if scheme in ('http', 'https') and response == 403:
        return 'access_denied'
    return ERRORS.get(code, 'transfer_failed')


def check(case_dir, url, observation, timeout=10, max_bytes=65536, starttls=False,
          user_env=None, password_env=None, cafile=None, executable=None):
    parsed, port = validate_url(url, starttls)
    if not observation.strip() or not 1 <= timeout <= 60 or not 1 <= max_bytes <= 1024 * 1024:
        raise InvestigationError('観測位置、1〜60秒の時間制限、1〜1048576バイトの取得上限を指定してください')
    auth = credentials(user_env, password_env)
    ca = Path(cafile).resolve() if cafile else None
    if ca and not ca.is_file():
        raise InvestigationError('CAファイルが見つかりません')
    info = tool_info(executable)
    required = {parsed.scheme} | ({'ftps'} if starttls else set())
    if not required.issubset(info['protocols']):
        raise InvestigationError('このcurlは指定したプロトコルに対応していません')
    request = {'scheme': parsed.scheme, 'host': parsed.hostname, 'port': port,
               'operation': 'retrieve', 'url_sha256': hashlib.sha256(url.encode('utf-8')).hexdigest(),
               'ftp_starttls': starttls, 'credentials_supplied': bool(auth), 'ca_sha256': digest(ca) if ca else None,
               'proxy': 'disabled', 'redirects': 'disabled', 'timeout_seconds': timeout, 'max_bytes': max_bytes}
    config = 'url = ' + config_value(url) + '\n'
    if auth:
        config += 'user = ' + config_value(auth) + '\n'
    env = os.environ.copy()
    for key in (user_env, password_env):
        if key:
            env.pop(key, None)
    # TLS/key logging and CA overrides are outside the recorded request profile.
    for key in ('SSLKEYLOGFILE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR'):
        env.pop(key, None)
    command = [info['path'], '-q', '--silent', '--show-error', '--globoff', '--proto', '=http,https,ftp,ftps',
               '--proxy', '', '--noproxy', '*', '--max-redirs', '0', '--max-time', str(timeout),
               '--connect-timeout', str(min(timeout, 5)), '--max-filesize', str(max_bytes), '--limit-rate', '64K',
               '--ftp-skip-pasv-ip', '--fail', '--output', os.devnull, '--write-out', WRITE_OUT, '--config', '-']
    if starttls or parsed.scheme == 'ftps':
        command.append('--ssl-reqd')
    if ca:
        command.extend(['--cacert', str(ca)])
    with case_lock(case_dir):
        root, _, _, analysis = latest(case_dir)
        folder = root / 'attachments' / ('curl-' + uuid.uuid4().hex)
        folder.mkdir(parents=True)
        execution = {'command': command, 'started_at': now(), 'scanner_identity': socket.gethostname(),
                     'tool': info, 'status': 'running', 'stdin': 'not_saved'}
        write_json(folder / 'execution.json', execution)
        metrics, code = None, None
        try:
            completed = subprocess.run(command, input=config.encode('utf-8'), capture_output=True, env=env,
                                       timeout=timeout + 5, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            code = completed.returncode
            metrics = metrics_from_output(completed.stdout)
            status = outcome(code, metrics, parsed.scheme)
            if code == 35 and b'schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS' in completed.stderr:
                status = 'local_tls_unavailable'
        except subprocess.TimeoutExpired:
            status = 'timeout'
        except OSError:
            status = 'execution_failed'
        except KeyboardInterrupt:
            execution.update(status='interrupted', finished_at=now())
            write_json(folder / 'execution.json', execution)
            raise
        execution.update(status=status, returncode=code, finished_at=now())
        write_json(folder / 'execution.json', execution)
        m = metrics or {}
        tls = parsed.scheme in ('https', 'ftps') or starttls
        stages = {'tcp': 'connected' if m.get('time_connect', 0) > 0 or m.get('response_code', 0) > 0 else 'not_observed',
                  'tls': ('verified' if m.get('time_appconnect', 0) > 0 and m.get('ssl_verify_result') == 0 else 'not_confirmed') if tls else 'not_requested',
                  'transfer': 'completed' if status == 'transfer_completed' else 'not_completed'}
        peer = m.get('remote_ip')
        connections = [c['id'] for c in analysis['connections'] if c['server'] == [peer, port]] if peer else []
        result = {'schema_version': 1, 'kind': 'curl', 'status': status, 'request': request,
                  'observation': observation, 'started_at': execution['started_at'], 'finished_at': execution['finished_at'],
                  'analysis_run_id': analysis['run_id'], 'execution': execution, 'metrics': metrics, 'stages': stages,
                  'correlation': {'relation': 'same_endpoint_only', 'connections': connections[:50], 'connections_total': len(connections)},
                  'limitations': list(LIMITATIONS), 'artifacts': {'execution.json': {'path': str(folder / 'execution.json'), 'sha256': digest(folder / 'execution.json')}}}
        write_json(folder / 'result.json', result)
        entry = add_evidence(root, 'curl', f"curl {parsed.scheme} {parsed.hostname}:{port}: {status} / {observation}",
                             source=folder / 'result.json', observed_at=result['started_at'], details=result)
        refresh_report(root)
        return {'evidence_id': entry['id'], 'status': status, 'stages': stages, 'metrics': metrics,
                'result_file': str(folder / 'result.json'), 'limitations': result['limitations']}


def compare_checks(case_dir, before_id, after_id):
    entries = {e['id']: e for e in external_evidence(case_dir) if e['kind'] == 'curl'}
    if before_id == after_id or before_id not in entries or after_id not in entries:
        raise InvestigationError('異なる2件のcurl根拠IDを指定してください')
    a, b = (entries[i]['details'] for i in (before_id, after_id))
    return {'before': before_id, 'after': after_id, 'before_status': a['status'], 'after_status': b['status'],
            'same_request_profile': a['request'] == b['request'], 'same_observation_label': a['observation'] == b['observation'],
            'before_time': a['started_at'], 'after_time': b['started_at'], 'before_metrics': a['metrics'], 'after_metrics': b['metrics'],
            'selected_transfer_completed_after': b['status'] == 'transfer_completed', 'application_recovery': 'not_verified',
            'limitations': ['認証情報や経路が同じことは保証できません。成功は指定した取得操作についての結果です']}
