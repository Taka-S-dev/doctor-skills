"""Explicit, single-host connection diagnostics. Never run by passive analyze."""
from datetime import datetime, timezone
import socket
import ssl
import time

from .models import InvestigationError
from .tls import certificate_validity


def ftp_reply(sock, timeout=5):
    data = bytearray()
    lines = []
    code = None
    deadline = time.monotonic() + timeout
    while len(data) < 65536:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("FTP応答がタイムアウトしました")
        sock.settimeout(remaining)
        byte = sock.recv(1)
        if not byte:
            raise ValueError("FTP応答の途中で接続が終了しました")
        data.extend(byte)
        if data.endswith(b"\r\n"):
            line = bytes(data[len(b"".join(lines)):])
            lines.append(line)
            if len(lines) == 1:
                if len(line) < 5 or not line[:3].isdigit() or line[3:4] not in (b" ", b"-"):
                    raise ValueError("FTP応答形式ではありません")
                code = line[:3]
                if line[3:4] == b" ":
                    return int(code)
            elif line.startswith(code + b" "):
                return int(code)
    raise ValueError("FTP応答が上限を超えました")


def probe(host, port, tls_mode="none", timeout=5, server_name=None, cafile=None):
    if not host or any(c in host for c in "\r\n\0") or not 1 <= port <= 65535:
        raise InvestigationError("接続先ホストと1〜65535のポートを指定してください")
    if not 0 < timeout <= 30 or tls_mode not in ("none", "direct", "ftp-starttls"):
        raise InvestigationError("timeoutは0超〜30秒、tlsはnone/direct/ftp-starttlsです")
    try:
        context = ssl.create_default_context(cafile=cafile) if tls_mode != "none" else None
    except (OSError, ValueError) as exc:
        raise InvestigationError(f"TLSの信頼CA設定を読み込めません: {exc}") from exc
    result = {"host": host, "port": port, "tls_mode": tls_mode, "server_name": server_name or host,
              "checked_at": datetime.now(timezone.utc).isoformat(), "steps": [], "findings": [],
              "limitations": ["この実行時点・実行端末からの確認です。過去の障害や別経路を証明しません",
                              "DNS解決はOSのリゾルバーを使用し、その処理時間はOS設定に依存します",
                              "TLSの成功はアプリケーションのログイン/転送成功や証明書の失効確認を意味しません"]}

    def finding(code, title, next_check):
        result["findings"].append({"code": code, "title": title, "next_check": next_check})

    started = time.monotonic()
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        result["steps"].append({"stage": "dns", "status": "failed", "error": str(exc)})
        finding("dns_resolution_failed", "実行端末で接続先名を解決できません", "接続先名、DNS設定、VPN/社内DNSへの到達性を確認する")
        result["status"] = "failed"
        return result
    # Bound attempts; report omitted addresses explicitly rather than scanning.
    unique = []
    for address in addresses:
        if (address[0], address[4]) not in [(a[0], a[4]) for a in unique]:
            unique.append(address)
    result["steps"].append({"stage": "dns", "status": "resolved", "elapsed_ms": (time.monotonic() - started) * 1000,
                            "addresses": [a[4][0] for a in unique]})
    result["omitted_addresses"] = [a[4][0] for a in unique[4:]]
    sock = None
    for family, kind, protocol, _, address in unique[:4]:
        candidate = socket.socket(family, kind, protocol)
        candidate.settimeout(timeout)
        started = time.monotonic()
        try:
            candidate.connect(address)
            sock = candidate
            result["steps"].append({"stage": "tcp", "status": "connected", "address": address[0],
                                    "elapsed_ms": (time.monotonic() - started) * 1000})
            break
        except OSError as exc:
            candidate.close()
            result["steps"].append({"stage": "tcp", "status": "failed", "address": address[0],
                                    "error": str(exc), "errno": exc.errno})
    if sock is None:
        finding("tcp_connect_failed", "確認した宛先でTCP接続が成立しませんでした", "待受、経路、FW拒否ログを確認する。タイムアウトだけでFW遮断と断定しない")
        result["status"] = "failed"
        return result
    try:
        if tls_mode == "none":
            result["status"] = "tcp_connected"
            return result
        if tls_mode == "ftp-starttls":
            greeting = ftp_reply(sock, timeout)
            if greeting == 120:
                greeting = ftp_reply(sock, timeout)
            if greeting != 220:
                raise ValueError(f"FTP greeting code={greeting}。TLS開始前に停止しました")
            sock.sendall(b"AUTH TLS\r\n")
            code = ftp_reply(sock, timeout)
            result["steps"].append({"stage": "ftp_auth_tls", "response_code": code})
            if code != 234:
                raise ValueError(f"FTP AUTH TLSが許可されませんでした: {code}")
        sock.settimeout(timeout)
        started = time.monotonic()
        sock = context.wrap_socket(sock, server_hostname=server_name or host)
        result["steps"].append({"stage": "tls", "status": "verified", "version": sock.version(),
                                "cipher": sock.cipher(), "elapsed_ms": (time.monotonic() - started) * 1000})
        result["certificate"] = certificate_validity(sock.getpeercert(binary_form=True), time.time_ns())
        result["status"] = "tls_verified"
    except ssl.SSLCertVerificationError as exc:
        result["steps"].append({"stage": "tls", "status": "verification_failed",
                                "verify_code": exc.verify_code, "verify_message": exc.verify_message})
        label = {10: "証明書の期限切れ", 9: "証明書の有効開始前", 62: "接続先名と証明書の名前の不一致"}.get(exc.verify_code, "証明書の検証失敗")
        finding("certificate_verify_failed", label + "でTLS接続が失敗しました",
                "検証エラー、端末時計、提示チェーン、信頼CA、接続先名を確認する")
        result["status"] = "failed"
    except (OSError, ValueError) as exc:
        result["steps"].append({"stage": "tls_or_starttls", "status": "failed", "error": str(exc)})
        finding("tls_negotiation_failed", "TLSまたはSTARTTLSの開始に失敗しました", "TLS方式・ポート・対応バージョンと相手のログを確認する")
        result["status"] = "failed"
    finally:
        sock.close()
    return result
