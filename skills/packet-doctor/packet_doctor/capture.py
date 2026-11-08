"""Bounded pcap/pcapng reader and TShark adapter.

TShark is the primary backend. The builtin decoder is the zero-install fallback for
common link types and unfragmented IPv4/IPv6; unsupported traffic is flagged, never guessed.
"""
from decimal import Decimal
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from .models import InvestigationError, Packet, digest
from .network import decode_frame

MAX_RECORD = 16 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_PACKETS = 500_000


def find_tool(name, explicit=None):
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file():
            return str(candidate.resolve())
        raise InvestigationError(f"ツールが見つかりません: {explicit}", "tool_missing")
    found = shutil.which(name)
    if found:
        return found
    product = "Nmap" if name == "nmap" else "Wireshark"
    for base in (f"C:/Program Files/{product}", f"C:/Program Files (x86)/{product}"):
        path = Path(base) / (name + ".exe")
        if path.is_file():
            return str(path)
    return None


def run_tool(args, timeout=120):
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise InvestigationError("ツール実行がタイムアウトしました", "timeout") from exc
    if result.returncode:
        raise InvestigationError(result.stderr.strip() or "ツール実行失敗", "tool_failed")
    return result.stdout


def exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise InvestigationError("キャプチャが途中で切れています", "invalid_capture")
    return data


def options(data, endian):
    offset = 0
    while offset + 4 <= len(data):
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + size > len(data):
            raise InvestigationError("pcapngオプションが不正です", "invalid_capture")
        yield code, data[offset:offset + size]
        offset += (size + 3) & ~3


def records(path, warnings):
    with Path(path).open("rb") as stream:
        magic = exact(stream, 4)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
                   b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
        if magic in formats:
            endian, scale = formats[magic]
            header = exact(stream, 20)
            major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header)
            if (major, minor) != (2, 4):
                raise InvestigationError("非対応pcapバージョンです", "unsupported_capture")
            while True:
                header = stream.read(16)
                if not header:
                    return
                if len(header) != 16:
                    raise InvestigationError("pcapレコードが不完全です", "invalid_capture")
                seconds, fraction, size, original = struct.unpack(endian + "IIII", header)
                if size > MAX_RECORD or size > snaplen or size > original:
                    raise InvestigationError("pcap長さが不正または上限超過です", "invalid_capture")
                if fraction * scale >= 1_000_000_000:
                    raise InvestigationError("pcap時刻が不正です", "invalid_capture")
                if size < original:
                    warnings.add("パケットの切り詰めを検出しました")
                yield seconds * 1_000_000_000 + fraction * scale, link & 0xffff, exact(stream, size), "0", original
        elif magic == b"\x0a\x0d\x0d\x0a":
            stream.seek(0)
            endian, interfaces, section = None, [], -1
            while True:
                head = stream.read(8)
                if not head:
                    return
                if len(head) != 8:
                    raise InvestigationError("pcapngブロックが不完全です", "invalid_capture")
                if head[:4] == magic:
                    bom = exact(stream, 4)
                    endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
                    if not endian:
                        raise InvestigationError("pcapngバイト順が不正です", "invalid_capture")
                    size = struct.unpack(endian + "I", head[4:])[0]
                    if not 28 <= size <= MAX_RECORD or size % 4:
                        raise InvestigationError("pcapngセクション長が不正です", "invalid_capture")
                    data = bom + exact(stream, size - 12)
                    interfaces, section = [], section + 1
                    kind = 0x0A0D0D0A
                else:
                    if endian is None:
                        raise InvestigationError("pcapngセクションがありません", "invalid_capture")
                    kind, size = struct.unpack(endian + "II", head)
                    if not 12 <= size <= MAX_RECORD or size % 4:
                        raise InvestigationError("pcapngブロック長が不正です", "invalid_capture")
                    data = exact(stream, size - 8)
                if struct.unpack(endian + "I", data[-4:])[0] != size:
                    raise InvestigationError("pcapng長さが一致しません", "invalid_capture")
                body = data[:-4]
                if kind == 1:
                    if len(body) < 8:
                        raise InvestigationError("pcapngインターフェースが不完全です", "invalid_capture")
                    link, _, snaplen = struct.unpack_from(endian + "HHI", body)
                    resolution, offset_seconds = 1_000_000, 0
                    for code, value in options(body[8:], endian):
                        if code == 9 and len(value) == 1:
                            n = value[0]
                            resolution = 2 ** (n & 127) if n & 128 else 10 ** n
                        if code == 14 and len(value) == 8:
                            offset_seconds = struct.unpack(endian + "q", value)[0]
                    interfaces.append((link, resolution, offset_seconds))
                elif kind == 6:
                    if len(body) < 20:
                        raise InvestigationError("pcapngパケットが不完全です", "invalid_capture")
                    index, high, low, size, original = struct.unpack_from(endian + "IIIII", body)
                    if index >= len(interfaces) or size > original or 20 + size > len(body):
                        raise InvestigationError("pcapngパケット情報が不正です", "invalid_capture")
                    link, resolution, offset_seconds = interfaces[index]
                    ticks = (high << 32) | low
                    ns, remainder = divmod(ticks * 1_000_000_000, resolution)
                    if remainder:
                        warnings.add("ナノ秒未満の時刻精度は切り捨てています")
                    if size < original:
                        warnings.add("パケットの切り詰めを検出しました")
                    yield ns + offset_seconds * 1_000_000_000, link, body[20:20 + size], f"{section}:{index}", original
                elif kind in (2, 3):
                    raise InvestigationError("旧Packet Block/Simple Packet Blockはtsharkで解析してください", "unsupported_capture")
        else:
            raise InvestigationError("pcap/pcapng形式ではありません", "invalid_capture")


def read_frame(path, frame):
    """Return the captured bytes of one frame number, or None."""
    for number, (_, _, data, _, _) in enumerate(records(path, set()), 1):
        if number == frame:
            return data
    return None


def interface_statistics(path):
    """Sum pcapng Interface Statistics Blocks; None means the file carries no counters."""
    totals = {"received": 0, "dropped_by_interface": 0, "dropped_by_os": 0, "blocks": 0}
    section_magic = b"\x0a\x0d\x0d\x0a"
    with Path(path).open("rb") as stream:
        if stream.read(4) != section_magic:
            return None
        stream.seek(0)
        endian = None
        while True:
            head = stream.read(8)
            if len(head) != 8:
                break
            if head[:4] == section_magic:
                endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(stream.read(4))
                if endian is None:
                    return None
                stream.seek(struct.unpack(endian + "I", head[4:])[0] - 12, 1)
                continue
            if endian is None:
                return None
            kind, size = struct.unpack(endian + "II", head)
            if size < 12 or size > MAX_RECORD:
                return None
            if kind != 5:
                stream.seek(size - 8, 1)
                continue
            body = stream.read(size - 8)[:-4]
            totals["blocks"] += 1
            if len(body) > 12:
                for code, value in options(body[12:], endian):
                    if len(value) == 8 and code in (4, 5, 7):
                        name = {4: "received", 5: "dropped_by_interface", 7: "dropped_by_os"}[code]
                        totals[name] += struct.unpack(endian + "Q", value)[0]
    return totals if totals["blocks"] else None


def load_capture(path, backend="auto", tshark=None):
    path = Path(path).resolve()
    if not path.is_file():
        raise InvestigationError(f"ファイルがありません: {path}")
    if path.stat().st_size > MAX_FILE:
        raise InvestigationError("初期版のファイル上限は512 MiBです", "resource_limit")
    sha = digest(path)
    cid = "cap-" + sha[:16]
    warnings = {"取得時のパケット欠落がないことは、この解析だけでは保証できません"}
    network_events = []
    tool = find_tool("tshark", tshark) if backend != "builtin" else None
    if backend == "tshark" and not tool:
        raise InvestigationError("tsharkがありません。Wiresharkを導入するか--backend builtinを指定してください", "tool_missing")
    if tool:
        packets, count, times, command, truncated = load_tshark(path, cid, tool, warnings, network_events)
        actual_backend = "tshark"
        version = run_tool([tool, "--version"], timeout=10).splitlines()[0]
    else:
        packets, times, count, truncated = [], [], 0, 0
        for count, (ns, link, data, interface, original) in enumerate(records(path, warnings), 1):
            if count > MAX_PACKETS:
                raise InvestigationError("初期版の上限は1ファイル50万パケットです", "resource_limit")
            times.append(ns)
            truncated += len(data) < original
            packet, event = decode_frame(data, link, cid, count, ns, interface, warnings)
            if packet:
                packets.append(packet)
            if event:
                network_events.append(event)
        actual_backend, command, version = "builtin", None, "builtin-v2"
        warnings.add("内蔵解析: 主要リンク種別・非断片IPのTCP/DNS/ICMP/ARP。チェックサム検証は未実施です")
    reversed_times = sum(a > b for a, b in zip(times, times[1:]))
    if reversed_times:
        warnings.add("取得順で時刻の逆転があります。解析では時刻順に並べます")
    if len({p.interface for p in packets}) > 1:
        warnings.add("複数インターフェースを検出。重複観測の可能性があります")
    meta = {"id": cid, "path": str(path), "sha256": sha, "backend": actual_backend,
            "tool_version": version, "command": command, "packet_count": count,
            "tcp_packet_count": len(packets), "start_ns": min(times) if times else None,
            "end_ns": max(times) if times else None, "truncated_frames": truncated,
            "time_reversals": reversed_times, "interface_statistics": interface_statistics(path),
            "warnings": sorted(warnings), "network_events": network_events}
    return packets, meta


TSHARK_FLAGS = ("retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order", "duplicate_ack",
                "lost_segment", "ack_lost_segment", "keep_alive", "keep_alive_ack", "zero_window", "zero_window_probe",
                "window_full")
TSHARK_FIELDS = ["frame.number", "frame.time_epoch", "frame.interface_id", "frame.cap_len", "frame.len",
                 "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.ttl", "ipv6.hlim", "ip.id",
                 "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.window_size_value",
                 "tcp.len", "tcp.payload", "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm",
                 "tcp.analysis.ack_rtt", "udp.srcport", "udp.dstport",
                 "dns.id", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.qry.type",
                 "dns.flags.truncated", "dns.a", "dns.aaaa", "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code",
                 "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.src.hw_mac"
                 ] + [f"tcp.analysis.{flag}" for flag in TSHARK_FLAGS]


def truthy(value):
    """TShark prints booleans as 1/0 or True/False depending on its version."""
    return value.strip().lower() in ("1", "true")


def number(value):
    return int(value, 16) if value.startswith("0x") else int(value)


def first(value):
    return value.split(",")[0]


def tshark_network_event(row, cid, ns, warnings):
    frame = row["frame.number"]
    src = row["ip.src"] or row["ipv6.src"]
    dst = row["ip.dst"] or row["ipv6.dst"]
    event = {"capture_id": cid, "frame": int(frame), "time_ns": ns, "src": first(src), "dst": first(dst),
             "sport": None, "dport": None, "id": f"{cid}:frame:{frame}", "filter": f"frame.number == {frame}",
             "interface": row["frame.interface_id"] or "0"}
    if row["arp.opcode"]:
        event.update(kind="arp", opcode=int(row["arp.opcode"]), sender_mac=row["arp.src.hw_mac"],
                     src=row["arp.src.proto_ipv4"], dst=row["arp.dst.proto_ipv4"])
        return event
    if row["dns.id"]:
        names = ("dns.id", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.qry.type")
        if any("," in row[name] for name in names):
            warnings.add("複数DNSメッセージ/質問を含むフレームのDNS診断は省略しました")
            return None
        answers = [a for a in (row["dns.a"] + "," + row["dns.aaaa"]).split(",") if a]
        event.update(kind="dns", transaction_id=number(row["dns.id"]), response=truthy(row["dns.flags.response"]),
                     rcode=int(row["dns.flags.rcode"] or "0"), name=row["dns.qry.name"].lower(),
                     qtype=int(row["dns.qry.type"] or "0"), answers=answers, truncated=truthy(row["dns.flags.truncated"]),
                     sport=int(row["udp.srcport"] or row["tcp.srcport"] or 0),
                     dport=int(row["udp.dstport"] or row["tcp.dstport"] or 0))
        return event
    version, kind_name, code_name = (6, "icmpv6.type", "icmpv6.code") if row["icmpv6.type"] else (4, "icmp.type", "icmp.code")
    if not row[kind_name]:
        return None
    icmp_type = int(first(row[kind_name]))
    if icmp_type not in ((1, 2, 3) if version == 6 else (3, 11)):
        return None
    event.update(kind="icmp", icmp_version=version, icmp_type=icmp_type, icmp_code=int(first(row[code_name] or "0")))
    if "," in src and "," in dst:
        event.update(quoted_src=src.split(",")[-1], quoted_dst=dst.split(",")[-1])
        sport, dport = row["tcp.srcport"] or row["udp.srcport"], row["tcp.dstport"] or row["udp.dstport"]
        if sport and dport:
            event.update(quoted_sport=int(sport.split(",")[-1]), quoted_dport=int(dport.split(",")[-1]))
    return event


def tshark_packet(row, cid, ns, warnings):
    src = row["ip.src"] or row["ipv6.src"]
    dst = row["ip.dst"] or row["ipv6.dst"]
    if row["icmp.type"] or row["icmpv6.type"] or not row["tcp.srcport"] or not src:
        return None
    names = ("ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags")
    if any("," in row[name] for name in names):
        warnings.add("多重IP/TCPヘッダーを含むフレームは汎用TCP解析から除外しました")
        return None
    payload = bytes.fromhex(row["tcp.payload"].replace(":", ""))
    wire_length = int(row["tcp.len"]) if row["tcp.len"] else len(payload)
    if len(payload) != wire_length:
        warnings.add("切り詰められたパケットはヘッダーのみ解析し、ペイロード解析の対象外にしました")
    ttl = row["ip.ttl"] or row["ipv6.hlim"]
    rtt = row["tcp.analysis.ack_rtt"]
    return Packet(cid, int(row["frame.number"]), ns, src, dst, int(row["tcp.srcport"]), int(row["tcp.dstport"]),
                  int(row["tcp.seq_raw"]), int(row["tcp.ack_raw"]), int(row["tcp.flags"], 16),
                  int(row["tcp.window_size_value"] or "0"), payload, row["frame.interface_id"] or "0",
                  ttl=int(first(ttl)) if ttl else None, ip_id=number(first(row["ip.id"])) if row["ip.id"] else None,
                  tcp_len=None if len(payload) == wire_length else wire_length,
                  mss=int(first(row["tcp.options.mss_val"])) if row["tcp.options.mss_val"] else None,
                  wscale=int(first(row["tcp.options.wscale.shift"])) if row["tcp.options.wscale.shift"] else None,
                  sack_permitted=bool(row["tcp.options.sack_perm"]),
                  analysis=tuple(f for f in TSHARK_FLAGS if row[f"tcp.analysis.{f}"]), analyzed=True,
                  rtt_ns=int(Decimal(first(rtt)) * 1_000_000_000) if rtt else None)


def load_tshark(path, cid, tool, warnings, network_events=None):
    args = [tool, "-n", "-r", str(path), "-T", "fields", "-E", "occurrence=a"]
    for field in TSHARK_FIELDS:
        args.extend(["-e", field])
    packets, times, count, truncated = [], [], 0, 0
    timeout = min(120 + Path(path).stat().st_size // (512 * 1024), 1800)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(args, stdout=output, stderr=errors, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise InvestigationError("tsharkがタイムアウトしました", "timeout") from exc
        errors.seek(0)
        message = errors.read(8192).decode("utf-8", "replace").strip()
        if result.returncode:
            raise InvestigationError(message or "tshark解析失敗", "tool_failed")
        if message:
            warnings.add("tshark: " + message)
        output.seek(0)
        for line in output:
            parts = line.decode("utf-8", "replace").rstrip("\r\n").split("\t")
            count += 1
            if count > MAX_PACKETS:
                raise InvestigationError("初期版の上限は1ファイル50万パケットです", "resource_limit")
            if len(parts) != len(TSHARK_FIELDS):
                raise InvestigationError("tshark出力形式が不正です", "tool_failed")
            row = dict(zip(TSHARK_FIELDS, parts))
            ns = int(Decimal(row["frame.time_epoch"]) * 1_000_000_000)
            times.append(ns)
            if row["frame.cap_len"] and row["frame.len"] and int(row["frame.cap_len"]) < int(row["frame.len"]):
                warnings.add("パケットの切り詰めを検出しました")
                truncated += 1
            if network_events is not None:
                event = tshark_network_event(row, cid, ns, warnings)
                if event:
                    network_events.append(event)
            packet = tshark_packet(row, cid, ns, warnings)
            if packet:
                packets.append(packet)
    return packets, count, times, args, truncated
