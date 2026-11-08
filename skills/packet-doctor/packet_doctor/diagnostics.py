"""Default cross-protocol diagnosis. Independent of user Markdown rules."""
from collections import Counter, defaultdict
import ipaddress
import re
from statistics import mean, pstdev

from .connections import is_one_way
from .stream import provenance, reassemble
from .tls import inspect_tls, name_matches

DNS_CODES = {1: "FORMERR（問い合わせ形式エラー）", 2: "SERVFAIL（DNSサーバー処理失敗）",
             3: "NXDOMAIN（名前が存在しないという応答）", 4: "NOTIMP（未対応）", 5: "REFUSED（問い合わせ拒否）"}
TLS_ALERTS = {40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
              44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
              48: "unknown_ca", 49: "access_denied", 70: "protocol_version", 71: "insufficient_security",
              112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol"}
SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}
MAX_FINDING_EVIDENCE = 20
MAX_FINDING_CONNECTIONS = 50
IDLE_TIMEOUT_MS = 30_000
IDLE_FAILURE_WINDOW_NS = 2_000_000_000
ARP_BEFORE_SYN_NS = 1_000_000_000
SLOW_TURNAROUND_MS = 500


def aggregate(findings):
    """Collapse same-kind findings on the same subject into one bounded finding."""
    groups = {}
    for finding in findings:
        subject = finding.pop("group")
        finding["peer"] = subject[0] if isinstance(subject, tuple) else subject
        groups.setdefault((finding["code"], subject), []).append(finding)
    merged = []
    for group in groups.values():
        finding = group[0]
        refs = list(dict.fromkeys(ref for f in group for ref in f["evidence_ids"]))
        connections = list(dict.fromkeys(c for f in group for c in f["connections"]))
        times = [f["time_ns"] for f in group if f["time_ns"] is not None]
        finding.update(count=len(group), evidence_ids=refs[:MAX_FINDING_EVIDENCE], evidence_total=len(refs),
                       connections=connections[:MAX_FINDING_CONNECTIONS], connections_total=len(connections),
                       time_ns=min(times) if times else None, last_time_ns=max(times) if times else None)
        if len(group) > 1:
            finding["title"] = re.sub(r"^conn-\d+: ", "", finding["title"]) + f"（同種 {len(group)} 件）"
        merged.append(finding)
    merged.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["scope"] != "selected", -f["count"], f["time_ns"] or 0))
    for index, finding in enumerate(merged, 1):
        finding["id"] = f"finding-{index:04d}"
    return merged


def diagnose(connections, network_events, target=None, port=None, measurements=None, protocol=None):
    findings, warnings = [], []
    connection_onsets = {c["id"]: failure_onsets([c]) for c in connections}
    coverage = {name: "not_observed" for name in ("arp", "dns", "icmp", "tcp", "tls", "certificate", "http", "ftp")}

    def add(code, layer, title, refs, next_check, candidates=None, details=None, severity="warning", scope="selected",
            group=None, conn=None, when=None):
        related = [conn["id"]] if conn else []
        if code == "arp_peer_answered":
            observed = [e["time_ns"] for e in network_events if e["id"] in refs]
            related = [c["id"] for c in connections
                       if group in connection_onsets[c["id"]] and any(
                           connection_onsets[c["id"]][group] < ns <= c["packets"][-1].time_ns
                           for ns in observed)]
        if code in ("administratively_prohibited", "icmp_unreachable"):
            for event in network_events:
                if event["id"] not in refs:
                    continue
                quoted = tuple(event.get("quoted_" + k) for k in ("src", "dst", "sport", "dport"))
                matches = [c["id"] for c in connections if None not in quoted
                           and c["packets"][0].time_ns <= event["time_ns"] <= c["packets"][-1].time_ns + 1_000_000_000
                           and any((p.src, p.dst, p.sport, p.dport) == quoted for p in c["packets"])]
                if len(matches) == 1:
                    related.extend(matches)
        findings.append({"id": "", "code": code, "layer": layer, "title": title, "status": "observed", "severity": severity,
                         "evidence_ids": list(dict.fromkeys(refs)), "next_check": next_check, "candidates": candidates or [],
                         "details": details or {}, "scope": scope, "group": group or (tuple(conn["server"]) if conn else None),
                         "connections": related, "time_ns": when})

    diagnose_arp(network_events, target, coverage, add, failure_onsets(connections))
    addresses = diagnose_dns(network_events, target, port, coverage, warnings, add)
    diagnose_icmp(network_events, target, port, coverage, add)

    selected = [c for c in connections if not port or any(port in (p.sport, p.dport) for p in c["packets"])]
    if selected:
        coverage["tcp"] = "observed"
    usual_ttl = sender_ttl_baseline(connections)
    passive, active = [], []
    for conn in selected:
        conn["names"] = sorted(addresses.get(conn["server"][0], ()))
        diagnose_tcp(conn, usual_ttl, add)
        if len({p.interface for p in conn["packets"]}) > 1:
            warnings.append(f"{conn['id']}: 複数インターフェースのためTLS・アプリのストリーム解析を省略しました")
            continue
        diagnose_streams(conn, coverage, warnings, add, passive, active)
    diagnose_ftp_data(connections, passive, active, add)
    diagnose_timing(selected, measurements or [], add)
    diagnose_protocol(protocol, add)
    return {"findings": aggregate(findings), "coverage": coverage, "warnings": list(dict.fromkeys(warnings)),
            "limitations": ["未観測の層は正常という意味ではありません", "パケットだけでFWの具体的な拒否ルールや端末内部のエラーを確定しません"]}


def failure_onsets(connections):
    """Return {peer ip: time after which ARP from it shows it was alive during the failure}."""
    onsets = {}
    for conn in connections:
        tail = silent_peer_tail(conn)
        if conn["start"] and not conn["syn_ack"] and not conn["end"]:
            ip, onset = conn["server"][0], conn["start"]["time_ns"] - ARP_BEFORE_SYN_NS
        elif tail:
            last = [p for p in conn["packets"] if p.src != tail[0].src][-1]
            ip, onset = last.src, last.time_ns
        else:
            continue
        onsets[ip] = min(onset, onsets.get(ip, onset))
    return onsets


def diagnose_arp(events, target, coverage, add, onsets):
    arp = [e for e in events if e["kind"] == "arp"]
    if arp:
        coverage["arp"] = "observed"
    answered, macs = set(), defaultdict(set)
    for e in arp:
        if e["src"] != "0.0.0.0":
            macs[e["src"]].add(e["sender_mac"].lower())
        if e["opcode"] == 2:
            answered.add(e["src"])
    for ip, seen in macs.items():
        if len(seen) > 1 and (target is None or ip == target):
            refs = [e["id"] for e in arp if e["src"] == ip]
            add("arp_duplicate_ip", "L2/ARP", f"{ip} を複数のMACアドレスが名乗っています", refs,
                "IP重複・冗長機器のフェイルオーバー・機器交換の有無を確認し、各MACの実機を特定する",
                ["IPアドレス重複", "冗長構成の切替", "機器交換"], {"macs": sorted(seen)}, group=ip, when=arp[0]["time_ns"])
    for ip, onset in sorted(onsets.items()):
        alive = [e for e in arp if e["src"] == ip and e["time_ns"] > onset]
        if alive and (target is None or ip == target):
            add("arp_peer_answered", "L2/ARP", f"応答が途絶えた時間帯に {ip} からのARPを観測しました", [e["id"] for e in alive],
                "その時点では相手が同じセグメント上で動いていたことを示します。MACが相手機器のものか確認する", severity="info", group=ip, when=alive[0]["time_ns"])
    unanswered = defaultdict(list)
    for e in arp:
        if e["opcode"] == 1 and e["src"] != "0.0.0.0" and e["src"] != e["dst"] and e["dst"] not in answered:
            unanswered[e["dst"]].append(e)
    for ip, group in unanswered.items():
        if len(group) >= 2 and (target is None or ip == target):
            add("arp_no_reply", "L2/ARP", f"{ip} へのARP要求に応答を観測できません（{len(group)} 回）", [e["id"] for e in group],
                "相手の電源・リンク・VLAN・IPアドレス設定を確認する。応答はユニキャストのため取得位置によっては見えない",
                ["相手の停止・未接続", "VLAN/セグメント違い", "応答が取得位置を通らない"], group=ip, when=group[0]["time_ns"])


def diagnose_dns(events, target, port, coverage, warnings, add):
    """Report DNS problems and return {ip: names} learned from successful answers."""
    dns = [e for e in events if e["kind"] == "dns"]
    if dns:
        coverage["dns"] = "observed"
    addresses, resolved_names = defaultdict(set), set()
    for e in dns:
        if e["response"] and not e["rcode"] and e.get("answers"):
            resolved_names.add((e["dst"], e["name"]))
            for address in e["answers"]:
                addresses[address].add(e["name"])

    def scope_of(name):
        related = target is not None and name in addresses.get(target, ())
        return "selected" if related else "capture_context"

    def is_search_suffix(client, name):
        return any(c == client and name != other and name.startswith(other + ".") for c, other in resolved_names)

    queries, responses = defaultdict(list), defaultdict(list)
    for e in dns:
        is_response = e["response"]
        client, server = (e["dst"], e["src"]) if is_response else (e["src"], e["dst"])
        client_port = e.get("dport") if is_response else e.get("sport")
        key = (client, server, client_port, e["transaction_id"], e["name"], e["qtype"])
        (responses if is_response else queries)[key].append(e)
        if is_response and e["rcode"]:
            suffix = e["rcode"] == 3 and is_search_suffix(e["dst"], e["name"])
            add("dns_error", "DNS", f"{e['name']}: {DNS_CODES.get(e['rcode'], 'DNSエラー ' + str(e['rcode']))}", [e["id"]],
                "接続先名の綴り・利用DNS・ゾーン設定を確認。クライアントのエラー時刻と照合する",
                ["名前・DNS設定の問題", "DNSサーバーまたは上流の問題"], {"rcode": e["rcode"], "search_suffix_like": suffix},
                severity="info" if suffix else "warning", scope=scope_of(e["name"]), group=(e["name"], e["rcode"]), when=e["time_ns"])
        if e.get("truncated"):
            add("dns_truncated", "DNS", "DNS応答に切り詰めフラグがあります", [e["id"]], "TCPでの再問い合わせと応答を確認する",
                severity="info", scope=scope_of(e["name"]), group=e["name"], when=e["time_ns"])
    for key, group in queries.items():
        if not any(r["time_ns"] >= group[0]["time_ns"] for r in responses[key]):
            add("dns_no_observed_response", "DNS", f"{group[0]['name']}: 対応するDNS応答を観測できません", [e["id"] for e in group],
                "取得終了時刻・双方向取得を確認し、DNSサーバー側のログと経路を調べる",
                ["応答待ちのまま取得終了", "取得漏れ", "DNS停止・経路障害・遮断"], scope=scope_of(group[0]["name"]),
                group=group[0]["name"], when=group[0]["time_ns"])
    if dns and (target or port):
        warnings.append("DNS所見はキャプチャ全体の参考情報です。指定IP・サービスの障害との関連は、応答のアドレスが一致した場合だけ関連付けます")
    return addresses


def diagnose_icmp(events, target, port, coverage, add):
    for e in events:
        if e["kind"] != "icmp":
            continue
        if target is not None and target not in (e["src"], e["dst"], e.get("quoted_src"), e.get("quoted_dst")):
            continue
        if port and e.get("quoted_dport") is not None and port not in (e.get("quoted_sport"), e.get("quoted_dport")):
            continue
        coverage["icmp"] = "observed"
        version, kind, code = e.get("icmp_version", 4), e["icmp_type"], e["icmp_code"]
        prohibited = kind == 3 and code in (9, 10, 13) if version == 4 else kind == 1 and code in (1, 5, 6)
        details = {"icmp_version": version, "icmp_type": kind, "icmp_code": code, "reporter": e["src"],
                   "quoted_destination": e.get("quoted_dst"), "quoted_port": e.get("quoted_dport")}
        subject = (e.get("quoted_dst"), e.get("quoted_dport"), kind, code)
        if prohibited:
            add("administratively_prohibited", "経路・アクセス制御", "通信が管理上禁止されたというICMP応答を観測しました", [e["id"]],
                "応答元のルーター/FWと対象フローの拒否ログ・適用ルールを照合する", ["FW/ACLによる拒否"], details,
                group=subject, when=e["time_ns"])
            continue
        titles = {(4, 3, 0): "ネットワーク到達不能", (4, 3, 1): "ホスト到達不能", (4, 3, 3): "ポート到達不能",
                  (4, 3, 4): "断片化が必要（MTUを確認）", (4, 11, 0): "TTL超過（経路を確認）", (6, 1, 0): "経路なし",
                  (6, 1, 3): "アドレス到達不能", (6, 1, 4): "ポート到達不能", (6, 2, 0): "パケットが大きすぎる（MTUを確認）",
                  (6, 3, 0): "ホップ数超過（経路を確認）"}
        reason = titles.get((version, kind, code), "ICMP到達不能/時間超過")
        details["reason"] = "port" if "ポート" in reason else "mtu" if "MTU" in reason else "route"
        add("icmp_unreachable", "経路", reason + "の通知を観測しました", [e["id"]],
            "通知に含まれる元の宛先・ポートと、経路・待受・MTU設定を照合する", details=details, group=subject, when=e["time_ns"])


def sender_ttl_baseline(connections):
    counts = defaultdict(Counter)
    for conn in connections:
        for p in conn["packets"]:
            if p.ttl is not None and not p.flags & 4:
                counts[p.src][p.ttl] += 1
    return {ip: seen.most_common(1)[0][0] for ip, seen in counts.items()}


def silent_peer_tail(conn):
    """Return retransmissions at the end of a connection the peer stopped answering."""
    if conn["start"] and not conn["syn_ack"]:
        return []
    tail = []
    for p in reversed(conn["packets"]):
        if tail and p.src != tail[0].src:
            break
        tail.append(p)
    if len(tail) == len(conn["packets"]):
        return []
    repeated = [p for p in tail if p.segment_length and {"retransmission", "fast_retransmission"} & set(p.analysis)]
    return repeated if len(repeated) >= 2 else []


def diagnose_tcp(conn, usual_ttl, add):
    stats = conn["stats"]
    one_way = is_one_way(conn)
    unanswered_tail = silent_peer_tail(conn)
    if conn["start"] and not conn["syn_ack"] and not conn["end"] and not one_way:
        add("tcp_no_reply", "TCP", f"{conn['id']}: 接続要求への応答を観測できません",
            [e["evidence_id"] for e in conn["events"] if e["kind"] in ("syn", "repeated_syn")],
            "相手の待受、両端取得、同じ時刻・送信元・宛先・ポートのFWログを確認する",
            ["経路/FWでの破棄", "相手停止", "取得漏れ", "取得終了が早すぎる"], {"syn_repeats": conn["syn_repeats"]},
            conn=conn, when=conn["start"]["time_ns"])
    end = conn["end"]
    if end and end["kind"] == "rst":
        reset_packet = next(p for p in conn["packets"] if p.evidence_id == end["evidence_id"])
        refused = conn["start"] and not conn["syn_ack"] and end["sender"] == "server"
        details = {"sender": end["sender"], "sender_ip": reset_packet.src, "ttl": end["ttl"], "usual_ttl": usual_ttl.get(reset_packet.src)}
        if refused:
            add("tcp_refused", "TCP", f"{conn['id']}: 接続要求がRSTで拒否されました", [conn["start"]["evidence_id"], end["evidence_id"]],
                "相手のポートの待受状態を確認し、RSTのTTLと相手の通常のTTLを比べてFW等の代理拒否でないか確認する",
                ["待受ポートなし", "待受数の上限", "FW等の能動的拒否"], details, conn=conn, when=end["time_ns"])
        else:
            # A sender giving up after unanswered retransmissions did not get reset by its peer.
            gave_up = bool(unanswered_tail) and unanswered_tail[0].src == reset_packet.src
            details["sender_gave_up_after_retransmissions"] = gave_up
            add("tcp_reset", "TCP", f"{conn['id']}: 接続{'成立後' if conn['established'] else '途中'}に{'サーバー' if end['sender'] == 'server' else 'クライアント'}側からRSTを観測しました",
                [end["evidence_id"]], "RSTの送信元とサーバー/クライアントのログを照合し、直前の通信内容とアクセス制御を確認する",
                ["送信側が応答なしで打ち切り"] if gave_up else ["アプリケーションによる中断", "FW等の能動的切断", "相手の再起動（古い接続への応答）"],
                details, severity="info" if gave_up else "warning", conn=conn, when=end["time_ns"])
        usual = usual_ttl.get(reset_packet.src)
        if usual is not None and reset_packet.ttl is not None and reset_packet.ttl != usual:
            add("tcp_rst_ttl_anomaly", "TCP", f"{conn['id']}: RSTのTTLが相手の通常の値と異なります（{reset_packet.ttl} / 通常 {usual}）",
                [end["evidence_id"]], "相手の手前の機器（FW/IPS/プロキシ）のログを確認し、可能なら相手側でもキャプチャして同じRSTが出ているか比べる",
                ["経路上の機器がRSTを生成", "相手が別のOSスタック/経路でRSTを送信"], details, conn=conn, when=end["time_ns"])
    if conn["syn_ack"] and not conn["established"] and not one_way:
        add("tcp_incomplete_handshake", "TCP", f"{conn['id']}: SYN/ACK後の接続成立を確認できません", [conn["syn_ack"]["evidence_id"]],
            "クライアントまで応答が届いたかと、ACKの戻り経路・取得漏れを確認する", conn=conn, when=conn["syn_ack"]["time_ns"])
    if conn["zero_windows"]:
        add("tcp_zero_window", "TCP", f"{conn['id']}: 受信余力ゼロの通知を観測しました",
            [e["evidence_id"] for e in conn["events"] if e["kind"] == "zero_window"], "通知した側の受信処理・負荷・バッファを確認する",
            ["受信アプリの処理停滞", "受信バッファ不足"], {"zero_window_ms": stats["zero_window_ms"]}, conn=conn, when=conn["events"][0]["time_ns"])
    retransmits = [p for p in conn["packets"] if p.segment_length and {"retransmission", "fast_retransmission", "spurious_retransmission"} & set(p.analysis)]
    if retransmits:
        client, server = stats["client"], stats["server"]
        details = {"client_sent": client["retransmissions"], "server_sent": server["retransmissions"],
                   "rto_like": client["rto_like_retransmissions"] + server["rto_like_retransmissions"],
                   "fast": client["fast_retransmissions"] + server["fast_retransmissions"],
                   "interval_ms": client["retransmit_interval_ms"] or server["retransmit_interval_ms"]}
        add("tcp_repeated_data", "TCP", f"{conn['id']}: 同じデータの再送を観測しました（{len(retransmits)} 回）", [p.evidence_id for p in retransmits],
            "どの方向で起きているか確認し、両端取得で区間を特定する。再送の観測だけで回線ロスと断定しない",
            ["経路上のパケットロス", "相手の受信処理遅延", "ACKの消失"], details, conn=conn, when=retransmits[0].time_ns)
        large = [p for p in retransmits if p.segment_length >= 1200]
        small_ok = any(p.segment_length and p.segment_length < 1200 and p not in retransmits for p in conn["packets"] if p.src == large[0].src) if large else False
        if len(large) >= 3 and len(large) == len(retransmits) and small_ok:
            add("tcp_large_segment_loss", "経路", f"{conn['id']}: 大きなセグメントだけが再送され続けています", [p.evidence_id for p in large],
                "経路のMTUを確認する。DF付きpingで通るサイズを調べ、VPN/トンネル区間やICMP「断片化が必要」の遮断を確認する",
                ["MTUブラックホール", "特定サイズで落ちる機器"], {"largest": max(p.segment_length for p in large)}, conn=conn, when=large[0].time_ns)
    if unanswered_tail and not one_way:
        add("tcp_unanswered_tail", "TCP", f"{conn['id']}: 再送を続けたまま相手の応答が途絶えています", [p.evidence_id for p in unanswered_tail],
            "相手の電源・リンク・プロセス状態と、その時刻の経路機器のログを確認する", ["相手の停止・ケーブル断", "経路断", "FWの状態テーブル切れ"],
            {"sender_ip": unanswered_tail[0].src, "retransmissions_in_tail": len(unanswered_tail)}, conn=conn, when=unanswered_tail[-1].time_ns)
    idle = stats["max_idle"]
    reset_after_idle = idle and end and end["kind"] == "rst" and 0 <= end["time_ns"] - idle["resumed_ns"] <= IDLE_FAILURE_WINDOW_NS
    if idle and idle["ms"] >= IDLE_TIMEOUT_MS and (reset_after_idle or any("retransmission" in p.analysis for p in conn["packets"][-3:])):
        add("tcp_failure_after_idle", "TCP", f"{conn['id']}: {idle['ms'] / 1000:.1f} 秒の無通信の直後に通信が失敗しています", idle["evidence_ids"],
            "経路上のFW/NATの無通信タイムアウト値と、アプリのKeepAlive/ハートビート間隔を比べる",
            ["FW/NATのセッション切れ", "アプリのアイドル切断"], {"idle_ms": idle["ms"]}, conn=conn, when=conn["packets"][-1].time_ns)


def diagnose_streams(conn, coverage, warnings, add, passive, active):
    cid = conn["id"]
    tls_events, any_tls = [], False
    for role in ("client", "server"):
        packets = [p for p in conn["packets"] if ([p.src, p.sport] == conn["client"]) == (role == "client")]
        raw, spans, warning = reassemble(packets)
        if warning and any(p.payload for p in packets):
            warnings.append(f"{cid}/{role}: {warning}")
        events, recognized = inspect_tls(raw, spans, role)
        tls_events.extend(events)
        any_tls |= recognized
        # HTTP status lines are recognized by protocol syntax, not port number.
        if role == "server" and raw.startswith(b"HTTP/"):
            for match in list(re.finditer(rb"(?:^|\r\n)HTTP/1\.[01] ([1-5][0-9]{2})[^\r\n]*\r\n", raw))[:200]:
                coverage["http"] = "observed"
                status = int(match[1])
                if status >= 400:
                    refs, ns = provenance(spans, match.start(), match.end())
                    add("http_error", "HTTP", f"{cid}: HTTP {status}のエラー応答を観測しました", refs,
                        "認証/権限・URL・サーバー/プロキシのログをステータスに応じて確認する", details={"status_code": status},
                        group=(tuple(conn["server"]), status), conn=conn, when=ns)
        ftp = conn["server"][1] in (21, 990) or (role == "server" and re.match(rb"220[^\r\n]*FTP", raw, re.I))
        if ftp and role == "server":
            diagnose_ftp_replies(conn, raw, spans, coverage, add, passive)
        elif ftp:
            diagnose_ftp_commands(conn, raw, spans, active)
    if any_tls:
        diagnose_tls(conn, tls_events, coverage, warnings, add)


def diagnose_ftp_replies(conn, raw, spans, coverage, add, passive):
    cid = conn["id"]
    for match in re.finditer(rb"^([1-5][0-9]{2}) ([^\r\n]*)\r\n", raw[:65536], re.M):
        coverage["ftp"] = "observed"
        status = int(match[1])
        refs, ns = provenance(spans, match.start(), match.end())
        if status >= 400:
            add("ftp_error", "FTP", f"{cid}: FTP {status}のエラー応答を観測しました", refs,
                "530なら認証/ログイン方針、425/426ならデータ接続、550ならパス/権限を確認する", details={"status_code": status},
                group=(tuple(conn["server"]), status), conn=conn, when=ns)
        if status == 227:
            address = re.search(rb"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", match[2])
            if address and all(int(v) <= 255 for v in address.groups()):
                numbers = [int(v) for v in address.groups()]
                announced = ".".join(map(str, numbers[:4]))
                passive.append((conn, conn["client"][0], announced, numbers[4] * 256 + numbers[5], refs, ns))
                if announced != conn["server"][0]:
                    private = ipaddress.ip_address(announced).is_private
                    add("ftp_pasv_address_mismatch", "FTPデータ接続", f"{cid}: PASVの通知先 {announced} が制御接続の相手と異なります", refs,
                        "サーバーのPASVアドレス設定（NAT配下なら外部IPの通知設定）を確認する",
                        ["NAT配下のサーバーが内部アドレスを通知" if private else "別アドレスのデータサーバー/設定誤り"],
                        {"announced": announced, "control_server": conn["server"][0], "announced_is_private": private}, conn=conn, when=ns)
        if status == 229:
            address = re.search(rb"\((.)(?:\1){2}(\d+)\1\)", match[2])
            if address and 1 <= int(address[2]) <= 65535:
                passive.append((conn, conn["client"][0], conn["server"][0], int(address[2]), refs, ns))


def diagnose_ftp_commands(conn, raw, spans, active):
    for match in re.finditer(rb"^PORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\r\n", raw[:65536], re.M | re.I):
        numbers = [int(v) for v in match.groups()]
        if all(v <= 255 for v in numbers):
            refs, ns = provenance(spans, match.start(), match.end())
            active.append((conn, ".".join(map(str, numbers[:4])), numbers[4] * 256 + numbers[5], refs, ns))


def diagnose_tls(conn, tls_events, coverage, warnings, add):
    cid = conn["id"]
    coverage["tls"] = "observed"
    hello = next((e for e in tls_events if e["kind"] == "client_hello"), None)
    if hello and hello.get("sni"):
        conn["names"] = sorted({*conn.get("names", []), hello["sni"]})
    certs = [e for e in tls_events if e["kind"] == "certificate"]
    if not certs:
        add("tls_certificate_unavailable", "TLS", f"{cid}: TLSを観測しましたが証明書の有効期間は確認できません", [r for e in tls_events for r in e["evidence_ids"]],
            "クライアントのTLSエラー、証明書ファイル、または対象を指定したprobeで確認する", ["TLS 1.3の暗号化", "セッション再開", "取得不足"],
            severity="info", conn=conn, when=tls_events[0]["time_ns"] if tls_events else None)
    for event in tls_events:
        if event["kind"] == "alert" and event["description"] != 0:
            name = TLS_ALERTS.get(event["description"], f"alert {event['description']}")
            add("tls_alert", "TLS", f"{cid}: TLS {name}の通知を観測しました", event["evidence_ids"],
                "通知を送った側のTLSログと、証明書の期間・信頼・名前・対応TLS設定を照合する",
                details={"alert": event["description"], "name": name, "level": event["level"]},
                group=(tuple(conn["server"]), event["description"]), conn=conn, when=event["time_ns"])
        if event.get("parse_warning"):
            warnings.append(f"{cid}: {event['parse_warning']}")
        for index, cert in enumerate(event.get("certificates", [])):
            coverage["certificate"] = "observed"
            status = cert["status"]
            title = "期限切れ" if status == "expired" else "有効開始前" if status == "not_yet_valid" else "有効期間内"
            add("certificate_" + status, "証明書", f"{cid}: {event['role']}が提示した証明書[{index}]は取得時刻基準で{title}です", event["evidence_ids"],
                "端末時計とTLS検証ログを確認し、実際の失敗理由と照合する。期間内でも信頼/ホスト名/失効の問題は別途確認する",
                details=cert, severity="info" if status == "within_dates" else "error",
                group=(tuple(conn["server"]), cert["sha256"]), conn=conn, when=event["time_ns"])
            if index == 0 and hello and hello.get("sni") and not name_matches(hello["sni"], cert):
                add("certificate_name_mismatch", "証明書", f"{cid}: 要求した名前 {hello['sni']} が証明書の記載名と一致しません", event["evidence_ids"],
                    "接続先名・サーバーの証明書設定・SNIの振り分けを確認する", ["証明書の入れ違い", "接続先名の誤り", "SNI未対応の仮想ホスト"],
                    {"requested": hello["sni"], "san": cert["san"], "subject_cn": cert["subject_cn"]}, severity="error",
                    group=(tuple(conn["server"]), hello["sni"]), conn=conn, when=event["time_ns"])
            if index == 0 and cert.get("self_issued"):
                add("certificate_self_issued", "証明書", f"{cid}: 自己署名の証明書が提示されています", event["evidence_ids"],
                    "クライアントの信頼ストアにこの証明書が登録されているか確認する", severity="info",
                    group=(tuple(conn["server"]), cert["sha256"]), conn=conn, when=event["time_ns"])
    if hello and not any(e["kind"] == "server_hello" for e in tls_events):
        add("tls_no_server_hello", "TLS", f"{cid}: ClientHello後のServerHelloを観測できません", hello["evidence_ids"],
            "相手のTLS待受方式・プロキシ・TLSログ・取得範囲を確認する", ["TLS方式/バージョンの不一致", "経路上の破棄", "取得不足"],
            conn=conn, when=hello["time_ns"])


def diagnose_ftp_data(connections, passive, active, add):
    for conn, client, server, data_port, refs, ns in passive:
        attempts = [c for c in connections if c["client"][0] == client and c["server"] == [server, data_port]]
        failed = [c for c in attempts if c["start"] and not c["established"]]
        if failed:
            add("ftp_data_connection_failed", "FTPデータ接続", f"{conn['id']}: 通知されたデータ接続先 {server}:{data_port} への接続成立を確認できません",
                refs + [c["start"]["evidence_id"] for c in failed], "PASV/EPSVの通知先、NAT、データ用ポート範囲のFW許可、サーバー待受を確認する",
                ["データ用ポートの遮断", "PASVの通知アドレス不整合", "データ待受なし", "取得不足"], conn=conn, when=ns)
        elif not attempts:
            add("ftp_data_connection_unobserved", "FTPデータ接続", f"{conn['id']}: データ接続先 {server}:{data_port} の接続を観測できません", refs,
                "制御ポートだけの取得フィルターになっていないか、実際に一覧/転送操作を行ったか確認する", severity="info", conn=conn, when=ns)
    for conn, client, data_port, refs, ns in active:
        attempts = [c for c in connections if c["server"] == [client, data_port]]
        if attempts and not any(c["established"] for c in attempts):
            add("ftp_data_connection_failed", "FTPデータ接続", f"{conn['id']}: アクティブモードのデータ接続 {client}:{data_port} の成立を確認できません",
                refs + [c["start"]["evidence_id"] for c in attempts if c["start"]], "クライアント側のFW/NATの着信許可を確認し、パッシブモードへの変更を検討する",
                ["クライアント側FW/NATが着信を遮断", "通知アドレスの誤り"], conn=conn, when=ns)
        elif not attempts:
            add("ftp_data_connection_unobserved", "FTPデータ接続", f"{conn['id']}: アクティブモードのデータ接続 {client}:{data_port} を観測できません", refs,
                "取得フィルターと実際の転送操作を確認する", severity="info", conn=conn, when=ns)


def doubling(intervals):
    return len(intervals) >= 2 and all(1.6 <= b / a <= 2.4 for a, b in zip(intervals, intervals[1:]) if a > 0)


def retry_pattern(intervals):
    """Name an OS-like retry schedule. Recent Linux repeats at a fixed interval before doubling."""
    if len(intervals) < 2:
        return None
    if doubling(intervals):
        return "doubling"
    ratios = [b / a for a, b in zip(intervals, intervals[1:]) if a > 0]
    if ratios and all(0.8 <= r <= 2.4 for r in ratios):
        return "fixed_then_doubling" if any(r >= 1.6 for r in ratios) else "fixed_interval"
    return None


def diagnose_timing(selected, measurements, add):
    """Timing signatures. Each is a candidate explanation, not a conclusion."""
    for conn in selected:
        stats = conn["stats"]
        intervals = stats["syn_retry_interval_ms"]
        pattern = retry_pattern(intervals)
        if conn["start"] and pattern:
            add("tcp_syn_retry_pattern", "タイミング", f"{conn['id']}: 接続要求がOSの再送に似た間隔で繰り返されています", [e["evidence_id"] for e in conn["events"] if e["kind"] in ("syn", "repeated_syn")],
                "同じ接続の再送です。アプリの再接続設定と混同せず、なぜ応答がないかを調べる", ["OSのTCP再送"], {"interval_ms": intervals, "pattern": pattern},
                severity="info", conn=conn, when=conn["start"]["time_ns"])
        for side in ("client", "server"):
            chain = stats[side]["retransmit_interval_ms"]
            if doubling(chain):
                add("tcp_rto_backoff", "タイミング", f"{conn['id']}: {side}側の再送間隔が倍々に伸びています（RTO）", [],
                    "ACKが届いていない状態が続いています。相手の到達性と経路を確認する", ["経路断・相手の停止", "連続したパケットロス"], {"interval_ms": chain, "side": side},
                    severity="info", conn=conn, when=stats["last_ns"])
        turnaround, rtt = stats["application_turnaround"], stats["rtt"]
        if turnaround and turnaround["max_ms"] >= SLOW_TURNAROUND_MS and (rtt is None or turnaround["max_ms"] >= 5 * rtt["median_ms"]):
            add("app_response_slow", "アプリ応答", f"{conn['id']}: 要求の後、サーバーの応答まで {turnaround['max_ms']:.1f} ms かかっています", turnaround["evidence_ids"],
                "TCPのACKが早く返っているか確認し、サーバーの処理ログ・負荷と同じ時刻で比較する",
                ["サーバー側アプリの処理待ち", "サーバーの負荷・バックエンド待ち"], {**turnaround, "rtt_median_ms": rtt["median_ms"] if rtt else None}, conn=conn, when=stats["first_ns"])
        delayed = stats["delayed_ack"]
        if delayed and delayed["count"] >= 3:
            add("delayed_ack_pattern", "タイミング", f"{conn['id']}: 約 {delayed['median_ms']:.0f} ms の遅延ACKが繰り返されています", [],
                "小さな書き込みを分けて送るアプリなら、TCP_NODELAYや送信のまとめ方を確認する", ["NagleとDelayed ACKの相互作用"], delayed, severity="info", conn=conn, when=stats["first_ns"])
    gaps = [m for m in measurements if m["name"] in ("observed_gap_before_next_connect_ms", "observed_silence_before_next_connect_ms")]
    values = [m["value_ms"] for m in gaps]
    if len(values) >= 3 and mean(values) > 0 and pstdev(values) / mean(values) < 0.05:
        add("reconnect_interval_regular", "タイミング", f"再接続までの観測間隔がほぼ一定です（約 {mean(values):.0f} ms、{len(values)} 回）",
            [ref for m in gaps for ref in m["evidence_ids"]], "固定のリトライ設定が候補です。設定値と機器ログの再接続開始時刻を照合する",
            ["アプリの固定リトライ間隔"], {"mean_ms": round(mean(values), 3), "samples": len(values)}, group="reconnect")


def diagnose_protocol(protocol, add):
    if not protocol:
        return
    labels = {"observed_late": ("protocol_response_late", "warning", "指定時間を超えた応答", ["機器の処理遅延", "経路の再送による遅延"]),
              "observed_error": ("protocol_error_response", "warning", "エラー応答", ["要求内容・機器状態の問題"]),
              "unobserved": ("protocol_response_unobserved", "info", "応答を観測できない要求", ["取得終了", "機器の無応答", "取得漏れ"])}
    for check in protocol["checks"]:
        if check["status"] in labels:
            code, severity, label, candidates = labels[check["status"]]
            add(code, "独自プロトコル", f"{check['connection_id']}: {protocol['name']}の{label}（コマンド {check['command']}）", check["evidence_ids"],
                "機器ログの処理時刻と照合し、同じ時間帯のTCP再送の有無を確認する", candidates,
                {"command": check["command"], "elapsed_ms": check["elapsed_ms"], "limit_ms": check["limit_ms"], "spec": check["spec_reference"]},
                severity=severity, group=(check["connection_id"], check["command"], check["status"]), when=check["time_ns"])
