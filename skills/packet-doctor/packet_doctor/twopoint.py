"""Match the same TCP traffic seen at two capture points to locate where it changes.

Packets are identified by direction, sequence, acknowledgment, flags, length and content so that address and
port translation do not break matching. Clock offset is estimated from the traffic itself.
"""
from collections import defaultdict
from hashlib import sha256
from statistics import median

from .capture import load_capture
from .connections import analyze_connections

MAX_FLOWS, MAX_EVIDENCE = 50, 10


def packet_key(p):
    return (p.seq, p.ack, p.flags, p.segment_length, sha256(p.payload).digest())


def usable(conn):
    return [p for p in conn["packets"] if "captured_duplicate" not in p.analysis]


def direction_key(conn, packet):
    direction = "client_to_server" if [packet.src, packet.sport] == conn["client"] else "server_to_client"
    return direction, packet_key(packet)


def packet_groups(conn):
    groups = defaultdict(list)
    for packet in usable(conn):
        if len(packet.payload) == packet.segment_length:
            groups[direction_key(conn, packet)].append(packet)
    return groups


def match_flows(near_client, near_server):
    """Require mutually unique best matches with at least two distinct packets.

    Direction and content survive ordinary NAT; endpoints are deliberately excluded.
    Repeated SYNs do not add votes. Ties and many-to-one assignments remain unmatched.
    """
    index = defaultdict(set)
    for number, conn in enumerate(near_server):
        for key in packet_groups(conn):
            index[key].add(number)
    scores, reverse = {}, defaultdict(dict)
    for i, conn in enumerate(near_client):
        votes = defaultdict(int)
        for key in packet_groups(conn):
            for j in index.get(key, ()):
                votes[j] += 1
        scores[i] = {j: score for j, score in votes.items() if score >= 2}
        for j, score in scores[i].items():
            reverse[j][i] = score

    def unique_best(votes):
        if not votes:
            return None
        best = max(votes.values())
        winners = [number for number, score in votes.items() if score == best]
        return winners[0] if len(winners) == 1 else None

    pairs = []
    for i, votes in scores.items():
        j = unique_best(votes)
        if j is not None and unique_best(reverse[j]) == i:
            pairs.append((near_client[i], near_server[j]))
    return pairs


def compare_flow(a, b):
    """Pair only unique occurrences; repeats seen at both points cannot be told apart.

    Repeats seen at one point and never at the other are not ambiguous: none of them was observed there.
    """
    groups_a, groups_b = packet_groups(a), packet_groups(b)
    incomplete = {direction_key(conn, p)[:1] + direction_key(conn, p)[1][:-1]
                  for conn in (a, b) for p in usable(conn) if len(p.payload) != p.segment_length}
    contents = defaultdict(set)
    for key in (*groups_a, *groups_b):
        contents[key[:1] + key[1][:-1]].add(key[1][-1])
    incomplete.update(key for key, hashes in contents.items() if len(hashes) > 1)
    matched = {"client_to_server": [], "server_to_client": []}
    only_a = {"client_to_server": [], "server_to_client": []}
    only_b = {"client_to_server": [], "server_to_client": []}
    for key in dict.fromkeys([*groups_a, *groups_b]):
        if key[:1] + key[1][:-1] in incomplete:
            continue
        left, right = groups_a.get(key, []), groups_b.get(key, [])
        if left and right and (len(left) > 1 or len(right) > 1):
            continue
        direction = key[0]
        if left and right:
            matched[direction].append((left[0], right[0]))
        elif left:
            only_a[direction].extend(left)
        else:
            only_b[direction].extend(right)
    return matched, only_a, only_b


def clock_offset(flows):
    """NTP-style estimate from minimum one-way deltas. Asymmetric paths bias it."""
    forward = [q.time_ns - p.time_ns for matched, _, _, _ in flows for p, q in matched["client_to_server"]]
    backward = [p.time_ns - q.time_ns for matched, _, _, _ in flows for p, q in matched["server_to_client"]]
    if not forward or not backward:
        return None, None
    if min(forward) + min(backward) < 0:
        return None, None
    return (min(forward) - min(backward)) / 2, (min(forward) + min(backward)) / 2


def two_point(near_client, near_server, port=None, backend="auto", tshark=None):
    packets_a, meta_a = load_capture(near_client, backend, tshark)
    packets_b, meta_b = load_capture(near_server, backend, tshark)
    if port:
        packets_a = [p for p in packets_a if port in (p.sport, p.dport)]
        packets_b = [p for p in packets_b if port in (p.sport, p.dport)]
    flows_a, flows_b = analyze_connections(packets_a), analyze_connections(packets_b)
    pairs = match_flows(flows_a, flows_b)
    compared = [(*compare_flow(a, b), a) for a, b in pairs]
    skipped = sum(len(usable(a)) + len(usable(b)) - 2 * sum(map(len, matched.values()))
                  - sum(map(len, only_a.values())) - sum(map(len, only_b.values()))
                  for (a, b), (matched, only_a, only_b, _) in zip(pairs, compared))
    offset, one_way = clock_offset(compared)
    def inside(packet, meta, shift):
        # Without a clock estimate we cannot establish common capture coverage.
        if offset is None or meta.get("start_ns") is None or meta.get("end_ns") is None:
            return False
        corrected = packet.time_ns + shift
        uncertainty = abs(one_way)
        return meta["start_ns"] + uncertainty <= corrected <= meta["end_ns"] - uncertainty

    flows, findings = [], []

    def finding(code, title, direction, packets, candidates, flow):
        findings.append({"code": code, "title": title, "direction": direction, "count": len(packets), "flow": flow,
                         "evidence_ids": [p.evidence_id for p in packets[:MAX_EVIDENCE]], "candidates": candidates})

    delays = []
    for matched, only_a, only_b, conn in compared:
        flow = f"{conn['client'][0]}:{conn['client'][1]} -> {conn['server'][0]}:{conn['server'][1]}"
        if offset is not None:
            delays += [(q.time_ns - p.time_ns - offset) / 1e6 for p, q in matched["client_to_server"]]
            delays += [(p.time_ns - q.time_ns + offset) / 1e6 for p, q in matched["server_to_client"]]
        # A packet travelling client->server passes the client-side point first.
        lost_forward = [p for p in only_a["client_to_server"] if inside(p, meta_b, offset)]
        lost_backward = [p for p in only_b["server_to_client"] if inside(p, meta_a, -offset if offset is not None else None)]
        appeared_forward = [p for p in only_b["client_to_server"] if inside(p, meta_a, -offset if offset is not None else None)]
        appeared_backward = [p for p in only_a["server_to_client"] if inside(p, meta_b, offset)]
        if lost_forward:
            finding("lost_between_points", f"{flow}: クライアント側で見えた送信をサーバー側で観測できません", "client_to_server", lost_forward,
                    ["2点の間での破棄・ロス", "サーバー側の取得漏れ"], flow)
        if lost_backward:
            finding("lost_between_points", f"{flow}: サーバー側で見えた送信をクライアント側で観測できません", "server_to_client", lost_backward,
                    ["2点の間での破棄・ロス", "クライアント側の取得漏れ"], flow)
        for direction, packets, where in (("client_to_server", appeared_forward, "クライアント側に"), ("server_to_client", appeared_backward, "サーバー側に")):
            resets = [p for p in packets if p.flags & 4]
            if resets:
                finding("generated_between_points", f"{flow}: RSTが{where}見えないまま反対側に現れています", direction, resets,
                        ["2点の間の機器（FW/IPS/プロキシ）がRSTを生成", "片側の取得漏れ"], flow)
            if len(packets) > len(resets):
                finding("seen_only_downstream", f"{flow}: 上流側に記録のないパケットが下流側にあります", direction, [p for p in packets if not p.flags & 4],
                        ["上流側の取得漏れ", "2点の間の機器が書き換え・生成"], flow)
        flows.append({"flow": flow, "matched": {d: len(v) for d, v in matched.items()},
                      "only_near_client": {d: len(v) for d, v in only_a.items()}, "only_near_server": {d: len(v) for d, v in only_b.items()}})
    unmatched = len(flows_a) - len(compared)
    warnings = []
    if skipped:
        warnings.append(f"{skipped} パケットは再送・内容不一致等で対応が曖昧、または取得が不完全なため、遅延・消失の判定から除外しました")
    if not compared:
        warnings.append("2つのファイルで同じ通信を対応付けられませんでした。取得時間帯、対象ポート、シーケンス番号を書き換える機器の有無を確認してください")
    elif unmatched:
        warnings.append(f"クライアント側の {unmatched} 接続はサーバー側と対応付けられませんでした")
    if offset is None and compared:
        warnings.append("往復の対応データが不足、または時計差が整合しないため、片道遅延と取得期間に依存する消失・生成の判定は行っていません")
    return {"near_client": {"id": meta_a["id"], "path": meta_a["path"], "frames": meta_a["packet_count"], "backend": meta_a["backend"]},
            "near_server": {"id": meta_b["id"], "path": meta_b["path"], "frames": meta_b["packet_count"], "backend": meta_b["backend"]},
            "matching_status": "unmatched" if not pairs else "partial" if skipped or offset is None or len(pairs) != len(flows_a) or len(pairs) != len(flows_b) else "matched",
            "packets_not_comparable": skipped, "flows_matched": len(compared), "flows_near_client": len(flows_a), "flows_near_server": len(flows_b),
            "clock_offset_ms": round(offset / 1e6, 3) if offset is not None else None,
            "clock_offset_uncertainty_ms": round(abs(one_way) / 1e6, 3) if one_way is not None else None,
            "one_way_delay_ms": {"min": round(min(delays), 3), "median": round(median(delays), 3), "max": round(max(delays), 3)} if delays else None,
            "findings": findings[:MAX_FLOWS], "findings_total": len(findings), "flows": flows[:MAX_FLOWS], "warnings": warnings,
            "limitations": ["時計のずれは往復が対称という仮定の推定で、不確かさの範囲内の差は判別できません",
                            "片側にしかないパケットは、その区間での消失とその取得点での取得漏れのどちらの可能性もあります",
                            "シーケンス番号を書き換える機器（一部のFW）を挟むと対応付けできません"]}
