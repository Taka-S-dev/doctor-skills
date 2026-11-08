"""Conservative TCP event reconstruction; no loss/root-cause inference."""
from collections import defaultdict

from .tcpstats import annotate


def endpoint(packet, source=True):
    return (packet.src, packet.sport) if source else (packet.dst, packet.dport)


def analyze_connections(packets):
    connections, current = [], {}
    for packet in sorted(packets, key=lambda p: (p.time_ns, p.capture_id, p.frame)):
        key = tuple(sorted((endpoint(packet), endpoint(packet, False))))
        conn = current.get(key)
        initial_syn = packet.flags & 2 and not packet.flags & 16
        if conn is None or (initial_syn and
                            (conn["end"] is not None or conn["client_seq"] != packet.seq
                             or conn["client"] != list(endpoint(packet)))):
            conn = {"id": f"conn-{len(connections) + 1:04d}",
                    "client": list(endpoint(packet)), "server": list(endpoint(packet, False)),
                    "start": None, "syn_ack": None, "established": None, "end": None,
                    "client_seq": None, "server_seq": None, "events": [], "packets": [],
                    "syn_repeats": 0, "zero_windows": 0, "limitations": []}
            if not initial_syn:
                conn["limitations"].append("開始SYN未観測。接続方向と開始時刻は未確定")
            connections.append(conn)
            current[key] = conn
        conn["packets"].append(packet)
        from_client = list(endpoint(packet)) == conn["client"]

        def event(kind):
            value = {"kind": kind, "time_ns": packet.time_ns, "evidence_id": packet.evidence_id,
                     "sender": "client" if from_client else "server", "ttl": packet.ttl}
            conn["events"].append(value)
            return value

        if initial_syn:
            if conn["start"] is None:
                conn["start"] = event("syn")
                conn["client_seq"] = packet.seq
            else:
                conn["syn_repeats"] += 1
                event("repeated_syn")
        elif packet.flags & 0x12 == 0x12 and not from_client and conn["start"]:
            if packet.ack == (conn["client_seq"] + 1) % (2 ** 32) and conn["syn_ack"] is None:
                conn["syn_ack"] = event("syn_ack")
                conn["server_seq"] = packet.seq
        elif (packet.flags & 16 and not packet.flags & (2 | 4) and from_client
              and conn["syn_ack"] and conn["established"] is None and conn["end"] is None):
            if (packet.ack == (conn["server_seq"] + 1) % (2 ** 32)
                    and packet.seq == (conn["client_seq"] + 1) % (2 ** 32)):
                conn["established"] = event("established")
        if packet.flags & 4:
            end = event("rst")
            if conn["end"] is None:
                conn["end"] = end
        elif packet.flags & 1:
            end = event("fin")
            if conn["end"] is None:
                conn["end"] = end
        if packet.window == 0 and packet.flags & 16 and not packet.flags & (2 | 4 | 1):
            conn["zero_windows"] += 1
            event("zero_window")
    for conn in connections:
        annotate(conn)
    return connections


def is_one_way(conn):
    """True when only one side is captured although the peer demonstrably sent traffic."""
    senders = {endpoint(p) for p in conn["packets"]}
    if len(senders) != 1:
        return False
    return any(p.flags & 16 and p.ack and not p.flags & 4 for p in conn["packets"])


def reconnect_measurements(connections):
    measurements, candidates = [], []

    def measurement(name, start, end, connection_ids, limitations):
        measurements.append({"id": f"m-{len(measurements) + 1:04d}", "name": name,
                             "value_ms": (end["time_ns"] - start["time_ns"]) / 1_000_000,
                             "start_ns": start["time_ns"], "end_ns": end["time_ns"],
                             "evidence_ids": [start["evidence_id"], end["evidence_id"]],
                             "connection_ids": connection_ids, "limitations": limitations})

    groups = defaultdict(list)
    for conn in connections:
        if conn["start"]:
            groups[(conn["client"][0], *conn["server"])].append(conn)
        if conn["start"] and conn["established"]:
            measurement("tcp_handshake_ms", conn["start"], conn["established"], [conn["id"]],
                        ["最初に観測したSYNから成立ACKまで。機器内部の接続開始時刻ではありません"])
    for group in groups.values():
        ordered = sorted(group, key=lambda c: c["start"]["time_ns"])
        for index, conn in enumerate(ordered):
            before = ordered[:index]
            ended = [c for c in before if c["end"] and c["end"]["time_ns"] <= conn["start"]["time_ns"]]
            if not ended:
                quiet = [c for c in before if c["end"] is None and c["packets"][-1].time_ns <= conn["start"]["time_ns"]]
                busy = [c for c in before if c["packets"][-1].time_ns > conn["start"]["time_ns"]]
                if len(quiet) == 1 and not busy:
                    last = quiet[0]["packets"][-1]
                    candidates.append({"connection_id": conn["id"], "previous_ids": [quiet[0]["id"]], "status": "candidate",
                                       "reason": "終了イベントなしで通信が途絶えた後の次の接続。因果関係は未確認"})
                    measurement("observed_silence_before_next_connect_ms",
                                {"time_ns": last.time_ns, "evidence_id": last.evidence_id}, conn["start"],
                                [quiet[0]["id"], conn["id"]],
                                ["前の接続の最終観測パケットから次のSYNまでの間隔です。切断時刻ではありません",
                                 "FIN/RSTを観測していません。相手の停止・経路断・取得終了前の無通信を区別できません"])
                continue
            latest_time = max(c["end"]["time_ns"] for c in ended)
            latest = [c for c in ended if c["end"]["time_ns"] == latest_time]
            overlaps = [c for c in before if c["end"] is None or c["end"]["time_ns"] > conn["start"]["time_ns"]]
            if len(latest) != 1 or overlaps:
                candidates.append({"connection_id": conn["id"], "previous_ids": [c["id"] for c in latest],
                                   "status": "ambiguous", "reason": "並行接続または複数候補があり関連を確定できません"})
                continue
            previous = latest[0]
            candidates.append({"connection_id": conn["id"], "previous_ids": [previous["id"]],
                               "status": "candidate", "reason": "同一クライアントIP・サービスへの次の接続。因果関係は未確認"})
            measurement("observed_gap_before_next_connect_ms", previous["end"], conn["start"],
                        [previous["id"], conn["id"]],
                        ["終了関連イベントから次のSYNまでの観測間隔です",
                         "FINは半閉鎖の場合があります。機器内部の検知時刻・リトライ設定は未確認",
                         "別目的の接続である可能性とキャプチャ欠落を除外できません"])
    return measurements, candidates


def performance_measurements(connections, first_id, limit=50):
    """Report each connection's slowest request/response turnaround, largest first."""
    rows = []
    for conn in connections:
        turnaround = conn["stats"]["application_turnaround"]
        if turnaround:
            rows.append((turnaround["max_ms"], conn, turnaround))
    result = []
    for value, conn, turnaround in sorted(rows, key=lambda r: -r[0])[:limit]:
        result.append({"id": f"m-{first_id + len(result):04d}", "name": "app_turnaround_max_ms", "value_ms": value,
                       "evidence_ids": turnaround["evidence_ids"], "connection_ids": [conn["id"]],
                       "limitations": ["クライアント要求の最終パケットからサーバー応答の最初のパケットまでの観測間隔です",
                                       "往復遅延を含みます。観測位置により内訳が変わり、処理時間そのものではありません"]})
    return result


def public_connection(conn):
    result = {k: v for k, v in conn.items() if k != "packets"}
    result["packet_count"] = len(conn["packets"])
    if conn["end"]:
        status = "terminated_observed"
    elif conn["established"]:
        status = "established_observed"
    elif conn["start"] is None:
        status = "midstream_observed"
    else:
        status = "incomplete"
    result["status"] = status
    result["one_way"] = is_one_way(conn)
    if conn["start"] and not conn["established"]:
        result["limitations"] = result["limitations"] + ["完全な接続成立シーケンスを観測できていません"]
    return result
