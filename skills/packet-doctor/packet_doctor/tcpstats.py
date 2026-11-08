"""Per-connection TCP behaviour: loss signals, RTT, stalls and application turnaround.

TShark's tcp.analysis flags are used when present. The builtin backend infers the same
flag names from sequence numbers so both backends feed one set of diagnostics.
"""
from statistics import median

SEQ_SPACE = 2 ** 32
RETRANSMIT_FLAGS = {"retransmission", "fast_retransmission", "spurious_retransmission"}
RTO_LIKE_NS = 200_000_000
DUPLICATE_WINDOW_NS = 1_000_000


def relative(value, base):
    offset = (value - base) % SEQ_SPACE
    return offset - SEQ_SPACE if offset >= SEQ_SPACE // 2 else offset


def infer_flags(packets):
    state = {}

    def side(key):
        return state.setdefault(key, {"base": None, "next": None, "seen": set(), "pending": {}, "ack": None, "window": None})

    for p in packets:
        if p.analyzed:
            continue
        mine, peer = side((p.src, p.sport)), side((p.dst, p.dport))
        flags = []
        syn, fin, rst, has_ack = p.flags & 2, p.flags & 1, p.flags & 4, p.flags & 16
        consumed = p.segment_length + bool(syn) + bool(fin)
        if mine["base"] is None:
            mine["base"] = p.seq
        position, end = relative(p.seq, mine["base"]), relative(p.seq, mine["base"]) + consumed
        key = (position, consumed)
        if p.segment_length <= 1 and not (syn or fin or rst) and has_ack and mine["next"] is not None and position == mine["next"] - 1:
            flags.append("keep_alive")
        elif consumed:
            if key in mine["seen"]:
                flags.append("retransmission")
                mine["pending"].pop(end, None)
            else:
                if mine["next"] is not None and position < mine["next"]:
                    flags.append("out_of_order")
                elif mine["next"] is not None and position > mine["next"]:
                    flags.append("lost_segment")
                mine["pending"][end] = p.time_ns
            mine["seen"].add(key)
            mine["next"] = end if mine["next"] is None else max(mine["next"], end)
        if has_ack and peer["base"] is not None:
            acknowledged = relative(p.ack, peer["base"])
            if peer["next"] is not None and acknowledged > peer["next"]:
                flags.append("ack_lost_segment")
            sent = peer["pending"].pop(acknowledged, None)
            if sent is not None:
                p.rtt_ns = p.time_ns - sent
            if (not consumed and not rst and mine["ack"] == acknowledged and mine["window"] == p.window
                    and peer["next"] is not None and acknowledged < peer["next"]):
                flags.append("duplicate_ack")
            mine["ack"], mine["window"] = acknowledged, p.window
        if p.window == 0 and has_ack and not (syn or fin or rst):
            flags.append("zero_window")
        p.analysis = tuple(flags)


def mark_capture_duplicates(packets):
    """A mirror port repeats the same IP datagram; a real retransmission gets a new send."""
    seen = {}
    for p in packets:
        key = (p.src, p.sport, p.seq, p.ack, p.flags, p.segment_length, p.ip_id, p.ttl)
        earlier = seen.get(key)
        if earlier is not None and p.ip_id and p.time_ns - earlier <= DUPLICATE_WINDOW_NS:
            p.analysis = tuple(f for f in p.analysis if f not in RETRANSMIT_FLAGS) + ("captured_duplicate",)
        seen[key] = p.time_ns


def direction_stats(packets):
    first_sent, worst_chain, retransmits, rto_like, chains = {}, [], 0, 0, {}
    for p in packets:
        if not p.segment_length and not p.flags & 3:
            continue
        key = (p.seq, p.segment_length)
        if p.segment_length and RETRANSMIT_FLAGS & set(p.analysis):
            retransmits += 1
            if p.time_ns - first_sent.get(key, p.time_ns) >= RTO_LIKE_NS:
                rto_like += 1
        first_sent[key] = p.time_ns
        chains.setdefault(key, []).append(p.time_ns)
    for times in chains.values():
        if len(times) > len(worst_chain):
            worst_chain = times

    def count(flag):
        return sum(flag in p.analysis for p in packets)

    handshake = next((p for p in packets if p.flags & 2), None)
    data = [p for p in packets if p.segment_length]
    return {"packets": len(packets), "payload_bytes": sum(p.segment_length for p in packets),
            "retransmissions": retransmits, "rto_like_retransmissions": rto_like,
            "fast_retransmissions": count("fast_retransmission"), "duplicate_acks": count("duplicate_ack"),
            "out_of_order": count("out_of_order"), "lost_segments": count("lost_segment"),
            "ack_of_unseen_data": count("ack_lost_segment"), "keep_alives": count("keep_alive"),
            "captured_duplicates": count("captured_duplicate"), "largest_segment": max((p.segment_length for p in data), default=0),
            "retransmit_interval_ms": [round((b - a) / 1e6, 3) for a, b in zip(worst_chain, worst_chain[1:])] if len(worst_chain) > 2 else [],
            "mss": handshake.mss if handshake else None, "wscale": handshake.wscale if handshake else None,
            "sack_permitted": handshake.sack_permitted if handshake else None}


def summarize_ms(values):
    if not values:
        return None
    return {"count": len(values), "min_ms": round(min(values) / 1e6, 3), "median_ms": round(median(values) / 1e6, 3),
            "max_ms": round(max(values) / 1e6, 3)}


def application_turnaround(packets, client):
    """Measure the gap between a client's last request bytes and the first server bytes."""
    gaps, last_client = [], None
    for p in packets:
        if not p.segment_length or RETRANSMIT_FLAGS & set(p.analysis) or "keep_alive" in p.analysis:
            continue
        if [p.src, p.sport] == client:
            last_client = p
        elif last_client is not None:
            gaps.append((p.time_ns - last_client.time_ns, last_client.evidence_id, p.evidence_id))
            last_client = None
    if not gaps:
        return None
    worst = max(gaps)
    return {"count": len(gaps), "median_ms": round(median(g[0] for g in gaps) / 1e6, 3),
            "max_ms": round(worst[0] / 1e6, 3), "evidence_ids": [worst[1], worst[2]]}


def delayed_ack_pattern(packets):
    delays = []
    for data, reply in zip(packets, packets[1:]):
        if data.segment_length and not reply.segment_length and reply.flags & 16 and not reply.flags & 7 and data.src != reply.src:
            delay = (reply.time_ns - data.time_ns) / 1e6
            if 30 <= delay <= 50 or 180 <= delay <= 220:
                delays.append(delay)
    return {"count": len(delays), "median_ms": round(median(delays), 3)} if delays else None


def zero_window_time(packets):
    total, started = {}, {}
    for p in packets:
        key = (p.src, p.sport)
        if p.window == 0 and p.flags & 16 and not p.flags & 7:
            started.setdefault(key, p.time_ns)
        elif key in started:
            total[key] = total.get(key, 0) + p.time_ns - started.pop(key)
    return round(sum(total.values()) / 1e6, 3)


def connection_stats(conn):
    packets = conn["packets"]
    client = [p for p in packets if [p.src, p.sport] == conn["client"]]
    server = [p for p in packets if [p.src, p.sport] != conn["client"]]
    gaps = [(b.time_ns - a.time_ns, a.evidence_id, b.evidence_id, b.time_ns) for a, b in zip(packets, packets[1:])]
    idle = max(gaps) if gaps else None
    split = None
    if conn["start"] and conn["syn_ack"]:
        split = {"server_side_ms": round((conn["syn_ack"]["time_ns"] - conn["start"]["time_ns"]) / 1e6, 3)}
        if conn["established"]:
            split["client_side_ms"] = round((conn["established"]["time_ns"] - conn["syn_ack"]["time_ns"]) / 1e6, 3)
    attempts = [e["time_ns"] for e in conn["events"] if e["kind"] in ("syn", "repeated_syn")]
    return {"client": direction_stats(client), "server": direction_stats(server),
            "first_ns": packets[0].time_ns, "last_ns": packets[-1].time_ns,
            "duration_ms": round((packets[-1].time_ns - packets[0].time_ns) / 1e6, 3),
            "rtt": summarize_ms([p.rtt_ns for p in packets if p.rtt_ns is not None and p.rtt_ns >= 0]),
            "handshake_split": split,
            "max_idle": {"ms": round(idle[0] / 1e6, 3), "evidence_ids": [idle[1], idle[2]], "resumed_ns": idle[3]} if idle else None,
            "application_turnaround": application_turnaround(packets, conn["client"]),
            "delayed_ack": delayed_ack_pattern(packets), "zero_window_ms": zero_window_time(packets),
            "syn_retry_interval_ms": [round((b - a) / 1e6, 3) for a, b in zip(attempts, attempts[1:])]}


def annotate(conn):
    infer_flags(conn["packets"])
    mark_capture_duplicates(conn["packets"])
    conn["stats"] = connection_stats(conn)
