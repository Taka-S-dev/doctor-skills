"""One-direction TCP byte-stream reconstruction with packet provenance."""
from bisect import bisect_right

STREAM_LIMIT = 16 * 1024 * 1024
SEQ_SPACE = 2 ** 32


def reassemble(packets, limit=STREAM_LIMIT):
    """Return (bytes, spans, warning). SYN required; a defect keeps the valid prefix.

    Each span is (start, end, arrival_ns, evidence_id), sorted and non-overlapping.
    """
    syn = next((p for p in packets if p.flags & 2), None)
    if syn is None:
        return b"", [], "SYN未観測のためストリーム先頭を確定できません"
    base = (syn.seq + 1) % SEQ_SPACE
    segments, truncated = [], False
    for p in packets:
        if not p.payload:
            continue
        offset = (p.seq + bool(p.flags & 2) - base) % SEQ_SPACE
        if offset >= SEQ_SPACE // 2:  # Before the stream start, e.g. a keep-alive probe.
            continue
        if offset >= limit:
            truncated = True
            continue
        payload = p.payload[:limit - offset]
        truncated |= len(payload) < len(p.payload)
        segments.append((offset, payload, p.time_ns, p.evidence_id))
    raw, spans = bytearray(), []
    conflicted = False
    warning = f"方向別{limit // (1024 * 1024)} MBより後は解析していません" if truncated else None
    for offset, payload, ns, ref in sorted(segments, key=lambda s: (s[0], s[2])):
        if offset > len(raw):
            if not conflicted:
                warning = "TCPデータに欠落があります。欠落より後は解析していません"
            break
        overlap = min(len(raw) - offset, len(payload))
        if raw[offset:offset + overlap] != payload[:overlap]:
            conflicted = True
            conflict = offset + next(i for i in range(overlap) if raw[offset + i] != payload[i])
            del raw[conflict:]
            spans = [(start, min(end, conflict), arrival, evidence)
                     for start, end, arrival, evidence in spans if start < conflict]
            warning = "内容の異なるTCP重複区間があるため、その位置より後は解析していません"
            continue
        if overlap < len(payload) and not conflicted:
            start = len(raw)
            raw.extend(payload[overlap:])
            spans.append((start, len(raw), ns, ref))
    return bytes(raw), spans, warning


def provenance(spans, start, end):
    """Return (evidence ids, latest arrival) for the bytes in [start, end)."""
    index, matched = max(bisect_right(spans, start, key=lambda s: s[0]) - 1, 0), []
    while index < len(spans) and spans[index][0] < end:
        if spans[index][1] > start:
            matched.append(spans[index])
        index += 1
    return list(dict.fromkeys(s[3] for s in matched)), max((s[2] for s in matched), default=0)
