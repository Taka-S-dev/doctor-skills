"""Evidence quality: what this capture can and cannot support, assessed before any cause."""
from .connections import is_one_way


def assess(connections, network_events, captures, target=None, port=None, incident_ns=None, observation=None):
    issues = []

    def issue(code, severity, message, effect, count=None, refs=()):
        issues.append({"code": code, "severity": severity, "message": message, "effect": effect,
                       "count": count, "evidence_ids": list(refs)[:5]})

    frames = sum(c["packet_count"] for c in captures)
    start = min((c["start_ns"] for c in captures if c["start_ns"] is not None), default=None)
    end = max((c["end_ns"] for c in captures if c["end_ns"] is not None), default=None)
    if not frames:
        issue("empty_capture", "blocking", "キャプチャにフレームがありません", "原因調査はできません。取得をやり直してください")
    selected = [c for c in connections if not port or port in (c["client"][1], c["server"][1])]
    if frames and not selected and (target or port):
        issue("target_not_observed", "blocking", "指定した相手・ポートのTCP通信を観測していません",
              "取得位置・フィルター・時間帯を確認するまで、対象通信について判断できません")
    one_way = [c for c in selected if is_one_way(c)]
    if one_way:
        issue("one_way_capture", "blocking" if len(one_way) == len(selected) else "limiting",
              "片方向の通信しか保存されていない接続があります（相手の送信を確認応答しているのに、その送信が見えません）",
              "「応答なし」を判断できません。ミラー設定・取得位置を見直してください",
              len(one_way), [c["packets"][0].evidence_id for c in one_way])
    midstream = [c for c in selected if c["start"] is None]
    if midstream:
        issue("midstream_connections", "info" if len(midstream) < len(selected) else "limiting",
              "開始（SYN）が記録されていない接続があります", "接続方向・開始時刻・アプリのメッセージ境界は判定できません", len(midstream))

    def totals(name):
        return sum(c["stats"]["client"][name] + c["stats"]["server"][name] for c in selected)

    unseen = totals("ack_of_unseen_data") + totals("lost_segments")
    if unseen:
        refs = [p.evidence_id for c in selected for p in c["packets"] if {"ack_lost_segment", "lost_segment"} & set(p.analysis)]
        issue("capture_gaps", "limiting", "記録に欠けがある兆候があります（確認応答されたのに見えていないデータ、シーケンスの飛び）",
              "パケット欠落と取得漏れを区別する必要があります。再送の数は下限として読んでください", unseen, refs)
    drops = [(c["id"], c["interface_statistics"]) for c in captures if c.get("interface_statistics")]
    dropped = sum(s["dropped_by_interface"] + s["dropped_by_os"] for _, s in drops)
    if dropped:
        issue("capture_tool_drops", "limiting", f"取得ツールの統計に {dropped} 件のドロップが記録されています",
              "記録にないことを「発生していない」と読めません", dropped)
    truncated = sum(c.get("truncated_frames", 0) for c in captures)
    if truncated:
        issue("truncated_frames", "limiting", "ペイロードが切り詰められたフレームがあります",
              "TCPヘッダーの解析はできますが、TLS証明書・HTTP/FTP応答・独自プロトコルの判定は欠ける場合があります", truncated)
    if any(c.get("time_reversals") for c in captures):
        issue("time_reversal", "limiting", "保存順で時刻が逆転しています", "短い区間の時間差は誤差を含む可能性があります",
              sum(c.get("time_reversals", 0) for c in captures))
    duplicates = totals("captured_duplicates")
    if duplicates:
        issue("mirror_duplicates", "info", "同じ送信が重複して記録されています（ミラー等）", "重複分は再送として数えていません", duplicates)
    oversized = [p for c in selected for p in c["packets"] if p.segment_length > 1460 and (p.mss or 1460) <= 1460]
    if oversized:
        issue("offload_on_sender", "info", "MTUを超える大きさのセグメントがあります（送信端末上での取得を示唆）",
              "実際の回線上の分割は見えていません。再送やRTTの解釈は取得位置を踏まえてください", len(oversized), [p.evidence_id for p in oversized])
    if incident_ns is not None and start is not None and not start <= incident_ns <= end:
        issue("incident_outside_capture", "blocking", "申告された発生時刻がキャプチャの範囲外です",
              "このファイルでは申告の事象を観測できません。発生時刻を含む記録が必要です")
    if frames and start is not None and end - start < 5_000_000_000:
        issue("short_capture", "info", "取得時間が5秒未満です", "再送タイムアウトや再接続の待機は取得範囲に収まらない場合があります")

    if observation == "未指定":
        issue("observation_not_specified", "info", "取得位置が指定されていません", "どの区間の通信を見ているか分からないため、応答なしや遅延の内訳の解釈に制約があります")

    order = {"blocking": 0, "limiting": 1, "info": 2}
    issues.sort(key=lambda value: order[value["severity"]])
    status = "blocked" if any(i["severity"] == "blocking" for i in issues) else "limited" if any(i["severity"] == "limiting" for i in issues) else "no_issue_detected"
    return {"status": status, "issues": issues, "observation_position": observation_position(selected),
            "duration_ms": round((end - start) / 1e6, 3) if start is not None else None,
            "note": "no_issue_detectedは検出項目に問題がなかったという意味で、完全な記録の保証ではありません"}


def observation_position(connections):
    """Infer where the capture sits from how the handshake delay divides around it."""
    near_client = near_server = 0
    for conn in connections:
        split = conn["stats"]["handshake_split"]
        if not split or "client_side_ms" not in split:
            continue
        server_side, client_side = split["server_side_ms"], split["client_side_ms"]
        if max(server_side, client_side) < 1:
            continue
        if client_side * 5 < server_side:
            near_client += 1
        elif server_side * 5 < client_side:
            near_server += 1
    if not near_client and not near_server:
        return {"estimate": "unknown", "basis": "ハンドシェイクの遅延分布から判断できません"}
    estimate = "near_client" if near_client > near_server else "near_server" if near_server > near_client else "mixed"
    return {"estimate": estimate, "near_client_connections": near_client, "near_server_connections": near_server,
            "basis": "SYN→SYN/ACK と SYN/ACK→ACK の遅延の偏りから推定した候補です。利用者の申告で確認してください"}
