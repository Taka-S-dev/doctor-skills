"""Markdown context plus an explicitly reviewed packet-rules JSON block.

No prose-to-code execution. Rules describe length-prefixed TCP request/response messages.
"""
import json
from pathlib import Path
import re

from .models import InvestigationError, digest
from .stream import provenance, reassemble


def load_protocol(path):
    path = Path(path).resolve()
    if path.stat().st_size > 1_000_000:
        raise InvestigationError("仕様Markdownは1 MB以下にしてください")
    text = path.read_text(encoding="utf-8-sig")
    blocks = re.findall(r"^```packet-rules\s*\n(.*?)^```\s*$", text, re.M | re.S)
    if len(blocks) > 1:
        raise InvestigationError("packet-rulesブロックは1つだけ指定してください")
    rules = None
    if blocks:
        try:
            rules = json.loads(blocks[0])
        except json.JSONDecodeError as exc:
            raise InvestigationError(f"仕様JSONが不正です: {exc}") from exc
        validate_rules(rules)
    return {"path": str(path), "sha256": digest(path), "markdown": text, "rules": rules,
            "status": "validated_rules" if rules else "context_only"}


def validate_rules(rules):
    if not isinstance(rules, dict):
        raise InvestigationError("packet-rulesはJSONオブジェクトです")
    required = {"version", "name", "revision", "service_port", "byte_order", "length", "command", "request_id", "pairs", "response_timeout_ms"}
    if set(rules) != required:
        raise InvestigationError(f"仕様キーを確認してください。必須: {sorted(required)}")
    if rules["version"] != 1 or rules["byte_order"] not in ("big", "little"):
        raise InvestigationError("仕様version=1、byte_order=big/littleを指定してください")
    for key in ("name", "revision"):
        if not isinstance(rules[key], str) or not rules[key].strip():
            raise InvestigationError(f"{key}は空でない文字列にしてください")
    for key, lower, upper in (("service_port", 1, 65535), ("response_timeout_ms", 1, 3_600_000)):
        if type(rules[key]) is not int or not lower <= rules[key] <= upper:
            raise InvestigationError(f"{key}が範囲外です")
    for name in ("length", "command", "request_id"):
        field = rules[name]
        keys = {"offset", "size"}
        if name == "length":
            keys.add("includes_header")
            if isinstance(field, dict) and field.get("includes_header") is False:
                keys.add("adjust")
        if not isinstance(field, dict) or set(field) != keys:
            raise InvestigationError(f"{name}のフィールド定義が不正です")
        if type(field["offset"]) is not int or not 0 <= field["offset"] <= 256 or type(field["size"]) is not int or field["size"] not in (1, 2, 4):
            raise InvestigationError(f"{name}のoffset/sizeが不正です")
    length = rules["length"]
    if type(length["includes_header"]) is not bool:
        raise InvestigationError("length.includes_headerはtrue/falseで指定してください")
    if not length["includes_header"] and (type(length["adjust"]) is not int or not 0 <= length["adjust"] <= 1024):
        raise InvestigationError("includes_header=falseの場合、値に足す全体長の補正adjust(0〜1024)が必要です")
    if not isinstance(rules["pairs"], list) or not rules["pairs"]:
        raise InvestigationError("pairsを1組以上指定してください")
    seen = set()
    for pair in rules["pairs"]:
        if not isinstance(pair, dict) or not {"request", "response"} <= set(pair) <= {"request", "response", "error"}:
            raise InvestigationError("pairsはrequest/response（任意でerror）で定義してください")
        if "error" in pair and type(pair["error"]) is not bool:
            raise InvestigationError("pairsのerrorはtrue/falseで指定してください")
        for value in (pair["request"], pair["response"]):
            if type(value) is not int or not 0 <= value < 2 ** (8 * rules["command"]["size"]):
                raise InvestigationError("コマンド値がフィールドの範囲外です")
        if (pair["request"], pair["response"]) in seen:
            raise InvestigationError("request/responseの組が重複しています")
        seen.add((pair["request"], pair["response"]))


def message_size(rules, value):
    return value if rules["length"]["includes_header"] else value + rules["length"]["adjust"]


def messages_for_direction(packets, rules, warnings):
    """Reassemble from observed SYN; messages after a hole or conflict are not judged.

    Span provenance records arrival time so out-of-order completion isn't backdated.
    """
    if not any(p.flags & 2 for p in packets):
        warnings.add("SYN未観測の方向は、メッセージ境界が不明なため仕様判定しません")
        return []
    raw, spans, problem = reassemble(packets)
    if problem:
        warnings.add(problem)
    header = max(rules[k]["offset"] + rules[k]["size"] for k in ("length", "command", "request_id"))
    result, pos = [], 0

    def field(name, offset):
        definition = rules[name]
        start = offset + definition["offset"]
        return int.from_bytes(raw[start:start + definition["size"]], rules["byte_order"])

    while pos + header <= len(raw):
        size = message_size(rules, field("length", pos))
        if size < header or size > 65535:
            warnings.add("仕様のメッセージ長とデータが一致しません。境界の推測は行いません")
            break
        if pos + size > len(raw):
            break
        refs, ns = provenance(spans, pos, pos + size)
        result.append({"command": field("command", pos), "request_id": field("request_id", pos),
                       "time_ns": ns, "evidence_ids": refs, "length": size})
        pos += size
    if pos < len(raw):
        warnings.add("未完了または解釈できないメッセージ末尾があります")
    return result


def pair_exchanges(requests, responses):
    """Pair same-key requests and responses only while they strictly alternate in time."""
    merged = sorted([(m["time_ns"], 0, m) for m in requests] + [(m["time_ns"], 1, m) for m in responses], key=lambda v: (v[0], v[1]))
    pairs, pending = [], None
    for _, is_response, message in merged:
        if bool(is_response) == (pending is None):
            return None
        if is_response:
            pairs.append((pending, message))
            pending = None
        else:
            pending = message
    if pending is not None:
        pairs.append((pending, None))
    return pairs


def check_protocol(connections, protocol):
    if not protocol:
        return None
    rules = protocol["rules"]
    result = {"name": rules["name"] if rules else Path(protocol["path"]).stem,
              "revision": rules["revision"] if rules else None, "sha256": protocol["sha256"],
              "status": protocol["status"], "checks": [], "warnings": [], "message_count": 0}
    if not rules:
        result["warnings"] = ["Markdownを参照資料として保存しました。構造化ルールがないため自動適合判定は行いません"]
        return result
    warnings = set()
    response_kinds = {}
    for pair in rules["pairs"]:
        response_kinds.setdefault(pair["request"], {})[pair["response"]] = pair.get("error", False)

    def record(conn, request, status, elapsed, evidence, response=None):
        result["checks"].append({"connection_id": conn["id"], "request_id": request["request_id"],
                                 "command": request["command"], "response_command": response["command"] if response else None,
                                 "status": status, "elapsed_ms": elapsed, "limit_ms": rules["response_timeout_ms"],
                                 "evidence_ids": evidence, "time_ns": request["time_ns"],
                                 "spec_reference": "protocol.md: packet-rules.response_timeout_ms",
                                 "definition": "要求と応答の全バイトが観測された時刻の差。機器内部の処理時間ではありません"})

    for conn in connections:
        if conn["server"][1] != rules["service_port"]:
            continue
        if len({p.interface for p in conn["packets"]}) > 1:
            warnings.add("複数インターフェースの接続は重複観測の可能性があるため仕様判定を省略しました")
            continue
        requests = messages_for_direction([p for p in conn["packets"] if [p.src, p.sport] == conn["client"]], rules, warnings)
        responses = messages_for_direction([p for p in conn["packets"] if [p.src, p.sport] != conn["client"]], rules, warnings)
        result["message_count"] += len(requests) + len(responses)
        groups = {}
        for request in requests:
            if request["command"] in response_kinds:
                groups.setdefault((request["command"], request["request_id"]), []).append(request)
        for (command, request_id), group in groups.items():
            kinds = response_kinds[command]
            matches = [r for r in responses if r["command"] in kinds and r["request_id"] == request_id]
            pairs = pair_exchanges(group, matches)
            if pairs is None:
                # Identifiers reused without strict request/response alternation cannot be paired.
                for request in group:
                    record(conn, request, "ambiguous", None, request["evidence_ids"][:])
                continue
            for request, response in pairs:
                if response is None:
                    record(conn, request, "unobserved", None, request["evidence_ids"][:])
                    continue
                elapsed = (response["time_ns"] - request["time_ns"]) / 1_000_000
                status = "observed_error" if kinds[response["command"]] else "observed_late" if elapsed > rules["response_timeout_ms"] else "observed_within_limit"
                record(conn, request, status, elapsed, request["evidence_ids"] + response["evidence_ids"], response)
    result["checks"].sort(key=lambda c: c["time_ns"])
    result["warnings"] = sorted(warnings)
    return result
