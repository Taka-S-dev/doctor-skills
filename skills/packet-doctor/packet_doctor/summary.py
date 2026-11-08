"""Bounded views for an AI agent or a colleague: summary, drill-down, handoff, anonymized export."""
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
from statistics import median

from .external import external_evidence, performed_checks
from .models import atomic_text, read_json, write_json
from .reasoning import open_causes, rank_checks
from .report import hypothesis_scope

MAX_FINDINGS, MAX_WARNINGS, MAX_NEXT_CHECKS = 10, 6, 4
FLAG_NAMES = ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH"))


def measurement_table(measurements):
    groups = {}
    for item in measurements:
        groups.setdefault(item["name"], []).append(item)
    rows = []
    for name, items in groups.items():
        values = [i["value_ms"] for i in items]
        worst = max(items, key=lambda i: i["value_ms"])
        rows.append({"name": name, "count": len(items), "min_ms": round(min(values), 3), "median_ms": round(median(values), 3),
                     "max_ms": round(max(values), 3), "max_id": worst["id"], "max_evidence_ids": worst["evidence_ids"]})
    return rows


def summarize(root, case, analysis, hypotheses):
    """Return everything needed to choose the next step, independent of capture size."""
    root = Path(root)
    diagnostics = analysis["diagnostics"]
    linked = [fid for h in hypotheses for fid in h.get("finding_ids", [])]
    order = {fid: index for index, fid in reversed(list(enumerate(linked)))}
    findings = sorted(diagnostics["findings"], key=lambda f: (order.get(f["id"], len(order)), {"error": 0, "warning": 1, "info": 2}[f["severity"]]))
    connections = analysis["connections"]
    talkers = Counter(f"{c['client'][0]} -> {c['server'][0]}:{c['server'][1]}" for c in connections)
    protocol = analysis.get("protocol")
    quality = analysis.get("quality", {"status": "unknown", "issues": []})
    checks = performed_checks(root)
    done = {c["check_id"] for c in checks if c.get("run_id") == analysis["run_id"]}
    causes = open_causes(hypotheses)
    external = external_evidence(root)
    run = root / "runs" / analysis["run_id"]
    return {"case": case.get("id"), "state": case.get("state"), "symptom": case.get("symptom"), "symptom_type": analysis.get("symptom_type"),
            "run_id": analysis["run_id"], "target": analysis.get("target"), "port": analysis.get("port"), "observation": analysis.get("observation"),
            "captures": [{"id": c["id"], "backend": c["backend"], "frames": c["packet_count"]} for c in analysis["captures"]],
            "quality": {"status": quality["status"], "issues": [{k: i[k] for k in ("code", "severity", "message", "effect", "count")} for i in quality["issues"][:6]],
                        "observation_position": quality.get("observation_position", {}).get("estimate"), "duration_ms": quality.get("duration_ms")},
            "coverage": diagnostics["coverage"],
            "findings_total": len(diagnostics["findings"]),
            "findings": [{"id": f["id"], "code": f["code"], "severity": f["severity"], "scope": f["scope"], "title": f["title"], "count": f.get("count", 1),
                          "candidates": f["candidates"], "next_check": f["next_check"], "evidence_ids": f["evidence_ids"][:3],
                          "connections_total": f.get("connections_total", 0)} for f in findings[:MAX_FINDINGS]],
            "measurements": measurement_table(analysis["measurements"]),
            "protocol": {"name": protocol["name"], "status": protocol["status"], "messages": protocol["message_count"],
                         "checks": dict(Counter(c["status"] for c in protocol["checks"]))} if protocol else None,
            "connections": {"total": len(connections), "by_status": dict(Counter(c["status"] for c in connections)),
                            "ended_by": dict(Counter(f"{c['end']['kind']}_from_{c['end']['sender']}" for c in connections if c["end"])),
                            "top": [{"flow": flow, "connections": count} for flow, count in talkers.most_common(5)]},
            "hypotheses": [{"id": h["id"], "status": h["status"], "cause": h.get("cause"), "statement": h["statement"], "next_check": h["next_check"],
                            "branches": h["branches"], "evidence": len(h.get("evidence_ids", [])), "contrary_evidence": len(h.get("contrary_evidence_ids", [])),
                            "contradicted": h.get("contradicted", False), "source": h.get("source"),
                            "scope": h.get("scope"), "needs_revalidation": h.get("needs_revalidation", False),
                            "carried_from_run": h.get("carried_from_run")} for h in sorted(hypotheses, key=lambda h: bool(h.get("needs_revalidation")))[:10]],
            "next_checks": rank_checks(causes, done)[:MAX_NEXT_CHECKS], "checks_performed": len(checks),
            "external_evidence": [{"id": e["id"], "kind": e["kind"], "summary": e["summary"][:200]} for e in external[-10:]],
            "warnings_total": len(analysis["warnings"]), "warnings": analysis["warnings"][:MAX_WARNINGS],
            "files": {"hypotheses": str(run / "hypotheses.json"), "report_html": str(run / "report.html")},
            "drill_down": "findingの全件は query --finding、接続の時系列は query --conn、前後のパケットは query --around、全データは analysis.json"}


def flag_text(flags):
    return "/".join(name for bit, name in FLAG_NAMES if flags & bit) or "-"


def packet_row(row, origin_ns):
    result = {"id": row["id"], "t_ms": round((row["time_ns"] - origin_ns) / 1e6, 3), "src": row["src"], "sport": row["sport"],
              "dst": row["dst"], "dport": row["dport"]}
    if "flags" in row:
        result.update(flags=flag_text(row["flags"]), seq=row["seq"], ack=row["ack"], len=row["payload_length"], win=row["window"], ttl=row.get("ttl"))
        if row.get("analysis"):
            result["analysis"] = row["analysis"]
    else:
        result.update({k: row[k] for k in ("kind", "name", "rcode", "response", "icmp_type", "icmp_code", "opcode") if k in row})
    return result


def load_rows(run):
    with (Path(run) / "evidence.jsonl").open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def page(rows, origin_ns, limit, offset):
    return {"total": len(rows), "offset": offset, "limit": limit, "rows": [packet_row(r, origin_ns) for r in rows[offset:offset + limit]]}


def query(run, analysis, conn=None, finding=None, around=None, before=10, after=10, limit=50, offset=0):
    rows = load_rows(run)
    origin = min((r["time_ns"] for r in rows), default=0)
    if conn:
        match = next((c for c in analysis["connections"] if c["id"] == conn), None)
        if not match:
            return {"error": f"接続がありません: {conn}"}
        endpoints = {(*match["client"], *match["server"]), (*match["server"], *match["client"])}
        stats = match["stats"]
        selected = [r for r in rows if (r["src"], r["sport"], r["dst"], r["dport"]) in endpoints and stats["first_ns"] <= r["time_ns"] <= stats["last_ns"]]
        return {"connection": {k: match[k] for k in ("id", "client", "server", "status", "packet_count", "syn_repeats", "limitations", "one_way")}, "stats": stats, **page(selected, origin, limit, offset)}
    if finding:
        match = next((f for f in analysis["diagnostics"]["findings"] if f["id"] == finding), None)
        if not match:
            return {"error": f"所見がありません: {finding}"}
        wanted = set(match["evidence_ids"])
        return {"finding": match, **page([r for r in rows if r["id"] in wanted], origin, limit, offset)}
    index = next((i for i, r in enumerate(rows) if r["id"] == around), None)
    if index is None:
        return {"error": f"根拠IDが最新の解析にありません: {around}"}
    capture = rows[index]["capture_id"]
    same = sorted((r for r in rows if r["capture_id"] == capture), key=lambda r: (r["time_ns"], r["frame"]))
    position = next(i for i, r in enumerate(same) if r["id"] == around)
    return page(same[max(position - before, 0):position + after + 1], origin, limit, offset)


def render_handoff(root, case, analysis, hypotheses):
    """Write the note a specialist needs to continue without repeating the work."""
    root = Path(root)
    quality = analysis.get("quality", {"issues": []})
    checks, external = performed_checks(root), external_evidence(root)
    done = {c["check_id"] for c in checks if c.get("run_id") == analysis["run_id"]}
    causes = open_causes(hypotheses)
    lines = ["# 通信調査の引き継ぎ", "", f"- 症状: {case.get('symptom')}", f"- 調査状態: {case.get('state')}", f"- 対象: {analysis.get('target') or '未指定'} / ポート {analysis.get('port') or '未指定'}",
             f"- 観測位置: {analysis.get('observation')}", f"- 実行ID: {analysis['run_id']}", "", "## 取得データ", ""]
    lines += [f"- {c['path']}（{c['packet_count']} frames / {c['backend']} / SHA-256 {c['sha256']}）" for c in analysis["captures"]]
    lines += ["", "## 証拠の品質と制約", ""]
    lines += [f"- [{i['severity']}] {i['message']} {i['effect']}" for i in quality["issues"]] or ["- 検出項目に問題なし（完全な記録の保証ではありません）"]
    lines += ["", "## 観測できた事実（主なもの）", ""]
    lines += [f"- {f['title']}（根拠: {', '.join(f['evidence_ids'][:3])}）" for f in analysis["diagnostics"]["findings"][:10] if f["severity"] != "info"] or ["- 確認すべき所見なし"]
    lines += ["", "## 原因候補", ""]
    for h in hypotheses:
        lines += [f"### [{h['status']}] {h['statement']}", "", f"- 根拠: {', '.join(h.get('evidence_ids', [])[:5]) or 'なし'}",
                  f"- 反する証拠: {', '.join(h.get('contrary_evidence_ids', [])[:5]) or 'なし'}"]
        lines.append(f"- 対象・観測期間: {hypothesis_scope(h)}")
        if h.get("needs_revalidation"):
            lines.append("- 再確認が必要: 過去の解析での判断であり、今回の条件では未検証です")
        if h.get("revalidation"):
            lines.append(f"- 再確認の内容（解析 {h.get('revalidated_in_run', '不明')}）: {h['revalidation']}")
        if h.get("verification"):
            lines.append(f"- 検証内容: {h['verification']}")
        lines.append("")
    lines += ["## 実施済みの確認", ""]
    lines += [f"- {c['check_id']}（解析 {c.get('run_id', '不明')}）: {c['result']}" for c in checks] or ["- なし"]
    lines += ["", "## ログ・外部の根拠", ""]
    lines += [f"- {e['id']} [{e['kind']}] {e['summary']}" for e in external] or ["- なし"]
    lines += ["", "## 次にお願いしたい確認", ""]
    requests = [f"- {c['purpose']}: {c['procedure']}（手間 {c['effort']} / {c['risk']}）\n  - 必要なもの: {c['needs']}\n  - 絞れる候補: {', '.join(c['narrows'])}" for c in rank_checks(causes, done)[:5]]
    lines += requests or ["- 候補を絞る確認は未設定"]
    lines.append("")
    path = root / "handoff.md"
    atomic_text(path, "\n".join(lines))
    return str(path)


MAC_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_PATTERN = re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:.])")
PATH_CHARS = r'[^\s"|`<>)]'
# A delimited path may contain spaces. A bare one may continue past a space only when the
# next word is itself a path segment, so a " / " separator in prose is never a path.
PATH_PATTERN = re.compile(
    r'''(?<=[`"'])(?:[A-Za-z]:[\\/]|\\\\|/)[^`"'\r\n]*(?=[`"'])'''
    r'''|(?<![\w:/\\.])(?:[A-Za-z]:[\\/]|\\\\|/(?=[^\s/\\]))''' + PATH_CHARS + r'''*(?: [^\s"|`<>)\\/]+[\\/]''' + PATH_CHARS + r'''*)*''')
NAME_EDGE = "A-Za-z0-9_-"
MIN_EXACT_VALUE = 4


class Anonymizer:
    """Replace addresses, names and paths consistently; the map stays with the case."""

    def __init__(self, root, names=(), paths=(), labels=()):
        self.path = Path(root) / "anonymize-map.json"
        self.mapping = read_json(self.path) if self.path.exists() else {}
        self.names = sorted({n.lower() for n in names if n}, key=len, reverse=True)
        self.known_paths = sorted({v for p in paths if len(p) >= MIN_EXACT_VALUE for v in (p, p.replace("\\", "/"))}, key=len, reverse=True)
        self.labels = sorted({l for l in labels if l and l != "未指定"}, key=len, reverse=True)

    def token(self, kind, value):
        key = value.lower()
        if key not in self.mapping:
            count = sum(v.startswith(kind + "-") for v in self.mapping.values())
            self.mapping[key] = f"{kind}-{count + 1:03d}"
        return self.mapping[key]

    def text(self, value):
        # Exact values first: they may contain spaces or addresses that the patterns would split.
        for path in self.known_paths:
            value = re.sub(re.escape(path), lambda m: self.token("path", path), value, flags=re.I)
        for label in self.labels:
            value = value.replace(label, self.token("label", label))
        value = PATH_PATTERN.sub(lambda m: self.token("path", m[0]), value)
        value = MAC_PATTERN.sub(lambda m: self.token("mac", m[0]), value)

        def ipv4(match):
            try:
                ipaddress.IPv4Address(match[0])
            except ValueError:
                return match[0]
            return self.token("ip", match[0])

        def ipv6(match):
            try:
                ipaddress.IPv6Address(match[0])
            except ValueError:
                return match[0]
            return self.token("ip", match[0])

        value = IPV4_PATTERN.sub(ipv4, value)
        value = IPV6_PATTERN.sub(ipv6, value)
        for name in self.names:
            value = re.sub(f"(?<![{NAME_EDGE}]){re.escape(name)}(?![{NAME_EDGE}])", lambda m: self.token("host", name), value, flags=re.I)
        return value

    def structured(self, value):
        """Mask whole absolute path values before serializing (including spaces)."""
        if isinstance(value, dict):
            return {k: self.structured(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.structured(v) for v in value]
        if isinstance(value, str):
            if re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|/)", value):
                return self.token("path", value)
            return self.text(value)
        return value

    def save(self):
        write_json(self.path, self.mapping)


def evidence_details(external):
    return [e["details"] for e in external if isinstance(e.get("details"), dict)]


def sensitive_paths(root, analysis, external):
    paths = {str(Path(root).resolve())} | {c["path"] for c in analysis["captures"] if c.get("path")}
    paths |= {e["source"] for e in external if e.get("source")}
    return paths | {d["source"] for d in evidence_details(external) if isinstance(d.get("source"), str)}


def sensitive_labels(analysis, external):
    """Observation labels are free text the user wrote about their own network."""
    return {analysis.get("observation")} | {d.get("observation") for d in evidence_details(external)} - {None}


def sensitive_names(analysis, external=()):
    names = set()
    for details in evidence_details(external):
        host, request, execution = (details.get(k) if isinstance(details.get(k), dict) else {} for k in ("host", "request", "execution"))
        names.update(v for v in (host.get("hostname"), request.get("host"), details.get("scanner_identity"), execution.get("scanner_identity"))
                     if isinstance(v, str) and v != "unknown")
    for finding in analysis["diagnostics"]["findings"]:
        details = finding.get("details", {})
        names.update(details.get("san", []))
        names.update(v for v in (details.get("subject_cn"), details.get("issuer_cn"), details.get("requested")) if v)
        match = re.match(r"([\w.-]+\.[A-Za-z]{2,}): ", finding["title"])
        if match:
            names.add(match[1])
    for conn in analysis["connections"]:
        names.update(conn.get("names", []))
    return {n for n in names if not n.startswith("*.")} | {n[2:] for n in names if n.startswith("*.")}


def case_anonymizer(root, analysis):
    external = external_evidence(root)
    return Anonymizer(root, sensitive_names(analysis, external), sensitive_paths(root, analysis, external), sensitive_labels(analysis, external))


def export_case(root, run, case, analysis, hypotheses, out, anonymize=False):
    """Write shareable views. With anonymize, the mapping is kept only in the case folder."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    handoff = Path(render_handoff(root, case, analysis, hypotheses)).read_text(encoding="utf-8")
    summary = summarize(root, case, analysis, hypotheses)
    documents = {"summary.json": json.dumps(summary, ensure_ascii=False, indent=2),
                 "handoff.md": handoff, "report.md": (Path(run) / "report.md").read_text(encoding="utf-8")}
    anonymizer = case_anonymizer(root, analysis) if anonymize else None
    for name, text in documents.items():
        if anonymizer:
            text = (json.dumps(anonymizer.structured(summary), ensure_ascii=False, indent=2)
                    if name == "summary.json" else anonymizer.text(text))
        atomic_text(out / name, text)
    if anonymizer:
        anonymizer.save()
    return {"directory": str(out.resolve()), "files": sorted(documents), "anonymized": anonymize,
            "note": "匿名化はアドレス・名前・パスの置換です。症状の文面や機器固有の情報は残る場合があるため、共有前に確認してください" if anonymize else None}
