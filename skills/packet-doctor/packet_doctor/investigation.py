from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import uuid

from . import __version__
from .capture import load_capture, MAX_PACKETS
from .connections import analyze_connections, performance_measurements, public_connection, reconnect_measurements
from .diagnostics import diagnose
from .external import FINAL_STATES, append_jsonl, external_ids, report_extras
from .models import InvestigationError, atomic_text, read_json, write_json
from .protocol import load_protocol, check_protocol
from .quality import assess
from .reasoning import CHECKS, build_hypotheses, classify_symptom
from .report import render_report
from .summary import summarize


@contextmanager
def case_lock(case_dir):
    case_dir = Path(case_dir).resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    lock = case_dir / ".write.lock"
    try:
        stream = lock.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise InvestigationError("同じ調査が実行中です。異常終了後のロックはプロセス停止を確認してから削除してください", "case_locked") from exc
    try:
        with stream:
            stream.write(f"{datetime.now(timezone.utc)} pid={os.getpid()}")
        yield case_dir
    finally:
        lock.unlink(missing_ok=True)


def parse_time(value, name="時刻"):
    """Parse ISO 8601 with a required timezone into nanoseconds."""
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvestigationError(f"{name}はISO 8601形式で指定してください: {value}") from exc
    if stamp.tzinfo is None:
        raise InvestigationError(f"{name}にはタイムゾーンを付けてください: {value}")
    return int(stamp.timestamp()) * 1_000_000_000 + stamp.microsecond * 1000


def previous_agent_hypotheses(root, case, current_analysis):
    """Return (agent-written hypotheses, evidence rows they cite) from the last good run."""
    run_id = case.get("latest_run")
    if not run_id or not (root / "runs" / run_id / "hypotheses.json").exists():
        return [], []
    run = root / "runs" / run_id
    prior_analysis = read_json(run / "analysis.json")
    def context(analysis):
        return ([c["id"] for c in analysis["captures"]],
                [analysis.get(k) for k in ("target", "port", "incident_time", "observation", "protocol")])
    changed = context(prior_analysis) != context(current_analysis)
    carried = [h for h in read_json(run / "hypotheses.json") if h.get("source") == "user_or_agent"]
    cited = {ref for h in carried for ref in h.get("evidence_ids", []) + h.get("contrary_evidence_ids", [])}
    rows = []
    if cited and (run / "evidence.jsonl").exists():
        for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row["id"] in cited:
                rows.append(row)
    for hypothesis in carried:
        hypothesis.setdefault("carried_from_run", run_id)
        if changed:
            hypothesis["needs_revalidation"] = True
            hypothesis.pop("revalidation", None)
            hypothesis.pop("revalidated_in_run", None)
        if hypothesis.get("finding_ids"):
            hypothesis["prior_finding_ids"] = {"run_id": run_id, "ids": hypothesis.pop("finding_ids")}
            hypothesis["finding_ids"] = []
        if hypothesis.get("measurement_ids"):
            hypothesis["prior_measurement_ids"] = hypothesis.pop("measurement_ids")
            hypothesis["measurement_ids"] = []
    return carried, rows


def merge_hypotheses(carried, generated):
    """Keep prior conclusions, but never let stale conclusions hide current causes."""
    covered = {h.get("cause") for h in carried if h.get("cause") and not h.get("needs_revalidation")}
    used = {h["id"] for h in carried}
    merged = list(carried)
    number = 0
    for hypothesis in generated:
        if hypothesis.get("cause") in covered:
            continue
        number += 1
        while f"h-{number:04d}" in used:
            number += 1
        hypothesis["id"] = f"h-{number:04d}"
        used.add(hypothesis["id"])
        merged.append(hypothesis)
    return merged


def analyze(case_dir, captures, symptom="通信の状態を確認したい", target=None, port=None,
            protocol_path=None, backend="auto", tshark=None, observation="未指定", incident_time=None):
    if target:
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise InvestigationError("targetはIPアドレスで指定してください") from exc
    if port is not None and not 1 <= port <= 65535:
        raise InvestigationError("portは1〜65535です")
    if not captures:
        raise InvestigationError("キャプチャを指定してください")
    incident_ns = parse_time(incident_time, "発生時刻") if incident_time else None
    protocol = load_protocol(protocol_path) if protocol_path else None
    if port is None and protocol and protocol["rules"]:
        port = protocol["rules"]["service_port"]
    with case_lock(case_dir) as root:
        case_file = root / "case.json"
        case = read_json(case_file) if case_file.exists() else {"schema_version": 2, "id": root.name, "symptom": symptom}
        case["symptom"] = symptom
        case["state"] = "analyzing"
        write_json(case_file, case)
        run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S-") + uuid.uuid4().hex[:8]
        run_dir = root / "runs" / run_id
        run_dir.mkdir(parents=True)
        manifest = {"schema_version": 2, "run_id": run_id, "version": __version__, "status": "running",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "options": {"target": target, "port": port, "backend": backend, "observation": observation,
                                "incident_time": incident_time, "capture_paths": [str(Path(p).resolve()) for p in captures],
                                "protocol_path": str(Path(protocol_path).resolve()) if protocol_path else None}}
        write_json(run_dir / "manifest.json", manifest)
        try:
            packets, metadata, seen, network_events = [], [], set(), []
            for path in captures:
                loaded, meta = load_capture(path, backend, tshark)
                if meta["id"] in seen:
                    raise InvestigationError("同じ内容のキャプチャが重複指定されています")
                seen.add(meta["id"])
                network_events.extend(meta.pop("network_events", []))
                metadata.append(meta)
                packets.extend(p for p in loaded if not target or target in (p.src, p.dst))
                if len(packets) + len(network_events) > MAX_PACKETS:
                    raise InvestigationError("1回の解析対象はTCPとDNS/ICMPの合計50万件までです", "resource_limit")
            all_connections = analyze_connections(packets)
            connections = [c for c in all_connections if not port or any(port in (p.sport, p.dport) for p in c["packets"])]
            protocol_result = check_protocol(connections, protocol)
            measurements, candidates = reconnect_measurements(connections)
            measurements += performance_measurements(connections, len(measurements) + 1)
            diagnostics = diagnose(all_connections, network_events, target, port, measurements, protocol_result)
            quality = assess(all_connections, network_events, metadata, target, port, incident_ns, observation)
            symptom_type = classify_symptom(symptom)
            generated, plan = build_hypotheses(diagnostics["findings"], measurements, symptom_type, quality, bool(target or port))
            by_id = {c["id"]: c for c in connections}
            for hypothesis in generated:
                related = {cid for f in diagnostics["findings"] if f["id"] in hypothesis["finding_ids"] for cid in f["connections"]}
                hypothesis["scope"] = {"run_id": run_id, "connections_total": len(related), "connections": [
                    {"id": cid, "client": by_id[cid]["client"], "server": by_id[cid]["server"],
                     "start_ns": by_id[cid]["packets"][0].time_ns, "end_ns": by_id[cid]["packets"][-1].time_ns}
                    for cid in sorted(related)[:10] if cid in by_id]}
            warnings = sorted({w for meta in metadata for w in meta["warnings"]})
            warnings.append("終了関連イベントは機器内部の切断検知時刻ではありません")
            if len(captures) > 1:
                warnings.append("複数ファイルは同じ観測点の連続取得を想定。別の観測点の突合はtwo-pointを使ってください")
            if not connections:
                warnings.append("指定条件に一致する解析可能なTCPパケットがありません")
            if observation == "未指定":
                warnings.append("観測位置が未指定です")
            analysis = {"schema_version": 2, "run_id": run_id, "captures": metadata, "target": target, "port": port,
                        "observation": observation, "symptom_type": symptom_type, "incident_time": incident_time,
                        "quality": quality, "connections": [public_connection(c) for c in connections], "measurements": measurements,
                        "reconnect_candidates": candidates, "protocol": protocol_result, "diagnostics": diagnostics,
                        "plan": plan, "warnings": warnings + diagnostics["warnings"]}
            carried, carried_rows = previous_agent_hypotheses(root, case, analysis)
            hypotheses = merge_hypotheses(carried, generated)
            evidence = [p.evidence() for p in packets]
            known_evidence = {p["id"] for p in evidence}
            for row in network_events + carried_rows:
                if row["id"] not in known_evidence:
                    known_evidence.add(row["id"])
                    evidence.append(row)
            atomic_text(run_dir / "evidence.jsonl", "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in evidence))
            write_json(run_dir / "analysis.json", analysis)
            if protocol:
                atomic_text(run_dir / "protocol.md", protocol["markdown"])
            write_json(run_dir / "hypotheses-initial.json", hypotheses)
            write_json(run_dir / "hypotheses.json", hypotheses)
            extras = report_extras(root)
            reports = render_report(run_dir, case, analysis, hypotheses, extras)
            manifest.update(status="complete", completed_at=datetime.now(timezone.utc).isoformat(),
                            capture_ids=[m["id"] for m in metadata], reports=reports)
            write_json(run_dir / "manifest.json", manifest)
            case.update(state="reviewing", latest_run=run_id)
            write_json(case_file, case)
            append_history(root, {"action": "analyze", "run_id": run_id})
            write_json(root / "latest.json", {"run_id": run_id, "reports": reports})
            return {"run_id": run_id, "case": str(root), "reports": reports,
                    "connections": len(connections), "measurements": measurements, "quality": quality,
                    "protocol": analysis["protocol"], "diagnostics": diagnostics, "warnings": analysis["warnings"],
                    "summary": summarize(root, case, analysis, hypotheses)}
        except (Exception, KeyboardInterrupt) as exc:
            manifest.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=str(exc))
            write_json(run_dir / "manifest.json", manifest)
            case["state"] = "needs_attention"
            write_json(case_file, case)
            raise


def append_history(root, event):
    event["time"] = datetime.now(timezone.utc).isoformat()
    with (root / "history.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def latest(root):
    root = Path(root).resolve()
    case = read_json(root / "case.json")
    run_id = case.get("latest_run")
    if not run_id or Path(run_id).name != run_id or "/" in run_id or "\\" in run_id:
        raise InvestigationError("完了した解析がありません")
    run = root / "runs" / run_id
    return root, run, case, read_json(run / "analysis.json")


def update_hypotheses(root, input_path):
    proposed = read_json(input_path)
    if not isinstance(proposed, list) or not proposed:
        raise InvestigationError("仮説は空でないJSON配列で指定してください")
    with case_lock(root):
        root, run, case, analysis = latest(root)
        evidence = {json.loads(line)["id"] for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines()}
        evidence |= external_ids(root)
        measurements = {m["id"] for m in analysis["measurements"]}
        previous = {h["id"]: h for h in read_json(run / "hypotheses.json")}
        ids = set()
        for h in proposed:
            if not isinstance(h, dict):
                raise InvestigationError("各仮説はオブジェクトで指定してください")
            for field in ("id", "statement", "next_check", "branches"):
                if not isinstance(h.get(field), str) or not h[field].strip():
                    raise InvestigationError(f"仮説の{field}は空でない文字列が必要です")
            if h["id"] in ids:
                raise InvestigationError("仮説IDが重複しています")
            ids.add(h["id"])
            if h.get("status") not in ("candidate", "supported", "verified", "rejected"):
                raise InvestigationError("仮説のstatusが不正です")
            for field, known in (("evidence_ids", evidence), ("contrary_evidence_ids", evidence), ("measurement_ids", measurements)):
                refs = h.get(field, [])
                if not isinstance(refs, list) or any(not isinstance(v, str) or v not in known for v in refs):
                    raise InvestigationError(f"存在しない根拠または不正な参照: {field}")
            if h["status"] in ("supported", "verified") and not (h.get("evidence_ids") or h.get("measurement_ids")):
                raise InvestigationError("支持・検証済みの仮説には根拠が必要です")
            if h["status"] == "verified" and (not isinstance(h.get("verification"), str) or not h["verification"].strip()):
                raise InvestigationError("verifiedには検証内容verificationが必要です")
            earlier = previous.get(h["id"])
            if earlier and earlier.get("needs_revalidation"):
                # Omitting the flag must not count as confirming the old judgment again.
                note = h.get("revalidation")
                if note is None:
                    h["needs_revalidation"] = True
                elif not isinstance(note, str) or not note.strip():
                    raise InvestigationError("revalidationは今回の条件で確認した内容を文字列で指定してください")
                elif not (h.get("evidence_ids") or h.get("measurement_ids")):
                    raise InvestigationError("再確認には根拠が必要です")
                else:
                    h.pop("needs_revalidation", None)
                    h["revalidated_in_run"] = analysis["run_id"]
            unchanged = earlier and {k: v for k, v in earlier.items() if k != "source"} == {k: v for k, v in h.items() if k != "source"}
            h["source"] = earlier["source"] if unchanged else "user_or_agent"
        revision = "hypotheses-" + uuid.uuid4().hex[:8] + ".json"
        write_json(run / revision, proposed)
        write_json(run / "hypotheses.json", proposed)
        reports = render_report(run, case, analysis, proposed, report_extras(root))
        append_history(root, {"action": "update_hypotheses", "run_id": analysis["run_id"], "revision": revision})
        return {"run_id": analysis["run_id"], "reports": reports, "revision": revision}


def known_evidence_ids(root, run):
    ids = {json.loads(line)["id"] for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines()}
    return ids | external_ids(root)


def refresh_report(root):
    root, run, case, analysis = latest(root)
    return render_report(run, case, analysis, read_json(run / "hypotheses.json"), report_extras(root))


def record_check(root, check_id, result, evidence_ids=()):
    """Record a performed check so the plan stops proposing it."""
    if check_id not in CHECKS and not check_id.startswith("custom:"):
        raise InvestigationError(f"確認IDが不明です: {check_id}。独自の確認は custom:名前 で指定してください")
    if not result or not result.strip():
        raise InvestigationError("resultは空にできません")
    with case_lock(root):
        root, run, _, analysis = latest(root)
        unknown = set(evidence_ids) - known_evidence_ids(root, run)
        if unknown:
            raise InvestigationError(f"存在しない根拠です: {sorted(unknown)}")
        entry = {"check_id": check_id, "result": result.strip(), "evidence_ids": list(evidence_ids), "run_id": analysis["run_id"],
                 "recorded_at": datetime.now(timezone.utc).isoformat()}
        append_jsonl(root / "checks.jsonl", entry)
        append_history(root, {"action": "record_check", "check_id": check_id})
        return {"recorded": entry, "reports": refresh_report(root)}


def set_state(root, state, reason):
    """Move the investigation to an explicit end or waiting state."""
    if state not in FINAL_STATES:
        raise InvestigationError(f"stateは{', '.join(FINAL_STATES)}のいずれかです")
    if not reason or not reason.strip():
        raise InvestigationError("reasonは空にできません")
    with case_lock(root):
        root, run, case, _ = latest(root)
        if state == "verified" and not any(h["status"] == "verified" and not h.get("needs_revalidation") for h in read_json(run / "hypotheses.json")):
            raise InvestigationError("verifiedにするには、検証済み（verified）の仮説が必要です")
        case.update(state=state, state_reason=reason.strip())
        write_json(root / "case.json", case)
        append_history(root, {"action": "set_state", "state": state, "reason": reason.strip()})
        return {"state": state, "reports": refresh_report(root)}
