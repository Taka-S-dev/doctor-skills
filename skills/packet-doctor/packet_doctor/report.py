import html
import json
from pathlib import Path
import re
from datetime import datetime, timezone

from .models import atomic_text

LABELS = {"tcp_handshake_ms": "TCP接続成立", "observed_gap_before_next_connect_ms": "終了関連イベント→次の接続要求",
          "observed_silence_before_next_connect_ms": "最後の通信→次の接続要求（終了イベントなし）", "app_turnaround_max_ms": "要求→応答の最大間隔"}
STATUS = {"terminated_observed": "終了関連イベントあり", "established_observed": "接続成立を観測", "incomplete": "成立を確認できず", "midstream_observed": "途中から観測（開始は未記録）",
          "candidate": "未検証の候補", "supported": "支持する証拠あり", "verified": "検証済み", "rejected": "棄却",
          "observed_error": "エラー応答", "observed_late": "指定時間を超過", "observed_within_limit": "指定時間内", "unobserved": "応答を未観測",
          "ambiguous": "対応が曖昧", "syn": "接続要求 (SYN)", "syn_ack": "接続応答 (SYN/ACK)",
          "established": "接続成立のACK", "rst": "接続リセット (RST)", "fin": "送信終了通知 (FIN)",
          "repeated_syn": "同じ接続要求を再観測", "zero_window": "受信余力ゼロの通知",
          "validated_rules": "構造化ルールを適用", "context_only": "参照資料のみ"}


def esc(value):
    return html.escape(str(value))


def md(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;")


QUALITY = {"blocked": "この記録では判断できない項目があります", "limited": "判断に制約があります", "no_issue_detected": "検出項目に問題はありません（完全な記録の保証ではありません）"}
STATES = {"reviewing": "確認中", "needs_attention": "処理エラーあり", "waiting_for_data": "追加データ待ち", "verified": "原因を検証済み",
          "handed_off": "専門家へ引き継ぎ", "inconclusive": "今回の範囲では判定不能", "analyzing": "解析中"}


def hypothesis_scope(hypothesis):
    scope = hypothesis.get("scope", {})
    rows = []
    for conn in scope.get("connections", []):
        times = [datetime.fromtimestamp(conn[k] / 1e9, timezone.utc).isoformat() for k in ("start_ns", "end_ns")]
        rows.append(f"{conn['id']}: {conn['client'][0]}:{conn['client'][1]} → {conn['server'][0]}:{conn['server'][1]} / {' ～ '.join(times)}")
    return f"解析 {scope.get('run_id', '不明')} / " + ("; ".join(rows) or "接続への対応付けなし")


def access_lines(check):
    """Say what would settle a check; runs saved before this field existed have none of it."""
    if not check.get("needs"):
        return []
    lines = [f"必要なもの: {check['needs']}（{check['provide']}）",
             f"絞れる候補: {', '.join(check['narrows'])}" + (f" / この確認では残る候補: {', '.join(check['leaves_open'])}" if check["leaves_open"] else "")]
    if check.get("direct_access"):
        lines.append(f"直接確認するなら: {check['direct_access']}")
    return lines


def nmap_rows(entries):
    rows = []
    for entry in entries[-10:]:
        details = entry.get('details', {})
        if entry['kind'] != 'nmap' or not isinstance(details, dict):
            continue
        for item in details.get('observations', [])[:50]:
            rows.append((entry['id'], details.get('observation', '不明'), details.get('status', '不明'),
                         item.get('started_at') or '時刻不明', f"{item['host']}:{item['port']}/{item['protocol']}",
                         item['state'], item.get('reason', '不明')))
    return rows[:50]


def curl_rows(entries):
    rows = []
    for entry in entries[-10:]:
        details = entry.get('details', {})
        if entry['kind'] != 'curl' or not isinstance(details, dict) or 'request' not in details:
            continue
        request, metrics = details['request'], details.get('metrics') or {}
        rows.append((entry['id'], details.get('observation'), details.get('started_at'),
                     f"{request['scheme']}://{request['host']}:{request['port']}", details['status'],
                     metrics.get('response_code', '不明'), metrics.get('size_download', '不明'), metrics.get('time_total', '不明')))
    return rows


def host_rows(entries):
    rows = []
    for entry in entries[-10:]:
        details = entry.get('details', {})
        if entry['kind'] != 'host_snapshot' or not isinstance(details, dict):
            continue
        for name, section in details.get('sections', {}).items():
            rows.append((entry['id'], details.get('host', {}).get('hostname', '不明'), details.get('role', '不明'),
                         details.get('started_at', '不明'), name, section.get('status', '不明'), section.get('rows', 0),
                         'あり' if section.get('truncated') else 'なし'))
    return rows


def render_report(directory, case, analysis, hypotheses, extras=None):
    directory = Path(directory)
    extras = extras or {"external": [], "checks": []}
    warnings = analysis["warnings"]
    quality = analysis.get("quality", {"status": "no_issue_detected", "issues": []})
    plan = analysis.get("plan", [])
    done = {c["check_id"] for c in extras["checks"] if c.get("run_id") == analysis["run_id"]}
    specs = analysis.get("protocol")
    diagnostics = analysis.get("diagnostics", {"findings": [], "coverage": {}, "warnings": []})
    overview = (f"TCP接続候補 {len(analysis['connections'])} 件、計測 {len(analysis['measurements'])} 件。"
                "観測結果を整理しました。原因は検証されていません。")
    if not analysis["connections"]:
        overview = "指定条件に一致する解析可能なTCP通信がありません。対象・取得位置・対応形式を確認してください。"
    else:
        gaps = [m["value_ms"] for m in analysis["measurements"] if m["name"] == "observed_gap_before_next_connect_ms"]
        if gaps:
            overview += f" 終了関連イベントから次の接続要求までの最大観測間隔は {max(gaps):.3f} ms でした。"
        if specs:
            late = sum(c["status"] == "observed_late" for c in specs["checks"])
            if late:
                overview += f" 指定された仕様の応答時間を超えた要求・応答が {late} 件あります。"
    actionable = sum(f["severity"] != "info" for f in diagnostics["findings"])
    if actionable:
        overview += f" 共通診断で確認すべき所見が {actionable} 件あります。"
    lines = ["# 通信調査レポート", "", f"症状: {md(case['symptom'])}", "",
             f"実行ID: `{analysis['run_id']}`", "", f"調査状態: {md(STATES.get(case.get('state'), case.get('state')))}", "",
             "## 現在わかっていること", "", overview, "",
             "## 証拠の品質", "", md(QUALITY.get(quality["status"], quality["status"])), ""]
    lines.extend(f"- [{md(i['severity'])}] {md(i['message'])} — {md(i['effect'])}" for i in quality["issues"])
    lines += ["", "## 取得条件・制約", ""]
    for capture in analysis["captures"]:
        lines.append(f"- {md(capture['path'])}: {capture['packet_count']} packets / {capture['backend']} / SHA-256 `{capture['sha256']}`")
    lines.extend(f"- {md(w)}" for w in warnings)
    lines += ["", "## 標準の共通診断（独自仕様は不要）", "",
              "未観測は正常を意味しません。DNSのキャプチャ全体の所見は、対象サービスとの関連を確認してください。", "",
              "| 層 | 観測状況 |", "|---|---|"]
    lines.extend(f"| {layer} | {'観測あり' if state == 'observed' else '未観測・未判定'} |" for layer, state in diagnostics["coverage"].items())
    for finding in diagnostics["findings"]:
        lines += ["", f"### {md(finding['title'])}", "", f"根拠: {md(', '.join(finding['evidence_ids']))}" + (f"（全 {finding['evidence_total']} 件中）" if finding.get("evidence_total", 0) > len(finding["evidence_ids"]) else ""), "",
                  f"次の確認: {md(finding['next_check'])}", "",
                  f"候補: {md(' / '.join(finding['candidates']))}", ""]
        if finding["details"]:
            lines += ["```json", json.dumps(finding["details"], ensure_ascii=False, indent=2), "```"]
    lines += ["", "## 計測", "", "| 区間 | 時間(ms) | 根拠 |", "|---|---:|---|"]
    for item in analysis["measurements"]:
        lines.append(f"| {LABELS.get(item['name'], item['name'])} | {item['value_ms']:.3f} | {', '.join(item['evidence_ids'])} |")
    lines.append("")
    for item in analysis["measurements"]:
        for limitation in item["limitations"]:
            lines.append(f"- 注記 ({item['id']}): {md(limitation)}")
    lines += ["", "## 接続の時系列", "", "```mermaid", "sequenceDiagram", "    participant C as Client", "    participant S as Server"]
    for conn in analysis["connections"][:20]:
        lines.append(f"    Note over C,S: {conn['id']}")
        for event in conn["events"][:50]:
            direction = "S-->>C" if event.get("sender") == "server" or event["kind"] == "syn_ack" else "C->>S"
            if event["kind"] == "zero_window":
                lines.append(f"    Note over C,S: {event['kind']} / {event['evidence_id']}")
            else:
                lines.append(f"    {direction}: {event['kind']} / {event['evidence_id']}")
    lines += ["```", "", "図は先頭20接続・各50イベントまで。全件はanalysis.jsonを参照。", "", "## 原因候補と次の確認", ""]
    for hypothesis in hypotheses:
        lines += [f"### {md(hypothesis['id'])}: {md(hypothesis['statement'])}", "",
                  f"状態: {md(hypothesis['status'])} / 作成元: {md(hypothesis.get('source', 'user'))}", "",
                  f"根拠: {md(', '.join(hypothesis.get('evidence_ids', [])))}", "",
                  f"反する証拠: {md(', '.join(hypothesis.get('contrary_evidence_ids', [])) or 'なし')}", "",
                  f"次の確認: {md(hypothesis['next_check'])}", "",
                  f"結果ごとの判断: {md(hypothesis['branches'])}", ""]
        lines += [f"対象・観測期間: {md(hypothesis_scope(hypothesis))}", ""]
        if hypothesis.get("needs_revalidation"):
            lines += ["**再確認が必要: 過去の解析での判断です。今回の取得データ・対象条件では未検証です。**", ""]
        if hypothesis.get("revalidation"):
            lines += [f"再確認の内容（解析 {md(hypothesis.get('revalidated_in_run', '不明'))}）: {md(hypothesis['revalidation'])}", ""]
        if hypothesis.get("verification"):
            lines += [f"検証内容: {md(hypothesis['verification'])}", ""]
    lines += ["## 候補を絞る確認（優先順）", ""]
    for check in [c for c in plan if c["check_id"] not in done][:5]:
        lines += [f"- **{md(check['purpose'])}**（手間 {check['effort']} / {md(check['risk'])}）: {md(check['procedure'])}"]
        lines.extend(f"  - {md(cause)}: {md(expected)}" for cause, expected in check["expected"].items())
        lines.extend(f"  - {md(line)}" for line in access_lines(check))
    if extras["checks"]:
        lines += ["", "## 実施した確認", ""]
        lines.extend(f"- {md(c['check_id'])}: {md(c['result'])}（根拠: {md(', '.join(c['evidence_ids']) or 'なし')}）" for c in extras["checks"])
    if extras["external"]:
        lines += ["", "## ログ・外部の根拠", ""]
        lines.extend(f"- `{md(e['id'])}` [{md(e['kind'])}] {md(e['summary'])}" for e in extras["external"])
    scan_rows = nmap_rows(extras['external'])
    if scan_rows:
        lines += ['', '## Nmapによる追加観測', '', '障害時の状態やアプリの復旧を確定するものではありません。最大50件。全件は根拠IDから参照できます。', '',
                  '| 根拠 | 観測位置 | 実行状態 | 観測開始 | 対象 | ポート状態 | 理由 |', '|---|---|---|---|---|---|---|']
        lines.extend('| ' + ' | '.join(md(value) for value in row) + ' |' for row in scan_rows)
    transfer_rows = curl_rows(extras['external'])
    if transfer_rows:
        lines += ['', '## curlによる取得確認', '', '成功は指定した取得操作の結果です。内容の正しさや業務全体の復旧は別途確認してください。', '',
                  '| 根拠 | 観測位置 | 開始時刻 | 接続先 | 結果 | 応答コード | 取得バイト | 合計秒 |', '|---|---|---|---|---|---|---|---|']
        lines.extend('| ' + ' | '.join(md(value) for value in row) + ' |' for row in transfer_rows)
    snapshot_rows = host_rows(extras['external'])
    if snapshot_rows:
        lines += ['', '## 端末状態の採取', '', '取得できなかった項目は異常なしを意味しません。採取時刻の状態であり、過去の障害時と一致するとは限りません。', '',
                  '| 根拠 | 端末 | 役割 | 採取開始 | 項目 | 状態 | 行数 | 打ち切り |', '|---|---|---|---|---|---|---|---|']
        lines.extend('| ' + ' | '.join(md(value) for value in row) + ' |' for row in snapshot_rows)
    lines.append("")
    if specs:
        lines += ["## 指定された通信仕様", "", f"{md(specs['name'])} / revision: {md(specs['revision'])} / {specs['status']}", "",
                  f"SHA-256: `{specs['sha256']}`", "",
                  "| 接続 | 要求番号 | 判定 | 応答時間(ms) | 根拠 |", "|---|---:|---|---:|---|"]
        for check in specs["checks"]:
            lines.append(f"| {check['connection_id']} | {check['request_id']} | {check['status']} | {check['elapsed_ms']} | {', '.join(check['evidence_ids'])} |")
        lines += ["", "応答時間は要求・応答の全バイトを観測した時刻の差です。未観測はタイムアウトの断定ではありません。", ""]
        lines.extend(f"- {md(w)}" for w in specs["warnings"])
    lines += ["", "## 再現情報", "", "同じフォルダのmanifest.json、analysis.json、evidence.jsonl、protocol.md（指定時）を参照。",
              "対象条件・ツール版・抽出コマンドを保存しています。AIへ自動送信する機能はありません。", ""]
    atomic_text(directory / "report.md", "\n".join(lines))

    referenced = {e["evidence_id"] for c in analysis["connections"] for e in c["events"]}
    referenced.update(ref for m in analysis["measurements"] for ref in m["evidence_ids"])
    referenced.update(ref for h in hypotheses for ref in h.get("evidence_ids", []))
    if specs:
        referenced.update(ref for c in specs["checks"] for ref in c["evidence_ids"])
    referenced.update(ref for f in diagnostics["findings"] for ref in f["evidence_ids"])
    evidence_rows = []
    evidence_path = directory / "evidence.jsonl"
    if evidence_path.exists():
        with evidence_path.open(encoding="utf-8") as stream:
            for line in stream:
                value = json.loads(line)
                if value["id"] in referenced:
                    evidence_rows.append(value)
                    if len(evidence_rows) >= 2000:
                        break
    visible_evidence = {e["id"] for e in evidence_rows}

    def cell(value):
        return re.sub(r"cap-[a-f0-9]{16}:frame:\d+", lambda m: f"<a href='#{m[0]}'>{m[0]}</a>" if m[0] in visible_evidence else m[0], esc(value))

    def table(headers, rows):
        return "<div class='scroll'><table><thead><tr>" + "".join(f"<th>{esc(x)}</th>" for x in headers) + "</tr></thead><tbody>" + "".join(
            "<tr>" + "".join(f"<td>{cell(x)}</td>" for x in row) + "</tr>" for row in rows) + "</tbody></table></div>"

    measurement_table = table(["区間", "時間(ms)", "根拠", "制約"],
                              [(LABELS.get(x["name"], x["name"]), f"{x['value_ms']:.3f}",
                                ", ".join(x["evidence_ids"]), " / ".join(x["limitations"])) for x in analysis["measurements"]])
    connection_table = table(["接続", "Client", "Server", "観測状態", "SYN反復", "制約"],
                             [(c["id"], ":".join(map(str, c["client"])), ":".join(map(str, c["server"])),
                               STATUS.get(c["status"], c["status"]), c["syn_repeats"], " / ".join(c["limitations"])) for c in analysis["connections"]])
    events = [(c["id"], e) for c in analysis["connections"] for e in c["events"]]
    events.sort(key=lambda x: x[1]["time_ns"])
    origin = events[0][1]["time_ns"] if events else 0
    timeline = table(["相対時刻(s)", "接続", "イベント", "根拠"],
                     [(f"{(e['time_ns'] - origin)/1e9:.6f}", c, STATUS.get(e["kind"], e["kind"]), e["evidence_id"]) for c, e in events[:1000]])
    cards = "".join(f"<article><span class='tag'>{esc(STATUS.get(h['status'], h['status']))}</span><h3>{esc(h['statement'])}</h3>"
                    + ("<p><b>再確認が必要: 過去の解析での判断です。今回の取得データ・対象条件では未検証です。</b></p>" if h.get("needs_revalidation") else "")
                    + (f"<p><b>再確認の内容（解析 {esc(h.get('revalidated_in_run', '不明'))}）</b><br>{esc(h['revalidation'])}</p>" if h.get("revalidation") else "")
                    + f"<p>対象・観測期間: {esc(hypothesis_scope(h))}</p>"
                    + f"<p><b>次の確認</b><br>{esc(h['next_check'])}</p><p><b>結果ごとの判断</b><br>{esc(h['branches'])}</p>"
                    + (f"<p><b>検証内容</b><br>{esc(h['verification'])}</p>" if h.get("verification") else "")
                    + f"<small>根拠: {cell(', '.join(h.get('evidence_ids', [])))}</small>"
                    + (f"<br><small>反する証拠: {cell(', '.join(h['contrary_evidence_ids']))}</small>" if h.get("contrary_evidence_ids") else "")
                    + "</article>" for h in hypotheses)
    open_checks = [c for c in plan if c["check_id"] not in done][:5]
    plan_cards = "".join(f"<article><span class='tag'>手間 {c['effort']} / {esc(c['risk'])}</span><h3>{esc(c['purpose'])}</h3><p>{esc(c['procedure'])}</p><ul>"
                         + "".join(f"<li>{esc(cause)}: {esc(expected)}</li>" for cause, expected in c["expected"].items()) + "</ul>"
                         + "".join(f"<p>{esc(line)}</p>" for line in access_lines(c)) + "</article>" for c in open_checks)
    quality_block = f"<h2>証拠の品質</h2><p>{esc(QUALITY.get(quality['status'], quality['status']))}</p>" + ("<ul>" + "".join(f"<li><b>{esc(i['severity'])}</b> {esc(i['message'])} — {esc(i['effect'])}</li>" for i in quality["issues"]) + "</ul>" if quality["issues"] else "")
    done_block = "".join(f"<li>{esc(c['check_id'])}: {esc(c['result'])}</li>" for c in extras["checks"])
    external_block = "".join(f"<li><code>{esc(e['id'])}</code> [{esc(e['kind'])}] {esc(e['summary'])}</li>" for e in extras["external"])
    specification = ""
    if specs:
        specification = f"<h2>通信仕様</h2><p>{esc(specs['name'])} / {esc(specs['revision'])} / {esc(STATUS.get(specs['status'], specs['status']))}</p>"
        specification += table(["接続", "要求番号", "判定", "応答時間(ms)", "期限(ms)", "根拠"],
                               [(c["connection_id"], c["request_id"], STATUS.get(c["status"], c["status"]), c["elapsed_ms"], c["limit_ms"],
                                 ", ".join(c["evidence_ids"])) for c in specs["checks"]])
        specification += "<p>未観測はタイムアウトの断定ではありません。計測は全バイトの観測完了時刻を使います。</p>"
        specification += "<ul>" + "".join(f"<li>{esc(w)}</li>" for w in specs["warnings"]) + "</ul>"
    document = """<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>通信調査レポート</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#192b40;font:15px/1.75 system-ui,sans-serif}
main{max-width:1240px;margin:auto;padding:40px 24px}header{padding:30px;background:#122b43;color:#fff;border-radius:16px}
h1{font-size:28px;margin:8px 0}h2{margin-top:36px}h3{font-size:17px}.tag{display:inline-block;background:#dcecf6;color:#214a68;padding:2px 10px;border-radius:20px;font-size:12px}
.scroll{overflow:auto;background:white;border:1px solid #dbe1e9;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e4e8ef;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f6;white-space:nowrap}
article{padding:20px;background:#fff;border:1px solid #dbe1e9;border-radius:12px;margin:12px 0}small{color:#546577}details{background:#fff;padding:16px;border-radius:10px}li{margin:8px 0}a{color:#216c9d}footer{margin:36px 0;color:#546577}@media print{body{background:white}main{padding:0}header{color:#192b40;background:white}.scroll{overflow:visible}article{break-inside:avoid}}
</style><main>"""
    document += f"<header><span>PACKET INVESTIGATION / 初期版</span><h1>通信の状況を、根拠からたどる</h1><p>{esc(case['symptom'])}</p><small style='color:#c4d8e8'>{esc(analysis['run_id'])}</small></header>"
    document += f"<p>調査状態: <b>{esc(STATES.get(case.get('state'), case.get('state')))}</b></p>"
    document += f"<h2>現在わかっていること</h2><p>{esc(overview)}</p>" + quality_block + "<details open><summary>取得条件と観測の限界</summary><ul>"
    document += "".join(f"<li>{esc(w)}</li>" for w in warnings) + "</ul></details>"
    document += "<h2>標準の共通診断</h2><p>独自仕様を指定しなくても調べます。未観測は正常という意味ではありません。</p>"
    document += table(["層", "観測状況"], [(layer.upper(), "観測あり" if state == "observed" else "未観測・未判定") for layer, state in diagnostics["coverage"].items()])
    for f in diagnostics["findings"]:
        scope = "キャプチャ全体の参考所見" if f["scope"] == "capture_context" else "観測した事実"
        document += f"<article><span class='tag'>{esc(f['layer'])} / {scope} / {f.get('count', 1)} 件</span><h3>{esc(f['title'])}</h3>"
        document += f"<p><b>次の確認</b><br>{esc(f['next_check'])}</p><p>原因候補: {esc(' / '.join(f['candidates']) or '追加確認で判断')}</p>"
        if f["details"]:
            document += "<details><summary>観測の詳細</summary><pre style='white-space:pre-wrap;overflow-wrap:anywhere'>" + esc(json.dumps(f["details"], ensure_ascii=False, indent=2)) + "</pre></details>"
        document += f"<small>根拠: {cell(', '.join(f['evidence_ids']))}</small></article>"
    document += "<h2>待ち時間の計測</h2>" + measurement_table + "<h2>接続一覧</h2>" + connection_table
    document += "<h2>通信の時系列</h2><p>最初のイベントからの相対時刻。先頭1,000イベントを表示。</p>" + timeline
    document += "<h2>原因候補と次の確認</h2>" + cards + ("<h2>候補を絞る確認（優先順）</h2>" + plan_cards if plan_cards else "") + specification
    if done_block:
        document += "<h2>実施した確認</h2><ul>" + done_block + "</ul>"
    if external_block:
        document += "<h2>ログ・外部の根拠</h2><ul>" + external_block + "</ul>"
    if scan_rows:
        document += '<h2>Nmapによる追加観測</h2><p>障害時の状態やアプリの復旧を確定するものではありません。最大50件。全件は根拠IDから参照できます。</p>'
        document += table(['根拠', '観測位置', '実行状態', '観測開始', '対象', 'ポート状態', '理由'], scan_rows)
    if transfer_rows:
        document += '<h2>curlによる取得確認</h2><p>成功は指定した取得操作の結果です。内容の正しさや業務全体の復旧は別途確認してください。</p>'
        document += table(['根拠', '観測位置', '開始時刻', '接続先', '結果', '応答コード', '取得バイト', '合計秒'], transfer_rows)
    if snapshot_rows:
        document += '<h2>端末状態の採取</h2><p>取得できなかった項目は異常なしを意味しません。採取時刻の状態であり、過去の障害時と一致するとは限りません。</p>'
        document += table(['根拠', '端末', '役割', '採取開始', '項目', '状態', '行数', '打ち切り'], snapshot_rows)
    sources = {c["id"]: c["path"] for c in analysis["captures"]}
    evidence_rows = [e for e in evidence_rows if e["capture_id"] in sources] + [e for e in evidence_rows if e["capture_id"] not in sources]
    document += "<h2>根拠パケット</h2><p>リンク先の原本をWiresharkで開き、表示フィルターをコピーして確認できます。参照された先頭2,000件まで。</p>"
    for e in evidence_rows:
        document += (f"<details id='{esc(e['id'])}'><summary>{esc(e['id'])} — {esc(e['src'])}:{esc(e['sport'] if e['sport'] is not None else '-')} → {esc(e['dst'])}:{esc(e['dport'] if e['dport'] is not None else '-')}</summary>"
                     f"<p>原本: {esc(sources.get(e['capture_id'], '以前の解析のファイル'))}<br>表示フィルター: <code>{esc(e['filter'])}</code></p></details>")
    document += "<footer>原因候補は未検証です。<a href='analysis.json'>解析JSON</a> / <a href='manifest.json'>実行条件</a> / <a href='report.md'>Markdown</a><br>外部サービス・CDNへの接続はありません。</footer></main></html>"
    atomic_text(directory / "report.html", document)
    return {"markdown": str((directory / "report.md").resolve()), "html": str((directory / "report.html").resolve())}
