"""Turn observed findings into competing causes and the check that best separates them.

Findings are facts; causes are explanations. A cause is listed only when an observation
supports it, and it stays a candidate until someone verifies it.
"""

SYMPTOMS = {
    "no_recovery": ("復帰", "再接続", "つながり直", "リカバリ", "reconnect", "recover"),
    "no_connect": ("つながらない", "繋がらない", "接続できない", "接続不可", "connect fail", "unreachable", "refused"),
    "drops": ("切れ", "切断", "落ちる", "disconnect", "reset"),
    "intermittent": ("たまに", "時々", "ときどき", "間欠", "intermittent"),
    "slow": ("遅い", "遅延", "時間がかか", "もたつ", "タイムアウト", "slow", "latency", "timeout"),
}
SYMPTOM_LAYERS = {
    "no_connect": ("name_or_address", "reachability", "service", "tls", "application"),
    "slow": ("performance", "transport_loss", "application", "reachability"),
    "drops": ("session_loss", "transport_loss", "application"),
    "no_recovery": ("recovery", "session_loss", "reachability", "service"),
    "intermittent": ("session_loss", "transport_loss", "name_or_address", "performance"),
    "unknown": (),
}


def classify_symptom(text):
    lowered = (text or "").lower()
    for kind, words in SYMPTOMS.items():
        if any(word in lowered for word in words):
            return kind
    return "unknown"


CAUSES = {
    "dns_failure": {"layer": "name_or_address", "statement": "名前解決の失敗が接続できない原因である",
                    "support": ("dns_error", "dns_no_observed_response"), "contra": (), "checks": ("resolve_on_client",)},
    "l2_address_problem": {"layer": "name_or_address", "statement": "同一セグメントのIP重複、または相手のARP未応答が原因である",
                           "support": ("arp_duplicate_ip", "arp_no_reply"), "contra": ("tcp_refused",), "checks": ("check_peer_link", "arp_table")},
    "no_listener": {"layer": "service", "statement": "相手のポートが待ち受けていない",
                    "support": ("tcp_refused", "icmp_port"), "contra": ("tcp_rst_ttl_anomaly", "administratively_prohibited"), "checks": ("listen_state", "two_point")},
    "active_reject": {"layer": "reachability", "statement": "経路上のFW/ACLが通信を能動的に拒否している",
                      "support": ("administratively_prohibited", "tcp_rst_ttl_anomaly"), "contra": (), "checks": ("firewall_log", "two_point")},
    "silent_drop": {"layer": "reachability", "statement": "経路上で通信が黙って破棄されている",
                    "support": ("tcp_no_reply",), "contra": ("tcp_refused", "tcp_reset", "administratively_prohibited", "icmp_port"), "checks": ("two_point", "firewall_log", "listen_state")},
    "peer_down": {"layer": "reachability", "statement": "相手機器が停止している、または回線から外れている",
                  "support": ("tcp_no_reply", "tcp_unanswered_tail", "arp_no_reply"), "contra": ("tcp_refused", "administratively_prohibited", "icmp_port", "tcp_large_segment_loss", "arp_peer_answered"), "checks": ("check_peer_link", "two_point")},
    "tls_certificate": {"layer": "tls", "statement": "サーバー証明書の問題でTLSが失敗している",
                        "support": ("certificate_expired", "certificate_not_yet_valid", "certificate_name_mismatch", "tls_alert_certificate"), "contra": (), "checks": ("probe_tls",)},
    "tls_negotiation": {"layer": "tls", "statement": "TLS方式・バージョンの不一致で交渉が失敗している",
                        "support": ("tls_no_server_hello", "tls_alert_other"), "contra": (), "checks": ("probe_tls", "server_tls_config")},
    "application_error": {"layer": "application", "statement": "通信は届いているが、アプリケーションがエラーを返している",
                          "support": ("http_error", "ftp_error", "protocol_error_response"), "contra": (), "checks": ("server_app_log",)},
    "ftp_data_path": {"layer": "application", "statement": "FTPのデータ接続の経路・通知アドレスに問題がある",
                      "support": ("ftp_data_connection_failed", "ftp_pasv_address_mismatch"), "contra": (), "checks": ("firewall_log", "server_tls_config")},
    "path_loss": {"layer": "transport_loss", "statement": "経路上のパケットロスで再送が起きている",
                  "support": ("tcp_repeated_data",), "contra": ("tcp_large_segment_loss", "tcp_zero_window", "tcp_unanswered_tail"), "checks": ("two_point", "interface_counters")},
    "mtu_blackhole": {"layer": "transport_loss", "statement": "MTUの不一致で大きなパケットだけが届いていない",
                      "support": ("tcp_large_segment_loss", "icmp_mtu"), "contra": (), "checks": ("df_ping", "two_point")},
    "receiver_stall": {"layer": "performance", "statement": "受信側アプリの処理が追いついていない",
                       "support": ("tcp_zero_window",), "contra": (), "checks": ("receiver_load",)},
    "server_app_delay": {"layer": "performance", "statement": "サーバー側アプリの処理が遅い",
                         "support": ("app_response_slow", "protocol_response_late"), "contra": ("tcp_repeated_data",), "checks": ("server_app_log", "two_point")},
    "application_restart_wait": {"layer": "recovery", "statement": "切断後、クライアント側アプリが再接続まで待機している",
                                 "support": ("measurement_reconnect_gap", "reconnect_interval_regular"), "contra": (), "checks": ("client_app_log",)},
    "session_timeout": {"layer": "session_loss", "statement": "経路機器やアプリの無通信タイムアウトで接続が失われている",
                        "support": ("tcp_failure_after_idle",), "contra": (), "checks": ("firewall_timeout", "keepalive_test")},
    "session_abort": {"layer": "session_loss", "statement": "相手アプリや経路機器が確立済みの接続を中断している",
                      "support": ("tcp_reset",), "contra": (), "checks": ("server_app_log", "two_point")},
}

CHECKS = {
    "two_point": {"purpose": "どの区間で通信が消える／生成されるかを切り分ける", "effort": 2, "risk": "読み取りのみ",
                  "procedure": "クライアント側とサーバー側の両方で同時にキャプチャし、`two-point` で突合する",
                  "predictions": {"silent_drop": "クライアント側のSYNがサーバー側に届かない", "peer_down": "サーバー側にSYNは届くが応答がない、または相手の取得自体ができない",
                                  "no_listener": "サーバー側でも同じRSTが相手自身から出ている", "active_reject": "RSTがサーバー側には見えない（途中の機器が生成）",
                                  "path_loss": "片方で見えるパケットが他方で欠ける", "mtu_blackhole": "大きなパケットだけがサーバー側に届かない",
                                  "server_app_delay": "サーバー側でも要求の受信から応答までが長い", "session_abort": "RSTの生成元が相手か途中の機器か分かる"}},
    "firewall_log": {"purpose": "経路機器が拒否・破棄したかを確定する", "effort": 2, "risk": "読み取りのみ",
                     "procedure": "同じ時刻・送信元・宛先・ポートのFW/ルーターのログと適用ルールを確認する（`log-match` で照合できる）",
                     "predictions": {"silent_drop": "DROPのログがある", "active_reject": "REJECT/DENYのログがある", "ftp_data_path": "データ用ポートの拒否ログがある",
                                     "peer_down": "拒否ログがなく許可の記録のみ", "no_listener": "許可の記録のみ"}},
    "listen_state": {"purpose": "相手のポートが待ち受けているか確認する", "effort": 1, "risk": "読み取りのみ",
                     "procedure": "相手機器で待受ポート一覧（ss -ltn / netstat -ano / 機器の状態画面）を確認する",
                     "predictions": {"no_listener": "対象ポートの待受がない", "silent_drop": "待受はある", "active_reject": "待受はある"}},
    "check_peer_link": {"purpose": "相手が生きていて回線上にいるか確認する", "effort": 1, "risk": "読み取りのみ",
                        "procedure": "相手の電源・リンクランプ・スイッチポート状態を確認し、同じセグメントからpingする",
                        "predictions": {"peer_down": "電源断・リンク断がある", "l2_address_problem": "リンクは正常だがIP設定やVLANが食い違う", "silent_drop": "相手は正常に動作している"}},
    "arp_table": {"purpose": "IPとMACの対応が正しいか確認する", "effort": 1, "risk": "読み取りのみ",
                  "procedure": "arp -a で相手IPのMACを確認し、機器のラベルのMACと照合する",
                  "predictions": {"l2_address_problem": "MACが想定と違う、または未解決"}},
    "resolve_on_client": {"purpose": "接続元で名前解決が成功するか確認する", "effort": 1, "risk": "読み取りのみ",
                          "procedure": "接続元で nslookup <名前> を実行し、利用DNSサーバーと応答を確認する", "predictions": {"dns_failure": "解決に失敗、または誤ったアドレスが返る"}},
    "probe_tls": {"purpose": "証明書と方式の問題を切り分ける", "effort": 1, "risk": "相手へ1回接続する",
                  "procedure": "`probe --host <相手> --port <ポート> --tls direct --case <調査>` を実行する（FTPSは ftp-starttls）",
                  "predictions": {"tls_certificate": "証明書検証エラーの理由が返る", "tls_negotiation": "検証に至らず交渉で失敗する"}},
    "server_tls_config": {"purpose": "サーバーの通信方式の設定を確認する", "effort": 2, "risk": "読み取りのみ",
                          "procedure": "サーバーのTLS/FTPS方式、対応バージョン、PASVアドレスとポート範囲の設定を確認する",
                          "predictions": {"tls_negotiation": "方式・バージョンが接続元と合わない", "ftp_data_path": "PASVの通知アドレスやポート範囲が合わない"}},
    "server_app_log": {"purpose": "サーバーアプリが要求を受けて何をしたか確認する", "effort": 2, "risk": "読み取りのみ",
                       "procedure": "同じ時刻のサーバーアプリのログを確認し、要求の受信時刻・処理時間・エラーを照合する（`log-match` で照合できる）",
                       "predictions": {"application_error": "エラーの理由が記録されている", "server_app_delay": "受信から応答までの処理が長い", "session_abort": "アプリが切断した記録がある"}},
    "client_app_log": {"purpose": "切断検知と再接続開始の時刻を確認する", "effort": 2, "risk": "読み取りのみ",
                       "procedure": "クライアント側の切断検知時刻と再接続処理の開始時刻をログで確認し、リトライ設定と比べる",
                       "predictions": {"application_restart_wait": "検知後にリトライ設定の分だけ待っている"}},
    "interface_counters": {"purpose": "物理・リンク層でエラーが出ているか確認する", "effort": 1, "risk": "読み取りのみ",
                           "procedure": "スイッチ・NICのエラーカウンタ（CRC、ドロップ）を前後で比較する", "predictions": {"path_loss": "エラー/ドロップが増えている"}},
    "df_ping": {"purpose": "経路で通るパケットサイズを調べる", "effort": 1, "risk": "ICMPを少量送る",
                "procedure": "ping -f -l <サイズ> <相手>（Linuxは ping -M do -s <サイズ>）でサイズを変えて試す", "predictions": {"mtu_blackhole": "特定サイズ以上だけ通らない"}},
    "receiver_load": {"purpose": "受信側の処理状況を確認する", "effort": 2, "risk": "読み取りのみ",
                      "procedure": "受信側のCPU、タスク状態、受信処理のログを同じ時刻で確認する", "predictions": {"receiver_stall": "受信処理が停滞している"}},
    "firewall_timeout": {"purpose": "無通信での切断条件を確認する", "effort": 2, "risk": "読み取りのみ",
                         "procedure": "経路上のFW/NATの無通信タイムアウト値を確認し、観測した無通信時間と比べる", "predictions": {"session_timeout": "タイムアウト値が無通信時間以下である"}},
    "keepalive_test": {"purpose": "定期通信で切断が防げるか確認する", "effort": 3, "risk": "設定変更を伴う。試験環境で実施",
                       "procedure": "試験環境でKeepAlive/ハートビートをタイムアウト未満の間隔で有効にして再現を確認する", "predictions": {"session_timeout": "切断が起きなくなる"}},
}


# What each check needs from the user. direct_access names read-only access that would let an
# agent collect it directly; None means a person must act or the check changes something.
ACCESS = {
    "two_point": {"needs": "接続先側で同じ時間帯に取得したキャプチャ", "provide": "pcapを渡してもらえれば `two-point` で突合する", "direct_access": "接続先側の取得ファイルへの読み取りアクセス"},
    "firewall_log": {"needs": "経路上のFW/ルーターの該当時間帯のログ", "provide": "ログファイルを渡してもらえれば `log-match` で接続と照合する", "direct_access": "FWログの読み取り専用アクセス"},
    "listen_state": {"needs": "接続先の待受ポート一覧", "provide": "ss -ltn / netstat -ano の出力か、機器の状態画面を渡してもらう", "direct_access": "接続先サーバーの読み取り専用シェル（稼働中の専用機器は対象外）"},
    "check_peer_link": {"needs": "接続先の電源・リンク状態とスイッチのポート状態", "provide": "現地の確認結果かスイッチの表示を渡してもらう", "direct_access": "スイッチのポート状態の読み取り専用アクセス"},
    "arp_table": {"needs": "接続元のARPテーブルと機器のMAC", "provide": "arp -a の出力と機器ラベルのMACを渡してもらう", "direct_access": "接続元端末の読み取り専用シェル"},
    "resolve_on_client": {"needs": "接続元での名前解決の結果", "provide": "nslookup の出力を渡してもらう", "direct_access": "接続元端末の読み取り専用シェル"},
    "probe_tls": {"needs": "接続先への接続確認の許可", "provide": "相手とポートの指定と許可をもらえれば `probe` を実行する", "direct_access": None},
    "server_tls_config": {"needs": "サーバーのTLS/FTPS設定", "provide": "設定内容を渡してもらう", "direct_access": "サーバー設定の読み取り専用アクセス"},
    "server_app_log": {"needs": "サーバーアプリの該当時間帯のログ", "provide": "ログファイルを渡してもらえれば `log-match` で照合する", "direct_access": "サーバーログの読み取り専用アクセス"},
    "client_app_log": {"needs": "クライアントアプリのログとリトライ設定", "provide": "ログファイルと設定値を渡してもらう", "direct_access": "クライアントログの読み取り専用アクセス"},
    "interface_counters": {"needs": "スイッチ・NICのエラーカウンタ（障害の前後）", "provide": "前後の表示を渡してもらう。Windows端末は `host-snapshot` と `host-compare` で比べられる", "direct_access": "スイッチ・NICのカウンタの読み取り専用アクセス"},
    "df_ping": {"needs": "接続元からサイズを変えたpingの結果", "provide": "ping の結果を渡してもらう", "direct_access": None},
    "receiver_load": {"needs": "受信側のCPU・タスク状態・受信処理のログ", "provide": "同じ時刻の記録を渡してもらう", "direct_access": "受信側の負荷情報の読み取り専用アクセス（稼働中の専用機器は対象外）"},
    "firewall_timeout": {"needs": "経路上のFW/NATの無通信タイムアウト設定", "provide": "設定値を渡してもらう", "direct_access": "FW/NAT設定の読み取り専用アクセス"},
    "keepalive_test": {"needs": "試験環境での再現", "provide": "試験環境の結果を渡してもらう", "direct_access": None},
}

INFORMATIVE_CODES = ("arp_peer_answered",)


def signals(findings):
    """Map findings to named signals, splitting codes whose meaning depends on details."""
    found = {}

    def add(name, finding):
        found.setdefault(name, []).append(finding)

    for finding in findings:
        code = finding["code"]
        if finding["severity"] == "info" and code not in INFORMATIVE_CODES:
            continue
        if code == "icmp_unreachable":
            reason = finding["details"].get("reason")
            add({"port": "icmp_port", "mtu": "icmp_mtu"}.get(reason, "icmp_route"), finding)
        elif code == "tls_alert":
            add("tls_alert_certificate" if finding["details"].get("alert") in (42, 43, 44, 45, 46, 48) else "tls_alert_other", finding)
        else:
            add(code, finding)
    return found


def applicable_contra(support, candidates):
    """Return contrary findings only when they cover every supporting finding.

    Connection-level findings are compared by connection and never on truncated lists.
    Findings without a connection (ARP, for example) are compared by peer address.
    """
    applicable = {}
    for finding in support:
        connections = set(finding.get("connections", []))
        if finding.get("connections_total", len(connections)) > len(connections):
            return []
        if connections:
            matched = [c for c in candidates if connections.intersection(c.get("connections", []))]
            if not connections.issubset({cid for c in matched for cid in c.get("connections", [])}):
                return []
        else:
            matched = [c for c in candidates if finding.get("peer") is not None and c.get("peer") == finding["peer"]]
            if not matched:
                return []
        applicable.update((c["id"], c) for c in matched)
    return list(applicable.values())


def build_hypotheses(findings, measurements, symptom_type, quality, target_specified):
    found = signals([f for f in findings if f["scope"] == "selected" or not target_specified])
    gaps = [m for m in measurements if m["name"] in ("observed_gap_before_next_connect_ms", "observed_silence_before_next_connect_ms")]
    priority = SYMPTOM_LAYERS.get(symptom_type, ())
    active = []
    for cause_id, cause in CAUSES.items():
        support = [f for name in cause["support"] for f in found.get(name, [])]
        measurement_ids = []
        if "measurement_reconnect_gap" in cause["support"] and gaps:
            measurement_ids = [m["id"] for m in gaps][:20]
        if not support and not measurement_ids:
            continue
        contra = applicable_contra(support, [f for name in cause["contra"] for f in found.get(name, [])])
        rank = priority.index(cause["layer"]) if cause["layer"] in priority else len(priority)
        active.append({"cause": cause_id, "support": support, "contra": contra, "measurement_ids": measurement_ids,
                       "rank": (bool(contra), rank, -max((f["count"] for f in support), default=0))})
    active.sort(key=lambda item: item["rank"])
    uncontradicted = [item["cause"] for item in active if not item["contra"]]
    plan = rank_checks(uncontradicted or [item["cause"] for item in active])
    hypotheses = []
    for item in active:
        cause = CAUSES[item["cause"]]
        check_id = next((c for c in cause["checks"] if item["cause"] in CHECKS[c]["predictions"]), cause["checks"][0])
        check = CHECKS[check_id]
        refs = [r for f in item["support"] for r in f["evidence_ids"]]
        contrary = [r for f in item["contra"] for r in f["evidence_ids"]]
        hypotheses.append({"id": f"h-{len(hypotheses) + 1:04d}", "status": "candidate", "source": "rule_template", "cause": item["cause"],
                           "statement": cause["statement"], "measurement_ids": item["measurement_ids"],
                           "evidence_ids": list(dict.fromkeys(refs))[:20], "contrary_evidence_ids": list(dict.fromkeys(contrary))[:20],
                           "finding_ids": [f["id"] for f in item["support"]], "next_check": check["procedure"],
                           "branches": f"{check['predictions'].get(item['cause'], '確認結果と照合する')}ならこの候補を支持。そうでなければ棄却して他の候補を確認する",
                           "check_id": check_id, "verification": None, "contradicted": bool(item["contra"])})
    if quality["status"] != "no_issue_detected" or not hypotheses:
        blocking = [i for i in quality["issues"] if i["severity"] in ("blocking", "limiting")]
        if blocking or not hypotheses:
            refs = [r for i in blocking for r in i["evidence_ids"]]
            hypotheses.append({"id": f"h-{len(hypotheses) + 1:04d}", "status": "candidate", "source": "rule_template", "cause": "capture_limitation",
                               "statement": "取得データの制約により、症状の原因を観測できていない可能性がある" if blocking else "今回の観測だけでは、申告された症状の原因を特定できません",
                               "measurement_ids": [], "evidence_ids": list(dict.fromkeys(refs))[:20], "contrary_evidence_ids": [], "finding_ids": [],
                               "next_check": " / ".join(i["effect"] for i in blocking) or "症状の発生時間、対象機器、期待する動作と機器ログを確認する",
                               "branches": "症状時間が取得範囲外なら再取得。範囲内なら該当通信とアプリケーション動作を照合", "check_id": None, "verification": None})
    return hypotheses, plan


def rank_checks(cause_ids, completed=()):
    """Prefer the cheapest check whose expected outcomes differ most across active causes."""
    ranked = []
    done = set(completed)
    for check_id, check in CHECKS.items():
        if check_id in done:
            continue
        relevant = {c: check["predictions"][c] for c in cause_ids if c in check["predictions"]}
        if not relevant:
            continue
        distinct = len(set(relevant.values()))
        score = distinct / check["effort"]
        ranked.append((-score, -len(relevant), check["effort"], check_id, relevant))
    ranked.sort(key=lambda r: r[:4])
    return [{"check_id": check_id, "purpose": CHECKS[check_id]["purpose"], "procedure": CHECKS[check_id]["procedure"],
             "effort": CHECKS[check_id]["effort"], "risk": CHECKS[check_id]["risk"], "separates": len(set(relevant.values())),
             "expected": relevant, **ACCESS[check_id], "narrows": list(relevant),
             "leaves_open": [c for c in cause_ids if c not in relevant]} for _, _, _, check_id, relevant in ranked]


def open_causes(hypotheses):
    """Causes still worth separating; contradicted ones count only if nothing else remains."""
    active = [h for h in hypotheses if h.get("cause") and h["status"] in ("candidate", "supported") and not h.get("needs_revalidation")]
    return [h["cause"] for h in active if not h.get("contradicted")] or [h["cause"] for h in active]
