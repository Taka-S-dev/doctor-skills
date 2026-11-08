# 専用機器との通信

## この領域で先に確認すること

- 同じセグメントが多い。ルーターを疑う前にARP（`arp_no_reply`、`arp_duplicate_ip`）とリンクを見る。
- 機器の同時接続数は少ないことが多い。上限に達すると `tcp_refused` や即時RSTになる。古い接続が残っていないか確認する。
- 機器のTCPスタックは小さく、再送やKeepAliveの動きがPCと異なる。PCの常識で異常と決めない。
- 電源断やケーブル抜けではFIN/RSTが出ない。`observed_silence_before_next_connect_ms` と `tcp_unanswered_tail` を見る。
- ポーリング周期の乱れは `max_idle` と仕様の応答時間で見る。
- 稼働中の機器へのポートスキャンは避ける。接続の試行だけで通信中のセッションに影響することがあるため、ミラーポートなどのパッシブな取得を優先し、`nmap-scan` は機器の管理者の了承があるときだけ使う（[active-checks.md](active-checks.md)）。

## 同梱のプロトコルルール

| プロトコル | ファイル | 確認状況 |
|---|---|---|
| Modbus/TCP | `<skill>/protocols/modbus-tcp/protocol.md` | 合成データとWiresharkの解析器で形式を確認 |
| EtherNet/IP（明示メッセージ） | `<skill>/protocols/ethernet-ip/protocol.md` | 合成データのみ |

応答時間の上限は例であり規格値ではない。機器の仕様に合わせて変更してもらう。

## 独自プロトコルのルールを書く

仕様書を読んで `packet-rules` を作るときは、推測で埋めない。分からない項目は利用者に聞く。

| キー | 意味 |
|---|---|
| `length` | 長さフィールド。全体長なら `includes_header: true`。先頭を含まないなら `false` と、値に足す `adjust` |
| `command` | コマンドIDの位置。1/2/4バイト |
| `request_id` | 要求と応答を対応付ける番号 |
| `pairs` | 要求と応答のコマンド対応。異常応答は `error: true` |
| `response_timeout_ms` | 応答時間の上限 |

作ったら `protocol-check` で検査し、人に内容を確認してもらう。構造の検査は内容の正しさを保証しない。

固定長ヘッダーで長さフィールドがないプロトコルや、UDPは対象外である。tsharkの解析器があれば表示フィルターで直接見る。

## 対応付けの判定

要求番号を再利用していても、要求と応答が交互に並ぶ間は対応付ける。交互でない場合は `ambiguous` とし、推測で対応付けない。`unobserved` はタイムアウトの断定ではない。
