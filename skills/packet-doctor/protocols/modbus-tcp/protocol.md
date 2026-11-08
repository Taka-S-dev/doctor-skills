# Modbus/TCP

公開仕様「MODBUS Messaging on TCP/IP Implementation Guide」に基づくプリセットです。自動判定に使う前に、対象機器の対応ファンクションと応答時間の期待値に合わせて `pairs` と `response_timeout_ms` を見直してください。

## 適用範囲

- TCPサーバーポート: 502
- バイト順: ビッグエンディアン
- 暗号化なし（Modbus/TCP Security は対象外）

## メッセージ構造（MBAPヘッダー＋PDU）

| オフセット | 長さ | 内容 |
|---|---|---|
| 0 | 2バイト | トランザクションID |
| 2 | 2バイト | プロトコルID（0） |
| 4 | 2バイト | 以降のバイト数（ユニットIDから末尾まで） |
| 6 | 1バイト | ユニットID |
| 7 | 1バイト | ファンクションコード |
| 8 | 可変 | データ |

長さフィールドは先頭6バイトを含まないため、全体長は「値＋6」です。

## 要求・応答

- 正常応答は要求と同じファンクションコードを返します。
- 例外応答は「ファンクションコード＋0x80」を返します（`error: true` で定義）。
- トランザクションIDを固定値で使う機器があります。要求と応答が交互に並ぶ間は対応付けますが、交互でない場合は `ambiguous` として扱います。
- 下記の500 msは例です。規格値ではないので、機器の仕様に合わせて変更してください。

## 自動判定ルール

```packet-rules
{
  "version": 1,
  "name": "Modbus/TCP",
  "revision": "preset-1",
  "service_port": 502,
  "byte_order": "big",
  "length": {"offset": 4, "size": 2, "includes_header": false, "adjust": 6},
  "command": {"offset": 7, "size": 1},
  "request_id": {"offset": 0, "size": 2},
  "pairs": [
    {"request": 1, "response": 1}, {"request": 1, "response": 129, "error": true},
    {"request": 2, "response": 2}, {"request": 2, "response": 130, "error": true},
    {"request": 3, "response": 3}, {"request": 3, "response": 131, "error": true},
    {"request": 4, "response": 4}, {"request": 4, "response": 132, "error": true},
    {"request": 5, "response": 5}, {"request": 5, "response": 133, "error": true},
    {"request": 6, "response": 6}, {"request": 6, "response": 134, "error": true},
    {"request": 15, "response": 15}, {"request": 15, "response": 143, "error": true},
    {"request": 16, "response": 16}, {"request": 16, "response": 144, "error": true},
    {"request": 23, "response": 23}, {"request": 23, "response": 151, "error": true}
  ],
  "response_timeout_ms": 500
}
```
