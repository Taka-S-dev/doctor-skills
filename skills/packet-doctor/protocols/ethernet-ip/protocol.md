# EtherNet/IP（TCP明示メッセージ）

EtherNet/IPのカプセル化ヘッダーの要求・応答を判定するプリセットです。合成データでのみ確認しており、実機の通信では未検証です。使う前に対象機器の動作と照らして確認してください。

## 適用範囲

- TCPサーバーポート: 44818
- バイト順: リトルエンディアン
- UDP 2222 の暗黙メッセージ（I/O通信）は対象外

## メッセージ構造（カプセル化ヘッダー24バイト）

| オフセット | 長さ | 内容 |
|---|---|---|
| 0 | 2バイト | コマンド |
| 2 | 2バイト | データ部の長さ（ヘッダーを含まない） |
| 4 | 4バイト | セッションハンドル |
| 8 | 4バイト | ステータス |
| 12 | 8バイト | 送信者コンテキスト |
| 20 | 4バイト | オプション |

全体長は「値＋24」です。

## 要求・応答

- コマンド 0x0063 ListIdentity、0x0065 RegisterSession、0x006F SendRRData を対象にします。
- 0x0066 UnRegisterSession は下記のルールに定義していないため判定しません。
- 0x0070 SendUnitData は要求と応答がこのヘッダーだけでは対応しないため対象外です。
- 対応付けには送信者コンテキストの先頭4バイトを使います。固定値を使う機器でも、要求と応答が交互に並ぶ間は対応付けます。
- ステータスの値は判定していません。下記の1000 msは例なので、機器の仕様に合わせて変更してください。

## 自動判定ルール

```packet-rules
{
  "version": 1,
  "name": "EtherNet/IP encapsulation",
  "revision": "preset-1",
  "service_port": 44818,
  "byte_order": "little",
  "length": {"offset": 2, "size": 2, "includes_header": false, "adjust": 24},
  "command": {"offset": 0, "size": 2},
  "request_id": {"offset": 12, "size": 4},
  "pairs": [
    {"request": 99, "response": 99},
    {"request": 101, "response": 101},
    {"request": 111, "response": 111}
  ],
  "response_timeout_ms": 1000
}
```
