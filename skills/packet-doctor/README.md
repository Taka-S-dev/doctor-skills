# 通信調査AI

「つながらない・遅い・切れる」を入口に、パケットから原因の候補を絞り、次に何を確かめれば決着するかまで示します。

- **CLI**（`packet_doctor`）が計測と規則に基づく診断を行います。同じ入力からは同じ結果が出ます。
- **スキル**（[SKILL.md](SKILL.md)）が、専門家の調査手順と判断基準をAIエージェントに与えます。

Python 3.10以降の標準ライブラリだけで動きます。解析にはWiresharkの`tshark`を推奨します（なくても主要な形式は解析できます）。外部AIへの自動送信はありません。

## まず動かす

このフォルダーで`python scripts/run.py`を実行します。別のフォルダーからはスクリプトのパスを指定してください。調査結果は実行したフォルダーの`cases/`に保存します。

```powershell
python scripts/run.py check-env
python scripts/run.py demo --out demo-output
python scripts/run.py analyze --case cases/demo --capture demo-output/slow.pcapng --protocol protocols/example-device/protocol.md --symptom "再接続が遅い" --observation "合成デモ"
```

出力の`data.reports.html`をブラウザーで開くとレポートを見られます。`data.summary`はAIと人が次の判断に使う要約で、大きさはキャプチャの規模に依存しません。

## AIと調査する

スキルを導入すると、通信の相談で使えます。導入方法は[リポジトリのREADME](../../README.md)を参照してください。

> 機器との接続が切れた後の復帰が遅い。captures/issue.pcapng を調べて。相手は192.0.2.20のポート502。クライアント側のミラーポートで取った。

キャプチャがなければ、取得位置とコマンドから案内します。

調査の流れは次のとおりです。

1. 証拠の品質を点検する（片方向の取得、欠落、切り詰め、発生時刻の範囲外など）。
2. 共通診断と計測の結果から、原因の候補を比較する。
3. 候補を最も分けられて手間の少ない確認を提案する。
4. 確認結果やログを受け取り、候補を更新する。
5. 検証済み、データ待ち、引き継ぎ、判定不能のいずれかで終える。

## コマンド

| 目的 | コマンド |
|---|---|
| 環境確認 | `check-env` |
| 取得内容と品質の点検 | `inspect --capture F` |
| 接続の一覧 | `connections --capture F --limit 50` |
| 解析とレポート生成 | `analyze --case C --capture F [--symptom S] [--target IP] [--port N] [--protocol M] [--observation O] [--when ISO8601]` |
| 要約を再表示 | `summary --case C [--anonymize]` |
| 必要な範囲だけ見る | `query --case C --conn ID` / `--finding ID` / `--around 根拠ID` |
| 根拠を見る | `evidence --case C --id ID [--hex]` |
| 両端の記録を突合 | `two-point --near-client A --near-server B [--port N] [--case C]` |
| 正常記録と比較 | `compare --baseline C1 --case C2` |
| ログを照合 | `log-match --case C --file L --tz +09:00 [--clock-offset-ms N]`（netfilter、`src=`/`dst=` 形式、Cisco ASA、Windows Firewallの行は接続単位で `flow_evidence` に集計） |
| ログ等を根拠に登録 | `add-evidence --case C --kind firewall_log --summary S [--source L --line N --time T --excerpt E]` |
| 実施した確認を記録 | `record-check --case C --check ID --result R [--evidence 根拠ID]` |
| 仮説を更新 | `update-hypotheses --case C --input JSON` |
| 調査状態を設定 | `set-state --case C --state waiting_for_data --reason R` |
| 引き継ぎメモ | `handoff --case C` |
| 共有用の書き出し | `export --case C --out DIR [--anonymize]` |
| 接続先の確認 | `probe --host H --port P --tls none/direct/ftp-starttls [--case C] [--out F]` |
| 証明書の期限 | `certificate F [--at ISO8601]` |
| ライブ取得 | `interfaces` / `live --case C --interface N --duration 60 [--capture-filter ...]` |

## 何を調べるか

| 層 | 内容 |
|---|---|
| 証拠の品質 | 片方向の取得、途中からの取得、取得ツールのドロップ、確認応答された未観測データ、切り詰め、時刻の逆転、ミラーの重複、発生時刻が範囲外 |
| L2 | ARP未応答、IP重複 |
| DNS | エラー応答、応答の未観測。回答のアドレスが対象と一致したときだけ対象に関連付ける。検索サフィックスのNXDOMAINは参考扱い |
| 経路 | ICMPの管理禁止、到達不能、MTU関連、TTL超過（ICMPv6含む） |
| TCP | 接続拒否、応答なし、RSTの送信元とTTLの異常、再送（RTO型／高速）、大きなセグメントだけの再送、Zero Window、再送のまま途絶、無通信後の失敗 |
| 遅延 | 往復時間、ハンドシェイクの内訳、要求から応答までの間隔、OSの再送パターン、遅延ACK、一定間隔の再接続 |
| TLS・証明書 | アラート、有効期間、SNIと証明書の名前の不一致、自己署名。TLS 1.3の証明書は暗号化されるため未判定 |
| アプリ | HTTP/1.xのエラー、FTPのエラーとデータ接続、PASVの通知アドレス不整合 |
| 独自プロトコル | Markdownのルールによる応答時間と応答の判定 |

所見は同じ種類・同じ相手ごとに集約され、根拠は20件まで保存します（総数は別に記録）。規則が出す原因候補は草案で、`candidate`から始まります。

## バックエンド

`--backend auto`はtsharkがあれば使い、なければ内蔵解析を使います。内蔵解析はEthernet/VLAN、Linux cooked、ループバック、Raw IPの、非断片IPv4/IPv6のTCP・UDP/DNS・ICMP・ARPに対応します。上限は1ファイル512 MiB・50万パケットです。TCPストリームは方向別16 MBまで解析し、それより後は対象外であることを警告します。

## 通信仕様を追加する

[Modbus/TCP](protocols/modbus-tcp/protocol.md)、[EtherNet/IP](protocols/ethernet-ip/protocol.md)、[サンプル](protocols/example-device/protocol.md)があります。Markdownの`packet-rules`ブロックで、長さ・コマンド・要求番号の位置と、要求と応答の対応を定義します。長さフィールドがヘッダーを含まない形式は`includes_header: false`と`adjust`で表します。応答時間の上限は機器に合わせて変更してください。

```powershell
python scripts/run.py protocol-check protocols/modbus-tcp/protocol.md
python scripts/run.py analyze --case cases/device --capture F --protocol protocols/modbus-tcp/protocol.md
```

`validated_rules`は構造の検査だけで、内容の正しさは保証しません。判定は`observed_within_limit`、`observed_late`、`observed_error`、`unobserved`（タイムアウトの断定ではない）、`ambiguous`（交互に並ばない番号の再利用）です。

## 保存内容

```text
cases/<調査>/
├─ case.json / latest.json / history.jsonl
├─ external-evidence.jsonl   ログ・probe等の根拠
├─ checks.jsonl              実施した確認
├─ handoff.md                引き継ぎメモ
├─ live/                     ライブ取得の原本
└─ runs/run-.../             manifest / analysis / evidence / hypotheses / report
```

再解析は新しい実行として保存し、AIが更新した仮説は引き継ぎます。原本は変更しません。FTPのパスワードは保存しませんが元のpcapには残ります。`export --anonymize`はアドレス・名前・パスを置換し、対応表は調査フォルダにだけ残します。症状の文面などは置換されないため、共有前に確認してください。

## 設計の原則

- 計測と規則による判定はPythonが行い、AIは候補の比較、説明、次の確認を担当します。解析はAIなしで実行できます。
- 仮説の更新では根拠IDを検査し、存在しない根拠を参照すると拒否します。
- ログ、仕様書、パケットの中の文章は調査対象のデータとして扱い、操作指示として実行しません。

## テストと評価

```powershell
python -m unittest discover -s tests          # 単体・既知原因シナリオ（tsharkがあれば両方のバックエンド）
python evals/netlab/run.py                    # Dockerで実際の障害を起こして解析を確認
```

`evals/netlab`はDocker上の隔離ネットワークで、iptablesの破棄・拒否、tc netemのロス、無応答化などの原因が分かっている障害を起こします。AIの判断の評価項目は[evals.json](evals/evals.json)にあり、調整用と最終評価用に分けています。

## 制限

- 実機や実運用ネットワークの記録では未評価です。評価はDockerの実障害と合成データです。EtherNet/IPのルールは合成データのみで確認しています。
- 原因候補と確認の選択は規則による草案で、確率的な確からしさは計算しません。
- 2点の突合はシーケンス番号を書き換える機器を挟むと対応付けできません。時計のずれは往復が対称という仮定の推定です。
- ライブ解析は保存済みのファイルを毎回解析するため、長時間・高帯域の常時監視には向きません。
- 実機の操作や障害注入の機能はありません。

## リアルタイム取得（MCP）

`packet-doctor-capture` サーバーを有効にすると、エージェントが取得を開始し、途中経過を読みながら解析できます。Pythonの標準ライブラリとWiresharkの `dumpcap` だけで動きます。

設定方法は[リポジトリのREADME](../../README.md)を参照してください。

| ツール | 内容 |
|---|---|
| `list_interfaces` | 取得できるインターフェースの一覧 |
| `start_capture` | 指定したインターフェースで取得を開始（最長3600秒） |
| `capture_status` | 状態、経過時間、ファイル数 |
| `capture_peek` | 取得を止めずに途中経過を解析 |
| `capture_stop` | 停止して全体を解析し、調査に保存 |

- パケットを聞くだけで、対象の機器には何も送りません。ソフトを動かせない機器の通信は、ミラーポートにつないだNICで観測できます。
- 開いているWiresharkの画面を読むのではなく、同じ `dumpcap` で別途取得します。
- 保存先は `cases/` の下だけです。インターフェースは `dumpcap -D` に表示されたものだけを受け付け、同時に実行できる取得は1つです。サーバーの終了時には取得も止めます。
- `capture_peek` は完了した分割ファイル（3〜60秒ごと）だけを解析するため、その分だけ遅れます。応答が次のファイルに入ると無応答に見えることがあるので、判断は `capture_stop` 後の全体解析で行ってください。
- 分割ファイルが上限（64個、1個あたり約8 MB）に達すると、指定時間の前でも取得は終わります。
- 取得にはパスワードなどが含まれることがあります。`capture_filter` で対象を絞ってください。

## 診断の根拠と判定範囲

- `two-point` は方向、TCPシーケンス番号・ACK・フラグ・長さ、ペイロードの一致を使います。アドレス・ポートの書き換え（NAT）は許容します。少なくとも2種類のパケットが一致し、双方から見て最良候補が一意な接続だけを対応付けます。
- 同順位の候補、両端で見えた再送のように個々の送信を区別できないパケット、取得が途中で切れているパケット、内容が一致しないパケットは判定を保留します。片側で何度再送されても反対側で一度も見えない場合は曖昧ではないため、消失の候補として報告します。`matching_status` と `packets_not_comparable`、警告を確認してください。`matched` は照合状況であり、通信が正常という意味ではありません。
- 時計差を推定できない場合、または両端の取得期間が重ならない場合は、区間内での消失・生成を判定しません。片側で未観測という事実だけでは、経路での破棄とキャプチャの取得漏れを区別できません。
- 原因候補には解析ID、関連する接続の送信元・宛先・ポート、観測期間を付けます。表示する接続は最大10件です。関連付けできない場合はその旨を表示します。
- 取得データや対象条件を変えて再解析すると、手動の判断は履歴として残り、`needs_revalidation: true` が付きます。以前の検証済み判断だけで今回の調査を検証済みにはできません。今回の候補を改めて検証するか、持ち越した仮説に `revalidation`（今回の条件で確認した内容）と根拠を付けて更新してください。フラグを省いただけでは解除されません。過去に実施した確認も解析IDを付けて残し、今回の確認計画からは自動除外しません。

設計上の参考: [TCPのシーケンス番号・再送（RFC 9293）](https://www.rfc-editor.org/rfc/rfc9293.html)、[Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html/)。上記の照合条件は本ツールの保守的な実装方針であり、TCP標準が規定する照合手法ではありません。

## Nmapの観測を調査に追加する

先に `analyze` で調査を作成します。Nmapは任意の外部ツールです。XMLの取り込みにはインストール不要で、`analyze` や取り込みから自動スキャンは行いません。

```powershell
# 他の端末で取得したXMLも、その端末の観測位置を明示して取り込めます
python scripts/run.py nmap-import --case cases/demo --file scan.xml --observation "FTPクライアント端末 / VLAN10"

# この端末から明示した1台・指定TCPポートに接続を試みます
python scripts/run.py nmap-scan --case cases/demo --host 192.0.2.20 --ports 21,990 --observation "調査端末 / VLAN10" --timeout 30

# 返された根拠IDで詳細を確認します
python scripts/run.py evidence --case cases/demo --id ext-nmap-XXXXXXXX

# 設定変更の前後を、各実行が返した根拠IDで比較します
python scripts/run.py nmap-compare --case cases/demo --before ext-nmap-XXXXXXXX --after ext-nmap-YYYYYYYY
```

`nmap-scan` はTCP connect方式で、単一のIPv4/IPv6アドレス、最大32個の明示ポートに限定します。DNS逆引き、サービス検出、NSEスクリプト、OS推定は行いません。並列プローブ1、送信間隔100 ms、再試行1回、ホスト制限時間1〜120秒（プロセス終了の猶予5秒）を指定します。対象ホスト名・CIDR・ポート範囲・任意の追加オプションは受け付けません。既存の `probe --tls direct` / `probe --tls ftp-starttls` と組み合わせて上位層を確認できます。

`check-env` でNmapの有無と版を確認できます。PATHまたはWindowsの標準インストール先で見つからない場合は `--nmap "C:\path\nmap.exe"` を指定してください。

原本XML、実行時の引数・端末名・時刻・終了状態、標準出力・標準エラーを `case/attachments/nmap-.../` に保存します。`result.json` と外部根拠レコードには原本のSHA-256を記録します。取り込み時の観測位置はユーザーの申告であり、元の実行端末をXMLから特定できない場合は `unknown` です。

同じ宛先IP・ポートのパケット所見を `same_endpoint_only` として関連付けます。時刻・経路が同じとは限らないため、自動で仮説を検証済みにはしません。レポートには観測位置・時刻・実行状態・ポート状態・判定理由を表示し、全件は `evidence` で確認できます。

XMLはUTF-8、8 MB、256ホスト、4096件のポート結果を上限とします。集約されたポート結果は、対象範囲と件数から一意に対応付けられ、上限に収まる場合だけ展開します。`-p-` のように広い範囲は個別のポート結果だけを取り込み、残りは `aggregated_ports` に状態と件数のまま残します。欠落・不完全な結果を `closed` と推定しません。タイムアウトやNmapの実行失敗も記録するため、CLIの保存成功だけでなく `data.status` を確認してください。

`nmap-compare` はポート状態の比較です。観測されなかったポートは `not_observed` と表示し、`application_recovery` は常に `not_verified` です。FTPならTLS・認証・制御接続・実際のデータ転送を確認してから復旧と判断します。

参考: [Nmap公式のXML出力](https://nmap.org/book/output-formats-xml-output.html)、[TCP connectスキャン](https://nmap.org/book/man-port-scanning-techniques.html)、[時間・並列数の制御](https://nmap.org/book/man-performance.html)。

## curlでHTTP・FTP・FTPSの取得を確認する

curlは現在のWindowsなどに搭載されていますが、すべての環境にあるとは限りません。`check-env` で実行ファイル・版・対応プロトコルを確認できます。この連携は、サイズ不明の転送にも上限を適用するため **curl 8.4.0以降** が必要です。見つからない場合は `--curl` で実行ファイルを指定できます。

```powershell
python scripts/run.py curl-check --case cases/demo --url "https://example.com/health" --observation "クライアント端末" --timeout 10 --max-bytes 65536

# ftp:// + --ftp-starttls は明示的FTPS。認証用の環境変数はあらかじめ設定します
python scripts/run.py curl-check --case cases/demo --url "ftp://ftp.example.com/test.txt" --ftp-starttls --username-env FTP_USER --password-env FTP_PASSWORD --observation "FTPクライアント"

python scripts/run.py curl-compare --case cases/demo --before ext-curl-XXXXXXXX --after ext-curl-YYYYYYYY
```

- HTTP/HTTPSはGET、FTP/FTPSは取得操作のみです。`ftps://` は暗黙的FTPS、`ftp://` は `--ftp-starttls` を指定した場合のみTLSを必須にします。独自CAは `--cafile` で指定でき、証明書検証を省略するオプションはありません。
- デフォルトは取得上限64 KiB・10秒、指定できる最大値は1 MiB・60秒です。取得速度は64 KiB/sに制限します。時間制限のほかにプロセス終了の猶予5秒を設けます。
- リダイレクトは追跡せず、環境変数のプロキシ設定や `.curlrc` は利用しません。FTPはパッシブ方式でPASV応答の通知IPを使わず、制御接続と同じIPに接続します。普段のアプリと条件が異なる場合があります。
- URL内のユーザー名・パスワードは受け付けません。指定した環境変数から読み取った認証情報は、標準入力の設定としてcurlへ渡し、実行引数や記録には残しません。認証情報は子プロセスの環境からも除きます。
- 取得内容・URLのパスとクエリ・生の標準エラーは保存しません。代わりにURLのSHA-256、接続先、終了コードに基づく結果、許可した計測項目を記録します。SSL鍵ログ出力用環境変数も子プロセスへ引き継ぎません。
- `transfer_completed` は指定した取得操作の完了です。HTTP 3xxは `redirect_not_followed`、認証拒否・証明書検証失敗・時間／サイズ上限・不完全な出力はそれぞれ区別し、成功扱いしません。WindowsのTLS資格情報APIが使えない場合は `local_tls_unavailable` と記録します。
- 記録する時間項目は開始からの累積秒数です。特にFTPは制御接続とデータ接続があるため、単純な差分を各段階の処理時間と断定しません。
- `curl-compare` は前後の結果・計測値・リクエスト条件の一致を示します。認証情報自体を保存しないため同じ利用者かは保証できず、取得内容の正しさや業務全体の復旧も自動確定しません。

結果は `case/attachments/curl-.../` と外部根拠に保存され、レポートにも表示します。CLIの保存成功だけでなく `data.status` を確認してください。参考: [curl公式マニュアル](https://curl.se/docs/manpage.html)、[Windows同梱版curl](https://curl.se/windows/microsoft.html)。

## 端末のネットワーク状態を採取する

`host-snapshot` は採取するWindows端末自身で実行します。PowerShellの標準コマンドによる読み取りのみで、設定変更・プロセス停止・外部送信・他の端末への接続は行いません。管理者としての自動再実行も行いません。

```powershell
# クライアント／サーバーの各端末で採取。既存ファイルは上書きしません
python scripts/run.py host-snapshot --out .runtime/client-state.json

# 調査側へJSONを持ち込み、端末の役割を指定して取り込む
python scripts/run.py host-import --case cases/demo --file .runtime/client-state.json --role client

# 同じ端末で取得した正常時／障害時のスナップショットを比較
python scripts/run.py host-compare --before .runtime/normal.json --after .runtime/client-state.json
```

採取項目は、起動時刻、IPアドレス、DNSサーバー、経路、TCP接続／待受ポート／PID、NICの状態／リンク速度／MAC、NICのバイト数・エラー・破棄カウンタです。プロセスのコマンドライン・環境変数・パスワードは採取しません。ファイルには内部ネットワークの情報が含まれるため、Git管理外で保管してください。`.runtime/` はこのリポジトリで除外済みです。

- デフォルトの全体採取枠は45秒、各項目のプロセスは最大10秒、各項目500行、1項目1 MiB・保存JSON全体8 MiBが上限です。`--timeout` は1〜120秒、`--max-rows` は1〜5000に変更できます。プロセス終了処理・ファイル保存の時間は別途かかります。
- 項目ごとに `ok` / `permission_denied` / `unsupported` / `failed` / `timeout` / `output_limit` と、行数・打ち切り・採取開始／終了時刻を記録します。`ok` かつ0行と、取得できなかった状態は別です。Windows以外で採取した場合は未対応として記録し、JSONの取り込みと比較は他のOSでも実行できます。
- PowerShellのプロファイルを読まず、固定の取得処理だけを実行します。取り込んだJSONの文字列をコマンドとして実行することはありません。Windowsの実行制限や権限不足で取得できない項目はそのまま残します。
- 取り込みではスキーマ・サイズ・時刻・型を検証し、原本を `case/attachments/host-.../snapshot.json` にコピーしてSHA-256を記録します。`role` は採取元端末の役割の申告であり、その端末や時刻が障害対象と一致することを自動確定しません。
- 差分は同じホスト名・OSで、採取期間が重ならず時系列が正しい場合に表示します。打ち切りや取得失敗のある項目から、設定・接続が「消えた」と判断しません。差分表示は各項目の追加・削除それぞれ最大100行です。
- NICカウンタは起動時刻とNIC GUIDを照合します。再起動、対応不明、カウンタ減少がある場合は増分を確定せず、`not_comparable` / `reset_or_wrap` とします。途中の初期化後に値が再び増えた場合など、2回の採取だけでは検出できない変化もあります。
- 採取時点の事実を保存する機能です。過去の障害原因の自動確定や、最適経路・FW設定の自動変更は行いません。

参考: [Windows NetTCPIPコマンド](https://learn.microsoft.com/en-us/powershell/module/nettcpip/)、[NIC統計の取得](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterstatistics)。

## ライセンス

[MIT](../../LICENSE)
