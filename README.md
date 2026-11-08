# doctor-skills

証拠に基づいて診断するAIエージェント用のスキル集です。現在は不具合の原因調査を行う2つのスキルを収録しています。どのスキルも観測した事実と判断を分けて扱います。

| スキル | 調べるもの |
|---|---|
| [packet-doctor](skills/packet-doctor) | つながらない・遅い・切れるといった通信障害を、pcap / pcapngやログから調べます |
| [binary-doctor](skills/binary-doctor) | アプリが保存したバイナリファイルの不具合を、正常なファイルとの比較から調べます |

Python 3.10以降の標準ライブラリだけで動きます。各スキルは[Agent Skills](https://agentskills.io/specification)形式の独立したフォルダーです。

## 導入

### Claude Code

```text
claude plugin marketplace add Taka-S-dev/doctor-skills
claude plugin install packet-doctor@doctor-skills
claude plugin install binary-doctor@doctor-skills
```

### GitHub Copilot CLI

```text
git clone https://github.com/Taka-S-dev/doctor-skills.git
copilot skill add doctor-skills/skills
```

### その他のツール

使いたいスキルのフォルダーを、ツールのスキル置き場へコピーします。GitHub Copilotの個人用の置き場は`~/.copilot/skills/`です。

```text
cp -r doctor-skills/skills/packet-doctor ~/.copilot/skills/
```

## packet-doctorのライブ取得

Claude Codeのプラグインでは自動で設定されます。それ以外のツールでは、次のコマンドをMCPサーバーとして登録してください。

```text
python -B <スキルのフォルダー>/scripts/run.py mcp
```

## 開発

スキルごとにテストを実行します。

```text
python -m unittest discover -s tests
cd skills/packet-doctor && python -m unittest discover -s tests
cd skills/binary-doctor && python tests/test_binx.py
```

スキルを追加するときは、`skills/<名前>/`を作り、この表と[.claude-plugin/marketplace.json](.claude-plugin/marketplace.json)に登録します。`.gitignore`は許可リスト方式のため、`references/`・`scripts/`・`tests/`以外のフォルダーを足すときは`.gitignore`にも追加してください。

## ライセンス

[MIT](LICENSE)
