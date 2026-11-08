# binary-doctor

アプリが保存したバイナリファイルの不具合を調べるエージェントスキルです。正常なファイルと不正なファイルを比べて異常な箇所を絞り込み、原因をコードで裏付けるまでの手順と解析ツールをまとめています。Agent Skills 形式（`SKILL.md`）なので、GitHub Copilot や Claude Code など、この形式に対応したツールから利用する想定です。

実行ファイルの逆コンパイルやマルウェア解析は対象外です。

## できること

- 複数の正常ファイルと比べ、タイムスタンプのように毎回変わる部分をノイズとして除外する
- 挿入や削除を検出し、データがずれ始めた位置を特定する
- C/C++ の構造体定義を読み、フィールド単位で表示・比較する
- 長さ付き文字列、TLV、版数で変わる構造などの可変長データを読む
- 長さやオフセットの矛盾、チェックサムの不一致、不正な enum 値などを検出する
- 正常と不正を並べて問題のバイトを色付けした HTML レポートを作る

## 導入

Python 3.10 以降が必要です（3.10 と 3.13 で動作確認）。標準ライブラリだけで動きます。

導入方法は[リポジトリのREADME](../../README.md)を参照してください。

エージェントに「保存データがおかしい」「正常時と不正時で何が違うか調べて」のように頼むと使われます。スラッシュコマンドに対応したツールでは `/binary-doctor` でも呼び出せます。

## コマンドとして使う

`scripts/binx.py` は単体でも使えます。

| コマンド | 内容 |
|---|---|
| `overview` | サイズ、エントロピー、埋められた領域、レコード長の候補、文字列 |
| `view` | 指定範囲の hex 表示 |
| `decode` | 構造体定義に沿ってフィールドを表示 |
| `multi` | 複数の正常ファイルと比較して異常を抽出 |
| `diff` | 2 ファイルを位置合わせして比較 |
| `check` | 不正な値、チェックサムや長さの整合性を確認 |
| `report` | 比較結果の HTML レポートを出力 |

```
python scripts/binx.py multi --good g1.bin g2.bin g3.bin --bad bad.bin \
  --defs format.h --layout "Header,Record[Header.count]" --save-mask mask.json
python scripts/binx.py report g1.bin bad.bin \
  --defs format.h --layout "Header,Record[Header.count]" --mask mask.json -o report.html
```

可変長データの定義の書き方は [SKILL.md](SKILL.md) を参照してください。出力とレポートは日本語です。

## 制限

- ヘッダの解析は簡易的なものです。`#ifdef` は評価せず、継承や `virtual` を含む構造体は警告を出します。オフセットは解析対象と同じビルド構成の `sizeof` / `offsetof` と照合してください。
- 構造体の配置は gcc の規則を想定しています。MSVC との一致は未確認です。
- 圧縮や暗号化された領域は展開しません。
- ファイル全体をメモリに読み込みます。

## テスト

```
python tests/test_binx.py
```

## ライセンス

[MIT](../../LICENSE)
