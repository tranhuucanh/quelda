# ポリシー

[English](policy.md) | **日本語**

ポリシーは quelda の厳しさを決めます：どの検出結果でファイルを無効にするか（`block`）、どれを報告だけするか（`warn`）、どれを無視するか（`off`）、さらにエンジンのサイズ上限といくつかの検出しきい値です。同じポリシー JSON が CLI でも npm パッケージでも使え、どちらでも同じ判定になります。

- [ポリシーの仕組み](#ポリシーの仕組み)
- [プリセット](#プリセット)
- [独自のポリシーを書く](#独自のポリシーを書く)
- [レシピ](#レシピ)
- [リファレンス](#リファレンス)
- [エンジンエラー](#エンジンエラー)

## ポリシーの仕組み

**ポリシーはプリセットを調整するものであり、ルールセットを置き換えることはありません。** quelda が知っているすべてのルール（[rules.ja.md](rules.ja.md) を参照）は、毎回のスキャンで実行されます。ポリシーが決めるのは、各検出結果をどう扱うかだけです：

```text
1. プリセット        すべてのルールに、プリセットがそのカテゴリに与える動作を適用
                     （デフォルトのプリセット: balanced）
2. カテゴリ          指定したカテゴリは、そのすべてのルールに指定した動作を適用
3. ルール            指定したルールは、指定した動作を適用（最も具体的な指定が優先）
4. ロックされたルール  "unsafe_allow_unlock": true でない限り、常に block
```

指定しなかったものはプリセットの動作のままです。たとえば次のポリシーは：

```json
{
  "preset": "strict",
  "categories": { "external": "warn" },
  "rules": { "EXTERNAL.URI": "off" }
}
```

次の意味になります：*56 個のルールすべてを `strict` の動作で実行する。ただし `external` カテゴリは警告だけにし、`EXTERNAL.URI`（普通のハイパーリンク）は無視する*。「external のルールだけを実行する」という意味では**ありません**。`off` に設定したルールはスキップされます。ポリシーでルールを追加する方法はありません。

ポリシーがまったくない場合（`{}`、または `--policy` フラグなし）は、デフォルトの上限での `balanced` プリセットになります。

3 つの動作：

| 動作 | 効果 |
|---|---|
| `block` | 検出結果がファイルを無効にします：`status` は `REJECT`、`violations` に記載、CLI の終了コードは 1。 |
| `warn` | `warnings` に報告し、ファイルは有効のままです。ブロックする前にルールの様子を見るのに使います。 |
| `off` | ルールを実行しません。 |

ルールとは別に、エンジンはファイル全体を検査できないとき（破損した構造、上限の超過、読み取れない入力）に `ERROR`（無効、CLI の終了コードは 2）で停止します。ポリシーでこれをオフにすることはできず、[上限](#上限)を引き上げることしかできません。[エンジンエラー](#エンジンエラー)を参照してください。

## プリセット

| カテゴリ | 対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `filetype` | PDF ではないもの、PostScript/EPS、PDF に偽装した他の形式、ポリグロット | block | block | block |
| `postscript` | PDF 内の PostScript コード | block | block | block |
| `encryption` | 暗号化されたファイル（内容を検査できない） | block | block | block |
| `active_content` | JavaScript、Launch、文書を開いたときやイベントで実行されるアクション | block | block | warn |
| `embedded` | 添付ファイル、ポートフォリオ、マルチメディアと 3D | block | block | warn |
| `xml` | DOCTYPE/ENTITY を含む XML（XXE、billion laughs） | block | block | warn |
| `resource` | ピクセル爆弾、巨大または壊れたページ、ページ数爆弾 | block | block | warn |
| `external` | リンク、リモート文書、フォーム送信、ネットワーク上のファイル参照 | block | warn | off |
| `forms` | AcroForm と XFA フォーム | block | warn | off |
| `structure` | 破損した、または曖昧な構造（xref、重複、末尾のデータなど） | block | warn | off |
| `codecs` | リスクのある画像コーデック（JBIG2、JPEG 2000）、フォント、カラープロファイル | block | warn | off |

20 個のルールはカテゴリと異なる動作をします：

| ルール | strict | balanced | permissive | 理由 |
|---|---|---|---|---|
| `ACTIVE.OTHER_ACTIONS` | block | warn | warn | 名前付きアクション（次のページ、印刷など）はよくあり、それ自体は無害です。 |
| `STRUCT.INCREMENTAL_UPDATE` | warn | off | off | 編集されたファイルや署名付きファイルには更新があります。quelda はいずれにせよすべてのリビジョンをスキャンします。 |
| `CODEC.TYPE1_FONT` | warn | off | off | 印刷用ファイルは Type 1 フォントを多用します。 |
| `EXTERNAL.STREAM_FILE` | block | block | warn | ファイル外部から読み込む内容は、検査したものと決して一致しません。実際のファイルは埋め込みます。 |
| `EXTERNAL.OPI` | block | block | warn | 同上：印刷される画像は PDF が指定したファイルです。古い OPI ワークフローでは `permissive` を使えます。 |
| `STRUCT.NAME_TOO_LONG` | block | block | block | 実際の PDF 作成ソフトは書き出さず、レンダラーのバッファを狙ったものです。 |
| `CODEC.DECODE_PARAMS` | block | block | block | 実際の PDF 作成ソフトは書き出さず、デコーダーのバッファを狙ったものです。 |
| `CODEC.FONT_MALFORMED` | block | block | warn | フォントツールは書き出しません。古い破損ファイルのアーカイブ向けに、`permissive` では警告のみです。 |
| `CODEC.ICC_MALFORMED` | block | block | warn | 同上、カラープロファイルについて。 |
| `EXTERNAL.REMOTE_GOTO` | block | block | warn | 別のファイルやネットワークパスを開くのは Web リンクの役割ではなく、普通の文書はしません。 |
| `EXTERNAL.SUBMIT_FORM` | block | block | warn | ユーザーが入力した内容を、ファイルが選んだ URL に送信します。 |
| `EXTERNAL.IMPORT_DATA` | block | block | warn | PDF が指定したファイルからフォームの値を読み込みます。 |
| `EXTERNAL.URL_FILESPEC` | block | block | warn | 文書を使うときにネットワークから取得されるファイルです。 |
| `FORMS.XFA` | block | block | warn | 2 つ目のスクリプトエンジンで、PDF 2.0 で非推奨です。古い官公庁や銀行のフォームでは `permissive` を使えます。 |
| `STRUCT.MISSING_EOF` | block | block | warn | 途中で切れた、または手作りのファイルです。PDF 作成ソフトは必ず `%%EOF` を書き出します。 |
| `STRUCT.MULTIPLE_HEADERS` | block | block | warn | 1 つの中に 2 つのファイルがあり、どちらを表示するかがリーダーによって異なります。 |
| `STRUCT.CONFLICTING_OBJECTS` | block | block | warn | どちらの定義が使われるかはリーダー次第です。 |
| `STRUCT.PAGE_TREE_CYCLE` | block | block | warn | 実際の PDF 作成ソフトは書き出さず、リーダーを停止させます。 |
| `STRUCT.REFERENCE_CYCLE` | block | block | warn | 同上、ブックマーク、アクション、オブジェクトストリーム、配列のチェーンについて。 |
| `STRUCT.BROKEN_OBJECT` | block | block | warn | quelda は解析できないオブジェクトを検査できません。 |

**ロックされたルール**はすべてのプリセットでブロックします（カテゴリとしては警告だけの `permissive` でも）：`FILETYPE.POSTSCRIPT_MAGIC`、`FILETYPE.NOT_PDF_HEADER`、`FILETYPE.FOREIGN_MAGIC`、`POSTSCRIPT.CONTENT_OP`、`POSTSCRIPT.XOBJECT`、`ACTIVE.LAUNCH`。これらは、ファイルが Ghostscript、ImageMagick、リーダーにコードを実行させる方法です。

どのプリセットを使うか：

- **`strict`**：誰から来たファイルでも、そのまま Ghostscript、ImageMagick、印刷 RIP、サムネイル生成に渡す場合。ハイパーリンク、フォーム、破損した構造を含め、通常と異なるものはすべて拒否するため、正当なファイルも一部拒否することを想定してください。拒否されたものを確認してから、ルールを 1 つずつ緩めます。
- **`balanced`**（デフォルト）：実行できるもの、ペイロードを運べるもの、サーバーを疲弊させられるものはすべてブロックし、通常の文書によくある機能（リンク、フォーム、構造の修復、リスクのあるコーデック）は警告だけにします。
- **`permissive`**：ほぼ信頼できる提供元からのファイル向け。ファイル種別、PostScript、暗号化、ロックされたルールは引き続きブロックし、それ以外はすべて最大でも警告です。

## 独自のポリシーを書く

プリセットから始めて、必要なところだけを変更します。CLI では：

```bash
quelda scan upload.pdf --preset strict                     # a preset only
quelda scan upload.pdf --policy policy.json                # a policy file
quelda scan upload.pdf --rule EXTERNAL.URI=off              # one rule, no JSON
quelda scan upload.pdf --policy-json '{"rules": {"EXTERNAL.URI": "off"}}'
quelda scan upload.pdf --policy policy.json --preset strict --stop-on-first
```

`--preset` はポリシーファイルの `preset` を置き換えます。`--rule ID=action`（繰り返し可）は `rules` の項目を 1 つ設定し、ファイルより優先されます。`--stop-on-first` は `stop_on_first` を設定します。`unsafe_allow_unlock` なしでロックされたルールを下げても引き続きブロックし、CLI は stderr に警告を出力します。`quelda help policy` はこのページの要約を出力します。

npm パッケージでは、同じオブジェクトを渡します：

```ts
const verdict = await scanner.scan(file, {
  preset: 'balanced',
  rules: { 'EMBED.EMBEDDED_FILE': 'warn' },
});
```

ユーザーに合わせてポリシーを調整するには：

1. 実際のアップロードのサンプルを、使いたいプリセットでスキャンします（`--format text` が読みやすいです）。
2. 正当なファイルを拒否するルールごとに、[rules.ja.md](rules.ja.md) でその意味を読んで決めます：維持する（`block`）、様子を見る（`warn`）、無視する（`off`）。カテゴリ全体より**ルール 1 つ**を、プリセットよりカテゴリを変更することを優先してください。
3. ポリシーファイルはバージョン管理に入れます。各判定は `policy.digest`（書かれたとおりのポリシーの SHA-256）を報告するので、どのポリシーで出た判定かがわかります。

## レシピ

添付ファイル付きの文書（一部の電子書籍やレポート）を受け入れつつ、報告は続ける：

```json
{ "rules": { "EMBED.EMBEDDED_FILE": "warn", "EMBED.FILE_ATTACHMENT": "warn" } }
```

Ghostscript の前で最大限の安全性を確保しつつ、普通のハイパーリンクは許可する：

```json
{ "preset": "strict", "rules": { "EXTERNAL.URI": "warn" } }
```

20 MiB までのアップロードのみ、できるだけ早く拒否する：

```json
{ "limits": { "max_file_bytes": 20971520 }, "stop_on_first": true }
```

大判印刷（長さ約 25 m までのバナー）：

```json
{ "thresholds": { "max_page_side_pt": 72000 } }
```

フォーム（入力可能な PDF）を扱う業務だが、どこにもデータを送信させない：

```json
{ "categories": { "forms": "off" }, "rules": { "EXTERNAL.SUBMIT_FORM": "block" } }
```

## リファレンス

すべてのフィールドは省略可能です（[`schemas/policy.schema.json`](../schemas/policy.schema.json)）。

| フィールド | 型 | 意味 |
|---|---|---|
| `preset` | `"strict"` \| `"balanced"` \| `"permissive"` | 出発点。デフォルトは `balanced`。 |
| `categories` | オブジェクト：カテゴリ → 動作 | カテゴリのすべてのルールの動作。 |
| `rules` | オブジェクト：ルール ID → 動作 | ルール 1 つの動作（カテゴリより優先）。 |
| `limits` | オブジェクト | エンジンの上限。超えると `ERROR`。 |
| `thresholds` | オブジェクト | 一部のルールの検出しきい値。超えると検出結果になります。 |
| `stop_on_first` | boolean | 最初の `block` の検出結果で停止：危険なファイルでは速くなり、列挙される理由は少なくなります。デフォルトは `false`。 |
| `unsafe_allow_unlock` | boolean | `categories` / `rules` でロックされたルールを下げられるようにします。判定に報告されます。信頼できないファイルには決して使わないでください。デフォルトは `false`。 |

カテゴリ: `filetype`, `postscript`, `active_content`, `embedded`, `external`, `forms`, `xml`, `structure`, `encryption`, `codecs`, `resource`。動作: `block`, `warn`, `off`。

### 上限

スキャンの時間とメモリを一定の範囲に収めるための安全装置です。上限を超えたファイルは `ERROR`（無効）になります：エンジンは完全に検査できなかったものの判定を拒否します。

| 上限 | デフォルト | エラー |
|---|---|---|
| `max_file_bytes` | `18446744073709551615`（上限なし） | `LIMIT.FILE_BYTES` |
| `max_objects` | `1000000` | `LIMIT.OBJECTS` |
| `max_revisions` | `1000` | `LIMIT.REVISIONS` |
| `max_nesting_depth` | `128`（最大 512） | `LIMIT.NESTING_DEPTH` |
| `max_decoded_bytes_per_stream` | `134217728`（128 MiB） | `LIMIT.STREAM_DECODED_BYTES` |
| `max_decoded_bytes_total` | `536870912`（512 MiB） | `LIMIT.DECODED_BYTES` |
| `max_compression_ratio` | `1000` | `LIMIT.COMPRESSION_RATIO` |

画像と添付ファイルは決して展開しません（判定に不要なため）。そのため展開の上限が数えるのは、エンジンが読む必要のあるデータだけです：ページ内容、オブジェクトストリーム、XML、役割が不明なストリーム。埋め込みフォントと ICC カラープロファイルは構造を検査するために展開し、それぞれ同じ上限内で処理しますが、スキャン全体の合計には数えません。上限に達したものは判定しません。

### しきい値

| しきい値 | デフォルト | ルール |
|---|---|---|
| `max_image_pixels` | `1000000000` | `RESOURCE.IMAGE_DIMENSIONS` |
| `max_page_side_pt` | `28800`（400 インチ、約 10 m） | `RESOURCE.PAGE_SIZE` |
| `max_pages` | `10000` | `RESOURCE.PAGE_COUNT` |
| `max_filter_chain` | `2` | `STRUCT.FILTER_CHAIN` |
| `max_trailing_bytes` | `1024` | `STRUCT.TRAILING_DATA` |

### 厳格な解析

ポリシー自体も厳格に検査されます。未知のフィールド、重複したキー、`null`、型の誤った値、未知のカテゴリ、そして**このバージョンのエンジンが知らないルール ID** があると、すべてのスキャンが `POLICY.INVALID` で `ERROR`（CLI の終了コードは 2）になります。タイプミスで黙ってルールがオフになるほうが、エラーよりも悪いからです。新しいバージョンの quelda 向けに書かれたポリシーを導入する前に、`quelda rules`（または `scanner.listRules()`）と照らし合わせてください。

## エンジンエラー

エラーは、ポリシーの設定にかかわらず判定を `ERROR` にし、ファイルを無効にします。

| コード | 意味 | 対処 |
|---|---|---|
| `ENGINE.PARSE` | エンジンが解析する必要のあるバイトが、正しい PDF 構文ではありません。 | 破損した、または細工されたファイル：拒否してください。 |
| `ENGINE.UNDECODABLE` | 検査が必要なストリーム（オブジェクトストリーム、ページ内容、XML）が未知のフィルタを使っているか、壊れたデータを含んでいます。 | 拒否してください：そこに隠されたものは検査できません。 |
| `ENGINE.READ` | 入力を読み取れませんでした（ファイルがない、I/O エラー、変更されたブラウザの `File`）。 | パスまたはアップロードを確認してください。 |
| `LIMIT.FILE_BYTES` | ファイルが `limits.max_file_bytes` より大きい（ポリシーで設定しない限り上限なし）。何も解析していません。 | そのようなファイルが想定されるなら上限を引き上げてください。 |
| `LIMIT.OBJECTS` | オブジェクトが `limits.max_objects` より多い。 | 非常に大きな文書なら上限を引き上げてください。 |
| `LIMIT.REVISIONS` | リビジョン（増分更新）が `limits.max_revisions` より多い。 | 通常は細工されたファイル：拒否してください。 |
| `LIMIT.NESTING_DEPTH` | 配列・辞書のネストが `limits.max_nesting_depth` より深い。 | 通常は細工されたファイル：拒否してください。 |
| `LIMIT.STREAM_DECODED_BYTES` | 1 つのストリームが展開すると `limits.max_decoded_bytes_per_stream` を超えます。 | 圧縮爆弾、または巨大なページ：想定される場合のみ引き上げてください。 |
| `LIMIT.DECODED_BYTES` | すべてのストリームの合計が展開すると `limits.max_decoded_bytes_total` を超えます。 | 同上。 |
| `LIMIT.COMPRESSION_RATIO` | ストリームが展開すると、元のサイズの `limits.max_compression_ratio` 倍を超えます。 | 圧縮爆弾：拒否してください。 |
| `LIMIT.FILTER_CHAIN` | ストリームが 16 個を超えるフィルタ（固定）を重ねています。 | 細工されたファイル：拒否してください。 |
| `LIMIT.PARSE_WORK` | 重なり合うオブジェクトのため、解析でファイルを何度も読み直す必要があります（固定）。 | 細工されたファイル：拒否してください。 |
| `POLICY.INVALID` | ポリシーが正しくない（[厳格な解析](#厳格な解析)を参照）、または CLI がポリシーファイルを読み取れませんでした。 | ポリシーを修正してください。何もスキャンしていません。 |
