# ルール

[English](rules.md) | **日本語**

quelda には **11 カテゴリ、56 個のルール**があります。各ルールは、攻撃者が PDF リーダーやサーバー側の PDF ツール（Ghostscript、ImageMagick、印刷 RIP、サムネイル生成）を攻撃するために使うもの、または PDF ソフトウェアごとに異なる文書が見えてしまう原因となるものを 1 つずつ探します。ルールに加えて、エンジンは完全に検査できないものの判定を拒否します（[エンジンエラー](policy.ja.md#エンジンエラー)を参照）。

表の列は、各[プリセット](policy.ja.md#プリセット)での各ルールの動作です：`block` はファイルを無効にし、`warn` は報告し、`off` はスキップします。🔒 は**ロックされた**ルールを示します：ポリシーの設定にかかわらずブロックします（`unsafe_allow_unlock` を除く）。それ以外のルールは[ポリシー](policy.ja.md#独自のポリシーを書く)で変更できます。`quelda rules`（または `scanner.listRules()`）は同じ一覧を、各ルールのより詳しい技術的な説明付きで出力します。

ルール ID は安定しています：ID の意味が変わることはなく、再利用されることもありません。

## 各ルールがファイルをどう見るか

ルールが自分でバイトを読むことはありません。エンジンがファイルを一度だけ解析し、すべてのルールに同じビューを渡します。そのため、あるルールから何かを隠す手口は、どのルールからも隠せません：

- **すべてのリビジョンのすべてのオブジェクト。** 古いリビジョン（増分更新）、どの相互参照テーブルにも載っていないオブジェクト、重複、圧縮オブジェクトストリームに格納されたオブジェクトもすべてスキャンします。quelda はファイルを「修復」して 1 つのバージョンを選ぶことはしません：どれかのリーダーが見る可能性があれば、検査します。
- **デコード済みの名前と文字列。** `/J#61vaScript`、16 進文字列、UTF-16 テキスト、エスケープは、ルールが見る前に正規化されます。
- **展開済みの内容。** ページ内容、オブジェクトストリーム、XML はフィルタチェーン（Flate、LZW、ASCII85、ASCIIHex、RunLength、predictor）を通り、圧縮爆弾に対する上限が適用されます。画像と添付ファイルは判定に不要なので、展開することはありません。埋め込みフォント（TrueType、OpenType、CFF）と ICC カラープロファイルは構造を検査するためだけに展開し、完全に展開できないものは判定しません。
- **ネストした値と間接参照の値。** 辞書の中の辞書、他のオブジェクトに格納された値、参照の配列：ルールは `/S /JavaScript` がどこにあっても見つけます。
- **フェイルクローズ。** エンジンが解析・デコード・読み取りできないもの、または上限を超えるものは、スキップせずにファイルを無効（`ERROR`）にします。

## ファイル種別 (`filetype`)

ファイルの本当の種類。quelda はファイルを名前ではなく、常にバイトで識別します。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `FILETYPE.FOREIGN_MAGIC` 🔒 | `.pdf` に名前を変えた別形式：SVG/HTML/XML、ImageMagick の MVG/MSL、ZIP/7z/RAR/GZIP アーカイブ、Office/RTF 文書、画像、Windows/Linux の実行ファイル。 | block | block | block |
| `FILETYPE.NOT_PDF_HEADER` 🔒 | `%PDF-1.` / `%PDF-2.` で始まらないファイル。ヘッダーをもっと後ろまで探すソフトウェアや、内容から形式を推測するソフトウェアは、別のものとして扱う可能性があります。 | block | block | block |
| `FILETYPE.POLYGLOT` | 開くプログラムによって ZIP アーカイブや HTML/SVG ページに*も*なる、本物の PDF。 | block | block | block |
| `FILETYPE.POSTSCRIPT_MAGIC` 🔒 | PostScript、EPS（バイナリの DOS EPS も）、旧形式の Illustrator ファイル。バイトオーダーマーク、空白、プリンタ（PJL）ヘッダーの後ろにあっても検出します。Ghostscript と ImageMagick は、ファイル名が何であれこれらをプログラムとして実行します。これらのツールを攻撃する最も一般的な方法です。 | block | block | block |

## PostScript (`postscript`)

PDF 内に隠された PostScript コード。Ghostscript ベースのツールが実行する可能性があります。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `POSTSCRIPT.CONTENT_OP` 🔒 | 任意のコンテンツストリーム（ページ、フォーム、外観、Type 3 グリフ）またはフォームのデフォルト外観文字列（`/DA`）内の `PS` 演算子：インタープリターに渡される生の PostScript です。 | block | block | block |
| `POSTSCRIPT.TYPE4_FUNCTION` | PDF 仕様で許可された 42 個の演算子以外を使う Type 4（計算機）関数、または大きすぎる・ネストが深すぎる関数。Illustrator や InDesign が書き出す普通のカラー関数は通ります。 | block | block | block |
| `POSTSCRIPT.XOBJECT` 🔒 | PostScript XObject と、PostScript の代替を持つフォーム：Ghostscript が実行する可能性のある PostScript コードです。 | block | block | block |

## アクティブコンテンツ (`active_content`)

PDF リーダー内で実行されるコードとアクション。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `ACTIVE.ADDITIONAL_ACTIONS` | クリックなしでイベント（開く、閉じる、ページ表示、フォーカス、キー入力、マウス）によって実行されるアクション。 | block | block | warn |
| `ACTIVE.JAVASCRIPT` | あらゆる場所の JavaScript：アクション、文書レベルのスクリプト、レンディションのスクリプト、テキストとしてもストリームとしても。最も一般的な PDF エクスプロイトの手段です。 | block | block | warn |
| `ACTIVE.LAUNCH` 🔒 | リーダーのコンピューター上でファイルやプログラムを開く・実行する Launch アクション。 | block | block | block |
| `ACTIVE.OPEN_ACTION` | 文書を開いたときに自動的に実行されるアクション。特定のページを開くだけのもの（単純な移動先）は報告しません。 | block | block | warn |
| `ACTIVE.OTHER_ACTIONS` | その他の対話的なアクション（名前付き、レンディション、非表示、レイヤー状態、サウンド、ムービーなど）。内容を連鎖させたり隠したりするのに使われます。 | block | warn | warn |
| `ACTIVE.XFA_SCRIPT` | XFA フォームの XML 内のスクリプト（JavaScript または FormCalc）。Acrobat は文書の JavaScript と同様に実行します。フォームデザイナーが残す空の `<script/>` 要素、config パケットの `<script>` 設定（`<runScripts>` など）、`script` という名前のフォームデータフィールドは報告しません。 | block | block | warn |
| `ACTIVE.DANGEROUS_URI` | スクリプトを実行する、またはローカルマシンやネットワーク共有にアクセスするリンク：`javascript:`、`vbscript:`、`data:`、`file:`、`smb:`、`\\server\share`、Windows のパス、`ms-*:` ハンドラー（`ms-msdt:`、Follina）、`search-ms:`。相対リンクの解決基準となる文書のベース URI（`/URI << /Base … >>`）がこれらの種類の場合も検出します。Web ビューアーでコードを実行したり、Windows の認証情報（NTLM）を漏洩させたりする可能性があります。普通のリンク（`http`、`https`、`mailto`、`ftp`、`tel`、相対リンク）は報告しません。 | block | block | warn |

## 埋め込みコンテンツ (`embedded`)

PDF 内で運ばれるペイロード。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `EMBED.EMBEDDED_FILE` | どのように参照されていても、あらゆる種類の埋め込みファイル（実行ファイル、スクリプト、他の文書）。Adobe の使用権限署名の `/EF` 配列（ファイルではなく権限名のリスト）は数えません。 | block | block | warn |
| `EMBED.FILE_ATTACHMENT` | ファイル添付注釈：ページ上のアイコンで、添付ファイルを開きます。 | block | block | warn |
| `EMBED.PORTFOLIO` | PDF ポートフォリオ：実際の内容が添付ファイルであるコンテナです。 | block | block | warn |
| `EMBED.RICH_MEDIA` | マルチメディアと 3D コンテンツ（RichMedia、Movie、Sound、Screen、U3D、PRC）。大規模でほとんど監査されていないプレーヤーが処理します。 | block | block | warn |

## 外部参照 (`external`)

文書がネットワークや他のファイルにアクセスする方法。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `EXTERNAL.IMPORT_DATA` | 外部ファイルから値を読み込むフォーム。 | block | block | warn |
| `EXTERNAL.OPI` | 画像やフォームに付いた OPI コメント：プリプレスソフトウェアが、PDF が指定した自分のディスクやネットワーク上のファイルに内容を差し替えます。最近のツールは書き出しません。 | block | block | warn |
| `EXTERNAL.REMOTE_GOTO` | 別の文書（ネットワーク経由の場合もあり、UNC/SMB パスは Windows の認証情報を漏洩させます）や添付ファイルを開くリンク：`GoToR`、`GoToE`、ファイルを指定するスレッドアクション。普通の文書がリンクするのは Web ページで、他のファイルではありません。 | block | block | warn |
| `EXTERNAL.STREAM_FILE` | PDF 外部のファイルから読み込む画像などの内容（外部ストリーム、参照 XObject）：レンダラーはファイルが選んだパスや URL を開くため、印刷されるものは検査したものと一致しません。実際の印刷用ファイルは画像を埋め込みます。 | block | block | warn |
| `EXTERNAL.SUBMIT_FORM` | データ（または文書全体）を URL に送信するフォーム：データの持ち出しとフィッシングです。 | block | block | warn |
| `EXTERNAL.URI` | Web リンク。通常の文書によくあり（そのため `balanced` は警告のみ）、フィッシング文書が頼りにするものです。 | block | warn | off |
| `EXTERNAL.URL_FILESPEC` | URL を指すファイル参照。ファイルはネットワークから取得されます。 | block | block | warn |

## フォーム (`forms`)

対話的なフォーム。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `FORMS.ACROFORM` | 対話的な（入力可能な）フォーム。フォームのスクリプトと送信アクションは、それぞれのルールが報告します。 | block | warn | off |
| `FORMS.XFA` | XFA フォーム：PDF 内にある別の XML レイアウト・スクリプトエンジンで、攻撃対象領域が大きいものです。PDF 2.0 で非推奨となり、今も実行するのは Adobe のリーダーだけです。 | block | block | warn |

## XML (`xml`)

PDF 内の XML（メタデータ、XFA フォーム）。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `XML.DOCTYPE` | 埋め込まれた XML（XMP メタデータ、XFA）内の `<!DOCTYPE` または `<!ENTITY`（どのエンコードでも）：リーダーやサーバーツールの XML パーサーに対する XML 外部実体（XXE）攻撃と billion laughs 攻撃です。 | block | block | warn |
| `XML.EXTERNAL_REFERENCE` | パーサーに何かを取得させる埋め込み XML：XInclude、`<?xml-stylesheet?>`、XFA の Web サービス接続。DOCTYPE なしでのサーバーサイドリクエストフォージェリやローカルファイルの読み取りです。名前空間 URI は参照ではないため報告しません。 | block | block | warn |

## 構造 (`structure`)

破損した、曖昧な、または通常と異なるファイル構造：PDF リーダーごとに異なる文書が見え始める箇所です。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `STRUCT.BROKEN_OBJECT` | 本体を解析できないオブジェクトヘッダー（`N G obj`）：途中で切れたファイル、または意図的に破損させたファイル。quelda はその中身を検査できませんが、ファイルを修復するリーダーはその一部を使う可能性があります。ヘッダーに見えるだけのテキスト（文字列、コメント、ストリームデータの中）は数えません。 | block | block | warn |
| `STRUCT.CONFLICTING_OBJECTS` | 1 つのリビジョン内で、同じオブジェクトが異なる内容で 2 回定義されているもの：リーダーがどちらを使うかは修復ロジック次第です。 | block | block | warn |
| `STRUCT.FILTER_CHAIN` | `thresholds.max_filter_chain` を超える数の圧縮・エンコードフィルタを重ねた、または同じフィルタを繰り返したストリーム：内容を隠し、デコードの手間を増やすために使われます。 | block | warn | off |
| `STRUCT.INCREMENTAL_UPDATE` | 作成後に編集されたファイル（増分更新）。quelda はもともとすべてのリビジョンをスキャンしており、これは複数あることを報告するだけです。 | warn | off | off |
| `STRUCT.MISSING_EOF` | `%%EOF` がまったくない：途中で切れた、または手作りのファイルで、リーダーによって修復の仕方が異なります。 | block | block | warn |
| `STRUCT.MULTIPLE_HEADERS` | `%PDF-` ヘッダーが複数ある：連結されたファイル、または先頭から見た場合と末尾から見た場合で違って見えるように作られたファイルです。 | block | block | warn |
| `STRUCT.NAME_TOO_LONG` | 255 バイトを超える名前：長いフォント名はレンダラーのバッファをオーバーフローさせたことがあります。PDF 作成ソフトは書き出しません（実際のファイルで最も長い名前は、Word のスタイル名をコピーした構造タグで、255 未満に収まります）。 | block | block | block |
| `STRUCT.PAGE_TREE_CYCLE` | ページツリー内のループや繰り返されるノード。単純なリーダーを無限ループさせたり、少数のオブジェクトを数百万ページとして描画させたりします。 | block | block | warn |
| `STRUCT.REFERENCE_CYCLE` | リーダーが最後までたどるチェーンを、終わらないように作ったもの：`/Next` でつながったブックマークやアクション、`/Extends` でつながったオブジェクトストリーム、自分自身を含む配列。単純なリーダーは停止するか、メモリを使い果たします。普通の逆参照（`/Parent`、`/Prev`）は数えません。 | block | block | warn |
| `STRUCT.SIGNATURE_MODIFIED` | 署名後に変更された署名付きファイル：署名範囲の後ろにあるバイト（後から保存された更新で、署名の検証は通ったまま表示内容を変えられます）、署名値以外の部分まで除外している署名範囲、または不正な `/ByteRange`。構造だけを検査し、暗号は検査しません。フォームの入力や 2 つ目の署名の追加でもバイトが追加されるため、`balanced` は警告のみです。 | block | warn | off |
| `STRUCT.PRINT_VIEW_MISMATCH` | 印刷されるが画面では非表示の内容（印刷専用フラグの付いた注釈、印刷時はオン・表示時はオフのレイヤー）：画面で承認したものと印刷されるものが異なります。印刷専用のスタンプを持つ実際のファイルもあるため、`balanced` は警告のみです。 | block | warn | off |
| `STRUCT.TRAILING_DATA` | 最後の `%%EOF` の後ろに `thresholds.max_trailing_bytes` を超えるデータ：ポリグロットや密輸されたペイロードは通常この方法で作られます。 | block | warn | off |
| `STRUCT.TRUNCATED_STREAM` | 途中で終わっている圧縮データ。雑な PDF 作成ソフトでよく起きます。quelda はリーダーが表示するものをそのまま検査します。 | block | warn | off |
| `STRUCT.XREF_MISMATCH` | 相互参照テーブルがファイルと一致しない（オフセットの誤り、載っていない・隠されたオブジェクト、使える xref がない、チェーンの破損）。リーダーはそれぞれ独自の方法でファイルを修復します：スキャナーにはある文書を、リーダーには別の文書を見せる古典的な手口です。 | block | warn | off |

## 暗号化 (`encryption`)

quelda が見ることのできない内容。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `CRYPT.ENCRYPTED` | 暗号化されたファイル。文字列とストリームを検査できないため、安全であることを示せません。 | block | block | block |

## コーデック (`codecs`)

エクスプロイトの歴史があるデコーダーとパーサー：画像、フォント、カラープロファイル。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `CODEC.DECODE_PARAMS` | 仕様外のデコーダーパラメーター（predictor、色数、成分あたりのビット数、列数、行数）：デコーダーはこれらからバッファサイズを決めるため、範囲外の値はオーバーフローを引き起こしてきました。実際のファイルは通ります。 | block | block | block |
| `CODEC.FONT_MALFORMED` | テーブルやインデックスがフォントの外を指している、埋め込みの TrueType、OpenType、CFF フォント（レンダラーやプリンターのフォントパーサーをオーバーフローさせる古典的な方法）。フォントツールは書き出しません。完全にデコードできないフォントは判定しません。 | block | block | warn |
| `CODEC.ICC_MALFORMED` | タグテーブルが収まらない、またはタグがプロファイルの末尾を超えている、埋め込みの ICC カラープロファイル：カラーエンジンはプロファイルが示すオフセットでタグを読みます。途中で切れたプロファイル（一部の OCR ツールが埋め込みます）はタグでは判定しません。`acsp` シグネチャのないデータは `CODEC.ICC_UNRECOGNIZED` の担当です。 | block | block | warn |
| `CODEC.ICC_UNRECOGNIZED` | すべての ICC プロファイルが持つ `acsp` シグネチャのない、埋め込みのカラープロファイルデータ：quelda は検査できず、カラーエンジンは拒否すべきものです。このようなプロファイル（空のストリーム、バイト順が入れ替わったヘッダー）を書き出す実際の PDF 作成ソフトも少数あるため、`balanced` は警告のみです。 | block | warn | off |
| `CODEC.JBIG2` | JBIG2 で圧縮された画像。そのデコーダーは実際の攻撃で悪用されました（FORCEDENTRY、CVE-2009-0658）。 | block | warn | off |
| `CODEC.JPX` | JPEG 2000 で圧縮された画像。そのデコーダーにはメモリ安全性のバグの長い歴史があります。 | block | warn | off |
| `CODEC.TYPE1_FONT` | 埋め込みの Type 1（PostScript）フォントプログラム。印刷用ファイルで多用されるため、`balanced` ではオフです。 | warn | off | off |

## リソース (`resource`)

レンダラーのメモリや時間を使い果たすように作られたファイル。

| ルール | 検出対象 | strict | balanced | permissive |
|---|---|---|---|---|
| `RESOURCE.IMAGE_DIMENSIONS` | `thresholds.max_image_pixels` を超えるピクセル数、または不正なサイズを宣言した画像：数バイトでレンダラーに数ギガバイトを確保させます（ピクセル爆弾）。 | block | block | warn |
| `RESOURCE.PAGE_COUNT` | 実際の、または宣言上の `thresholds.max_pages` を超えるページ数：サムネイル生成やラスタライザーを疲弊させます。 | block | block | warn |
| `RESOURCE.PAGE_SIZE` | 5 種類のページボックスのいずれかで、一辺が `thresholds.max_page_side_pt` を超える、またはサイズがゼロや不正なページ。 | block | block | warn |
| `RESOURCE.DRAW_RECURSION` | 直接または他を経由して自分自身を描画するフォーム、タイリングパターン、ソフトマスク、Type 3 グリフ：レンダラーはクラッシュするか停止するまで再帰します。リソースの一覧ではなく、実際に描画される内容で判定します。 | block | block | warn |
| `RESOURCE.FUNCTION_SIZE` | 64 MiB を超えるサンプルを宣言したサンプル関数（色変換、シェーディング）：テーブルを確保するレンダラーはメモリを使い果たします。実際のカラールックアップテーブルは大きくても数 MiB です。 | block | block | warn |
