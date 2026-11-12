# quelda — PDF・Illustrator セキュリティスキャナー

[English](README.md) | **日本語**

quelda は **PDF と Illustrator（`.ai`）ファイル**に悪意のある内容が含まれていないかを検査します。**ブラウザでもサーバーでも、同じルールで同じ判定**を返します。

| quelda を選ぶ理由 | |
|---|---|
| 🌐 **ブラウザとサーバーで同じエンジン** | ブラウザでもバックエンドでも、同じルールで同じ判定 |
| ⚡ **ブラウザで WebAssembly、ネイティブに近い速度** | PDF 500 ファイルを 0.82 秒で、アップロードせずに検査 |
| 🛡️ **実際の攻撃ファイルでテスト済み** | 実在する約 32,000 の PDF ファイル（マルウェア、エクスプロイト、正常な文書）で検証：strict モードで攻撃の 98.9% を拒否、正常なファイルの誤ブロックは 0 件（[結果](#実際の攻撃でのテスト)） |
| 🧱 **複雑な PDF でもクラッシュしない** | 900,000 オブジェクト、5,000 個の圧縮オブジェクトストリームに入った 505,000 オブジェクトでテスト済み |
| 🪶 **高速・軽量** | 1 GB の PDF 1 ファイルを 0.44 秒、メモリ 3 MB で検査。5,820 ファイル（8 GB）のフォルダを 6.3 秒で検査（[数値](#-速度とメモリ)） |
| 📦 **単体で完結** | 外部ツール、外部サービス、ネットワーク通信は不要：サーバーでは静的バイナリ 1 つ、ブラウザでは npm パッケージ 1 つ |
| 🔎 **明確な理由** | 拒否したファイルごとに、どのルールに違反したか、ファイルのどこで、なぜかを示します |
| 🎚️ **調整が簡単** | 用途に合ったモード（`strict` · `balanced` · `permissive`）を選び、ルールを 1 つずつオン・オフできます：`--rule EXTERNAL.URI=off`（[モード](#-モード-strict-balanced-permissive)） |

| | クライアント（ブラウザ） | サーバー（バックエンド） |
|---|---|---|
| **形態** | npm の WebAssembly パッケージ：[`quelda`](https://www.npmjs.com/package/quelda) | `quelda` CLI、静的バイナリ 1 つ（[docs/cli.ja.md](docs/cli.ja.md)） |
| **動作環境** | ユーザーのブラウザの Web Worker 内 | macOS と Linux（x64、arm64）、Docker、あらゆるバックエンド言語 |
| **用途** | 危険なファイルを、アップロードする前にその場で拒否 | 危険なファイルを、Ghostscript、ImageMagick、印刷 RIP、サムネイル生成に渡る前にブロック |
| **対応** | Vite、webpack、esbuild、素の `<script type="module">`、CDN | Python、Ruby、Node.js、Go、PHP、Java など |

PDF に偽装した PostScript/EPS、埋め込まれた PostScript、JavaScript、Launch アクション、圧縮爆弾、改ざんされた構造を阻止し、各ファイルがどのルールに違反しているかを示します。

## ⚡ 速度とメモリ

Apple M2 Pro（10 コア）での CLI のスキャン時間とピークメモリです。

### 単一ファイル

| ファイル | サイズ | 時間 | ピークメモリ |
|---|---:|---:|---:|
| 実際のパンフレット | 54 MB | 0.02 秒 | 3 MB |
| 画像とテキストを含む文書 | 50 MB | 0.02 秒 | 3 MB |
| 画像とテキストを含む文書 | 200 MB | 0.09 秒 | 3 MB |
| 画像とテキストを含む文書 | 1 GB | 0.44 秒 | 3 MB |

### 深くネストしたフォルダ

`quelda scan uploads/` はフォルダツリー内のすべてのファイルを、深くネストしたサブフォルダも含めて再帰的に、CPU コアごとに 1 ファイルずつ並列でスキャンし、各ファイルをフルパスで報告します（[フォルダをスキャン](docs/cli.ja.md#フォルダをスキャン)）：

| フォルダ | ジョブ数 | 時間 | ピークメモリ |
|---|---:|---:|---:|
| 実際の PDF と `.ai` ファイル 133 個、約 800 MB | 10（デフォルト） | 0.55 秒 | 343 MB |
| ネストしたフォルダ内の 5,820 ファイル、8 GB（実際の文書と攻撃テスト用ファイル） | 10（デフォルト） | 6.3 秒 | 370 MB |

### 重いファイル

ファイルが重くなるのはサイズではなく構造のためです：大量のオブジェクト、深いネスト、展開が必要なページ内容。これはまさに攻撃者がスキャナーをクラッシュさせたり停止させたりするために作るものです。quelda は、実際の文書をはるかに超える、作れる限り重いファイルでテストされており、それでもクラッシュせず、メモリを制限内に収めたまま、数秒で答えを返します：

| 重いファイル | サイズ | 時間 | ピークメモリ |
|---|---:|---:|---:|
| 900,000 オブジェクト | 62 MB | 1.5 秒 | 443 MB |
| 5,000 個の圧縮オブジェクトストリームに入った 505,000 オブジェクト | 10 MB | 0.84 秒 | 333 MB |
| 120 階層にネストした 10,000 オブジェクト | 18 MB | 0.55 秒 | 218 MB |
| `#xx` エスケープだらけの 200,000 オブジェクト | 33 MB | 0.44 秒 | 164 MB |
| 999 回の増分更新、100,000 オブジェクト | 7 MB | 0.17 秒 | 57 MB |
| 展開すると 480 MiB になるページストリーム 4 本 | 53 MB | 3.0 秒 | 290 MB |
| 100,000 階層にネストした配列（パーサーをクラッシュさせる攻撃） | 0.2 MB | < 0.01 秒 | 2 MB |

## 🔍 quelda が検査する内容

**11 カテゴリ、56 個のルール**に加え、12 個のエンジン保護機能があり、完全に検査できないものは判定せずに拒否します。説明付きの全一覧：[docs/rules.ja.md](docs/rules.ja.md)。

| カテゴリ | ルール数 | 検出する例 |
|---|---|---|
| `filetype` | 4 | `.pdf` に名前を変えた PostScript/EPS/旧形式の `.ai`（BOM やプリンタヘッダーの後ろに隠れていても）、PDF に偽装した SVG/HTML/MVG/ZIP/実行ファイル、PDF + ZIP/HTML のポリグロット |
| `postscript` | 3 | PDF 内の PostScript コード：`PS` 演算子、PostScript XObject、規格外の Type 4 関数 |
| `active_content` | 7 | JavaScript（どこにあっても、どのエンコードでも、XFA フォームのスクリプトも）、Launch アクション、文書を開いたときやイベントで実行されるアクション、スクリプト・ローカルファイル・ネットワーク共有へのリンク |
| `embedded` | 4 | 添付ファイル、ファイル添付注釈、ポートフォリオ、Flash/3D/マルチメディア |
| `external` | 7 | リンク、リモート文書（SMB による認証情報の漏洩）、URL へのフォーム送信、ネットワーク上のファイル参照、ファイル外部から読み込む画像（外部ストリーム、OPI） |
| `forms` | 2 | AcroForm と XFA フォーム |
| `xml` | 2 | XMP や XFA 内の DOCTYPE/ENTITY（XXE、billion laughs）、XInclude などの外部参照（UTF-8/16/32） |
| `structure` | 14 | 改ざんされた、または曖昧な構造：隠れたリビジョン、矛盾するオブジェクト、解析できないオブジェクト、xref の不一致、ページツリーやブックマークのループ、`%%EOF` 以降のデータ、複数のヘッダー、長すぎる名前、印刷されるが画面では非表示の内容、署名後に変更されたファイル |
| `encryption` | 1 | 内容を検査できない暗号化ファイル |
| `codecs` | 7 | JBIG2（FORCEDENTRY）、JPEG 2000、Type 1 フォント、規格外のデコーダーパラメーター、不正なフォントと ICC カラープロファイル |
| `resource` | 5 | ピクセル爆弾、巨大または壊れたページ、ページ数爆弾、描画ループ、巨大なカラー関数テーブル |

### 実際の攻撃でのテスト

| データセット | 提供元 | 内容 |
|---|---|---|
| [CIC-Evasive-PDFMal2022](https://www.unb.ca/cic/datasets/pdfmal-2022.html) | Canadian Institute for Cybersecurity | 実際のマルウェアと正常な文書 |
| [PDF Insecurity](https://pdf-insecurity.org/)（PDF101 を含む） | ルール大学ボーフム | PDF リーダー、署名、暗号化への攻撃 |

| 約 32,000 ファイル | balanced（デフォルト） | strict |
|---|---|---|
| 🔴 攻撃ファイル | ✅ 95.4% を拒否 | ✅ 98.9% を拒否 |
| 🟢 正常なファイル | ✅ ルールの誤りによる拒否は 0 件 | |

- **意図的に拒否される正常なファイル：** balanced がブロックする JavaScript、添付ファイル、暗号化を含むもの。ユーザーにそれらが必要なら、該当するルール 1 つだけを緩めてください。
- **まだ受け入れてしまう攻撃：** 主にリンクだけのフィッシング文書（quelda は URL の良し悪しを判断できません）と、署名後に変更された署名付きファイル（balanced では警告）です。

すべてのルールは生成したファイルでもテストされています：攻撃のバリエーション、ルールが反応してはいけない正常な類似ファイル、破損したファイルや偽装したファイル。テスト用ファイルはウイルス対策ソフトに検出される可能性があるため公開していません。必要な場合はメンテナー（tranhuucanh39@gmail.com）にメールしてください。

## 🎚 モード: strict, balanced, permissive

**すべてのルールはすべてのモードで実行されます。** モード（プリセット）が決めるのは、検出結果をどう扱うかだけです：**block**（ファイルを拒否）、**warn**（報告するがファイルは受け入れる）、**off**。

| カテゴリ | strict | balanced（デフォルト） | permissive |
|---|---|---|---|
| `filetype`, `postscript`, `encryption` | block | block | block |
| `active_content`, `embedded`, `xml`, `resource` | block | block | warn |
| `external`, `forms`, `structure`, `codecs` | block | warn | off |

- **strict**：誰から来たファイルでも、そのまま Ghostscript、ImageMagick、印刷 RIP に渡す場合。リンク、フォーム、破損した構造を含め、通常と異なるものはすべて拒否します。
- **balanced**：コードを実行できるもの、ペイロードを運べるもの、サーバーに過負荷をかけられるものはすべてブロックし、通常の文書によくある機能（Web リンク、フォームフィールド、編集履歴）は警告だけにします。
- **permissive**：ほぼ信頼できる提供元からのファイル向け。

ロックされたルール（PostScript、Launch アクション、PDF ではないファイル）はどのモードでもブロックします。モードを選んでから、ルールを 1 つずつ変更します：`quelda scan file.pdf --preset strict --rule EXTERNAL.URI=warn`、またはポリシーで `{ "preset": "strict", "rules": { "EXTERNAL.URI": "warn" } }`。カテゴリと異なる動作をするルールもいくつかあります。各モードでの全ルールの動作は [rules.ja.md](docs/rules.ja.md) に、ポリシーの書き方は [policy.ja.md](docs/policy.ja.md) にあります。

## 📚 ドキュメント

| ガイド | 内容 |
|---|---|
| [**ルール**](docs/rules.ja.md) | 全ルールの一覧：何を検出するか、各プリセットで block・warn・off のどれになるか |
| [**ポリシー**](docs/policy.ja.md) | プリセットの選び方、独自ポリシーの書き方、ルール 1 つの緩め方・締め方、上限の引き上げ |
| [**CLI**](docs/cli.ja.md) | サーバーや Docker へのインストール、オプション、終了コード、Python・Ruby・Node.js・Go・PHP・Java からの呼び出し |
| [**npm パッケージ**](packages/quelda-js/README.ja.md) | ブラウザでの利用：React、Vite、webpack、バンドラーなし、CDN |

## 📦 インストール

**macOS（Apple Silicon）、Homebrew で：**

```bash
brew install tranhuucanh/quelda/quelda
```

**Linux サーバー**（どのディストリビューションでも、x64 または arm64。静的バイナリ 1 つ、依存関係なし）：

```bash
curl -fsSL "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" \
  | sudo tar -xz -C /usr/local/bin quelda
```

Docker イメージ（ECS、Kubernetes、Cloud Run など）での利用、バージョンの固定、ダウンロードの検証、ソースからのビルド：[docs/cli.ja.md](docs/cli.ja.md#インストール)。各リリースには `SHA256SUMS` とビルドの来歴証明（provenance attestation）が付いています。

## 🚀 クイックスタート

```bash
quelda scan upload.pdf                          # JSON verdict on stdout
quelda scan upload.pdf --preset strict --format text
quelda scan uploads/ --format text              # a whole folder, recursively: every file, then a summary
quelda rules --format text                      # every rule and its default action
```

終了コード `0` は有効、`1` は拒否、`2` は検査できなかった（無効）、`64` は使い方の誤りです。**`0` 以外はすべて無効として扱ってください。** フォルダのスキャンでは、各ファイルをフルパスで、すべての CPU コアで並列に（5,820 ファイルを 6 秒で）、JSON Lines・テキスト・CSV で報告します：[フォルダをスキャン](docs/cli.ja.md#フォルダをスキャン)を参照してください。バックエンドからは、引数の配列で（シェルを使わずに）タイムアウトを付けて呼び出します：[Python、Ruby、Node.js、Go、PHP、Java](docs/cli.ja.md#バックエンドから呼び出す) の例を参照してください。

## 🌐 ブラウザで使う

同じエンジンを WebAssembly にコンパイルしたものが npm の [**`quelda`**](https://www.npmjs.com/package/quelda) です。`File` を Web Worker 内で、アップロードせずに、ページを止めずにスキャンし、CLI と同じ判定を返します。ファイルが拒否されることをユーザーにすぐ伝えるのに使えます。インストール、フレームワーク、CDN の例：[npm パッケージの README](packages/quelda-js/README.ja.md)。

ブラウザでのチェックは利便性のためのもので、セキュリティ境界ではありません：必ずサーバーでも再スキャンしてください。

## 📄 対応ファイル

quelda はファイルを拡張子ではなく内容で識別します。

- **PDF** と**最近の Adobe Illustrator `.ai` ファイル**（Illustrator 9 以降。Illustrator 独自のデータを加えた PDF ファイルです）はスキャンします。
- **PostScript、EPS、旧形式の `.ai` ファイル**（Illustrator 8 以前。中身は PostScript です）は `FILETYPE.POSTSCRIPT_MAGIC` で**常に拒否**します。これはロックされたルールです。PostScript は完全なプログラミング言語なので静的スキャンでは安全を証明できず、攻撃者が Ghostscript を狙う主な手段でもあります。どうしても EPS を受け入れる必要がある場合は、quelda の外で処理してください：埋め込まれたプレビュー画像を使うか、隔離したサンドボックスで PDF に変換し、その結果をスキャンします。

## 🔧 開発

ルールを追加したい、何かを修正したい場合は、まず [CONTRIBUTING.md](CONTRIBUTING.md)（英語）をお読みください。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p quelda-core --target wasm32-unknown-unknown --profile release-wasm
cargo deny check licenses
```

テスト用 PDF はリポジトリに含めず、生成します。フィクスチャが必要なテストを実行する前に生成してください：

```bash
cargo run -p quelda-testkit --bin gen-fixtures   # writes tests/fixtures/ and tests/conformance/
```

npm パッケージ（`packages/quelda-js`、Node ≥ 20）：

```bash
scripts/wasm-build.sh                               # WASM engine → target/wasm-pkg
cargo run -p quelda-wasm --example wasm_golden      # native verdicts the package must match
cd packages/quelda-js && npm ci && npm test
npm run test:examples   # Vite, webpack, esbuild, no bundler, import map, CDN in headless Chrome
```

リリースされる形の CLI（コンテナ内の静的 Linux バイナリ、各言語の公式イメージでの呼び出し例、docs/cli.md のインストール手順。Docker と Node ≥ 20 が必要）：

```bash
cargo run -p quelda-wasm --example wasm_golden      # native verdicts every binary must match
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release -p quelda-cli --target x86_64-unknown-linux-musl
node scripts/cli-dist-test.mjs --bin target/x86_64-unknown-linux-musl/release/quelda --docker linux/amd64
node scripts/docs-examples-test.mjs --bin target/x86_64-unknown-linux-musl/release/quelda --docker linux/amd64
```

リリース：`scripts/bump-version.sh X.Y.Z`（または `X.Y.Z-rc.N`）で、すべての場所のバージョンを一度に設定します。`main` にマージしてから、タグ `vX.Y.Z` を push します。`.github/workflows/release.yml` がバイナリをビルド・テストし、GitHub Release、npm パッケージ、（正式リリースでは）Homebrew の formula を公開します。

| パス | 内容 |
|---|---|
| `crates/quelda-core` | エンジン：パーサー、フィルタ、ファクト、ルール、ポリシー、判定 |
| `crates/quelda-wasm` | WebAssembly バインディング（薄いラッパー） |
| `crates/quelda-cli` | `quelda` CLI（薄いラッパー） |
| `crates/quelda-testkit` | 開発専用：決定的な PDF ビルダーとフィクスチャ生成 |
| `packages/quelda-js` | npm パッケージ `quelda` |
| `schemas/` | ポリシー、判定、ルール一覧の JSON Schema |
| `fuzz/` | cargo-fuzz のターゲット |
| `docs/cli.md` | CLI ガイド：インストール、オプション、終了コード、判定、バックエンドからの呼び出し例 |
| `docs/policy.md` | ポリシー：仕組み、プリセット、独自ポリシー、上限、エンジンエラー |
| `docs/rules.md` | 全ルール：何を検出するか、プリセットごとの動作 |
| `docs/examples/cli/` | バックエンドからの呼び出し例（テスト済み） |
| `CONTRIBUTING.md` | 貢献の方法、ルール追加時のチェックリスト |
| `packaging/homebrew/` | Homebrew formula のテンプレート |

## 🔒 セキュリティ

脆弱性は [SECURITY.md](SECURITY.md)（英語）に記載の方法で、非公開でご報告ください。

## 📜 ライセンス

[MIT](LICENSE)。
