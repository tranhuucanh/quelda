# quelda — PDF・Illustrator セキュリティスキャナー

[English](README.md) | **日本語**

悪意のある **PDF と Adobe Illustrator（`.ai`）ファイル**を、アップロードされる前にブラウザ内で阻止します。ファイルを描画したりプレビューしたりすることはありません。

| quelda を選ぶ理由 | |
|---|---|
| 🌐 **ブラウザとサーバーで同じエンジン** | ここでも[サーバー版](https://github.com/tranhuucanh/quelda/blob/main/README.ja.md)でも、同じルールで同じ判定 |
| ⚡ **ブラウザで WebAssembly、ネイティブに近い速度** | PDF 500 ファイルを 0.82 秒で、Web Worker 内で検査：ページは固まらず、ファイルがマシンの外に出ることもありません |
| 🛡️ **実際の攻撃ファイルでテスト済み** | 実在する約 32,000 の PDF ファイル（マルウェア、エクスプロイト、正常な文書）で検証：strict モードで攻撃の 98.9% を拒否、正常なファイルの誤ブロックは 0 件（[結果](#実際の攻撃でのテスト)） |
| 🧱 **複雑な PDF でもクラッシュしない** | 900,000 オブジェクト、5,000 個の圧縮オブジェクトストリームに入った 505,000 オブジェクトでテスト済み |
| 🪶 **高速・軽量** | 1 GB の PDF 1 ファイルを 0.8 秒、エンジンメモリ 2.4 MB で検査：ファイルはその場で読み、全体を読み込むことはありません（[数値](#-速度とメモリ)） |
| 📦 **単体で完結** | 外部ツール、外部サービス、ネットワーク通信は不要：エンジンはパッケージに同梱され、依存関係もありません |
| 🔎 **明確な理由** | 拒否したファイルごとに、どのルールに違反したか、ファイルのどこで、なぜかを示します |
| 🎚️ **調整が簡単** | 用途に合ったモード（`strict` · `balanced` · `permissive`）を選び、ルールを 1 つずつオン・オフできます：`{ rules: { 'EXTERNAL.URI': 'off' } }`（[モード](#-モード-strict-balanced-permissive)） |
| 🧩 **どんなフロントエンドでも** | Vite、webpack、esbuild、素の HTML、CDN。React、Vue、Svelte など（[実際のブラウザでテスト済み](#-対応環境)） |

> **ブラウザはセキュリティ境界ではありません。** ブラウザでのチェックはユーザーに即座にフィードバックを返し、無駄なアップロードを省きますが、誰でもそれを回避してファイルを直接サーバーに送れます。ファイルが Ghostscript、ImageMagick などの PDF 処理に渡る前に、**必ずサーバーでも再スキャンしてください**。quelda には同じエンジン・同じ判定のサーバー版があります：[プロジェクトページ](https://github.com/tranhuucanh/quelda/blob/main/README.ja.md)を参照してください。

## ⚡ 速度とメモリ

Apple M2 Pro（Node 22）での WebAssembly エンジンのスキャン時間とエンジンメモリです。

### 単一ファイル

| ファイル | サイズ | 時間 | エンジンメモリ |
|---|---:|---:|---:|
| 実際のパンフレット | 54 MB | 0.06 秒 | 2.4 MB |
| 画像とテキストを含む文書 | 50 MB | 0.04 秒 | 2.4 MB |
| 画像とテキストを含む文書 | 200 MB | 0.14 秒 | 2.4 MB |
| 画像とテキストを含む文書 | 1 GB | 0.8 秒 | 2.4 MB |

### 深くネストしたフォルダ

[サーバー版](https://github.com/tranhuucanh/quelda/blob/main/README.ja.md)は、フォルダツリー内のすべてのファイルを、深くネストしたサブフォルダも含めて CPU コアごとに 1 ファイルずつ並列でスキャンし、各ファイルをフルパスで報告します。ブラウザでは、ファイルを 1 つずつスキャンします。

| フォルダ | ジョブ数 | 時間 | ピークメモリ |
|---|---:|---:|---:|
| 実際の PDF と `.ai` ファイル 133 個、約 800 MB | 10（デフォルト） | 0.55 秒 | 343 MB |
| ネストしたフォルダ内の 5,820 ファイル、8 GB（実際の文書と攻撃テスト用ファイル） | 10（デフォルト） | 6.3 秒 | 370 MB |

### 重いファイル

ファイルが重くなるのはサイズではなく構造のためです：大量のオブジェクト、深いネスト、展開が必要なページ内容。これはまさに攻撃者がスキャナーをクラッシュさせたり停止させたりするために作るものです。quelda は、実際の文書をはるかに超える、作れる限り重いファイルでテストされており、それでもクラッシュせず、メモリを制限内に収めたまま、数秒で答えを返します：

| 重いファイル | サイズ | 時間 | エンジンメモリ |
|---|---:|---:|---:|
| 900,000 オブジェクト | 62 MB | 1.9 秒 | 284 MB |
| 5,000 個の圧縮オブジェクトストリームに入った 505,000 オブジェクト | 10 MB | 1.1 秒 | 246 MB |
| 120 階層にネストした 10,000 オブジェクト | 18 MB | 0.73 秒 | 126 MB |
| `#xx` エスケープだらけの 200,000 オブジェクト | 33 MB | 0.55 秒 | 112 MB |
| 999 回の増分更新、100,000 オブジェクト | 7 MB | 0.20 秒 | 34 MB |
| 展開すると 480 MiB になるページストリーム 4 本 | 53 MB | 3.7 秒 | 271 MB |
| 100,000 階層にネストした配列（パーサーをクラッシュさせる攻撃） | 0.2 MB | < 0.01 秒 | 1.6 MB |

## 🔍 quelda が検査する内容

**11 カテゴリ、56 個のルール**に加え、12 個のエンジン保護機能があり、完全に検査できないものは判定せずに拒否します。説明付きの全一覧：[docs/rules.ja.md](https://github.com/tranhuucanh/quelda/blob/main/docs/rules.ja.md)。

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

ロックされたルール（PostScript、Launch アクション、PDF ではないファイル）はどのモードでもブロックします。モードを選んでから、ルールを 1 つずつ変更します：`{ "preset": "strict", "rules": { "EXTERNAL.URI": "warn" } }`。カテゴリと異なる動作をするルールもいくつかあります。各モードでの全ルールの動作は [rules.ja.md](https://github.com/tranhuucanh/quelda/blob/main/docs/rules.ja.md) に、ポリシーの書き方は [policy.ja.md](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.ja.md) にあります。

## 📚 ドキュメント

| ガイド | 内容 |
|---|---|
| [**ルール**](https://github.com/tranhuucanh/quelda/blob/main/docs/rules.ja.md) | 全ルールの一覧：何を検出するか、各プリセットで block・warn・off のどれになるか |
| [**ポリシー**](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.ja.md) | プリセットの選び方、独自ポリシーの書き方、ルール 1 つの緩め方・締め方、上限の引き上げ |
| [**サーバー版**](https://github.com/tranhuucanh/quelda/blob/main/README.ja.md) | 同じファイルをサーバーで再スキャンし、同じ判定を得る |

## 📦 インストール

```bash
npm install quelda
```

インストールせずに使うこともできます：CDN から読み込みます（[下記](#ビルド不要-cdn)）。

## 🚀 クイックスタート

```ts
import { createScanner } from 'quelda';

const scanner = await createScanner();   // starts a worker, loads the engine once
const verdict = await scanner.scan(file, { preset: 'balanced' });

if (verdict.valid) {
  upload(file);
} else {
  showError(verdict.violations.map((v) => v.message).join('\n'));
}
```

**`verdict.valid === true` 以外はすべて無効として扱ってください**。判定は次のような形です（一部省略）：

```json
{
  "valid": false,
  "status": "REJECT",
  "violations": [
    {
      "rule_id": "ACTIVE.JAVASCRIPT",
      "action": "block",
      "message": "Document contains JavaScript"
    }
  ],
  "warnings": [],
  "errors": []
}
```

`status` は `PASS`（有効）、`REJECT`（`block` に設定されたルールが反応）、`ERROR`（ファイルを完全には検査できなかった：破損、上限超過、またはスキャンの失敗）のいずれかです。完全な形式：[`verdict.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/verdict.schema.json)。

### ファイル入力

```html
<input type="file" id="upload" accept=".pdf,.ai,application/pdf" />
<p id="result"></p>

<script type="module">
  import { createScanner } from 'quelda';

  const scanner = await createScanner();

  document.getElementById('upload').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const verdict = await scanner.scan(file);
    document.getElementById('result').textContent = verdict.valid
      ? 'OK, uploading…'
      : `Refused: ${[...verdict.violations, ...verdict.errors].map((r) => r.message).join('; ')}`;
  });
</script>
```

（バンドラーを使う場合は、スクリプトをアプリのコードに入れてください。使わない場合は[対応環境](#-対応環境)を参照してください。）

### 深くネストしたフォルダ

`webkitdirectory` でユーザーはフォルダを選べます。その中のすべてのファイルが、どの階層のものでも、`webkitRelativePath` にパスを持って渡されます：

```html
<input type="file" id="folder" webkitdirectory multiple />
<ul id="results"></ul>

<script type="module">
  import { createScanner } from 'quelda';

  const scanner = await createScanner();

  document.getElementById('folder').addEventListener('change', async (event) => {
    const files = [...event.target.files]
      .filter((f) => /\.(pdf|ai)$/i.test(f.name))
      .sort((a, b) => a.webkitRelativePath.localeCompare(b.webkitRelativePath));
    const list = document.getElementById('results');
    list.replaceChildren();
    for (const file of files) {
      const verdict = await scanner.scan(file); // one at a time; the page stays responsive
      const item = document.createElement('li');
      item.textContent = `${verdict.status}  ${file.webkitRelativePath}`;
      list.append(item);
    }
  });
</script>
```

すべての判定が有効な場合にだけ、フォルダをアップロードしてください。スキャンはワーカー内で順番に 1 つずつ実行されます（[API](#scannerscaninput-policy-options) を参照）。

### React

コンポーネントの存続期間中、スキャナーは 1 つです。エンジンを一度だけ読み込み、ファイルを順番にスキャンします。

```tsx
import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import { createScanner, type Scanner, type Verdict } from 'quelda';

export function PdfUpload({ onAccepted }: { onAccepted: (file: File) => void }) {
  const scanner = useRef<Promise<Scanner> | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);

  useEffect(() => {
    const started = createScanner();
    scanner.current = started;
    return () => {
      started.then((s) => s.terminate(), () => {});
    };
  }, []);

  async function onChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !scanner.current) return;
    const v = await (await scanner.current).scan(file, { preset: 'balanced' });
    setVerdict(v);
    if (v.valid) onAccepted(file);
  }

  return (
    <>
      <input type="file" accept=".pdf,.ai,application/pdf" onChange={onChange} />
      {verdict && !verdict.valid && (
        <ul>
          {[...verdict.violations, ...verdict.errors].map((r, i) => (
            <li key={i}>{r.message}</li>
          ))}
        </ul>
      )}
    </>
  );
}
```

Vue、Svelte、Angular なども同じ方法で使えます：スキャナーを一度だけ作成し（マウント時）、変更時に `scan(file)` を呼び、アンマウント時に `terminate()` を呼びます。

### ビルド不要 (CDN)

```html
<script type="module">
  import { createScanner } from 'https://cdn.jsdelivr.net/npm/quelda/dist/index.js';

  const scanner = await createScanner();
  // … same as above
</script>
```

[jsDelivr](https://www.jsdelivr.com/package/npm/quelda) や [unpkg](https://unpkg.com/quelda/) などの公開 npm CDN は、npm に公開されたすべてのパッケージを自動的に配信します：設定は不要で、バージョンが npm に公開されるとすぐに URL が使えます。本番環境ではバージョンを固定してください（`…/npm/quelda@X.Y.Z/dist/index.js`、バージョンは `npm view quelda version` で確認）。そうすれば、新しいリリースで判定が予告なく変わることはありません。パッケージは CDN からワーカーを自動的に起動します。ファイルを自分のサーバーから配信する場合は、[バンドラーなし](#-対応環境)を参照してください。

## 🧩 対応環境

パッケージは素の ESM です。API と並べてワーカー（`dist/worker.js`）とエンジン（`dist/wasm/quelda_bg.wasm`、インライン化されていない別ファイル）を同梱し、`new URL(..., import.meta.url)` でそれらを見つけます。以下の各構成は、リリースのたびにヘッドレス Chrome でビルド・実行しています（実際のワーカーとエンジンを通して、正常な PDF は通り、PostScript は拒否されなければなりません）：

| 構成 | 必要な作業 |
|---|---|
| **Vite** | `vite.config.js` に `optimizeDeps: { exclude: ['quelda'] }` と `worker: { format: 'es' }`（下記） |
| **webpack 5** | 不要 |
| **esbuild** | 通常どおりバンドルし（`--format=esm`）、`node_modules/quelda/dist/` をバンドルの隣にコピー |
| **バンドラーなし** | `node_modules/quelda/dist/` をサイトにコピーし（例：`/quelda/`）、`import { createScanner } from './quelda/index.js'` |
| **Import map** | 上と同じに加え、`import … from 'quelda'` が動くように `<script type="importmap">{ "imports": { "quelda": "./quelda/index.js" } }</script>` |
| **CDN** | [上記を参照](#ビルド不要-cdn) |

```js
// vite.config.js: pre-bundling breaks new URL(..., import.meta.url) in dev mode
export default { optimizeDeps: { exclude: ['quelda'] }, worker: { format: 'es' } };
```

その他のバンドラー：`worker.js` と `.wasm` ファイルを自動でコピーしない場合は、esbuild と同様に `dist/` をバンドルの隣にコピーするか、パッケージにそれらの場所を指定します：

```ts
const scanner = await createScanner({
  wasm: '/static/quelda_bg.wasm',
  worker: () => new Worker('/static/quelda/worker.js', { type: 'module' }),
});
```

動作するプロジェクト例：[Vite](https://github.com/tranhuucanh/quelda/tree/main/packages/quelda-js/examples/vite)、[webpack](https://github.com/tranhuucanh/quelda/tree/main/packages/quelda-js/examples/webpack)。

最速で読み込むには、`.wasm` ファイルを `application/wasm` として配信してください。

**Content Security Policy：** WebAssembly には `script-src 'wasm-unsafe-eval'` が必要です。ワーカーには `worker-src 'self'`（または配信元）が必要です。CDN からの場合は `worker-src blob:`、そして `script-src` と `connect-src` に CDN を追加します。

**ブラウザ：** モジュールワーカーと WebAssembly SIMD：Chrome/Edge 91 以降、Firefox 114 以降、Safari 16.4 以降。

## 📄 対応ファイル

ファイルは拡張子ではなく内容で識別します。**PDF** と**最近の `.ai` ファイル**（Illustrator 9 以降。中身は PDF です）はスキャンします。**PostScript、EPS、旧形式の `.ai`**（Illustrator 8 以前）は、ロックされたルール `FILETYPE.POSTSCRIPT_MAGIC` で常に拒否します：PostScript はプログラミング言語であり、スキャンで安全を証明することはできません。

## 🔌 API

### `createScanner(options?)`

ワーカーを起動し、エンジンの読み込みが終わると resolve します。起動できない場合（Web Worker が使えない、`.wasm` が見つからない、CSP など）は `QueldaError`（`code`、`message`）で reject します。

| オプション | デフォルト | |
|---|---|---|
| `timeoutMs` | `30000` | スキャン / `listRules` / ワーカー起動ごと。`Infinity` で無効になります。 |
| `wasm` | 同梱の `.wasm` | URL（文字列または `URL`、ページを基準に解決）またはコンパイル済みの `WebAssembly.Module`。 |
| `worker` | 同梱のワーカー | 上級者向け：`quelda/worker.js` を実行する `Worker` を返す関数。 |

### `scanner.scan(input, policy?, options?)`

- `input`：`File`、`Blob`、`ArrayBuffer`、または任意の型付き配列 / `DataView`（`Uint8Array` など）。ビューの場合は、そのビューのバイトだけをスキャンします。
- `policy`：ポリシーオブジェクト、またはポリシーの JSON テキスト。デフォルトの `{}` は `balanced` プリセットです。[ポリシー](#-ポリシー)を参照してください。
- `options.timeoutMs`：このスキャンだけ、スキャナーのタイムアウトを上書きします。
- `options.signal`：`AbortSignal`。
- `options.transfer`：[メモリ](#-メモリと転送)を参照してください。

**`scan` が reject することはありません。** どんな失敗も `status: "ERROR"`、`valid: false` の判定になります（フェイルクローズ）：

| `errors[].code` | 発生元 | 発生する場合 |
|---|---|---|
| `LIMIT.*`, `ENGINE.*`, `POLICY.INVALID` | エンジン | 上限を超えた、ファイルを検査できなかった、ポリシーが無効 |
| `LIMIT.TIMEOUT` | パッケージ | スキャンが `timeoutMs` より長くかかった。ワーカーは強制終了されます |
| `ENGINE.ABORTED` | パッケージ | `signal` が発火した、または `terminate()` が呼ばれた |
| `ENGINE.WORKER` | パッケージ | ワーカーまたはエンジンがクラッシュした、読み込みに失敗した、または不正な応答を返した |
| `ENGINE.INPUT` | パッケージ | 入力が対応していない型、ファイルを読み取れなかった、またはオプションが無効 |
| `ENGINE.READ` | エンジン | スキャン中に `File` / `Blob` を読み取れなかった（例：変更された、削除された） |
| `POLICY.INVALID` | パッケージ | ポリシーオブジェクトを JSON に変換できない（循環参照、`BigInt` など） |

WebAssembly 内のエンジンには時計がないため、パッケージは `stats.duration_ms` に、ワーカー内で計測したエンジン呼び出しの時間を入れます（ミリ秒単位の整数。待ち時間とファイルの読み取りは含みません）。

スキャンは呼び出し順に**1 つずつ**実行されます（WebAssembly はシングルスレッドです）。スキャンのタイムアウトは、キューに入ったときではなく、スキャンが始まったときから数えます。タイムアウト、実行中のスキャンの中止、クラッシュはワーカーを強制終了し、次のスキャンは新しいワーカーで始まります。エンジンが例外を投げたワーカーは再利用されません。WebAssembly のメモリが 64 MiB を超えて増えたワーカーも同様です（メモリは縮まないため、新しいワーカーにすることでシステムに返します）。

### `scanner.listRules(options?)`

エンジンが知っているすべてのルール（`id`、`category`、`severity`、`default_action`、`locked`、`stage`、`since`、`message`、`description`。[`rules.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/rules.schema.json) を参照）を `id` 順で返します。設定画面に便利です。失敗時は `QueldaError` で reject します。`scanner.engineVersion` はエンジンのバージョンです。

### `scanner.terminate()`

ワーカーを強制終了します。待機中のスキャンは `ENGINE.ABORTED` で resolve し、以降の呼び出しは失敗します。2 回呼んでも安全です。

## 📋 ポリシー

**すべてのルールが常に実行されます**：ポリシーはプリセットから始まり、指定したカテゴリとルールの動作（`block`、`warn`、`off`）を変更します。それ以外はプリセットの動作のままです。完全なガイド（プリセット、レシピ、上限、エンジンエラー）：[policy.ja.md](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.ja.md)。

3 つの段階があり、最も具体的なものが優先されます：**プリセット → カテゴリ → ルール**（[`policy.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/policy.schema.json)）。

```ts
await scanner.scan(file, {
  preset: 'balanced',                                   // strict | balanced | permissive
  categories: { external: 'warn', codecs: 'off' },      // block | warn | off
  rules: { 'ACTIVE.OPEN_ACTION': 'off' },
  limits: { max_file_bytes: 50 * 1024 * 1024 },
});
```

各プリセットの動作：[モード](#-モード-strict-balanced-permissive)。

デフォルトは意図的に厳しくしています。ユーザーが正当にアップロードするファイルをルールがブロックする場合は、カテゴリやプリセット全体ではなく、**そのルール**を緩めてください。たとえば `EMBED.EMBEDDED_FILE` は添付ファイルを持つファイル（一部の電子書籍やレポート）をブロックします：

```ts
{ rules: { 'EMBED.EMBEDDED_FILE': 'warn' } }   // still reported in verdict.warnings
```

ロックされたルール（`listRules()` で `locked: true`：PostScript、Launch アクション、PDF ではないファイルなど）は、ポリシーが `unsafe_allow_unlock: true` も設定しない限り、ポリシーの内容にかかわらず `block` のままです（これは `verdict.policy` に報告されます。信頼できないファイルには使わないでください）。

エンジンはポリシーを**厳格に**解析します：未知のフィールド、`null`、誤った型、未知のカテゴリ、そして**このバージョンのエンジンが知らないルール ID** は、無視されずに `ERROR` の判定（`POLICY.INVALID`）になります。黙って無視されたタイプミスが、ルールをオフにしてしまう可能性があるからです。

### ブラウザとサーバーを同じルールセットに保つ

新しいエンジン向けに書かれたポリシー（古いエンジンにないルールを指定したもの）は、古いエンジンのすべてのスキャンを `ERROR` にします。ブラウザとサーバーで同じバージョンの quelda を使うか、スキャンの前にエンジンが知らないルールを取り除いてください：

```ts
const known = new Set((await scanner.listRules()).map((r) => r.id));
const policy = { ...serverPolicy, rules: Object.fromEntries(
  Object.entries(serverPolicy.rules ?? {}).filter(([id]) => known.has(id))) };
```

（サーバーでは引き続き完全なポリシーを使ってください。）

## 🧠 メモリと転送

`File` / `Blob` そのものを渡すことをおすすめします（上限：`limits.max_file_bytes`、デフォルト 256 MiB）。

- `File` / `Blob`（推奨）：**全体を読み込むことはありません。** ワーカーは `FileReaderSync` でその場で読みます：1 MiB ブロックで 1 回通して読み、その後はエンジンが解析・デコードする必要のある部分だけを読みます（画像などの不透明なデータは再度読みません。フォントとカラープロファイルは構造を検査するためにもう一度読みます）。エンジンのメモリは、ファイルサイズにかかわらず数 MiB と、展開が必要なデータの分にとどまります。渡したオブジェクトには触れません。スキャンが resolve するまでファイルを変更してはいけません（変更された場合：`ENGINE.READ`）。
- `ArrayBuffer` / 型付き配列：**`scan` を呼んだ時点でコピー**され、その後エンジンのメモリに丸ごとコピーされます。その後にバッファを変更しても、スキャンには影響しません。
- `transfer: true`：`ArrayBuffer`（またはバッファ全体にまたがる型付き配列のバッファ）をコピーせずにワーカーに渡します。**`scan` を呼んだ時点でバッファは切り離されます（長さ 0）。** バッファの一部だけのビューは引き続きコピーされます。

## 💻 Node

このパッケージはブラウザを対象としています。Node（≥ 20）には Web Worker がないため、`createScanner()` はそのままでは動きません。サーバーでは、[プロジェクトページ](https://github.com/tranhuucanh/quelda/blob/main/README.ja.md)のサーバー版を使ってください。

## 📜 ライセンス

[MIT](https://github.com/tranhuucanh/quelda/blob/main/LICENSE)。

セキュリティ上の問題は、非公開でご報告ください（[SECURITY.md](https://github.com/tranhuucanh/quelda/blob/main/SECURITY.md)、英語）。
