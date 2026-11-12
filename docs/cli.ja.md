# quelda CLI

[English](cli.md) | **日本語**

`quelda` はファイル 1 つ、またはフォルダ全体をスキャンし、判定を出力します：有効か無効か、そしてファイルが違反した各ルールの理由です。ランタイム依存のない静的バイナリ 1 つで、あらゆる言語で書かれたバックエンドから、ファイルが Ghostscript、ImageMagick などの PDF 処理に渡る前に呼び出すことを想定しています。

- [インストール](#インストール)
- [ファイルをスキャン](#ファイルをスキャン)
- [フォルダをスキャン](#フォルダをスキャン)（数千ファイル、ネストしたフォルダも）
- [終了コード](#終了コード)
- [判定結果](#判定結果)
- [ポリシー](#ポリシー)（詳細：[policy.ja.md](policy.ja.md)、[rules.ja.md](rules.ja.md)）
- [バックエンドから呼び出す](#バックエンドから呼び出す)
- [その他のコマンド](#その他のコマンド)

## インストール

依存関係のない静的バイナリ 1 つ：**Linux x64 と arm64**（どのディストリビューションでも、`scratch` や distroless のコンテナでも）、**Apple Silicon の macOS**。

### Homebrew（macOS、Apple Silicon）

```bash
brew install tranhuucanh/quelda/quelda
```

### Linux サーバー（コマンド 1 つ）

<!-- install: linux -->
```bash
curl -fsSL "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" | sudo tar -xz -C /usr/local/bin quelda
quelda --version
```

`$(uname -m)` が適切なバイナリ（`x86_64` または `aarch64`）を選びます。

### Docker（ECS、Kubernetes、Cloud Run など）

Dockerfile にステージを 1 つ追加し、バイナリを自分のイメージにコピーします。`linux/amd64` と `linux/arm64`（AWS Graviton）のビルドで動作し、どのベースイメージ（Debian、Ubuntu、Alpine、distroless）でも使えます：

<!-- install: docker -->
```dockerfile
FROM alpine:3.20 AS quelda
RUN wget -qO- "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" | tar -xz -C /usr/local/bin quelda

FROM your-app-image
COPY --from=quelda /usr/local/bin/quelda /usr/local/bin/quelda
```

あとは[バックエンドから呼び出す](#バックエンドから呼び出す)のとおりに、アプリケーションから `quelda` を呼び出します。

### バージョンを固定する

`latest` は最新のリリースです。本番環境では 1 つに固定してください：`releases/latest/download/` を `releases/download/vX.Y.Z/` に置き換え（[Releases](https://github.com/tranhuucanh/quelda/releases) を参照）、サーバーとブラウザのパッケージは一緒にアップグレードします（[すべてのエンジンを同じルールセットに保つ](#すべてのエンジンを同じルールセットに保つ)を参照）。

### ダウンロードを検証する

各リリースには `SHA256SUMS` と、署名付きのビルド来歴証明（provenance attestation）があります：

```bash
asset=quelda-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO "https://github.com/tranhuucanh/quelda/releases/latest/download/$asset"
curl -fsSLO https://github.com/tranhuucanh/quelda/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "$asset" --repo tranhuucanh/quelda
```

| プラットフォーム | アーカイブ |
|---|---|
| Linux x64 | `quelda-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `quelda-aarch64-unknown-linux-musl.tar.gz` |
| macOS、Apple Silicon | `quelda-aarch64-apple-darwin.tar.gz` |

### ソースから

Rust（stable、[rustup](https://rustup.rs) 経由）があれば、Rust が対応するどのプラットフォームでも：

```bash
cargo install --locked --git https://github.com/tranhuucanh/quelda quelda-cli
```

## ファイルをスキャン

```bash
quelda scan upload.pdf                         # default preset (balanced); JSON verdict on stdout
quelda scan upload.pdf --preset strict
quelda scan upload.pdf --policy policy.json
quelda scan upload.pdf --rule EMBED.EMBEDDED_FILE=warn --rule EXTERNAL.URI=off
quelda scan upload.pdf --policy-json '{"rules": {"EMBED.EMBEDDED_FILE": "warn"}}'
quelda scan - < upload.pdf                     # read the file from stdin
quelda scan upload.pdf --format text           # human-readable
```

| オプション | 意味 |
|---|---|
| `-p`, `--preset strict\|balanced\|permissive` | プリセット。`--policy` / `--policy-json` のプリセットより優先されます。デフォルト：`balanced`。 |
| `--rule <ID>=<action>` | ルール 1 つの動作：`off`、`warn`、`block`。複数のルールには繰り返し指定します。`--policy` / `--policy-json` 内の同じルールより優先されます。 |
| `--policy <file>` | ポリシーの JSON ファイル。 |
| `--policy-json <json>` | JSON 文字列で指定するポリシー。 |
| `--stop-on-first` | 最初のブロック対象の検出結果で停止：危険なファイルでは速くなり、列挙される理由は少なくなります。 |
| `-f`, `--format json\|text` | `json`（デフォルト）はプログラム向け、`text` は人間向けです。 |
| `--` | オプションの終わり。`-` で始まるファイル名のために使います。 |

通常のファイルは必要な部分だけを読むため、メモリ使用量はファイルサイズに比例して増えず、デフォルトではサイズの上限もありません。stdin、パイプ、デバイスはメモリに読み込む必要があります：`limits.max_file_bytes` まで、ポリシーで上限を設定していない場合は 4 GiB まで保持します。それより大きな入力は `ERROR`（`LIMIT.FILE_BYTES`）となり保持しないため、終わりのないストリームでメモリを使い果たすことはありません。

ファイルは拡張子ではなく内容で識別します。PDF と最近の Adobe Illustrator `.ai` ファイル（Illustrator 9 以降）はスキャンします。PostScript、EPS、旧形式の `.ai` ファイルは**常に拒否**します（`FILETYPE.POSTSCRIPT_MAGIC`、ロックされたルール）。

## フォルダをスキャン

フォルダ、ファイル、またはその両方を指定します。フォルダは再帰的にスキャンし、各ファイルにフルパス付きの個別の結果を出します：

```bash
quelda scan uploads/                           # one JSON line per file
quelda scan uploads/ --format text             # for people: each file, then a summary by rule
quelda scan uploads/ --format csv > report.csv # for a spreadsheet
quelda scan uploads/ upload.pdf --preset strict
quelda scan uploads/ | jq -r 'select(.verdict.valid | not) | .file'   # the invalid files
```

`--format text`：

<!-- batch-text -->
```text
REJECT  uploads/2026/11/brochure.pdf
  block  FILETYPE.NOT_PDF_HEADER  [critical]  File does not start with a PDF header
         at file, offset 0, file starts with "%!PS-Ado"
  block  FILETYPE.POSTSCRIPT_MAGIC  [critical]  File is PostScript/EPS, not PDF
         at file, offset 0, PostScript magic `%!`
  warn   STRUCT.XREF_MISMATCH  [medium]  Cross-reference data does not match the file (×2)
PASS    uploads/2026/11/invoice.pdf
REJECT  uploads/2026/12/form.pdf
  block  ACTIVE.JAVASCRIPT  [high]  Document contains JavaScript
         at object 10 0, file, offset 519
PASS    uploads/2026/12/logo.AI

4 files: 2 PASS, 2 REJECT, 0 ERROR in 0.0 s (4 jobs)
Skipped: 1 file not .pdf or .ai (--all scans them)

ACTIVE.JAVASCRIPT (block): 1 file
  uploads/2026/12/form.pdf

FILETYPE.NOT_PDF_HEADER (block): 1 file
  uploads/2026/11/brochure.pdf

FILETYPE.POSTSCRIPT_MAGIC (block): 1 file
  uploads/2026/11/brochure.pdf

STRUCT.XREF_MISMATCH (warn): 1 file
  uploads/2026/11/brochure.pdf
```

デフォルトの出力は [JSON Lines](https://jsonlines.org/) です：1 ファイルにつき 1 行（[`schemas/scan-line.schema.json`](../schemas/scan-line.schema.json)）で、パス、ファイルの SHA-256、単一ファイルのスキャンと同じ[判定](#判定結果)を含みます：

```jsonl
{"file":"uploads/2026/12/form.pdf","sha256":"5a4d17bf…","verdict":{"valid":false,"status":"REJECT",…}}
```

`--format csv` は 1 ファイルにつき 1 行で、列は `file`、`status`、`valid`、`violations` と `warnings`（スペース区切りのルール ID）、`errors`（`CODE: message` を `; ` で区切ったもの）、`sha256`、`bytes`、`duration_ms` です。`=`、`+`、`-`、`@` で始まるセルには先頭に `'` を付けるため、表計算ソフトがファイル名を数式として実行することはありません。

スキャンされるもの：

- **コマンドラインで指定したすべてのファイル**（名前にかかわらず）。
- **フォルダ内の `.pdf` と `.ai` ファイル**（大文字小文字を問わず：`.PDF`、`.Ai`）、どの階層でも。`--all` を付けるとすべてのファイルをスキャンします（ファイルは常に内容で識別するため、偽装したファイルも検出します）。サマリーには、対象外としたファイルの数と理由が表示されます。
- **フォルダ内のシンボリックリンクはたどりません**。パイプやデバイスもたどりません（スキップとして数えます）。コマンドラインで指定したリンクはたどります。
- 読み取れないファイルやフォルダには、それぞれ `ERROR` の結果（`ENGINE.READ`）が出ます：黙って除外されるものはありません。

順序は固定です：引数の順に、フォルダ内では名前順に並べたパスで処理するため、2 回実行しても同じ出力になります。パスは入力したとおりに表示されます（`uploads/…`、`./uploads/…`、`/srv/uploads/…`）。`--absolute` で絶対パスを表示します。

| オプション | 意味 |
|---|---|
| `-f`, `--format jsonl\|text\|csv` | デフォルト：`jsonl`。（`json` はファイル 1 つの場合専用です。） |
| `--all` | フォルダ内の `.pdf` と `.ai` だけでなく、すべてのファイルをスキャンします。 |
| `--absolute` | 絶対パスを表示します。 |
| `--no-hash` | SHA-256 を計算しません（`"sha256": null`）。約 15% 速くなります。 |
| `-j`, `--jobs <n>` | 同時にスキャンするファイル数。デフォルト：CPU コアごとに 1 つ。 |

`--preset`、`--rule`、`--policy`、`--policy-json`、`--stop-on-first` はすべてのファイルに適用されます。ポリシーが無効な場合は何もスキャンしません（終了コード `2`、メッセージは stderr）。

**終了コード**：すべてのファイルが `PASS` の場合のみ `0`、いずれかのファイルが `ERROR` の場合、またはスキャンするファイルが見つからなかった場合は `2`、それ以外は `1` です。`jsonl` と `csv` ではサマリー行が stderr に出るため、stdout は機械で読める形のままです。

**速度**：ファイルは CPU コアごとに 1 つずつ並列でスキャンします。Apple M2 Pro（10 コア）で、ネストしたフォルダ内の 5,820 ファイル（8 GB）は 6 秒、1 ファイルずつ（`-j 1`）では 26 秒かかります。**メモリ**：スキャン中のファイルはそれぞれ専用のメモリを必要とします（ほとんどのファイルは数 MB、[最も重いもの](../README.ja.md#-速度とメモリ)は数百 MB）。上記の 5,820 ファイルではピークが 370 MB でした。小さなサーバーでメモリを抑えるには `-j` を下げてください。

1 つの名前で渡した PDF 1 つをスキャンする場合は何も変わりません：`quelda scan upload.pdf` は判定を 1 つ出力します。ファイルが 1 つでも 1 ファイル 1 行の形式にしたい場合（たとえば 1 ファイルにしか一致しない可能性のある glob から）は、`--format jsonl` を指定します。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | `PASS`：ポリシーのもとでファイルは有効です。 |
| `1` | `REJECT`：少なくとも 1 つのルールがファイルをブロックしています。 |
| `2` | `ERROR`：ファイルを完全には検査できなかった（破損、大きすぎる、読み取れない）、またはポリシーが無効・読み取れない。ファイルは無効です。 |
| `64` | 使い方の誤り（未知のオプション、ファイル名がない）。stdout には何も出力しません。 |
| `74` | 判定を書き出せませんでした（stdout が閉じている）。 |

**`0` 以外の終了コードはすべて無効として扱ってください**。クラッシュ、シグナル、タイムアウトも含みます。コード 0〜2 では判定の JSON が stdout に、それ以外ではメッセージが stderr に出ます。フォルダや複数のファイルの場合、コードはいずれかのファイルの最も悪いステータスです（[フォルダをスキャン](#フォルダをスキャン)を参照）。

## 判定結果

1 行の JSON オブジェクトです。ここでは整形して示します（[`schemas/verdict.schema.json`](../schemas/verdict.schema.json)）：

<!-- verdict: rules/ACTIVE.JAVASCRIPT/bad/plain.pdf -->
```json
{
  "valid": false,
  "status": "REJECT",
  "violations": [
    {
      "rule_id": "ACTIVE.JAVASCRIPT",
      "category": "active_content",
      "severity": "high",
      "action": "block",
      "message": "Document contains JavaScript",
      "count": 1,
      "locations": [{ "object": "10 0", "offset": 519, "source": "file" }]
    }
  ],
  "warnings": [],
  "errors": [],
  "engine_version": "…",
  "policy": {
    "preset": "balanced",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "unsafe_allow_unlock": false,
    "stop_on_first": false
  },
  "stats": { "bytes": 816, "objects": 7, "revisions": 1, "decoded_bytes": 0, "duration_ms": 0 }
}
```

- `valid` は、`status` が `PASS` のとき（そして終了コードが `0` のとき）に限り `true` です。
- `violations`：動作が `block` のルール。`warnings`：動作が `warn` のルール（ファイルを無効にはしません）。1 ルールにつき 1 項目で、合計の `count` と最大 64 個の `locations` を含みます。
- `errors`：エンジンがすべてを検査できなかった理由（`ENGINE.*`、`LIMIT.*`）、またはポリシーが拒否された理由（`POLICY.INVALID`）。エラーが 1 つでもあればステータスは `ERROR` です。
- `policy.digest` は書かれたとおりのポリシーを識別します。判定と一緒にログに残してください。

## ポリシー

ポリシーはスキャンの厳しさを選びます。完全なガイド：**[policy.ja.md](policy.ja.md)**（仕組み、プリセット、レシピ、すべてのフィールドと上限、エンジンエラー）。各ルールが何を検出するか：**[rules.ja.md](rules.ja.md)**。

要点：

- **すべてのルールが常に実行されます。** ポリシーはプリセット（`strict`、`balanced`（デフォルト）、`permissive`）から始まり、指定したカテゴリとルールの動作（`block`、`warn`、`off`）を変更します。それ以外はプリセットの動作のままです。
- 最も具体的な設定が優先されます：プリセット → `categories` → `rules`。
- ロックされたルール（PostScript、Launch、PDF ではないファイルなど）は常にブロックします。
- ポリシーは厳格に解析されます：タイプミス、未知のフィールド、このエンジンが知らないルール ID は `ERROR`（`POLICY.INVALID`、終了コード 2）となり、黙って無視されることはありません。

```json
{
  "preset": "balanced",
  "categories": { "external": "warn", "codecs": "off" },
  "rules": { "EMBED.EMBEDDED_FILE": "warn" },
  "limits": { "max_file_bytes": 52428800 }
}
```

`--policy policy.json` または `--policy-json '…'` で渡します。`--preset` と `--stop-on-first` は、ポリシーの `preset` と `stop_on_first` より優先されます。

コマンドラインでいくつかのルールを変えるなら、`--rule` のほうが JSON より短く書けます（ポリシー内の同じルールより優先されます）：

```bash
quelda scan upload.pdf --preset strict --rule EXTERNAL.URI=off --rule EMBED.EMBEDDED_FILE=warn
```

ロックされたルール（`quelda rules -f text` で `[locked]` と表示）を下げても効果はありません：ルールは引き続きブロックし、quelda は stderr に警告を出力します。`quelda help policy` がこれらをまとめて表示します。

### すべてのエンジンを同じルールセットに保つ

新しいバージョンの quelda 向けに書かれたポリシー（古いバージョンにないルールを指定したもの）は、古いバージョンのすべてのスキャンを `ERROR` にします。CLI と npm パッケージは一緒にアップグレードするか、デプロイ前にポリシーを `quelda rules` と照らし合わせてください。アップグレード後、新しいルールはプリセットの動作で適用されます。まず [changelog](../CHANGELOG.md)（英語、**Rules** の節）を読んでください。

## バックエンドから呼び出す

1. **引数は配列で渡し**、決してシェルを経由しないこと。そして**ファイル名は自分で付けること**（たとえば非公開の一時ディレクトリ内の UUID）。ユーザーがアップロードした名前は決して使わないでください。
2. **タイムアウトを設定すること**（ほとんどのファイルには 30 秒で十分です。100 MB のファイルのスキャンは約 1 秒です）。タイムアウトは無効を意味します。
3. **有効を意味するのは終了コード `0` だけです。** 理由は判定の JSON を読んでください。
4. ブラウザですでにスキャンしていても、サーバーでスキャンすること：ブラウザのチェックは誰でも回避できる利便性のためのものです。
5. 代わりに別のパーサー（qpdf、pdf.js など）を Ghostscript の前のフィルタとして使わないこと：PDF リーダーは破損したファイルの解釈で食い違い、攻撃はその食い違いに潜んでいます。

以下の各例は完全なプログラムで、各言語の公式コンテナイメージ内で実際のバイナリに対してテストされています（`scripts/docs-examples-test.mjs`）。`<program> upload.pdf` として実行すると、`valid=true status=PASS` または `valid=false status=…` を出力します。

### Python

<!-- example: python/scan.py -->
```python
import json
import subprocess
import sys


def quelda_scan(path, policy=None, timeout=30):
    """Scans one file with the quelda CLI. Only exit code 0 means valid."""
    args = ["quelda", "scan", path]
    if policy:
        args += ["--policy", policy]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"valid": False, "status": "TIMEOUT"}
    try:
        verdict = json.loads(r.stdout)
    except ValueError:
        verdict = {"status": f"EXIT {r.returncode}"}
    verdict["valid"] = r.returncode == 0
    return verdict


if __name__ == "__main__":
    v = quelda_scan(sys.argv[1])
    print(f"valid={str(v['valid']).lower()} status={v['status']}")
```

### Ruby

<!-- example: ruby/scan.rb -->
```ruby
require "json"
require "open3"

# Scans one file with the quelda CLI. Only exit code 0 means valid.
def quelda_scan(path, policy: nil, timeout: 30)
  args = ["quelda", "scan", path]
  args += ["--policy", policy] if policy
  Open3.popen3(*args) do |stdin, stdout, stderr, wait|
    stdin.close
    out = Thread.new { stdout.read }
    Thread.new { stderr.read }
    unless wait.join(timeout)
      Process.kill("KILL", wait.pid)
      return { "valid" => false, "status" => "TIMEOUT" }
    end
    code = wait.value.exitstatus
    verdict = begin
      JSON.parse(out.value)
    rescue JSON::ParserError
      { "status" => "EXIT #{code}" }
    end
    verdict.merge("valid" => code == 0)
  end
end

if __FILE__ == $PROGRAM_NAME
  v = quelda_scan(ARGV.fetch(0))
  puts "valid=#{v['valid']} status=#{v['status']}"
end
```

### Node.js

<!-- example: node/scan.mjs -->
```js
import { execFile } from 'node:child_process';

/** Scans one file with the quelda CLI. Only exit code 0 means valid. */
export function queldaScan(path, policy) {
  const args = ['scan', path, ...(policy ? ['--policy', policy] : [])];
  return new Promise((resolve) => {
    execFile('quelda', args, { timeout: 30_000, maxBuffer: 16 << 20 }, (err, stdout) => {
      let verdict;
      try {
        verdict = JSON.parse(stdout);
      } catch {
        verdict = { status: err?.killed ? 'TIMEOUT' : `EXIT ${err?.code}` };
      }
      resolve({ ...verdict, valid: err === null });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const v = await queldaScan(process.argv[2]);
  console.log(`valid=${v.valid} status=${v.status}`);
}
```

### Go

<!-- example: go/scan.go -->
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type Verdict struct {
	Valid      bool   `json:"valid"`
	Status     string `json:"status"`
	Violations []struct {
		RuleID  string `json:"rule_id"`
		Message string `json:"message"`
	} `json:"violations"`
}

// QueldaScan scans one file with the quelda CLI. Only exit code 0 means valid.
func QueldaScan(path string) Verdict {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "quelda", "scan", path).Output()
	var v Verdict
	if ctx.Err() != nil {
		v.Status = "TIMEOUT"
	} else if json.Unmarshal(out, &v) != nil {
		v.Status = fmt.Sprintf("NO VERDICT (%v)", err)
	}
	v.Valid = err == nil // a non-zero exit, a timeout or a failed start is an error
	return v
}

func main() {
	v := QueldaScan(os.Args[1])
	fmt.Printf("valid=%t status=%s\n", v.Valid, v.Status)
}
```

### PHP

<!-- example: php/scan.php -->
```php
<?php
// Scans one file with the quelda CLI. Only exit code 0 means valid.
function quelda_scan(string $path, ?string $policy = null, int $timeout = 30): array
{
    $args = ['quelda', 'scan', $path];
    if ($policy !== null) {
        array_push($args, '--policy', $policy);
    }
    // An array command runs without a shell (PHP >= 7.4).
    $proc = proc_open($args, [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if ($proc === false) {
        return ['valid' => false, 'status' => 'NOT STARTED'];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $deadline = microtime(true) + $timeout;
    do {
        $out .= stream_get_contents($pipes[1]);
        $status = proc_get_status($proc);
        if ($status['running'] && microtime(true) > $deadline) {
            proc_terminate($proc, 9);
            proc_close($proc);
            return ['valid' => false, 'status' => 'TIMEOUT'];
        }
        usleep(10000);
    } while ($status['running']);
    $out .= stream_get_contents($pipes[1]);
    proc_close($proc);
    $verdict = json_decode($out, true) ?? ['status' => 'EXIT ' . $status['exitcode']];
    $verdict['valid'] = $status['exitcode'] === 0;
    return $verdict;
}

if (realpath($argv[0] ?? '') === __FILE__) {
    $v = quelda_scan($argv[1]);
    echo 'valid=' . ($v['valid'] ? 'true' : 'false') . ' status=' . $v['status'] . "\n";
}
```

### Java

<!-- example: java/QueldaScan.java -->
```java
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QueldaScan {
    /** {@code valid}: exit code 0; {@code json}: the verdict (parse it with your JSON library). */
    record Result(boolean valid, String json) {}

    /** Scans one file with the quelda CLI. Only exit code 0 means valid. */
    static Result scan(String path) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(List.of("quelda", "scan", path))
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> {
            try {
                return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return new Result(false, "{\"status\":\"TIMEOUT\"}");
        }
        return new Result(p.exitValue() == 0, out.join());
    }

    public static void main(String[] args) throws Exception {
        Result r = scan(args[0]);
        Matcher m = Pattern.compile("\"status\":\"(\\w+)\"").matcher(r.json());
        System.out.println("valid=" + r.valid() + " status=" + (m.find() ? m.group(1) : "?"));
    }
}
```

## その他のコマンド

```bash
quelda rules                    # every rule as JSON (schemas/rules.schema.json)
quelda rules -f text            # ID, category, default action, [locked], message
quelda version                  # version, commit, build date, number of rules (also -v)
quelda version -f json
quelda --help                   # the commands, common options and examples (also -h)
quelda help scan                # every scan option
quelda help policy              # how to change rules, with examples
```

短いオプション：`-p` は `--preset`、`-f` は `--format`、`-j` は `--jobs`、`-h` は `--help`、`-v`（または `-V`）は `--version` です。短いオプションは値を次の引数として、または続けて書いて受け取ります（`-f text`、`-ftext`）。
