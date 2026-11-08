# NyanQL（にゃんくる）

NyanQL（にゃんくる）は、SQLを書くだけで、データベースにアクセスするAPIサービスを手軽に作るための軽量フレームワークです。

「猫の手も借りたい」くらい忙しい業務システム開発で、APIサーバ作りの手間を小さくし、まずは大事なSQLに集中できるようにすることを目指しています。

NyanQLでは、APIを呼び出すと、`api.json` に紐づけられたSQLファイル、またはJavaScriptファイルが実行されます。SQLの実行結果はJSONで返ります。検索だけでなく、登録・更新・削除、複数SQLのトランザクション、JavaScriptによる複雑な処理、WebSocketによるPush配信にも対応しています。

このREADMEは、Version1方針を反映したリポジトリの現行ソースを説明します。配布バイナリを使う場合は、ダウンロードしたリリースと同じタグのREADME・リリースノートを参照してください。現行ソースの機能が過去のバイナリにも含まれるとは限りません。`config.json` の `version` はサービスの表示用設定値で、バイナリの版を判定する値ではありません。

はじめに：[入手とビルド](#インストールと起動) → [最小起動例](#quickstart)。機能別：[MCPの設定](#mcp-setup)、[公開・運用の前提](#deployment)。

---

## NyanQLでできること

NyanQLは、主に次のような用途に向いています。

- SQLを中心にして、データベース用のAPIをすばやく作る
- SELECTの結果をJSONとして返すAPIを作る
- INSERT、UPDATE、DELETEなどの更新処理をAPI化する
- 複数のSQLを1つのトランザクションとしてまとめて実行する
- JavaScriptで、SQLだけでは書きにくい一連の処理をまとめる
- `api.json` をincludeして、API定義を複数ファイル・複数階層に分割する
- WebSocketを使って、API実行後の結果を別の画面へPush配信する
- `/nyan/` で、利用できるAPIの情報を取得する

NyanQLは、画面を作るためのフレームワークではありません。役割は、データベースアクセスに特化したAPIサービスを作ることです。

---

## 基本の考え方：SQLファースト

NyanQLは「SQLファースト」という考え方を大事にしています。

まず、単体で正しく動くSQLを書きます。次に、そのSQLファイルを `api.json` でAPI名に紐づけます。すると、HTTPからAPIを呼び出したときに、そのSQLが実行され、結果がJSONで返ります。

流れはとてもシンプルです。

1. SQLファイルを書く
2. `api.json` にAPI定義を書く
3. API名とSQLファイルを紐づける
4. HTTP、またはJSON-RPCでAPIを呼び出す
5. 実行結果をJSONで受け取る

たとえば、次のようなSQLを書きます。

```sql
SELECT
  id AS id,
  name AS name,
  price AS price
FROM items
WHERE id = /*id*/1;
```

そして、`api.json` に次のように書きます。

```json
{
  "getItem": {
    "sql": ["./sql/getItem.sql"],
    "description": "商品を1件取得します"
  }
}
```

この状態で、次のように呼び出せます。

```bash
curl -u admin:secret "http://localhost:8080/getItem?id=1"
```

返り値は、次のようなJSONになります。

```json
{
  "success": true,
  "status": 200,
  "result": [
    {
      "id": 1,
      "name": "にゃんくるTシャツ",
      "price": 3000
    }
  ]
}
```

SELECT句の `AS` で指定した列名が、そのままJSONの項目名になります。

---

## 対応データベース

現在の実装では、次のデータベースに対応しています。

- MySQL
- PostgreSQL
- SQLite
- DuckDB

`config.json` の `DBType` に、`mysql`、`postgres`、`sqlite`、`duckdb` のいずれかを指定します。

---

## インストールと起動

### 1. 入手する

GitHub Releasesから、使っているOSに合うファイルをダウンロードします。

https://github.com/NyanQL/NyanQL/releases

ソースからビルドする場合は、[go.mod](go.mod)に記載されたGoバージョン（現時点では1.26.9）と、対象OS/CPU向けのC/C++コンパイラを用意してください。SQLite・DuckDBのネイティブ依存があるためCGOが必要です。macOSはXcode Command Line Tools、LinuxはC/C++開発ツール、Windowsは対応するMinGW-w64等が必要です。別OS向けのビルドには対応するクロスコンパイラも必要です。DBTypeを変更してもビルド時のネイティブ依存はなくなりません。

```bash
git clone https://github.com/NyanQL/NyanQL.git
cd NyanQL
CGO_ENABLED=1 go build -o nyanql .
```

WindowsのPowerShellでは `$env:CGO_ENABLED="1"` を設定して `go build -o nyanql.exe .` を実行します。配布バイナリを利用する場合、Goやコンパイラは不要です。配布物のOS/CPUと必要な実行時ライブラリは、該当リリースで確認してください。

### 2. 設定ファイルを用意する

少なくとも次の2つのファイルを用意します。最初の確認には[最小起動例](#quickstart)を使用してください。同梱の業務・background例を使う場合は、参照するSQL/JSの実在、DBテーブル、接続URL、cron式を用途に合わせて確認・準備します。

- `config.json`
- `api.json`

SQLファイルやJavaScriptファイルも、`api.json` から参照できる場所に置いてください。API定義を分割する場合は、ルートの `api.json` からinclude先を相対パスまたは絶対パスで指定します。

デフォルトでは、NyanQLは実行ファイルと同じ場所にある `config.json` と `api.json` を読み込みます。起動時オプションや環境変数による指定は必須ではありません。別の場所に置きたい場合だけ、追加で指定できます。

### 3. 起動する

```bash
./nyanql
```

`config.json` と `api.json` を任意の場所から読み込む場合は、次のように指定します。

```bash
./nyanql --config /path/to/config.json --api /path/to/api.json
```

環境変数でも指定できます。

```bash
NYAN_CONFIG_PATH=/path/to/config.json \
NYAN_API_PATH=/path/to/api.json \
./nyanql
```

設定ファイルの場所は、次の優先順位で決まります。

1. 起動時オプション `--config`、`--api`
2. 環境変数 `NYAN_CONFIG_PATH`、`NYAN_API_PATH`
3. 実行ファイルと同じ場所にある `config.json`、`api.json`

Windowsでは、ビルド済みの実行ファイルをダブルクリックして起動することもできます。ただし、動作確認やエラー確認をしやすくするため、最初はターミナルから起動することをおすすめします。

---

<a id="quickstart"></a>
### 最小起動例：テーブルを作らずSQLを実行する

実行ファイルのあるディレクトリに、新しい `quickstart` フォルダを作り、次の3ファイルを保存します。既存の同梱 `config.json`・`api.json` やサンプルDBは使いません。以下のシェル例はmacOS/Linux用です。Windowsでは実行ファイルを `.\nyanql.exe` に読み替えてください。

`quickstart/config.json`：

```json
{
  "name": "NyanQL quickstart",
  "Port": 8080,
  "DBType": "sqlite",
  "DBName": "./demo.sqlite",
  "BasicAuth": {"Username": "demo", "Password": "local-demo-only"},
  "javascript_include": [],
  "log": {"EnableLogging": false, "Level": "info"}
}
```

`quickstart/api.json`：

```json
{
  "hello": {"sql": ["./hello.sql"], "description": "SQLの動作確認"}
}
```

`quickstart/hello.sql`：

```sql
SELECT 1 AS ok;
```

起動すると `quickstart/demo.sqlite` を作成します。外部DBには接続せず、テーブル作成や初期データも不要です。HTTPは全インターフェースで待ち受けるため、この例は信頼できるローカル環境で確認し、外部公開前に[公開・運用の前提](#deployment)を確認してください。

```bash
./nyanql --config ./quickstart/config.json --api ./quickstart/api.json
```

別のターミナルで確認します。

```bash
curl -u demo:local-demo-only http://127.0.0.1:8080/hello
```

HTTP 200で次のJSONが返ります（キーの順序は問いません）。終了は起動したターミナルで `Ctrl+C` です。`items` 等の業務テーブルを使う前述の例へ進む場合は、別途そのテーブルとデータを用意してください。

```json
{"success":true,"status":200,"result":[{"ok":1}]}
```

## config.json

`config.json` には、サーバ全体の設定を書きます。

```json
{
  "name": "NyanQL Sample API",
  "profile": "NyanQLのサンプルAPIです",
  "version": "v1.0.0",
  "Port": 8080,
  "CertPath": "",
  "KeyPath": "",
  "DBType": "sqlite",
  "DBUser": "",
  "DBPassword": "",
  "DBName": "./stamps.db",
  "DBHost": "localhost",
  "DBPort": "",
  "MaxOpenConnections": 10,
  "MaxIdleConnections": 5,
  "ConnMaxLifetimeSeconds": 300,
  "BasicAuth": {
    "Username": "admin",
    "Password": "secret"
  },
  "APIHotReload": {
    "Enabled": true,
    "Interval": "1s"
  },
  "log": {
    "Filename": "./logs/nyanql.log",
    "MaxSize": 5,
    "MaxBackups": 3,
    "MaxAge": 7,
    "Compress": true,
    "EnableLogging": true,
    "Level": "info"
  },
  "javascript_include": [
    "./javascript/common.js"
  ]
}
```

主な項目は次のとおりです。

| 項目 | 説明 |
|---|---|
| `name` | `/nyan/` で返すサーバ名です。 |
| `profile` | `/nyan/` で返すサーバ説明です。 |
| `version` | `/nyan/` で返す設定上のバージョンです。 |
| `Port` | NyanQLが待ち受けるポート番号です。 |
| `CertPath`, `KeyPath` | 両方を指定するとHTTPSで起動します。空ならHTTPで起動します。 |
| `DBType` | `mysql`、`postgres`、`sqlite`、`duckdb` のいずれかを指定します。 |
| `DBName` | データベース名、またはSQLite/DuckDBのファイルパスです。 |
| `DBUser`, `DBPassword` | MySQL/PostgreSQLへ接続するユーザー名・パスワード（文字列）です。HTTPの `BasicAuth` とは独立しています。SQLite/DuckDBの接続には使いません。 |
| `DBHost` | MySQL/PostgreSQLの接続先ホスト（文字列）です。SQLite/DuckDBの接続には使いません。 |
| `DBPort` | MySQL/PostgreSQLの接続先ポートを文字列で指定します（例：`"3306"`、`"5432"`）。SQLite/DuckDBの接続には使いません。 |
| `MaxOpenConnections` | DB接続プールの最大オープン接続数（整数）。正数ならその値、未指定・0・負数なら無制限です。 |
| `MaxIdleConnections` | プールに保持する最大アイドル接続数（整数）。正数ならその値を設定します。未指定・0・負数ならGoの `database/sql` の既定値を使います。 |
| `ConnMaxLifetimeSeconds` | DB接続を再利用できる最大時間（整数、秒）。正数ならその時間、未指定・0・負数なら経過時間による破棄を設定しません。 |
| `BasicAuth` | API呼び出し時のBasic認証ユーザ名とパスワードです。 |
| `APIHotReload` | `api.json` の定期的な変更確認を設定します。省略時も有効です。 |
| `webSocketLimits` | 全チャネル合計のWebSocket受入接続数の上限です。省略時は128件です。[設定仕様](#websocket-connection-limits)を参照してください。 |
| `oauthRuntime` | OAuth用VMの混雑時の応答を選択します。省略時は従来の応答を維持します。[混雑応答の設定](#oauth-runtime-busy-response)を参照してください。 |
| `sqlResultLimits` | SQL結果ごとの行数・JSONバイト数の上限です。省略時は10,000行・4MiBです。 |
| `javascript_include` | `check` や `script` の実行前に読み込む共通JavaScriptです。 |
| `javascript_include_cache` | `true`で共通JSのソースを起動時に読み込み、再起動まで保持します。省略時は`false`です。 |

`config.json` 内の相対パスは、`config.json` がある場所を基準にして扱われます。対象は `CertPath`、`KeyPath`、SQLite/DuckDB の `DBName`、`log.Filename`、`javascript_include` です。

DB接続設定の未指定文字列は空文字列です。NyanQLは `DBHost` や `DBPort` を補完せず、その値をドライバの接続文字列へ渡します。上のSQLite用サンプルをMySQL/PostgreSQLへ変更する場合は、接続先・認証情報も指定してください。接続プールの3項目は全DB種類で共通です。`MaxIdleConnections` の既定値は現在のGo標準ライブラリでは2ですが、正の `MaxOpenConnections` がそれより小さければ、その上限までに調整されます。明示したアイドル接続数も同様に最大オープン接続数を超えません。

NyanQLは `MaxIdleConnections` が0以下のとき `SetMaxIdleConns` を呼ばないため、`MaxIdleConnections: 0` は「アイドル接続を保持しない」の指定にはなりません。`ConnMaxLifetimeSeconds` は実行中SQLのタイムアウトではなく、接続の再利用期間です。DB接続設定の変更には再起動が必要です。

### SQL結果の上限と共通JSの読込設定

次は既存の`config.json`へ追加する項目の例です。SQL結果の上限を10万行・32MiBに引き上げ、共通JSのソースを再起動まで保持します。

```json
{
  "sqlResultLimits": {
    "maxRows": 100000,
    "maxBytes": 33554432
  },
  "javascript_include": ["./javascript/common.js"],
  "javascript_include_cache": true
}
```

`sqlResultLimits.maxRows`は行数、`maxBytes`はSQL結果をJSONに変換したときのバイト数です。項目の省略または`0`は、それぞれ10,000行・4MiB（4,194,304バイト）を意味し、無制限にはなりません。正の整数で上限を上げ下げできます。負数・小数・文字列・実行環境の整数範囲を超える値は起動時エラーになります。

上限は各SQL結果セットに適用され、超過時は途中までの結果を返さずエラーにします。通常HTTP、JSON-RPC、内部呼び出し、`nyanRunSQL`と、それらを使うMCP・WebSocket・scheduleで共通です。SQLの更新件数や、複数のSQL結果を組み合わせた最終応答全体の上限ではありません。MCPのTool結果2MiB・応答全体4MiBなどの応答制限は別に適用されます。

`javascript_include_cache: true`では、共通JSを設定順に起動時に読み込みます。読み込めないファイルがあれば起動を中止します。起動後にファイルを変更・削除しても、再起動までは読み込んだソースを使用します。`false`または省略時は、従来どおり各実行時にファイルを読み込みます。

保持するのは共通JSのソースだけです。実行結果や変数は引き継がず、本体JSやチェックJSは引き続き各実行時に読み込みます。チェック、本体、OAuth用の制限付き実行、scheduleなどで同じ設定を使用します。これらの`config.json`設定の変更には再起動が必要です。

### ログ

ログは1行につき1つのJSONとして記録します。`time`、`level`、`msg`（処理名）に加え、API名、ファイル名、件数など、処理に応じた項目が付きます。従来のテキスト形式でログを解析している場合は、JSON形式への対応が必要です。

- `log.EnableLogging: true` は指定ファイルへの出力です。`Filename`、`MaxSize`、`MaxBackups`、`MaxAge`、`Compress` のローテーション設定は従来どおり使えます。
- `log.EnableLogging: false` は標準エラーへの出力です。ログ自体の無効化ではありません。設定読み込み前の起動エラーも標準エラーに出ます。
- 標準出力にはサービスのログを出しません。MCPのstdioモードではJSON-RPC応答専用です。
- `log.Level` は `debug`、`info`、`warn`、`error` から選びます。省略時は `info` で、指定以上の重大度のログを出します。不正な値では起動を中止します。

通常の `info` では、起動、設定変更、ジョブ完了、接続状態、警告、エラーを記録します。SQL全文、チェック用JavaScript全文、API設定全体、リクエスト・WebSocket・Push・ジョブ結果の本文は自動出力しません。WebSocket接続先は資格情報・パス・クエリ・フラグメントを除いたschemeとhostだけを記録します。エラーには処理名と型、取得できる場合はSQLSTATEやWebSocket終了コードを記録します。

正常なAPI呼び出しを毎回記録するアクセスログはなく、すべてのリクエストのURL・ステータス・処理時間を出力するものではありません。ジョブ完了ログの `result_bytes` は結果文字列のバイト数で、結果本文やDBの行数ではありません。以下はログの出力例です。

```json
{"time":"2026-09-09T12:00:00+09:00","level":"INFO","msg":"schedule_completed","job":"daily_update","result_bytes":128}
```

`debug` では、SQL更新件数、Pushや受信メッセージのバイト数、ジョブの次回実行時刻も記録します。さらに、**エラーの詳細文字列と、通常のJavaScriptの `console.log(...)` が出力されます**。これらにはパラメータや認証情報が含まれ得るため、調査時に限って有効にしてください。詳細文字列・consoleメッセージはそれぞれ4096バイトまでとし、改行はJSON内でエスケープします。制限付きJavaScriptのconsoleは、debugでも引数の個数だけを記録します。

`debug` にしてもSQL全文や結合したJavaScript全文の自動出力は行いません。`log.Level` を変更した場合は再起動が必要です。

### api.jsonのホットリロード

NyanQLは既定で、ルートの `api.json` と、そこから `type: "include"` で読み込まれるすべてのJSONファイルの変更を定期的に確認します。`APIHotReload` を省略した場合は、`Enabled: true`、`Interval: "1s"` として動作します。外部のファイル監視ライブラリは使わず、Go標準ライブラリによる定期確認を行います。

```json
{
  "APIHotReload": {
    "Enabled": true,
    "Interval": "1s"
  }
}
```

ホットリロードを無効にする場合だけ、`Enabled` に `false` を指定します。

`Interval` はリロードの実行間隔ではなく、変更の確認間隔です。`1s`、`500ms` など、Goのduration形式で0より大きい値を指定します。`APIHotReload` または `Interval` の省略時は `1s` です。

主な指定例は次のとおりです。

| 確認間隔 | 設定値 |
|---|---|
| 500ミリ秒 | `"500ms"` |
| 1秒 | `"1s"` |
| 1分 | `"1m"` |
| 1時間 | `"1h"` |
| 1日 | `"24h"` |

Goのduration形式には日を表す `d` 単位がないため、1日は `"1d"` ではなく `"24h"` と指定します。`"1h30m"` のような複合指定も可能です。

確認時刻はNyanQLを起動した時点を基準にします。たとえば `"24h"` は起動後24時間ごとの確認であり、「毎日午前0時」のような固定時刻での確認ではありません。間隔を長くすると、`api.json` の変更反映にも最大でその間隔と同程度の時間がかかります。

確認のたびに監視対象ごとのファイル内容のSHA-256とリンク解決後のパスを比較し、いずれかが変わった場合はルートからincludeグラフ全体を1回再構築します。ルート設定やinclude先がシンボリックリンクの場合、その参照先の差し替えも検知します。同じ実体を指す複数のリンクも個別に監視します。子ファイルだけを部分的に差し替えることはありません。読み込み中に再編集されて整合性検証に失敗した場合は、次の確認で安定した最新内容を再試行します。

includeの追加・変更・削除に成功すると、監視対象も同時に追加・削除されます。参照中のincludeファイルが削除された場合や、候補設定のinclude先がまだ存在しない場合は、現在稼働中の正常な設定を維持したまま、そのパスの確認を続けます。ファイルが再作成または修正されると、次の変更確認時に再読み込みします。

不正なJSON、循環参照、名前競合、scheduleやws_clientの設定エラーなどがある場合は、候補全体を採用しません。同じファイル状態とエラーについて、確認間隔ごとに同じログを繰り返し記録することもありません。すべての検証に成功した場合だけ、通常API、public API、API一覧、schedule、ws_client、監視対象を新しい設定へ交換します。

通常API、public API、`/nyan/`、JSON-RPC、`schedule`、`ws_client`が参照する定義を更新できます。

| 定義 | 追加 | 変更 | 削除 |
|---|---|---|---|
| `schedule` | 新しいジョブを開始 | 次回実行から新しいscript／cronを使用 | 次回以降の実行を停止 |
| `ws_client` | 新しく接続 | script／descriptionは接続を維持して更新し、connectURLは再接続 | 接続と再接続処理を停止 |

不正なcron式や必須項目の不足がある場合は変更全体を採用せず、現在稼働中の定義を維持します。接続先WebSocketサーバーが停止しているだけの場合は定義を採用し、通常のバックオフ処理で再接続を続けます。

`config.json`、SQL、JavaScript、public配下のファイル自体は監視しません。ただしAPI実行時のSQL・JavaScript本体と、`/nyan/{API名}` で表示するスキーマは、それぞれのリクエスト時にファイルを読み直します。そのためSQL、script、paramCheck、outCheck内のスキーマ記述は、ファイル保存後の次のAPI詳細取得から反映され、NyanQLの再起動や `api.json` の更新は不要です。`Enabled: false` の場合は、ルートとincludeファイルのどちらも監視しません。

---


### HTTPサーバーのタイムアウト（3製品共通）

`config.json` の `httpTimeouts` で、NyanQLのHTTPサーバーが受け付ける接続のタイムアウトを設定します。各設定値が未指定・`null`・`"0s"` の場合は下記の既定値を使い、無制限にはなりません。`nyanGetAPI`・`nyanJsonAPI`（別名 `nyanCallAPI`）による外部HTTP通信には適用されません。

以下は `config.json` の抜粋です。既存の設定のトップレベルに `httpTimeouts` を追加してください。

```json
"httpTimeouts": {
  "readHeaderTimeout": "30s",
  "readTimeout": "20m",
  "writeTimeout": "30m",
  "idleTimeout": "5m"
}
```

| 設定 | 既定値 | 対象 |
|---|---|---|
| `readHeaderTimeout` | 30秒 | HTTPヘッダーの受信 |
| `readTimeout` | 20分 | 本文を含むHTTPリクエスト全体の受信 |
| `writeTimeout` | 30分 | HTTP応答の書き込み期限 |
| `idleTimeout` | 5分 | Keep-Aliveで次のHTTPリクエストを待つ時間 |

値は `"30s"`・`"20m"`・`"1h"`・`"500ms"` のような時間単位付き文字列です。負数・空文字列・単位なしの数値・範囲外は設定エラーです。変更の反映には再起動が必要です。

受信時間は「最後にデータを受け取ってから」ではなく受信全体の期限です。通常のHTTP/1では応答期限はヘッダー読込後から進むため、本文受信に20分かかった場合は処理・送信に残り約10分となります。TLSやHTTP/2ではプロトコルに応じた期限の適用になります。タイムアウトは通信を制限するもので、実行中のJavaScriptやDB処理を強制終了する設定ではありません。HTTPステータスが返るとは限らず、接続終了やHTTP/2ストリームのエラーとなる場合もあります。

サイズ上限 `receiveLimits` と時間上限の両方が適用されます。WebSocketへ切り替えた後はHTTPの期限を引き継がず、既存のWebSocket接続管理を使います。ログインやセッションの有効期限には影響しません。前段プロキシや利用側クライアントに短い期限がある場合は、そちらが先に適用されます。

### 受信サイズの上限（3製品共通）

`config.json` の `receiveLimits` で受信上限を `"20MB"`・`"1GB"`・`"2MB"` のような文字列で指定できます。従来の整数によるバイト指定も使用できます。

以下は `config.json` の抜粋です。既存の設定のトップレベルに `receiveLimits` を追加してください。

```json
"receiveLimits": {
  "httpBodyBytes": "20MB",
  "webSocketMessageBytes": "20MB"
}
```

| 設定 | 対象 | 未指定・0の場合 |
|---|---|---|
| `httpBodyBytes` | 通常API・JSON-RPC・MCP/OAuth・静的配信等のHTTPリクエスト本文全体 | 20 MB（20 MiB = 20,971,520バイト） |
| `webSocketMessageBytes` | WebSocketの1メッセージ全体。受信接続と `ws_client` の受信の両方 | 20 MB（20 MiB = 20,971,520バイト） |

サイズ検証では上限と同じサイズを許可し、超過時はHTTP 413、WebSocketはclose code 1009で拒否します。HTTPはJSON・フォーム・multipart等の本文形式を問わず、`Content-Length` がない場合も読み込んだバイト数で制限します。multipartは添付ファイルだけでなく境界やフォーム項目も含む本文全体、WebSocketは複数フレームを合計したメッセージ単位です。上限超過した本文・メッセージをJavaScriptへ渡しません（WebSocket接続時のチェックはメッセージ受信前に実行されます）。

HTTPでは、本文のサイズ検証に先立ち、各経路のヘッダーで判定できる認証・Origin検証・レート制限・同時実行制限を適用します。これらで拒否される場合は、本文が上限を超えていても401・403・429・503などを返し、413の判定には進みません。

本文を使うJavaScriptの `paramCheck` はサイズ検証後に実行します。許可されたOriginへの413応答にもCORSヘッダーを付けます。上限超過時は残りの本文を待たずに応答し、HTTP/1接続は再利用しません。

単位は `B`・`KB`・`MB`・`GB`（`KiB`・`MiB`・`GiB` も可）で、大文字・小文字は区別しません。既定値との整合のため1024倍で換算します（`1MB = 1,048,576` バイト、`1GB = 1,073,741,824` バイト）。前後および数値と単位の間の空白は許可し、単位なしの文字列はバイト数として扱います。負数・小数・不明な単位・空文字列・換算後にint64の範囲外となる値は設定エラーです。0は無制限にはなりません。変更の反映にはサービスの再起動が必要です。この設定はURL・HTTPヘッダー・HTTPクライアントの取得応答・出力本文・MCPのstdioメッセージには適用しません。MCP/OAuthのHTTP本文の従来の固定1 MiB上限はこの設定へ置き換わり、出力・state等の既存上限は維持します。

MCP stdioの入力には、別途 [stdioのメッセージ上限](#mcp-stdio-limits) を適用します。

<a id="websocket-connection-limits"></a>

### WebSocketの同時接続数上限

`config.json` のトップレベルに `webSocketLimits` を追加し、`maxConnections` に受入接続数の上限を整数で指定します。以下は512件に増やす例です。128未満の正数を指定すれば上限を減らせます。

```json
"webSocketLimits": {
  "maxConnections": 512
}
```

| 指定 | 動作 |
|---|---|
| `webSocketLimits` を省略・`null`・`{}` | 従来どおり128件 |
| `maxConnections` を省略・`0`・`null` | 従来どおり128件。無制限や接続禁止の指定にはならない |
| `maxConnections` が正の整数 | 指定件数まで許可 |
| 負数・小数・文字列（`"512"` 等）・真偽値・Goの `int` の範囲外 | 設定エラーで起動しない |

NyanQL独自の固定最大値は設けません。設定可能な数値の上限は実行バイナリのGoの `int` に従い、64ビットでは9,223,372,036,854,775,807、32ビットでは2,147,483,647です。これは設定値として受理できる範囲であり、その件数の接続を維持できる保証ではありません。実運用の上限はOSのファイルディスクリプタ数、メモリ、通信量、Push配信量等に依存するため、利用環境と想定負荷で確認してください。

上限は**1プロセス内の全チャネルで共有**します。接続済みクライアントに加えて、アップグレード前の本文サイズ検証・`paramCheck` 実行中の要求も1件として数えます。`nyan_mode=checkOnly` も処理終了まで数えます。満杯の場合は待機せず、本文読み取り・`paramCheck` より前にHTTP 503と `too many WebSocket connections` を返します。本文エラー・チェック拒否・チェックのみの完了・アップグレード失敗・接続終了で枠を解放します。

`ws_client` が接続先へ張る外向きの接続は対象外です。`ws_client.connectURL` のパスを使ってNyanQLへ接続する購読クライアントは対象です。変更の反映にはサービスの再起動が必要です。`APIHotReload` による再読み込みの対象ではありません。1メッセージの受信バイト数は、別設定の `receiveLimits.webSocketMessageBytes` で制御します。

## api.json

`api.json` には、API名と、実行するSQLまたはJavaScriptの対応を書きます。

各 `api.json` 内の相対パスは、その定義が書かれているJSONファイルの場所を基準にして扱われます。対象はincludeの `path`、`sql`、`script`、`paramCheck`、`outCheck`、public APIの `path` です。

### api.jsonを複数ファイルに分ける

`type: "include"` を使うと、API定義を複数ファイルへ分割できます。include定義のJSONキーがmount名になり、`path` に読み込むJSONファイルを指定します。

ルートの `api.json`：

```json
{
  "health": {
    "sql": ["./sql/health.sql"],
    "description": "稼働確認"
  },
  "sub": {
    "type": "include",
    "path": "./sub/api.json"
  }
}
```

`sub/api.json`：

```json
{
  "getItem": {
    "sql": ["./sql/getItem.sql"],
    "description": "商品を取得します"
  },
  "admin": {
    "type": "include",
    "path": "./admin/api.json"
  }
}
```

`sub/admin/api.json`：

```json
{
  "getUser": {
    "sql": ["./sql/getUser.sql"],
    "description": "ユーザーを取得します"
  }
}
```

展開後の完全API名は、それぞれ `health`、`sub/getItem`、`sub/admin/getUser` です。includeの階層数は固定されていません。include先には通常APIだけでなく、`public`、`schedule`、`ws_client`、さらに別のincludeも記述できます。

include定義で使用できる項目は `type` と `path` だけです。`sql`、`script`、`trigger`、`connectURL`、`description` などを混在させると設定エラーになります。mount名は空文字、`.`、`..`、`/` を含む名前、前後に空白がある名前を使用できません。

同じ階層にmount `sub` がある場合、直接定義されたAPI名 `sub` と `sub/...` はmount名前空間と競合するためエラーになります。includeを使用しない既存API名の `/` は一律禁止されず、mountと競合しなければ従来どおり利用できます。

循環参照は正規化した絶対パスを使って検出され、エラーにはincludeの参照経路が表示されます。同じファイルを異なるmountから読み込むことはできますが、現在処理中のinclude経路へ同じ物理ファイルが再登場すると循環参照になります。

### SQLを実行するAPI

```json
{
  "listItems": {
    "sql": ["./sql/listItems.sql"],
    "description": "商品一覧を取得します"
  }
}
```

この例では、`/listItems` または `/?api=listItems` を呼び出すと、`./sql/listItems.sql` が実行されます。

### paramCheckで入力を確認してからSQLを実行するAPI

```json
{
  "getItem": {
    "paramCheck": "./javascript/checkGetItem.js",
    "sql": ["./sql/getItem.sql"],
    "description": "商品を1件取得します"
  }
}
```

`paramCheck` に指定したJavaScriptが先に実行されます。ここでエラーを返すと、SQLは実行されません。古い `check` キーも互換性のため読み込めます。

### scriptを実行するAPI

```json
{
  "createOrder": {
    "paramCheck": "./javascript/checkCreateOrder.js",
    "script": "./javascript/createOrder.js",
    "description": "注文伝票を1件登録します"
  }
}
```

`script` を指定したAPIでは、JavaScriptファイルを実行します。この場合、同じAPI定義の中に `sql` は書けません。実装上、`script` と `sql` を同時に指定すると起動時にエラーになります。

### publicフォルダを公開するAPI

`type: "public"` を指定すると、`path` のフォルダ配下にあるファイルをそのまま配信します。`path` は `api.json` がある場所からの相対パス、または絶対パスで指定できます。

```json
{
  "public": {
    "type": "public",
    "path": "./public",
    "description": "publicフォルダ"
  }
}
```

この例では `./public/app.js` を `http://localhost:8080/public/app.js` で取得できます。空パス、存在しないファイル、ディレクトリへのアクセスは 404 になります。ディレクトリ一覧や `index.html` の自動探索は行いません。

public定義がmount `sub` のinclude先にある場合、公開エンドポイントも完全名になり、`sub/assets` なら `/sub/assets/app.js` で取得します。`path` の相対パスは、そのpublic定義が書かれたJSONファイルを基準に解決されます。

`type: "public"` はBasic認証を通さずに配信します。認証や認可が必要なファイル公開では、`paramCheck` を指定してください。`paramCheck` と `outCheck` では、公開エンドポイント名とリクエストされた相対パスを参照できます。

通常のファイル要求では、`paramCheck` が未設定なら配信処理へ進みます。設定されている場合は `success:true` で通過し、入力チェックの `status` が201や503でも配信を止めません。`success:false` ならチェック結果を返し、ファイル配信と `outCheck` は実行しません。通過した入力チェックの `status` をファイル応答へ引き継ぐことはなく、最終HTTPステータスはファイル配信処理が決めます。`outCheck` の通過時もそのステータスを維持し、拒否時にはチェック結果を返します。

```js
var endpoint = nyanAllParams.nyan_public_endpoint;
var path = nyanAllParams.nyan_public_path;
```

---

## APIの呼び出し方

NyanQLのAPIは、主に次の形で呼び出せます。

```bash
curl -u admin:secret "http://localhost:8080/listItems"
```

```bash
curl -u admin:secret "http://localhost:8080/?api=listItems"
```

POSTでJSONを送る場合は、`Content-Type: application/json` を指定します。

```bash
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -d '{"api":"getItem","id":1}' \
  "http://localhost:8080/"
```

URLのパスにAPI名を書いた場合、NyanQLはそのパスで実行対象を固定します。たとえば `/getItem?id=1` は、`api=getItem` として扱われます。クエリや本文に別の `api` があっても実行先は変更せず、`nyanAllParams.api` にはURLの完全API名を設定します。API名はURLか、ルート `/` に渡す `api` のどちらかで指定してください。以前のように `/getItem?api=other` で `other` を呼び出していた場合は、`/other` または `/?api=other` に変更してください。

ルート `/` の場合だけ、クエリ・本文を統合した `api` で実行対象を選びます。同名項目は本文を優先します。URLパスを優先しても、`nyanRequest.query`・`nyanRequest.form`・`nyanRequest.json` にある送信元の値は変更しません。

通常APIの公開パスはAPI名から決まります。`api.json` のAPI定義に `http` 設定は指定できません。ファイルの公開には `type: "public"` を使います。

mount配下のAPIは完全API名を指定します。たとえば `sub/getItem` は、次のいずれの形式でも呼び出せます。

```bash
curl -u admin:secret "http://localhost:8080/sub/getItem?id=1"
curl -u admin:secret "http://localhost:8080/?api=sub/getItem&id=1"
```

```json
{
  "api": "sub/getItem",
  "id": 1
}
```

JSON-RPCの `method`、`nyanCallMe` の `api`、`push` の参照先にも同じ完全API名を指定します。mount内からの相対API参照は行わないため、`getItem` が `sub/getItem` に自動補正されることはありません。

---

## レスポンス形式

SQL実行が成功した場合は、次の形式で返ります。

```json
{
  "success": true,
  "status": 200,
  "result": []
}
```

`SELECT` や `RETURNING` を含むSQLでは、`result` に検索結果の配列が入ります。

```json
{
  "success": true,
  "status": 200,
  "result": [
    { "id": 1, "name": "にゃんくる" }
  ]
}
```

`INSERT`、`UPDATE`、`DELETE` など、行を返さないSQLでは、現在の実装では `result` は空のオブジェクトになります。

```json
{
  "success": true,
  "status": 200,
  "result": {}
}
```

エラー時は、次のような形式で返ります。

```json
{
  "success": false,
  "status": 500,
  "error": {
    "message": "Error executing SQL query"
  }
}
```

---

## 2way-SQLによる動的SQL

NyanQLでは、SQLコメントの中にパラメータ名を書けます。この書き方は、S2Daoなどで使われてきた2way-SQLの考え方を参考にしています。

2way-SQLとは、SQLツールなどでそのまま実行できるSQLを書きながら、アプリから実行するときにはコメント部分をパラメータとして差し替える書き方です。

### パラメータ置換

```sql
SELECT
  id AS id,
  name AS name
FROM items
WHERE id = /*id*/1;
```

`id=10` を指定してAPIを呼び出すと、NyanQLは `/*id*/1` の部分をプレースホルダーに変換し、値として `10` を渡します。

PostgreSQLでは `$1`、それ以外のデータベースでは `?` の形のプレースホルダーに変換されます。

### 配列パラメータ

リクエスト値が配列の場合、NyanQLは `IN` 句などで使えるように、複数のプレースホルダーへ展開します。

```sql
SELECT
  id AS id,
  name AS name
FROM items
WHERE id IN (/*ids*/1);
```

たとえば、JSONで次のように送れます。

```json
{
  "api": "listItemsByIds",
  "ids": [1, 2, 3]
}
```

GETのクエリ文字列では、`ids=1,2,3` のようにカンマ区切りで渡すこともできます。

通常HTTP・ルートHTTPの入力は、URLクエリを先に取り込み、JSON本文またはURLエンコードされたフォーム本文の同名項目で上書きします。本文にないクエリ項目は保持します。例えば `POST /?api=example&tenant=abc&value=query` に `{"value":"body"}` を送ると、`api=example`・`tenant=abc`・`value=body` になります。本文の空文字列・`null`なども上書きする値として扱います。

クエリとフォーム本文に同じ名前があっても、それらを連結して配列にはしません。同じ入力元の `tag=a&tag=b` は配列のまま保持し、カンマ区切りやJSON形式の値の変換も各入力元で行います。JSON本文の文字列はカンマで分割しません。`nyanRequest.query`・`nyanRequest.form`・`nyanRequest.json` には統合前の入力情報を保持します。

`nyan_mode` も本文を優先します。クエリだけの `nyan_mode=checkOnly` はJSON本文があっても有効で、クエリとフォーム本文の両方に1件ずつ指定した場合も文字列の `checkOnly` として扱います。本文に `nyan_mode:""`（フォームでは `nyan_mode=`）を指定すると、クエリの指定を上書きして通常実行になります。

### JSONパラメータ

リクエスト値がオブジェクトの場合、NyanQLはJSON文字列に変換して、SQLの1つの値として渡します。PostgreSQLのJSONB列などへ渡すときに使えます。

---

SQLファイルの文字列リテラル内の空白・タブ・改行は、通常のSQL APIと `nyanRunSQL()` のどちらでも保持します。デフォルト値の引用符エスケープ（例：`/*name*/'O''Reilly'`）にも対応します。先頭に行コメントやブロックコメントのあるSELECTも、結果行を返します。

DBドライバがバイト列で返すJSONオブジェクト・配列は、SQL結果のJSON化で数値の桁を保持します。JavaScriptへ渡す経路ではJavaScriptの数値精度の制約があるため、大きなIDを正確に扱う場合は文字列を使用してください。

## 条件つきSQL

検索条件があるときだけWHERE句を出したい場合は、`/*BEGIN*/` と `/*IF ...*/` を使います。

```sql
SELECT
  id AS id,
  name AS name,
  category AS category
FROM items
/*BEGIN*/
WHERE
  /*IF id != null*/ id = /*id*/1 /*END*/
  /*IF category != null*/ AND category = /*category*/'book' /*END*/
/*END*/;
```

`id` や `category` が指定されていない場合、その条件は出力されません。

現在の実装で使える条件は、主に次の形です。

```sql
/*IF id != null*/ ... /*END*/
/*IF id == null*/ ... /*END*/
```

`AND` と `OR` を使った条件判定は、`/*BEGIN*/` の内外で同じように利用できます。`AND` を先に評価し、次に `OR` を評価します。演算子の大文字・小文字は区別せず、`ORG_ID` や `BRAND` などのパラメータ名の一部を演算子として扱いません。括弧を使った任意の式には対応していません。

BEGIN内で先頭の条件が消えた場合は、残ったWHERE句先頭の不要な `AND` / `OR` を取り除きます。上の例は、条件なし・idのみ・categoryのみ・両方指定に対応します。SQLの文字列リテラルや通常のコメント内に書かれたIF風の文字列は条件として処理しません。

---

## `/nyan/` でAPI情報を見る

NyanQLでは、APIの一覧や、各APIが受け取るパラメータ情報を確認できます。

API一覧のURLは末尾スラッシュ付きの `/nyan/` です。`/nyan` はGo標準のHTTPルーターにより `/nyan/` へリダイレクトされます。リダイレクトを追わないクライアントでもJSONを取得できるよう、一覧取得には最初から `/nyan/` を指定してください。API一覧・詳細の取得にはBasic認証が必要です。

### API一覧を見る

```bash
curl -u admin:secret "http://localhost:8080/nyan/"
```

返り値の例です。

```json
{
  "name": "NyanQL Sample API",
  "profile": "NyanQLのサンプルAPIです",
  "version": "v1.0.0",
  "apis": {
    "listItems": {
      "description": "商品一覧を取得します"
    },
    "getItem": {
      "description": "商品を1件取得します"
    },
    "sub/admin/getUser": {
      "description": "ユーザーを取得します"
    }
  }
}
```

`apis` は `type: "api"`（type省略時を含む）の通常APIだけを完全API名のキーで示すフラットな一覧です。`include` 定義、`public`、`schedule`、`ws_client`、`mcp` 定義は一覧に含まれません。include先の通常API、MCP ToolやOAuthの参照先になっている通常APIは一覧に含まれます。

### APIごとの詳細を見る

```bash
curl -u admin:secret "http://localhost:8080/nyan/getItem"
```

mount配下のAPIも完全API名で取得できます。

```bash
curl -u admin:secret "http://localhost:8080/nyan/sub/admin/getUser"
```

返り値の例です。

```json
{
  "api": "getItem",
  "description": "商品を1件取得します",
  "nyanAcceptedParams": {
    "id": 1
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {
        "type": "integer",
        "examples": [1]
      }
    },
    "required": ["id"],
    "additionalProperties": true
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "success": {"const": true},
      "status": {"const": 200},
      "result": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "id": {}
          },
          "required": ["id"],
          "additionalProperties": false
        }
      }
    },
    "required": ["success", "status", "result"],
    "additionalProperties": false
  },
  "schemaSource": {
    "input": "sql",
    "output": "sql"
  }
}
```

SQL内の `/*id*/1` のようなコメントから、受け付けるパラメータを拾います。これにより、API利用者は「どんなパラメータを渡せばよいか」を確認しやすくなります。

`script` を使うAPIでは、JavaScriptファイル内に次の定数を書くと、`/nyan/{API名}` の情報に反映できます。

```js
const nyanAcceptedParams = {
  order_no: "A-001",
  details: [
    { item_id: 1, quantity: 2 }
  ]
};
```

旧形式の `nyanOutputColumns` は廃止しました。JavaScript内に宣言しても解析されず、`/nyan/{API名}` のレスポンスにも含まれません。script APIの出力スキーマを公開する場合は、`outCheck` に `nyanOutputSchema` を定義してください。

現在の `test2` は、入力スキーマを `paramCheck`、出力スキーマを `outCheck` に分けた例です。

```json
{
  "test2": {
    "paramCheck": "./javascript/check_test1.js",
    "script": "./javascript/script.js",
    "outCheck": "./javascript/out_check_test2.js",
    "description": "paramCheckが実行されscriptが動くサンプルです。"
  }
}
```

- `check_test1.js` の `nyanInputSchema` が入力仕様を表します。
- `out_check_test2.js` の `nyanOutputSchema` が正常レスポンス全体の出力仕様を表します。
- `out_check_test2.js` の実行部分は、scriptの実際の出力を確認します。

`/nyan/test2` を取得すると、`schemaSource.input` は `paramCheck`、`schemaSource.output` は `outCheck` になります。

```bash
curl -u admin:secret "http://localhost:8080/nyan/test2"
```

`nyanOutputSchema` は出力仕様を公開するための定義です。MCP経由を含め、NyanQLはこのスキーマで実際の出力を自動検証しません。出力を許可・拒否する条件は `outCheck` のJavaScriptに実装してください。`outCheck` が `success: true` を返した場合は、本体の実行結果を使用します。

### 入出力スキーマを明示する

入力スキーマは `paramCheck` ファイルのトップレベルに `nyanInputSchema` として定義します。出力スキーマは `outCheck` ファイルのトップレベルに `nyanOutputSchema` として定義します。どちらもJSON Schema Draft 2020-12形式のオブジェクトを想定しています。

```js
const nyanInputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    id: {
      type: "integer",
      minimum: 1,
      description: "取得する商品ID",
      examples: [1]
    },
    include_deleted: {
      type: "boolean",
      default: false
    }
  },
  required: ["id"],
  additionalProperties: false
};

if (!nyanAllParams.id) {
  ({success: false, status: 400, error: {message: "idを指定してください"}});
} else {
  ({success: true, status: 200, error: null});
}
```

```js
const nyanOutputSchema = {
  type: "object",
  properties: {
    success: {const: true},
    status: {const: 200},
    result: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: {type: "integer"},
          name: {type: "string"}
        },
        required: ["id", "name"],
        additionalProperties: false
      }
    }
  },
  required: ["success", "status", "result"],
  additionalProperties: false
};

const output = JSON.parse(nyanAllParams.nyan_output.body);
({success: output.success === true, status: output.success === true ? 200 : 500});
```

`nyanOutputSchema` は `result` の中身だけではなく、NyanQLが返す正常レスポンス全体を表します。`$schema` は任意です。記載した場合はそのまま公開され、省略した場合にNyanQLが自動追加することはありません。

これらのスキーマは `/nyan/{API名}` とMCPのツール定義で公開します。通常のAPI呼び出しでは、入出力の判定を `paramCheck` / `outCheck` のJavaScriptで行います。MCP経由では入力スキーマによる引数の自動検証も行いますが、出力スキーマによる実行結果の自動検証は行いません。出力の判定は `outCheck` のJavaScriptが担当します。

### スキーマの取得優先順位

入力スキーマは次の順で決まります。

1. `paramCheck` 内の `nyanInputSchema`
2. SQLファイルからの自動生成
3. API本体のscript内にある `nyanAcceptedParams`
4. 型不明の空スキーマ `{}`

出力スキーマは次の順で決まります。

1. `outCheck` 内の `nyanOutputSchema`
2. SQLファイルからの自動生成
3. 型不明の空スキーマ `{}`

`paramCheck` や `outCheck` が設定されていても、対象の明示スキーマが書かれていなければ次の候補へ進みます。`schemaSource.input` には `paramCheck`、`sql`、`scriptLegacy`、`unknown` のいずれか、`schemaSource.output` には `outCheck`、`sql`、`unknown` のいずれかが入ります。`scriptLegacy` は、入力をscript内の `nyanAcceptedParams` から取得したことを表します。

スキーマはAPI設定のスナップショットには保存せず、`/nyan/{API名}` を取得するたびに関連ファイルから解決します。`/nyan/` のAPI一覧取得ではスキーマファイルを読みません。

`paramCheck` 内に明示的な `nyanInputSchema` がある場合、API詳細では新しい `inputSchema` を正として扱い、旧形式の `nyanAcceptedParams` は省略します。明示スキーマがない場合は、SQLコメントやscript内の `nyanAcceptedParams` から取得できた従来の値を引き続き `nyanAcceptedParams` に表示します。SQLまたはlegacyから自動生成した `inputSchema` も、これまでどおり同時に公開します。

### SQLから自動生成されるスキーマ

入力では、2way-SQLのテスト値から次の型を推測します。

| SQL記述 | 推測結果 |
|---|---|
| `/*id*/1` | `integer` |
| `/*price*/1.5` | `number` |
| `/*name*/'cat'` | `string` |
| `/*enabled*/true` | `boolean` |
| `IN (/*ids*/1)` | `array`、要素は `integer` |
| `IN (/*codes*/'A')` | `array`、要素は `string` |

コメント後の値はAPIの既定値ではなくSQL単体実行用のテスト値なので、`default` ではなく `examples` に入ります。`/*IF ...*/` の外にあるパラメータは必須、IF内だけにあるパラメータは任意です。`/*BEGIN*/` の内側という理由だけでは任意になりません。複数SQLでは、入力パラメータをすべてのファイルから統合します。同名パラメータの型が競合した場合は、誤った型を断定せずそのプロパティを `{}` にします。SQL由来の入力スキーマは、SQL以外で使われる追加パラメータを拒否しないよう `additionalProperties: true` になります。

出力では、`SELECT` または `RETURNING` の列名を取得し、各列の型は確定せず `{}` とします。明示的な `AS` 別名と単純な列参照を安全に取得できた場合だけ列を限定します。`SELECT *`、別名のない式、条件で変化する列などを含む場合は、実際のレスポンスを過度に制限しないスキーマへフォールバックします。行を返さない更新SQLの `result` は空オブジェクトです。複数SQLでは、実際のレスポンスに使われる最後のSQLから出力スキーマを生成します。

### 静的スキーマ定義の制約

明示スキーマはJavaScriptを実行せず、構文木から静的に読み取ります。使用できる値は、オブジェクト、配列、文字列、数値、真偽値、`null` と、それらのネストです。

次のような動的な定義は対象外です。

```js
const nyanInputSchema = createSchema();
```

```js
const nyanInputSchema = {
  ...commonSchema
};
```

```js
const nyanInputSchema = {
  type: schemaType
};
```

同一ファイル内の別の `const` を参照する場合も、現時点では動的な参照として扱います。通常APIとしてだけ使用する場合、明示スキーマが動的、非オブジェクト、重複宣言などで静的に取得できなくても、API設定の読み込みは妨げず、`/nyan/{API名}` の取得時にスキーマ解決エラーを返します。一方、MCP Toolから参照するAPIは、設定読込時にもスキーマを解決し、入力スキーマを検証します。不正なら起動時は設定エラー、ホットリロード時は候補を採用せず直前の設定を維持します。ファイル修正後の詳細取得はその内容を読み直します。paramCheckやoutCheckのJavaScript本体も実行可能なコードである必要があります。

---

## 入力チェック：paramCheck

`paramCheck` は、SQLやscriptを実行する前に、リクエスト内容を確認するためのJavaScriptです。
古い設定との互換性のため、`check` も `paramCheck` の別名として使えます。

たとえば、`id` が指定されていない場合にエラーを返すには、次のように書きます。

```js
if (!nyanAllParams.id) {
  JSON.stringify({
    success: false,
    status: 400,
    error: {
      message: "idを指定してください"
    }
  });
} else {
  JSON.stringify({
    success: true,
    status: 200,
    error: null
  });
}
```

`paramCheck` の戻り値は、JSON文字列またはオブジェクトにしてください。NyanQLは、そのJSONを読んで、`success` が `true` なら次の処理へ進みます。`false` の場合は、SQLやscriptを実行せずにエラーを返します。

`paramCheck`・`outCheck`の `success` は必須の真偽値です。省略・`null`・文字列（`"true"` / `"false"`）・数値などは、通常のチェック拒否ではなく実装不備として、下記の形式不正と同じ実行エラーにします。明示的な `success:false` は有効な拒否結果として、従来どおり `result`・`error` を保持します。API本体の返却JSONに `success` を必須とする変更ではありません。

`paramCheck`・`outCheck`の結果には、200〜599の整数の `status` が必須です。省略・`null`・文字列・小数・範囲外（0や1xxを含む）はチェックの実装不備として扱い、200への補完はしません。`success:true` でも `status` は必要ですが、有効な形式なら入力チェックの通過条件は引き続き `success` だけです（`success:true,status:503` も通過）。通常HTTP・ルートHTTP・public・JSON-RPCでは、不正なチェック結果をHTTP応答に使う前に検出してHTTP 500を返します。`nyanCallMe()`ではJavaScript例外、WebSocketメッセージではstatus 500のエラー応答、MCPでは `isError:true` のToolエラーになります。入力チェックの形式不正では本体・`outCheck`・Pushを開始せず、出力チェックの形式不正では実行済みの本体を取り消さずにPushを停止します。この必須ルールはチェック結果に対するもので、API本体の `status` 省略時の扱いは変更しません。

通常のAPI実行には本体の `script` または `sql` が必要です。入力チェック通過後、両方が未設定なら通常HTTP・ルートHTTPではHTTP 400を返し、`outCheck`・Pushは実行しません。`paramCheck` の成功結果を本体の代わりには使用しません。`nyanCallMe()` ではJavaScript例外になり、MCP・WebSocketでも実行エラーとなります。Push先のAPIに本体がない場合も配信しません。入力チェックの拒否結果と、明示的な `nyan_mode=checkOnly` の結果は、本体がなくても従来どおり返します。

拒否結果には `result` と `error` の両方を指定できます。`result` は呼び出し元で使うデータや補足情報、`error` はエラーの詳細に使えます。失敗の判定はメッセージの有無ではなく `success` で行います。

```javascript
({
  success: false,
  status: 403,
  result: { contactAdmin: true },
  error: { code: "ACCOUNT_DISABLED", message: "このアカウントは無効です" }
});
```

通常HTTP・ルートHTTP・`nyanCallMe()`・WebSocketのAPI実行・MCPのTool実行では、入力チェックの拒否結果として `success`・`status`・`error` に加え、指定された `result` も保持します。`result` はオブジェクト・配列・文字列・数値・真偽値・`null` を使用でき、省略時は追加しません。既存の `error` も保持し、省略または `null` の場合は従来どおり `"Request check failed"` を補います。`checkOnly` の拒否時も同じです。JSON-RPCでは、既存のHTTP 400・`error.code:-32602`・`error.data.message`・`error.data.detail` を維持し、同じ形式のチェック結果を `error.data.checkResult` に追加します。

`success:false, status:500` をチェックから返すことと、チェック自体で例外が起きることは別です。前者は有効な拒否結果として `result` / `error` を返し、`nyanCallMe()`でも戻り値になります。後者は従来どおり実行エラーで、通常HTTPでは `result` を付けないHTTP 500の `error` 応答、`nyanCallMe()`ではJavaScript例外になります。拒否されたAPIの本体・`outCheck`・Pushは実行しません。

### checkだけを実行する

public配信でも `nyan_mode=checkOnly` は入力チェックだけを実行します。`paramCheck`（または `check`）が未設定の場合はHTTP 404・`No check script for this API`を返し、ファイル配信・`outCheck`を実行しません。以前の固定の200成功応答から変更しています。

通常HTTP・JSON-RPC・`nyanCallMe()`・WebSocket・MCP（HTTP／stdio）からのAPI呼び出しで `nyan_mode=checkOnly` を指定すると、`paramCheck` だけを実行し、その結果を返します。本体のscript／SQL・`outCheck`・Pushは実行しません。`check` で指定した古い設定も、`paramCheck` として同じように実行されます。`paramCheck`（または `check`）が未設定の場合は、本体を実行せずエラーを返します。

`nyan_mode` は省略または空文字列なら通常実行、文字列 `"checkOnly"` ならチェックのみです。それ以外の文字列・配列・`null`・数値・真偽値・オブジェクトは不正な指定として、`paramCheck`を実行する前に拒否します。大文字・小文字と前後の空白は区別するため、`"CHECKONLY"` や `" checkOnly "` もエラーです。通常HTTP・ルートHTTP・public・OAuth・WebSocket接続前はHTTP 400、JSON-RPCはHTTP 400と `error.code:-32602`、WebSocketのAPI実行はstatus 400のエラー応答、`nyanCallMe()`はJavaScript例外になります。本体・`outCheck`・Push・publicのファイル配信は開始しません。認証・認可は従来どおり適用します。

クエリやフォーム内で `nyan_mode` を重複指定すると配列になり、エラーになります。クエリと本文の両方にある場合は、既存の本文優先ルールで統合した最終値を検証します。例えばクエリが `checkOnly` でも本文が空文字列なら通常実行、本文が `null` ならエラーです。

MCPでは `tools/call` の `arguments` に `"nyan_mode":"checkOnly"` を指定します。MCP用の入力スキーマには、この制御項目を任意の文字列プロパティ（許可値は空文字列と `checkOnly`）として追加し、`tools/list` でも公開します。通常実行では省略または空文字列を指定できます。APIの入力スキーマが `additionalProperties:false` でも指定できますが、必須項目・型など、その他のスキーマ制約は引き続き適用されます。認証・認可も省略しません。不正な `nyan_mode` はToolエラーとなり、入力チェック・本体を実行しません。入力チェック自身が行うDB更新などの副作用を取り消す機能ではありません。

最上位の入力スキーマが同一リソース内の `$ref`（例：`#/$defs/Input`、ローカルアンカー）を使う場合は、参照の連鎖をたどって入力全体に適用するスキーマにも `nyan_mode` を追加します。公開用の参照先を複製するため、同じ定義を子オブジェクトに使っていても、その子の許可項目は増えません。`$anchor`・`$dynamicAnchor` は元の定義に保持し、複製先では再宣言しません。子の `$dynamicRef` による再帰検証も元の定義を使用します。必須項目・型・その他の追加項目の禁止は維持します。Version1では、参照先が `$id` を持つ埋め込みリソース、Draft-04で `id`（アンカーを含む）を持つ定義や、`allOf` 等の合成先への自動追加は対象外です。それらを使う場合は、入力全体を検証する各スキーマで `nyan_mode` を明示的に許可してください。外部 `$ref` は引き続き使用できません。

```bash
curl -u admin:secret "http://localhost:8080/getItem?id=1&nyan_mode=checkOnly"
```

### OAuth経路のチェック

OAuth参照先APIの `paramCheck`（別名 `check`）と `outCheck` も実行します。

| 対象 | 実行順序 |
|---|---|
| `authorize` / `token` / `register` / `adminUser` | 入力チェック → 本体スクリプト → 出力チェック → HTTP応答 |
| `authorizationServerMetadata` / `protectedResourceMetadata` | 入力チェック → Goによるメタデータ生成 → 出力チェック → HTTP応答。参照先の本体スクリプトは実行しません |
| `verifyAccess` | 入力チェック → トークン検証スクリプト → 出力チェック → 認証判定 |

チェックはJSON文字列またはオブジェクトを返し、真偽値の `success` と200〜599の整数 `status` を必須とします。入力チェック・出力チェックともに `success:true` で通過します。出力チェックが通過した場合は、本体のステータス・本文・ヘッダーを保持します。チェックの `status`・`result` で本体の応答を変更しません。HTTPの拒否時にはチェック結果全体をその `status` で返し、本体の `Set-Cookie` / `Location` などは送信しません。チェックの例外・形式不正・ファイル欠落は詳細を含まないHTTP 500になります。チェック結果にも既存の応答本文上限（4 MiB）を適用します。

OAuthのHTTP要求でも `nyan_mode=checkOnly` を指定すると、入力チェックの結果だけを返します。クエリと本文の両方に指定した場合はJSON／フォーム本文を優先し、空文字列は通常実行、`checkOnly` 以外の非空値や文字列以外はHTTP 400とします。入力チェック未設定時は本体を実行せずHTTP 500です。HTTPメソッド・Content-Type・本文上限・管理者認証などの検証は省略しません。OPTIONSではチェックも本体も実行しません。メタデータを含むHTTP経路にOAuthのレート・同時実行数制限を適用します。

OAuthのHTTP経路では、役割ごとの既定上限（管理者ユーザー作成・クライアント登録は毎分10回、認可は毎分30回、その他は毎分60回）と、`rateLimit` に指定した回数・期間を両方適用します。いずれかに達するとHTTP 429を返し、`Retry-After` は両方の枠が利用可能になるまでの待ち秒数です。レート制限で拒否された要求は枠を消費しません。

前後チェックと本体は、それぞれ新しいOAuth用VMで実行します。参照先APIの `runtime.capabilities`、SQLファイルの許可リスト、戻り値変換とDB接続取得・実行にも適用する実行ごとの15秒の期限とトランザクションを使います。既存の `javascript_include` も読み込みます。各段階に入力情報のコピーを渡すため、チェック内でのパラメータ書換えを後段の入力変更には使えません。チェックや本体で既に完了したDB更新などは、後続の拒否では取り消しません。

出力チェックの `nyanAllParams.nyan_output` には、送信予定の本文全体を文字列の `body` として渡し、`status`、`contentType`、検証済みの `headers`、`bodyBase64`、本文バイト数も渡します。`headers` のキーはHTTPの標準表記（`Location`、`Set-Cookie` など）で、値は1件なら文字列、複数件なら配列です。これらを書き換えても送信内容は変わりません。`verifyAccess` ではHTTP応答の代わりに認証判定全体のJSONを `body` に渡し、検査用の `status` は200とします。

`verifyAccess` のチェック拒否・エラーは401／`invalid_token`として扱い、MCPのToolを実行しません。Tool側の `checkOnly` は認証側へ引き継がず、トークン検証とその前後チェックを最後まで実行します。

入力フォームの事前チェックなどに使えます。

### 出力前チェック：outCheck

`outCheck` を指定すると、SQLやscriptの実行後、または `type: "public"` のファイル送信前にJavaScriptを実行できます。有効な形式のチェック結果で `success: true` なら、`status` が201や503でも出力チェックは通過します。本体のステータス・本文・ヘッダーを保持します。`success: false` なら `outCheck` の結果をJSONとして返し、Pushを停止します。ステータスの形式・範囲の検証やJavaScript例外の扱いは維持します。

例えば本体が `success:true,status:201`、出力チェックが `success:true,status:200` なら、本体のJSON本文をHTTP 201で返し、Pushを開始できます。`outCheck` は出荷前検査であり、本体のステータスや本文を作り直す処理ではありません。チェックの `status` は通過時も形式検証しますが、本体の応答には適用しません。

出力チェック通過後のPushは、本体の応答ステータスと結果で判定します。本体が200〜399以外、または `success:false` の場合はPushを開始しません。通過したチェックのstatusで失敗を成功へ変えたり、Pushを抑止したりしません。通常HTTP・JSON-RPC・内部呼び出し・WebSocket・MCP・Push先・public・OAuthで、通過時に本体の結果を保持する規則は共通です。publicは通常のHEAD・条件付き要求・Range処理へ進みます。

JSON-RPCでは応答本文が必要なため、送信するHTTPステータスが204・205・304の場合だけ200に置き換えます。本体結果・チェック拒否結果・成功したcheckOnlyに適用し、結果内のstatusは書き換えません。チェック拒否時の各経路の応答形式は維持します。

```json
{
  "checked-api": {
    "script": "./javascript/main.js",
    "outCheck": "./javascript/out_check.js",
    "description": "出力前チェック付きAPI"
  }
}
```

本体の実行結果は `nyanAllParams.nyan_output` で参照できます。互換用に `nyan_output_body` なども使えます。

```js
if (nyanAllParams.nyan_output.body.indexOf("expected") >= 0) {
  ({ success: true, status: 200, result: {} });
} else {
  ({ success: false, status: 409, result: { message: "output mismatch" } });
}
```

---

## JavaScriptによる処理：script

SQLだけでは書きにくい一連の処理は、`script` にまとめられます。

たとえば「注文ヘッダを1件登録し、注文明細を複数件登録する」という処理では、受け取ったJSONの明細配列をJavaScriptでループし、その中でSQLを実行できます。

`api.json` の例です。

```json
{
  "createOrder": {
    "check": "./javascript/checkCreateOrder.js",
    "script": "./javascript/createOrder.js",
    "description": "注文伝票を1件登録します"
  }
}
```

`script` の例です。

```js
var order = nyanAllParams.order;

var headerResult = nyanRunSQL("./sql/insertOrderHeader.sql", {
  order_no: order.order_no,
  customer_id: order.customer_id
});

for (var i = 0; i < order.details.length; i++) {
  var detail = order.details[i];
  nyanRunSQL("./sql/insertOrderDetail.sql", {
    order_no: order.order_no,
    item_id: detail.item_id,
    quantity: detail.quantity
  });
}

JSON.stringify({
  success: true,
  status: 200,
  result: {
    message: "注文を登録しました"
  }
});
```

`script` では、最初のSQL実行時にNyanQLがトランザクションを開始します。`nyanRunSQL()` で実行したSQLは、同じトランザクションの中で処理されます。途中でエラーが起きた場合はロールバックされます。

通常HTTP・ルートHTTPでは、本体が返したJSONオブジェクトのトップレベルの `status` をHTTP応答ステータスに使います。例えば `{"success":false,"status":503}` はHTTP 503、`{"status":201}` はHTTP 201になります。`success:false` だけではHTTPステータスは変更しません。本文の `status` は保持しますが、204・304などではHTTPの規則により本文は送信されません。

通常HTTP・ルートHTTPでは、`status` を省略したJSON、配列、プレーンテキストは従来どおり200です。`status` を指定する場合は200〜599の整数にしてください。文字列・`null`・小数・範囲外は実行エラー（通常HTTPでは500）になり、`outCheck`・Pushは実行しません。JSON-RPCでは本体結果をJSONオブジェクトとして扱い、その `status` にも同じ検証を行います。`status` はHTTPステータスに使い、RPCの `result` からは取り除きます。204・205・304の場合は、JSON-RPCの応答本文を保持するため、外側のHTTPステータスを200にします。

`outCheck` の `nyan_output.status` と `nyan_output_status` にも本体のステータスを渡します。`nyanCallMe()`・WebSocketのAPI実行・MCP・Push先の出力チェックでも同様です。`outCheck` が通過したら本文・ステータスとも本体のものを使い、拒否したら出力チェックの結果を返してPushを止めます。`outCheck` 未設定時は本体のステータスを使います。MCPのHTTP応答やWebSocketの通信形式は変更しません。内部呼び出しで本体が `status:503` を返しても、それだけではJavaScript例外になりません。

本体の返却ステータスは、SQL更新のロールバックを指示するものではありません。最上位scriptが戻り値変換まで正常終了し、コミットした後のステータス検証や `outCheck` でエラーになっても、コミット済みの更新は取り消しません。`nyanCallMe()` の子APIの更新は親scriptと共有し、親がコミットするまでは未確定です。

---

## JavaScriptで使える主な変数と関数

`check` と `script` の中では、次の変数や関数を使えます。

| 名前 | 説明 |
|---|---|
| `nyanAllParams` | 実行中のAPIのパラメータです。予約項目 `nyan_request` にはサーバーが取得した元リクエスト情報が入ります。 |
| `nyanRequest` | JavaScriptから直接参照できる元リクエスト情報です。`nyanAllParams.nyan_request` と同じデータを参照します。 |
| `nyanAcceptedParamsKeys` | SQLコメントから拾った受け付けパラメータ名です。主にcheckで使います。 |
| `nyanRunSQL(path, params)` | 一番親の `api.json` のフォルダを基準にSQLファイルを実行します。scriptでは同じトランザクション内で実行されます。 |
| `nyanGetAPI(url, user, pass)` | 外部APIへGETリクエストを送ります。 |
| `nyanJsonAPI(url, jsonText, user, pass, headers)` | 外部APIへJSONをPOSTします。 |
| `nyanCallAPI(...)` | `nyanJsonAPI` と同じ動きをする別名です。 |
| `nyanCallMe(params)` | `api.json` に定義した別のAPIを内部呼び出しします。 |
| `nyanGetFile(path)` | 一番親の `api.json` のフォルダを基準にファイルを読みます。存在しない場合やフォルダの場合は `null` を返します。 |
| `nyanBase64Encode(text)` | 文字列をBase64に変換します。 |
| `nyanBase64Decode(base64)` | Base64を文字列に戻します。 |
| `nyanRandomBase64URL(bytes)` | 1〜1024バイトの乱数を、末尾の `=` なしのBase64URL文字列として返します。引数省略時は32バイトです。 |
| `nyanCrypto.randomBase64URL(bytes)` | 同じ形式の乱数を生成します。1〜1024バイトの指定が必須です。 |
| `nyanCrypto.sha256Base64URL(text)` | 文字列化した値のUTF-8バイト列をSHA-256でハッシュ化し、パディングなしのBase64URL文字列（43文字）を返します。引数はちょうど1つ必要です。 |
| `nyanCrypto.sha256Hex(text)` | 同じSHA-256を小文字の16進文字列（64文字）で返します。引数はちょうど1つ必要です。 |
| `nyanCrypto.timingSafeEqual(a, b)` | 2つの値を文字列化して比較し、真偽値を返します。引数はちょうど2つ必要です。比較方法は下記を参照してください。 |
| `nyanSHA256Base64URL(value)` | 文字列のSHA-256を、パディングなしのBase64URL文字列で返します。引数省略時は `TypeError`。明示した空文字列は有効です。 |
| `nyanSaveFile(base64, path)` | Base64文字列をデコードし、一番親の `api.json` のフォルダを基準に保存します。 |
| `nyanWriteTextFile(path, text)` | UTF-8テキストを保存します。成功時true、失敗時例外。 |
| `nyanWriteBase64File(path, base64)` | 標準Base64をデコードして保存します。成功時true、失敗時例外。 |
| `sha256(text)` | SHA-256のハッシュ文字列を返します。 |
| `sha1(text)` | SHA-1のハッシュ文字列を返します。 |
| `nyanHostExec(command)` | OSコマンドを実行し、`success`・`exit_code`・`stdout`・`stderr`を持つオブジェクトを返します。 |


`nyanGetAPI` のURL引数は必須です。引数なしの `nyanGetAPI()` は、送信前に `TypeError: nyanGetAPI requires a URL` を投げます。
認証引数は省略可能で、省略した値は空文字列として扱います。URLだけなら認証なし、ユーザー名だけなら空パスワードでBasic認証を付けて送信します。ユーザー名が空文字列ならBasic認証は付けません。
明示的な `undefined`・`null` は省略とは異なり、従来どおり文字列 `"undefined"`・`"null"` に変換します。

GETのパラメータはURLのクエリ文字列に含めます。値に日本語・空白・`&` などが含まれる場合は `encodeURIComponent()` でエンコードしてください。戻り値は応答本文の文字列です。

```javascript
const name = "猫 & neko";
const url = "https://example.com/api?name=" + encodeURIComponent(name) + "&limit=10";
const response = nyanGetAPI(url); // 認証なし
// Basic認証が必要なら nyanGetAPI(url, "alice", "password")
```

`nyanJsonAPI(url, jsonText, user, pass, headers)`（別名 `nyanCallAPI`）の認証引数も省略可能です。省略した値は空文字列として扱い、`nyanJsonAPI(url, jsonText)` は `nyanJsonAPI(url, jsonText, "", "")` と同じくBasic認証ヘッダーを自動付与しません。ユーザー名だけ指定すると空パスワードでBasic認証を付けます。ユーザー名が空文字列なら、パスワードの指定にかかわらずBasic認証は付けません。戻り値は応答本文の文字列です。

明示的に渡した認証引数は従来どおり文字列に変換します。`undefined`・`null` は引数の省略とは区別し、それぞれ文字列 `"undefined"`・`"null"` になります。

第5引数の `headers` はオブジェクトまたはJSON文字列で指定できます。追加ヘッダーは自動付与するヘッダーより優先され、`Authorization` や `Content-Type` も上書きできます。Basic認証を使わずに追加ヘッダーを渡す場合は、認証引数に `"", ""` を指定してください。

```javascript
const jsonText = JSON.stringify({ id: 1 });
nyanJsonAPI(url, jsonText);         // 認証なし
nyanJsonAPI(url, jsonText, "", ""); // 上と同じ動作
nyanJsonAPI(url, jsonText, "alice", "password"); // Basic認証
nyanJsonAPI(url, jsonText, "", "", {
  Authorization: "Bearer " + token
});
```

`nyanRandomBase64URL()` のサイズは、Base64URL変換前のバイト数です。省略時の32バイトは43文字になります。範囲外の値や明示的な `undefined`・`null`、乱数生成の失敗はJavaScript例外になります。`nyanCrypto.randomBase64URL(bytes)` も同じサイズ範囲ですが、引数をちょうど1つ指定する必要があります。

`nyanCrypto` の各メソッドは、引数が不足している場合だけでなく、上記の個数を超える場合もJavaScript例外になります。`sha256Base64URL`・`sha256Hex`・`timingSafeEqual` では、明示した `undefined`・`null` もそれぞれ文字列 `"undefined"`・`"null"` に変換します。空文字列も有効です。`timingSafeEqual` は各文字列のSHA-256ダイジェストを定数時間比較し、元の文字列のUTF-8バイト長も一致するときに `true` を返します。入力のハッシュ計算も含めた総処理時間が、入力長によらず一定になるという保証ではありません。OAuth用VMでは、これらの関数に [crypto capability](#oauth-runtime-capabilities) が必要です。

`nyanSaveFile()`・`nyanGetFile()`・`nyanRunSQL()` に渡す相対パスは、起動時に指定した一番親の `api.json` があるフォルダを基準にします。include先のAPIや `nyanCallMe()` で呼び出したAPI、`paramCheck`・`outCheck` の中でも同じ基準です。絶対パスはそのまま使用します。

たとえば、一番親が `/srv/app/api.json` の場合、`nyanSaveFile(data, "./files/result.txt")` の保存先は `/srv/app/files/result.txt` です。保存先のフォルダがなければ作成します。以前の実行ファイルのフォルダやカレントディレクトリを基準にしていたスクリプトは、この基準に合わせてパスを調整してください。

`api.json` 内の `script`・`sql`・`paramCheck`・`outCheck` などの設定値は、その定義を書いたJSONファイルのフォルダ基準です。JavaScript関数に渡すパスとは区別してください。

`nyanHostExec` は、サーバ上でOSコマンドを実行できる強い機能です。公開環境や、外部から入力を受ける処理では、安易に使わないでください。

`nyanHostExec()` はNyan8と同様に、コマンドの非0終了も例外にせず、`success:false`・実際の `exit_code`・取得した `stdout` / `stderr` を返します。終了コード0なら `success:true` で、標準エラーに出力があっても成功扱いです。シェル内でコマンドが見つからない場合も非0終了の結果になります。引数不足は3製品共通の `TypeError: nyanHostExec: command required` になります。シェル自体を起動できない場合もJavaScript例外です。明示的な `undefined`・`null` 等の文字列変換は従来どおりで、引数省略とは区別します。

```javascript
const execution = nyanHostExec("some-command");
if (!execution.success) {
  // 失敗時にスクリプトを中断したい場合は明示的に例外を投げます。
  throw new Error(execution.stderr || `終了コード: ${execution.exit_code}`);
}
JSON.stringify(execution);
```

以前は非0終了でスクリプトが中断していたため、既存の呼び出しでは戻り値の `success` / `exit_code` を確認してください。非0終了だけではAPIの処理やトランザクションを自動中断しません。結果をそのままAPIの応答にすると、既存のPush判定がトップレベルの `success:false` を検出してPushを停止します。スクリプトが失敗を処理して最終的に `success:true` の応答を返した場合は、その最終応答でPushを判定します。

### リクエスト情報と内部呼び出し・Push

`nyanRequest` は通常HTTP・ルートHTTP・JSON-RPC・publicのチェック・WebSocket・HTTP MCP・OAuthで、サーバーが実際のHTTP要求から生成します。`paramCheck`・本体・`outCheck` から参照できます。外部入力の `nyan_request` はこの情報の代わりに採用しません。WebSocketメッセージでは従来どおり予約名の指定をエラーにし、MCPでは入力スキーマ検証後に利用者の値を除いてから設定します。

```javascript
const ip = nyanRequest.remoteIP;
const agent = nyanRequest.headers["user-agent"];
const session = nyanRequest.cookies.session;
// 同じデータを nyanAllParams.nyan_request からも参照できます。
```

| プロパティ | 内容 |
|---|---|
| `method` / `path` | 元のHTTPメソッドとURLパス。内部呼び出し先のAPI名へは変更しません。 |
| `host` / `scheme` | 受信Hostと実接続の `http` / `https`。 |
| `remoteAddress` / `remoteIP` | 実接続のアドレス（通常ポート付き）とポートを除いたIP。`X-Forwarded-For` による置き換えはしません。 |
| `userAgent` | 受信したUser-Agent。 |
| `headers` | 受信ヘッダー。キーは小文字と標準表記（例：`authorization` / `Authorization`）で参照可能。値は1件なら文字列、複数件なら配列。 |
| `cookies` | Cookie名から値へのオブジェクト。 |
| `query` / `form` | URLクエリとフォーム本文を分離した値。1件なら文字列、同名の複数値は配列。 |
| `json` / `body` | 取り込んだJSON本文の値と、解析時に読み取った本文文字列。JSON本文がない場合の `json` は `null`。 |

ヘッダー・Cookieなどは受信した値であり、それ自体が認証済みの身元を保証するわけではありません。WebSocketでは接続時のHTTP情報を使用し、各メッセージのJSONは `nyanAllParams` に入ります。接続前チェックと各メッセージではそれぞれ情報を生成するため、前のチェック／メッセージでの書き換えを次のメッセージへ引き継ぎません。JSON-RPCとHTTP MCPの `json` / `body` は、引数部分だけでなく元のプロトコル要求全体です。HTTP要求がないstdio・schedule・ws_clientのスクリプトでは `nyanRequest` と互換参照は空オブジェクト `{}` です。

`nyanCallMe({api:"child", id:2})` は、子APIの通常引数には明示した `id:2` だけを渡し、リクエスト情報を別途自動継承します。親の業務パラメータは自動統合せず、`api` は子API名になります。引数に `nyan_request` を指定しても、継承する元情報の置き換えには使いません。通常引数は従来どおり浅いコピーなので、親の入れ子のオブジェクトを渡した場合、その内容の変更は親にも影響し得ます。

Push先には、呼び出し元の処理後のパラメータとリクエスト情報を入れ子までコピーして渡し、`api` をPush先API名にします。子APIのPushは子の引数、親APIのPushは親の引数が基準です。Push先の変更は元へ戻らず、購読者の接続情報や購読時の引数は混ぜません。呼び出し元の戻り値JSONをPush先の引数へ自動追加することもありません。通常APIでは入力チェック・本体で補正／追加したパラメータもPushへ渡ります。`outCheck` は浅いコピーで実行するため、最上位への追加・置き換えは渡りませんが、共有された入れ子の変更は影響します。

**運用ルール：通常の業務パラメータは必要に応じて補正・追加して構いませんが、`nyanRequest` と `nyanAllParams.nyan_request` は参照専用として扱ってください。** JavaScriptの読み取り専用化は強制しません。内容を書き換えると同じ情報を参照する後続処理にも影響し得ます。変数や互換参照の丸ごとの置き換えも避けてください。OAuthの各段階は既存仕様どおり入力のコピーで実行します。`nyanAllParams` 全体には元リクエストのヘッダー・Cookie・本文も含まれるため、ログや応答へ丸ごと出力せず、必要な業務項目だけを選んでください。

---



### Argon2idハッシュの生成と検証

`nyanArgon2idHash(password)` と `nyanArgon2idVerify(password, encodedHash)` の計算・検証条件はNyanQL・Nyan8・NyanPUIで共通です。

新規生成は従来どおり `m=65536,t=3,p=2`（メモリ64 MiB）、ソルト16バイト、ハッシュ32バイトです。生成するパスワードは1〜4096バイト。ランダムなソルトを使うため、同じパスワードでも生成するハッシュ文字列は通常異なります。

検証では、ハッシュに記録された条件を使い、以下の範囲を受け付けます。新規生成の設定とは独立しています。

| 項目 | 検証で許可する範囲 |
|---|---|
| アルゴリズム・バージョン | Argon2id、v=19 |
| メモリ量 `m` | 65536〜262144 KiB（64〜256 MiB） |
| 反復回数 `t` | 3〜10 |
| 並列度 `p` | 1〜16 |
| ソルト長 | 16〜64バイト |
| ハッシュ長 | 16〜64バイト |
| 検証パスワード長 | 4096バイト以内（UTF-8文字列のバイト数） |

正しいパスワードなら、例えば `t=4` や `p=1` で生成されたハッシュも検証できます。条件の数字だけを書き換えたハッシュを受理するという意味ではありません。

PHC文字列は `$argon2id$v=19$m=65536,t=3,p=2$ソルト$ハッシュ` の形で、パラメータは `m,t,p` の順序、符号・先頭ゼロのない10進整数とします。余分な文字・空白・項目は拒否します。ソルトとハッシュはパディングなしの標準Base64で、改行・Base64URL・非正規の末尾ビットを拒否します。

検証関数は一致時に `true`、不一致・不正形式・範囲外・長すぎるパスワードでは `false` を返します。検証時の空文字列は従来どおり照合対象にできますが、生成関数は空パスワードを拒否します。引数の省略・型変換に関する既存のJavaScriptラッパーの仕様は今回変更していません。

形式・上限の検査はArgon2計算前に行い、1プロセス内の生成・検証を合わせて同時2件までに制限します。この計算枠は、通常APIとOAuth用VM、`nyanArgon2idHash`・`nyanArgon2idVerify`・`nyanPassword.hash`・`nyanPassword.verify` のすべてで共有します。枠が埋まっている場合、検査を通った計算は空きができるまで待機します。記録された `m` や `t` が大きいハッシュは、標準設定よりメモリや処理時間を使います。

NyanQLのOAuth用VMには計算枠とは別に、`password` capabilityを持つVM全体を1プロセスで同時1件までにする受付制限があります。この受付は待機せず、競合した実行をスクリプト開始前にエラーにします。そのため「Argon2の計算枠では待機する」ことから「OAuth要求もすべて待機する」と解釈しないでください。適用単位・処理順・HTTP応答は [OAuthの受付制限と実行枠](#oauth-execution-limits) に示します。

既存の標準ハッシュはそのまま利用できます。ハッシュの自動再生成・保存やパスワード再設定は行いません。QL/Nyan8で以前読めた非正規の表記は拒否されるため、外部から取り込んだハッシュは上記形式を確認してください。生成・検証条件を変更するconfig.json項目を追加したものではありません。

`nyanPassword.hash(password)` / `nyanPassword.verify(password, encodedHash)` も同じ生成・検証処理を使います。引数はそれぞれちょうど1個・2個で、個数の過不足はJavaScript例外です。capabilitiesで制限する実行環境では、`password` の許可が必要です。

### 共通ファイル保存：nyanWriteTextFile / nyanWriteBase64File

NyanQL・Nyan8・NyanPUIで同じ引数順・戻り値を使えます。第1引数が保存先、第2引数が保存する内容です。

```javascript
nyanWriteTextFile("./files/hello.txt", "こんにちは");
nyanWriteTextFile("./files/result.json", JSON.stringify({ok: true}));
nyanWriteBase64File("./files/hello.bin", "aGVsbG8="); // hello のバイト列を保存
```

- `nyanWriteTextFile(path, text)`：文字列をUTF-8で保存します。
- `nyanWriteBase64File(path, base64)`：標準Base64をデコードして保存します。Base64URLやData URLは受け付けません。必要な `=` は省略できません。CR/LFの改行は許容します。
- 成功時は `true`、失敗時はJavaScript例外です。引数不足・文字列以外・空または空白だけのパス・不正なBase64は `TypeError`、保存時のI/Oエラーは `GoError` です。オブジェクト等の暗黙の文字列化は行いません。余分な引数は無視します。
- 第2引数の空文字列は有効で、空ファイルを保存します。既存ファイルは上書きします。
- 相対パスは実行開始時の最上位API定義ファイルのフォルダが基準です。include先でも同じで、設定の再読込後も実行中の基準を保持します。絶対パスはそのまま使えます。最上位設定の絶対パスを取得できない実行環境では、相対パスを例外として拒否します。
- 親フォルダがなければmode `0750` で作成します（umaskの影響を受けます）。同じフォルダの一時ファイルへmode `0600` で書き込み、同期・close成功後にrenameで置き換えます。上書き後のファイルもmode `0600` になります。保存先がシンボリックリンクならリンク自体を置き換えます。

既存の `nyanSaveFile(base64, path)` は引数順・保存形式・戻り値（`undefined`）を変更せず残しています。既存コードの書き換えは不要です。新関数も、既存のファイル操作と同様にcapabilitiesで制限された実行環境では使用できません。


## 複数SQLのトランザクション

`api.json` の `sql` に複数のSQLファイルを指定すると、NyanQLはそれらを1つのトランザクションとして実行します。

たとえば「入庫テーブルに追加し、在庫テーブルを更新する」という処理は、次のように書けます。

```json
{
  "addItem": {
    "sql": [
      "./sql/insertNyuko.sql",
      "./sql/updateZaiko.sql"
    ],
    "description": "商品を1件入庫します"
  }
}
```

この場合、1つ目のSQLと2つ目のSQLは同じトランザクションで実行されます。途中でエラーが起きると、全体がロールバックされます。

最上位のSQL APIで `sql` が1つだけの場合は明示的なトランザクションを開始せず、データベース側の通常の自動コミット動作になります。scriptの `nyanCallMe()` から呼ばれた場合は、ファイル数にかかわらず親scriptのトランザクションに参加します。

---

## scriptでのトランザクション

`script` を使うAPIでは、最初のSQL実行時にトランザクションを開始します。SQLを使わないscriptはDB接続を確保しません。接続プールの空き待ちは最大30秒で、呼び出し元のキャンセルやOAuthの15秒の期限が先に来た場合はそちらを優先します。

script内で `nyanRunSQL()` を何度呼んでも、同じトランザクションの中で実行されます。`nyanCallMe()` の子API・孫APIのSQL、script、前後チェックもこのトランザクションを共有します。子APIは親の未コミット更新を参照でき、接続上限が1でも別接続の空きを待ちません。子APIの `paramCheck`・`outCheck` は、戻り値のgetter評価中も親scriptのキャンセルに従います。

最上位scriptの実行と戻り値の変換が正常に終了してから、まとめてコミットします。親・子の実行で例外が起きた場合は全体をロールバックします。子APIの例外や `nyanRunSQL()` の引数評価・SQLファイル読込・SQL実行・結果読込のエラーをJavaScriptの `try/catch` で捕捉しても、失敗した共有トランザクションはコミットせず、最上位scriptをエラーにします。`success:false` やエラーステータスを通常の戻り値として返すだけでは、ロールバックは指示しません。

子APIのPushは呼び出し完了時の引数を保持し、共有トランザクションのコミット後に実行します。親の本体が失敗した場合は未送信のPushも取り消します。ファイル保存や外部HTTPなど、DB以外の副作用はロールバックできません。

この共有はscriptからの同期的な内部呼び出しに適用します。最上位APIの本体より前の `paramCheck`、コミット後の `outCheck`、Push先は別の実行です。

複雑な登録処理をひとまとまりにしたい場合は、複数SQLの配列よりも `script` が向いています。

---

## WebSocketによるPush配信

NyanQLには、APIの実行後に別APIの結果をWebSocketへ配信するPush機能があります。

たとえば、画面Aで「登録API」を呼び出した後、画面Bに「一覧API」の最新結果を送る、という使い方ができます。

### Pushの基本

Push先の `paramCheck`・本体・`outCheck` では、`nyanAllParams.api` は **現在実行しているPush先APIの名前** です。NyanQL・Nyan8・NyanPUIで共通です。例えば `saveItem` の `push` が `itemsChanged` なら、Push先では `itemsChanged` になります。複数の起動元が同じPush先を使う場合も同じ名前です。`group/itemsChanged` のような完全なAPI名を保持します。

Push用にコピーしたパラメータの `api` を設定するため、起動元の `api` や応答は変更しません。起動元のAPI名を記録したい場合は、起動元の処理でPush実行前に記録してください。起動元名を自動設定する `sourceApi` 等の項目は追加していません。既存のNyan8/PUIでPush内の `api` を起動元の識別に使っていたコードは、この仕様に合わせて調整してください。Push先の選択・配信チャンネルは引き続き `push` 設定で決まります。



`api.json` のAPI定義に `push` を書きます。

```json
{
  "listItems": {
    "sql": ["./sql/listItems.sql"],
    "description": "商品一覧を取得します"
  },
  "addItem": {
    "sql": ["./sql/insertItem.sql"],
    "description": "商品を追加します",
    "push": "listItems"
  }
}
```

この例では、`addItem` が実行されたあと、NyanQLは `listItems` を実行し、その結果を `listItems` チャネルに接続しているWebSocketクライアントへ配信します。

WebSocketクライアントは、次のように接続します。

```js
var ws = new WebSocket("ws://localhost:8080/listItems");

ws.onmessage = function (event) {
  var data = JSON.parse(event.data);
  console.log("Pushを受信しました", data);
};
```

NyanQLのWebSocketサーバでは、先頭の `/` を除いたURLパス全体がチャネル名になります。上の例では、`listItems` がチャネル名です。mount配下の `sub/listItems` をpush先にする場合は、WebSocketも `/sub/listItems` へ接続してください。

通常WebSocketの受入枠は、1プロセス内の全チャネルで既定128件までです。`config.json` の `webSocketLimits.maxConnections` で増減できます。接続済みのクライアントだけでなく、アップグレード前の本文サイズ検証・`paramCheck` の実行中も1枠を使用します。`nyan_mode=checkOnly` の要求もチェック終了まで数えます。満杯の場合は待機せず、`paramCheck` を実行する前にHTTP 503と `too many WebSocket connections` を返します。チェック拒否・アップグレード失敗・接続終了で枠を解放します。チャネル単位の上限ではありません。設定値・再起動要否は [WebSocketの同時接続数上限](#websocket-connection-limits) を参照してください。

この枠はNyanQLが受け付ける接続に適用します。`ws_client` が接続先へ張る外向きの接続は数えません。`ws_client.connectURL` のパスを使ってNyanQLへ接続する購読クライアントは受信接続なので数えます。受信メッセージのバイト上限は、別途 `receiveLimits.webSocketMessageBytes` を使います。

接続先APIに `paramCheck`（旧名 `check`）がある場合は、WebSocketへのアップグレード・購読登録の前に実行します。チェックにはURLのクエリパラメータを渡します（単一値は文字列、同名の複数値は文字列配列）。`api` は接続先の完全API名に固定し、クエリでは変更できません。入力チェックが必要とするパラメータは、`/sub/listItems?token=...` のように接続URLにも指定してください。`success:true` なら接続を許可し、拒否時はチェック結果のJSONと `status` をHTTP応答で返します。例外・チェックファイルの読み込み失敗・不正なステータス（200〜599の整数以外）はHTTP 500となり、接続しません。接続時にはAPI本体・`outCheck`・Pushを実行しません。

接続URLに `nyan_mode=checkOnly` を指定した場合は、成功時もチェック結果をHTTP応答で返し、WebSocketへアップグレードしません。チェック未設定ならHTTP 404です。`nyan_mode` は省略または空文字列で通常接続となり、それ以外の値や複数指定はHTTP 400です。チェック未設定の通常接続と、`ws_client` の `connectURL` による既存の購読パスは引き続き利用できます。購読接続への一律のBasic認証は追加せず、接続後のAPI実行には下記の認証を適用します。

### WebSocket接続可否の判断方針

通常のWebSocket接続では、次のように責務を分担します。

- **接続時**：`paramCheck` があれば、サーバー側のJavaScriptで接続を許可するか判断します。未設定なら事前チェック不要として接続を許可します。`ws_client` の `connectURL` による既存の購読パスも、接続前チェックがなければ同じ扱いです。
- **接続後**：各APIの `paramCheck`・本体処理で、そのAPI処理を受け付けるか判断します。接続しただけではAPI本体を実行しません。接続後のAPI実行に必要なBasic認証は、下記の説明どおり適用します。
- **Go側**：WebSocketの通信手順、接続先の存在確認、接続数・受信サイズの上限など、通信基盤の処理を担当します。Originを理由とした接続の許可・拒否はJavaScript側の責務とします。

Originを制限したい場合は、`paramCheck` で `nyanRequest.headers.origin` を参照して判断します。Originがない要求を受け入れるかどうかもJavaScript側で決めます。`paramCheck` 未設定時にはOriginによる制限を設けず、通信基盤の条件を満たす接続を受け入れます。

Go側では、通常WebSocketのOriginの形式や接続先Hostとの一致による固定判定を行いません。別HostのOriginも、`paramCheck` が許可すれば接続できます。MCP/OAuthでは別途 `allowedOrigins` に基づくOrigin検証を行い、この通常WebSocketの責務分担は適用しません。

### WebSocketからAPIを呼び出す

接続後、`api` に実行対象を指定したJSONオブジェクトをテキストメッセージとして送信できます。その他の項目はAPIのパラメータになります。

```json
{"api":"getItem","id":1}
```

呼び出しごとに、対象APIの `paramCheck` → 本体のscript／SQL → `outCheck` → 応答送信の順に実行します。設定されていないチェックは省略します。`paramCheck` が拒否した場合は本体を実行せず、`outCheck` が拒否した場合は本体の結果を送らず、それぞれのチェック結果を呼び出した接続だけに返します。`outCheck` では通常HTTPと同じ `nyan_output.body` などで送信予定の本文を確認できます。チェックや本体処理で例外が発生した場合も、その呼び出しのエラーを返し、次の呼び出しを受け付けます。

API実行には通常HTTPと同じBasic認証が必要です。接続時のHTTPリクエストに認証情報を含めてください。接続先のチャネル名と実行対象の `api` は別に指定でき、mount配下のAPIには `sub/getItem` のような完全API名を使います。対象は `type: "api"`（省略時を含む）のAPIです。内部コンテキスト用の `nyan_request`・`nyan_guard`・`mcp_principal` はメッセージに指定できません。

`nyan_mode: "checkOnly"` を指定した呼び出しでは `paramCheck` だけを実行し、本体処理・`outCheck`・Pushは実行しません。接続しただけではAPI本体は実行せず、`api` を含まないJSONオブジェクトやバイナリメッセージもAPI実行の対象にはしません。

### Pushで配信される内容

Pushは、呼び出し元のAPIがチェック拒否・実行エラー・`checkOnly`で終了していない場合に、返却結果を確認して開始します。応答ステータスが200〜399で、結果JSONのトップレベルの `success` が真偽値の `false` ではないことが条件です。トップレベルに数値の `status` がある場合は、その値も200〜399の整数である必要があります。例えば、本文が `{"success":false,"status":200}` や `{"success":true,"status":503}` ならPushを開始しません。通常HTTPでは前者のHTTPステータスは200、後者は503です。`status` を省略した結果やプレーンテキストは、実行経路の応答ステータス（通常は200）で判定します。

この判定は通常HTTP・ルートHTTP・JSON-RPC・WebSocket・`nyanCallMe()`・MCP（HTTP／stdio）に適用します。停止時はPush先の入力チェック・本体・出力チェック・配信をすべて実行しません。呼び出し元の出力チェックや応答内容・HTTPステータスは、このPush判定によって変更しません。

MCP（HTTP／stdio）では、本体・`outCheck`の処理後、返却する本文がJSONとして解析でき、Tool結果の本文サイズ上限（2 MiB）以内であることを確認します。さらに `content.text`・`structuredContent`・要求IDを含むMCP応答全体をJSON化し、応答上限（4 MiB）以内であることを確認してから、そのAPI自身のPushを判定します。正常時は設定されたPushを実行します。不正なJSON・本文や応答全体のサイズ超過・応答のJSON化失敗では `isError:true` のToolエラーを返し、Push先の処理を開始しません。HTTP版のToolエラーはHTTP 200で返し、stdioも次の要求を引き続き処理します。配列・数値・真偽値・`null`・JSON文字列も有効なJSONとして扱います。

MCP（HTTP／stdio）の本体結果に、最上位の真偽値 `success: false` があれば `isError: true` を返します。元の結果は `content` のtextと `structuredContent` に保持します。文字列の `"false"`、`null`、数値、入れ子の値、`success` の省略は、この条件ではエラーにしません。チェック・実行・応答検証の既存のエラー判定は引き続き適用します。

内部呼び出し先と親APIのPushは、それぞれの結果で独立して判定します。script内の内部呼び出し先のPushは、親と共有するトランザクションのコミット後に実行し、親の本体が失敗した場合は実行しません。コミット後に子のPushが完了し、その後に親の `outCheck` が拒否・エラーになった場合は、完了済みの配信を取り消しません。上記の成功条件は呼び出し元に対するもので、Push先自身が返すエラー通知を一律に配信禁止にするものではありません。

`push` の参照先がSQL APIの場合、NyanQLはそのSQLを実行し、次のような形に包んで配信します。

SQLの実行方法は通常のAPI呼び出しと同じです。元APIから引き継いだパラメータを使って2way-SQLのパラメータ・条件分岐を処理し、`sql` 配列の全ファイルを指定順に実行します。複数ファイルは1つのトランザクションで実行し、途中でSQLの読み込みや実行に失敗すると、そのPush先でのトランザクションをロールバックして配信を中止します。配信する `result` は最後のSQLの結果です。

```json
{
  "success": true,
  "status": 200,
  "result": [
    { "id": 1, "name": "にゃんくる" }
  ]
}
```

`push` の参照先がscript APIの場合は、そのscriptが返した文字列をそのまま配信します。script側でJSON文字列を返すようにしておくと扱いやすくなります。

Push先に `paramCheck`・`outCheck` が設定されている場合は、`paramCheck` → 本体のscript／SQL → `outCheck` → 配信の順に実行します。Push処理には元APIのパラメータをコピーして渡し、`nyanAllParams.api` はPush先のAPI名に設定します。`outCheck` の `nyan_output.body` には配信予定の本文が入ります。

チェックで拒否された場合や、チェック・本体処理でエラーが発生した場合は、ログに記録してそのPush配信を中止します。チェックの拒否結果やエラーを元APIの応答に置き換えることはなく、元APIで完了した更新も取り消しません。Push処理は引き続き同期実行するため、その処理時間は元APIの応答までの時間に含まれます。

配信対象は、配信開始時にコピーした購読接続の一覧です。ネットワーク送信中は接続一覧のロックを保持せず、接続の登録・削除や別接続への送信を進められます。同じ接続へのAPI応答とPushは接続ごとに直列化し、各データ書き込みに5秒の期限を設けます。送信失敗・期限超過した接続は閉じて購読一覧から除去し、残りの接続への配信を続けます。古い接続の終了や送信失敗で、再接続後の新しい接続を削除することはありません。

同じ配信処理内では各接続へ順番に送信するため、遅い接続があれば後続の接続はその書き込みが終了するまで待ちます。5秒は個々の書き込みの期限であり、Push全体の完了時間の上限ではありません。

### Pushでよくある勘違い

`push` は、呼び出したAPI自身の結果をそのまま配信する機能ではありません。`push` に指定した別APIを実行し、その結果を指定チャネルへ配信する機能です。

つまり、更新APIの後に一覧APIを配信する、という形が基本です。

---

## WebSocketクライアント機能

NyanQLは、WebSocketサーバとしてPushを配信するだけでなく、NyanQL自身がWebSocketクライアントとして外部のWebSocketサーバへ接続することもできます。

`api.json` で `type: "ws_client"` を指定します。

```json
{
  "receiveExternalMessage": {
    "type": "ws_client",
    "script": "./javascript/ws/receiver.js",
    "connectURL": "ws://localhost:8890/hello",
    "description": "外部WebSocketからメッセージを受信します"
  }
}
```

この設定を書くと、NyanQLは起動時またはホットリロードでの追加時に `connectURL` へ接続します。接続が切れた場合は、時間をあけながら再接続を試みます。

`ws_client`では `paramCheck`・`outCheck` は不要であり、実行しません。これらにスクリプトを指定すると、起動時・ホットリロード時の設定読み込みで、クライアント名と対象項目を含むWARNログ（`ws_client_check_ignored`）を出力します。その指定は不要で適用できず、実行されないことと、設定の削除を案内します。互換名の `check`・`paramcheck`・`outcheck` も同じ扱いです。接続・受信・script実行・返信は従来どおり継続し、受信や再接続のたびにこの警告を繰り返すことはありません。受信内容や返信の検証はscript内で行ってください。script内から `nyanCallMe()` で通常APIを呼ぶ場合は、呼び出し先APIのチェックが通常どおり適用されます。

ws_clientがinclude先にある場合、内部名と `nyanAllParams.ws_client` には `sub/receiveExternalMessage` のような完全名が入ります。mountを削除すると、その配下の接続と再接続処理も停止します。

ホットリロードで `script` または `description` だけを変更した場合は、現在の接続を維持し、次に受信するメッセージから新しい設定を使用します。`connectURL` を変更した場合は現在の接続を閉じ、新しい接続先へ接続します。切り替え中に接続先から送信されたメッセージの受信は保証されません。

受信したメッセージは、`script` に渡されます。scriptの中では、次の値を `nyanAllParams` から参照できます。

| 名前 | 内容 |
|---|---|
| `nyanAllParams.ws_client` | `api.json` 上のWebSocketクライアント名です。 |
| `nyanAllParams.ws_message_type` | `text`、`binary` などのメッセージ種別です。 |
| `nyanAllParams.ws_message_text` | 受信したメッセージの文字列です。 |
| `nyanAllParams.ws_message_json` | テキストメッセージがJSONとして読めた場合の値です。 |
| `nyanAllParams.ws_message_base64` | バイナリメッセージをBase64にした値です。 |
| `nyanAllParams.ws_connect_url` | 接続先URLです。 |
| `nyanAllParams.ws_description` | `api.json` に書いた説明です。 |

scriptの結果は前後の空白・改行を除去してから扱います。空文字または空白・改行だけなら返信せず、それ以外は除去後の文字列をWebSocketのテキストメッセージとして送信します。

`connectURL` には、環境変数を使うこともできます。

```json
{
  "receiveExternalMessage": {
    "type": "ws_client",
    "script": "./javascript/ws/receiver.js",
    "connectURL": "env:NYANQL_WS_URL",
    "description": "環境変数で接続先を指定します"
  }
}
```

この場合、起動時または `api.json` の再読み込み時に `NYANQL_WS_URL` の値を接続先として使います。

---

## 定期実行ジョブ

`api.json` で `type: "schedule"` を指定すると、NyanQLの起動時またはホットリロードでの追加時に定期実行ジョブとして登録されます。

```json
{
  "dailyJob": {
    "type": "schedule",
    "script": "./javascript/daily_job.js",
    "trigger": {
      "type": "cron",
      "value": "0 10 * * *"
    },
    "description": "毎日10:00に実行します"
  }
}
```

この例では、毎日10:00に `./javascript/daily_job.js` が実行されます。`type: "schedule"` の定義はHTTP APIとしては公開されないため、外部リクエストから直接実行されません。

scheduleでは `paramCheck`・`outCheck` は不要であり、実行しません。これらにスクリプトを指定すると、起動時・ホットリロード時の設定読み込みで、ジョブ名と対象項目を含むWARNログ（`schedule_check_ignored`）を出力します。ログには、その指定は不要で適用できず、実行されないことと、設定の削除を案内します。互換名の `check`・`paramcheck`・`outcheck` も同じ扱いです。ジョブ自体の登録・実行は継続し、定期実行のたびにこの警告を繰り返すことはありません。script内から `nyanCallMe()` で通常APIを呼ぶ場合は、呼び出し先APIのチェックが通常どおり適用されます。

scheduleがinclude先にある場合、ジョブ名と `nyanAllParams.nyan_job_name` には `sub/dailyJob` のような完全名が入ります。mountを削除すると、その配下のジョブも次回以降実行されません。

cronは5フィールド形式です。

```text
分 時 日 月 曜日
```

たとえば、次のように指定できます。

| cron | 実行タイミング |
|---|---|
| `* * * * *` | 1分ごと |
| `*/10 * * * *` | 10分ごと |
| `0 10 * * *` | 毎日10:00 |
| `15,45 * * * *` | 毎時15分と45分 |
| `0 9-18 * * *` | 9時から18時まで毎時0分 |

現在の実装では秒単位の指定には対応していません。最短の実行間隔は1分です。`*/10` は「起動してから10分ごと」ではなく、crontabと同じく時計の分が `00, 10, 20, 30, 40, 50` のタイミングで実行されます。

ホットリロードでscriptまたはcronを変更すると、待機中のtimerを停止し、新しいcronから次回時刻を計算します。script実行中に変更または削除された場合、その実行は途中で強制終了せず最後まで継続します。同じschedule名を変更前後で同時実行することはなく、実行中に過ぎた発火時刻を後からまとめて実行することもありません。

scheduleのscript内では、通常のscriptと同じように `nyanAllParams` や `nyanRunSQL()` などを使えます。加えて、次の値が `nyanAllParams` に入ります。

| 名前 | 内容 |
|---|---|
| `nyanAllParams.nyan_job_name` | `api.json` 上のジョブ名です。 |
| `nyanAllParams.nyan_schedule_trigger_type` | 現在は `cron` です。 |
| `nyanAllParams.nyan_schedule_trigger` | cron式です。 |
| `nyanAllParams.nyan_schedule_time` | 実行予定時刻です。 |

動作確認用のscript例です。

```js
const now = new Date();

console.log(
  "[schedule_debug]",
  "executed_at=" + now.toISOString(),
  "job=" + nyanAllParams.nyan_job_name,
  "scheduled_at=" + nyanAllParams.nyan_schedule_time,
  "trigger=" + nyanAllParams.nyan_schedule_trigger
);

"schedule_debug executed at " + now.toISOString();
```

`javascript_include` に設定した共通JavaScriptは、scheduleにも適用されます。`javascript_include_cache`が`false`または省略時は毎回読み込み、`true`では起動時に保持したソースを使用します。

---

<a id="mcp-setup"></a>
## MCPサーバーの設定

`type: "mcp"` の `tools` に、**実在するscriptを持つ通常API**の名前を指定します。SQLだけのAPIは直接指定できません。SQLを利用するToolはJavaScriptから `nyanRunSQL` を呼びます。入力スキーマを自動検証し、設定されたparamCheck/outCheckを実行します。出力スキーマは公開用で、QLでは本体結果を自動検証しません。

### stdioで試す

[最小起動例](#quickstart)のconfigを使い、次の2ファイルを追加します。JavaScriptだけのToolでも起動時にDBへ接続するため、DB設定は必要です。

`quickstart/mcp-tool.js`：

```javascript
({status: 200, result: {message: "Hello, MCP!"}});
```

`quickstart/mcp-api.json`：

```json
{
  "hello": {"script": "./mcp-tool.js", "description": "固定メッセージを返す"},
  "local_mcp": {"type": "mcp", "transport": "stdio", "tools": ["hello"]}
}
```

```bash
./nyanql --config ./quickstart/config.json --api ./quickstart/mcp-api.json --mcp-server local_mcp
```

標準入力に次のJSONを1行ずつ渡せます。initializeの応答後にinitialized通知を送り、Tool一覧・呼出しへ進みます。Tool呼出しの応答には `Hello, MCP!` が含まれます。

```jsonl
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"readme-demo","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hello","arguments":{}}}
```

stdioでは標準出力がMCP専用です。サービスログは標準エラーまたは設定したログファイルへ出ます。HTTP待受・schedule・ws_client・ホットリロードは開始しません。設定変更時は再起動します。

<a id="mcp-stdio-limits"></a>

#### stdioのメッセージ上限

入力は1行に1つのJSON-RPCメッセージです。1行の固定上限は **1 MiB（1,048,576バイト）** で、文字数ではなく入力バイト数（日本語などはUTF-8のバイト数）で数えます。終端のLFは上限に含めません。CRLFを使う場合、LF直前のCRも入力バッファの上限を消費します。JSON文字列の改行は実際の改行ではなく `\n` としてエスケープしてください。

上限を超える行はJSON-RPCとして解析せず、`stdio MCP input failed` の読み取りエラーでstdio処理を終了します。その行に対するJSON-RPCエラー応答は生成せず、後続の行も処理しません。`config.json` の `receiveLimits` ではこの固定上限を変更できません。HTTP MCPの入力本文は `receiveLimits.httpBodyBytes` の対象であり、この1 MiB制限は適用しません。

出力側は別の制限です。Tool結果本文は2 MiB、JSON化したMCP応答全体は4 MiBまでです。stdioの4 MiBには末尾に付加するLFを含めません。stdioは入力を1行ずつ順番に処理し、MCPのHTTP向け `rateLimit`・`maxConcurrent` による受付制限は使いません。

### Streamable HTTPと設定フィールド

同じToolをHTTPで試す場合、上の `local_mcp` 定義を次に置き換え、`--mcp-server` を付けずに起動します。このJSONはAPI定義の一部分です。

```json
{
  "local_mcp": {
    "type": "mcp",
    "transport": "streamable_http",
    "allowedOrigins": ["https://example.com"],
    "tools": ["hello"]
  }
}
```

接続先は `http://127.0.0.1:8080/local_mcp` です。`allowedOrigins` はブラウザの許可Originであり、公開URLを指定する項目ではありません。この例はOAuth未設定で、MCPの呼出しに通常APIのBasic認証は適用されません。認証なしの動作確認用なので、そのまま外部公開しないでください。

```bash
curl http://127.0.0.1:8080/local_mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

| 項目 | 内容 |
|---|---|
| `transport` | `stdio` または `streamable_http`。必須 |
| `tools` | scriptを持つ通常API名の配列。1件以上。include先は完全名 |
| `protocolVersions` | 省略時 `2025-11-25` と `2025-06-18`。この2版に対応 |
| `allowedOrigins` | HTTPで空でない配列が必須。HTTP(S)のOrigin文字列。scheme・hostは小文字、user情報・path（末尾`/`も含む）・query・fragmentは不可。重複・`*`・`null` というOrigin文字列は不可 |
| `instructions` | initializeに返す利用説明 |
| `rateLimit` | `{"requests":120,"window":"1m"}` 等。requestsは1〜10000、windowは1秒〜24時間 |
| `maxConcurrent` | 正の整数1〜256。未指定・0は16。負数・257以上は設定エラー。HTTP MCPとOAuthの受付枠に使用し、stdioには適用しない |
| `oauth` | 下記の通常APIへの役割参照。HTTPのみ |
| `redirectURIAllowedPrefixes` | OAuthで必須。HTTPSで末尾`/`のredirect URI prefix配列 |

対応メソッドはinitialize・ping・tools/list・tools/callです。HTTPはstatelessで、バッチ要求やセッション管理は提供しません。Toolのtitle・description・securitySchemes・annotations、paramCheck/outCheckのスキーマは参照先APIから解決します。

MCP/OAuthのハンドラーに到達したHTTP要求では、Go側でOriginを検証します。Originが未指定または前後の空白を除いて空なら通過します。指定されている場合は、HTTP(S)のOriginとしての形式を確認したうえで、接続先のscheme・host・portから生成したOrigin、または `allowedOrigins` のいずれかと一致すれば許可します。scheme・hostの大文字小文字は正規化しますが、明示したポートは比較に含まれ、既定ポートの省略と明示は同一視しません。不正形式・未許可OriginはHTTP 403 `forbidden origin` です。これは通常WebSocketの `paramCheck` によるOrigin判断とは別の処理です。CORSプリフライト（`OPTIONS` と `Access-Control-Request-Method`）は手前の共通CORS層で応答し、この判定やOAuth hookの実行には進みません。

MCPの接続URLはAPI名とリクエストのHost/TLS情報から生成します。次の設定項目はURL指定の手段には使えません。

| 設定 | 現在の設定読込時の扱い |
|---|---|
| `http`・`resource`・`guard` | API定義JSONの許可フィールドに含まれません。値が空・`null` でも、キーを書けば設定エラーになります。 |
| `path` | `type: "mcp"` では空でない値を指定すると設定エラーです。空文字列を指定してもMCPの経路は変わりません。public APIの配信パス設定とは別です。 |

これらの設定エラーは、起動時には起動中止、ホットリロード時には候補設定の不採用となります。MCP名とOAuth参照先の名前については [MCP/OAuthのAPI名の制約](#mcp-api-names) を参照してください。

### OAuth hookを実装する場合

OAuth設定は認証処理そのものを生成しません。利用者認証、PKCE、認可コードの一回限り消費、token発行・期限・scopeの検証はアプリケーションのJavaScriptで実装します。MCP定義の `oauth` に次の役割を、それぞれ異なる通常API名で指定します。

| oauthのキー | 参照先の役割 |
|---|---|
| `authorizationServerMetadata` / `protectedResourceMetadata` | Goがメタデータを生成するAPI。script不要 |
| `authorize` / `token` / `register` | 認可・token・クライアント登録を行うscript付きAPI |
| `verifyAccess` | access tokenと要求scopeを検証するscript付きAPI。API定義の `scopes` に許可scopeを列挙 |
| `adminUser` | 任意の管理用API。設定時はloopbackからの接続とconfigのBasic認証が必要 |

OAuthを使う各Toolには `securitySchemes: [{"type":"oauth2","scopes":["example:read"]}]` 等のscopeを宣言し、verifyAccess側のscopesに含めます。hookは `nyanAllParams` の `oauth_hook`、`oauth_api`、`issuer`、`resource`、`scopes` 等を参照できます。HTTP hookにはmethod/query/form/body/cookies/headersが渡り、query/formの各値は、1件なら文字列、同じキーが複数件あれば文字列の配列です。単一値に `[0]` を付けると先頭の1文字になるため、そのまま参照してください。verifyAccessには `authorization`、`tool`、`required_scopes` と `nyan_request` が渡ります。

HTTP hookで使えるヘッダー参照には、次の違いがあります。

| 参照先 | キーと値 |
|---|---|
| `nyanAllParams.headers` | `Authorization`・`Content-Type`・`Accept`・`Origin` の4キーだけ。キーはこの大文字小文字で参照します。値は常に文字列で、未受信なら空文字列、同名ヘッダーが複数ある場合は先頭の値です。 |
| `nyanRequest.headers`（`nyanAllParams.nyan_request.headers` と同じ） | GoのHTTPリクエストのヘッダーマップに含まれる全項目。小文字と標準表記のキーで参照できます。値は1件なら文字列、複数件なら文字列配列です。未受信のキーは存在しません。 |

例えば独自ヘッダーは `nyanRequest.headers["x-custom-token"]` で参照します。HostはGoのヘッダーマップとは別管理なので `nyanRequest.host` を使います。`verifyAccess` には前者の4キーの `headers` は生成せず、元のMCP要求の `nyanRequest.headers` と `nyanAllParams.authorization` を渡します。hookの戻り値に指定する `headers` は送信する応答ヘッダーであり、これらの受信ヘッダーとは別です。

HTTP hookは `{status, contentType, headers, body}` を返します（status省略時200、指定時は100〜599の整数）。例えば拒否応答は `({status:400,contentType:"application/json",body:{error:"invalid_request"}});` です。verifyAccessはHTTP応答ではなく `{authenticated:true,principal:{...}}` または拒否の `{authenticated:false}` を返します。認証成功にはprincipalも必要です。JSオブジェクトと、それをJSON化した文字列を利用できます。チェックの `{success,status,result}` とは別の契約です。

OAuthのscriptと前後チェックは、通常APIより機能を制限したVMで実行します。各参照先APIの `runtime` に `capabilities`（`sql`・`crypto`・`password`）を指定し、`sql`を使う場合は `sqlFiles` に許可SQLファイルを列挙します。`settings` は `nyanRuntimeSettings` から取得できます。例えば `"runtime":{"capabilities":["crypto","password"],"settings":{}}` です。外部HTTP、HostExec、汎用ファイル操作、nyanCallMeは利用できません。各script・前後チェックの開始から15秒の期限を設け、JavaScript本体と戻り値変換中のgetterを監視します。同じ期限をSQLの接続取得・実行にも渡します。SQLを使わないscriptはDB接続を確保しません。期限切れや戻り値変換の例外では、その実行の未コミットSQLをロールバックします。これは各段階の期限であり、複数のチェックと本体を含むHTTP要求全体が15秒で完了する保証ではありません。同期ファイル読み込み、暗号計算、DBドライバ内のキャンセル不能な処理は、処理が戻るまで待つ場合があります。通常API全体を隔離する設定ではありません。

<a id="oauth-runtime-capabilities"></a>

#### OAuth用VMのcapabilitiesと利用可能な関数

この表は、OAuthの役割として実行されるscript・`paramCheck`・`outCheck` に適用します。設定場所は参照先の通常API定義の `runtime` です。MCPサーバー定義そのものや `config.json` に設定するものではありません。同じAPIを通常APIとして実行する経路に、OAuth用VMの機能制限を自動適用する設定でもありません。

| capability | 許可される関数 |
|---|---|
| `sql` | `nyanRunSQL`。実行できるSQLファイルは `runtime.sqlFiles` の許可リストに限定します。 |
| `crypto` | `nyanCrypto.randomBase64URL`・`nyanCrypto.sha256Base64URL`・`nyanCrypto.sha256Hex`・`nyanCrypto.timingSafeEqual`、`nyanRandomBase64URL`、`nyanSHA256Base64URL`、`sha256`、`nyanBase64Encode`、`nyanBase64Decode`。 |
| `password` | `nyanPassword.hash`・`nyanPassword.verify`、`nyanArgon2idHash`、`nyanArgon2idVerify`。下記のVM受付枠も適用します。 |

未許可の機能は対応するグローバル関数・オブジェクトが `undefined` になります。`capabilities` を未指定または空配列にすると、上の3群はいずれも利用できません。`sha1` は `crypto` を付けてもOAuth用VMでは常に `undefined` です。`nyanGetAPI`・`nyanJsonAPI`・`nyanCallAPI`・`nyanCallMe`・`nyanHostExec`・`nyanGetFile`・`nyanSaveFile`・`nyanWriteTextFile`・`nyanWriteBase64File` も、capabilityの組合せによらず利用できません。

未知のcapability名や同じ名前の重複は設定エラーです。`sql` を指定する場合は空でない `sqlFiles` が必要で、`sql` なしで空でない `sqlFiles` を指定することも設定エラーです。許可SQLファイルのパスは、API定義を書いたJSONファイルの場所を基準に解決します。空のパスや、絶対パスへ正規化した結果が重複する指定も設定エラーです。

<a id="oauth-execution-limits"></a>

#### OAuthの受付制限と実行枠

以下はNyanQLの1プロセス内の制限です。HTTPの受付枠、VMの実行枠、Argon2の計算枠は独立しており、後段の枠が空いていても前段で拒否される場合があります。表の `L` はMCP定義の `maxConcurrent` の実効値で、未指定・0なら16です。

| 対象 | 枠の共有範囲 | 上限 | 満杯の場合 |
|---|---|---|---|
| Streamable HTTPのMCP要求 | MCPサーバー名ごと | `L` | 待機せずHTTP 503 `server is busy`、`Retry-After: 1`。 |
| OAuth `adminUser` のHTTP要求 | MCPサーバー名＋役割ごと | `min(L, 1)` | 待機せずHTTP 503 `OAuth endpoint is busy`、`Retry-After: 1`。 |
| OAuth `authorize` のHTTP要求 | MCPサーバー名＋役割ごと | `min(L, 2)` | 待機せずHTTP 503 `OAuth endpoint is busy`、`Retry-After: 1`。 |
| OAuth `token`・`register`・両メタデータのHTTP要求 | MCPサーバー名＋役割ごと | 各役割に `L` | 待機せずHTTP 503 `OAuth endpoint is busy`、`Retry-After: 1`。 |
| `password` を許可したOAuth用VM | MCP名・API名・役割によらずプロセス全体 | 同時1実行 | スクリプト開始前に `restricted JavaScript runtime is busy` エラー。待機しません。 |
| Argon2の生成・検証計算 | 通常API・OAuth用VM・関数名によらずプロセス全体 | 合計同時2計算 | 入力検査を通った計算は、枠が空くまで待機します。 |

HTTPのMCP枠とOAuth各役割の枠は別々です。`verifyAccess` は独立したHTTP受付ではなく、MCPの `tools/call` の処理中に呼ばれるため、そのMCP要求の枠を使います。`OPTIONS` は上記の受付枠を使いません。MCP/OAuthのHTTP要求では、レート制限→同時実行枠→本文読み取り・処理の順に進みます。OAuthのレート制限は既述の既定値と `rateLimit` を併用し、HTTP 429を返す条件であり、同時実行枠のHTTP 503とは別です。

レート制限は、MCPではサーバー名、OAuthではサーバー名＋役割を基準に、直接接続している送信元IPごとに数えます。送信元IPは `RemoteAddr` のポートを除いた値で、`X-Forwarded-For` からは取得しません。同時実行枠は送信元IPごとには分かれず、そのサーバー名・役割の要求全体で共有します。HTTP同時実行枠は実効上限値ごとにも分かれるため、ホットリロードで上限値を変更した場合、進行中の要求は元の枠を保持し、新しい要求は新上限の枠を使います。進行中の要求を中断して新上限以下へ減らす処理は行いません。

OAuthの `paramCheck`・本体script・`outCheck` は、それぞれ別のVM実行です。`password` が許可されていれば、その段階で実際にパスワード関数を呼ぶかどうかにかかわらず、開始時に同時1件の枠を取得し、段階の終了時に解放します。次の段階が始まるまで同じ要求が枠を予約し続けるわけではありません。`password` を許可していないVMと、通常APIとしての実行にはこのVM受付枠は適用しません。

VM受付で拒否された場合、既定ではOAuthのHTTP hookはHTTP 500 `OAuth hook failed` を返します。MCPの `verifyAccess` の実行中に拒否された場合は認証判定失敗となり、`tools/call` はHTTP 401と `WWW-Authenticate` の `invalid_token` を返します。`config.json` の `oauthRuntime.busyResponse` を `"serviceUnavailable"` にすると、このVM受付の混雑をHTTP 503として区別できます。詳細は [混雑応答の設定](#oauth-runtime-busy-response) を参照してください。VMの1件・Argon2の2件は固定値で、`maxConcurrent` や `busyResponse` を変更しても件数は変わりません。

Argon2の計算枠待ちと計算自体は同期処理です。OAuth用VMの15秒の期限を過ぎても、枠待ちや計算が終わるまで制御が戻らない場合があります。15秒で計算や待機を必ず打ち切る仕様ではありません。

<a id="oauth-runtime-busy-response"></a>

#### OAuth用VMの混雑応答を設定する

`config.json` のトップレベルに次の設定を追加すると、Go側のOAuth用VM受付枠が満杯の場合にHTTP 503を返します。全MCPサーバーのOAuth経路で共通です。`api.json` の `oauth` や各APIの `runtime` に指定する項目ではありません。

```json
"oauthRuntime": {
  "busyResponse": "serviceUnavailable"
}
```

| `busyResponse` の指定 | 動作 |
|---|---|
| 未指定・`null`・`"legacy"` | 従来どおり、OAuth HTTP hookは500、MCP `verifyAccess` は401・`invalid_token`。既存の応答本文・認証要求ヘッダーも維持します。 |
| `"serviceUnavailable"` | Goの専用VM混雑エラーに限り、両経路とも503に変更します。 |
| 上記以外の文字列（空文字列・大文字小文字違い・前後空白を含む値も含む）、数値・真偽値・配列・オブジェクト | 設定エラーで起動しません。 |

`oauthRuntime` 自体が未指定・`null`・`{}` の場合も従来の動作です。サンプルの `config.json` は `"legacy"` を明記しています。設定変更の反映にはサービスの再起動が必要で、`APIHotReload` の対象ではありません。

503モードのOAuth HTTP hookは、本文 `OAuth runtime is busy`（末尾改行付き）のテキスト応答になります。MCPの `tools/call` は要求IDを保持したJSON-RPC応答で、`result.isError: true` と同じ文言のテキストcontentを返します。この混雑応答には `WWW-Authenticate` ヘッダーと `mcp/www_authenticate` メタデータを付けません。`verifyAccess` を完了できなかった場合はToolの入力チェック・本体を実行しません。

`Retry-After` は次の条件で扱います。ここでの「実行済み」は、同じOAuth hookの呼び出し内で前のJavaScript段階が正常終了したことを指します。共通JSもその段階の実行に含みます。

| 混雑した位置 | 503モードの `Retry-After` |
|---|---|
| 最初の `paramCheck`（旧名 `check`）のVM受付 | `1` |
| 入力チェックがない場合の本体scriptのVM受付 | `1` |
| 入力チェックがないメタデータ経路の `outCheck` のVM受付（メタデータ本体はGoで生成） | `1` |
| 入力チェックの正常終了後、本体scriptのVM受付 | 付けない |
| 本体scriptまたは入力チェックの正常終了後、`outCheck` のVM受付 | 付けない |

`Retry-After: 1` は再試行までの待ち時間の目安（秒）であり、1秒後の受付成功を保証しません。許可されたOriginへの応答では、ブラウザーからこのヘッダーを読めるよう公開します。`nyan_mode=checkOnly` でも、その経路で実行する入力チェックのVM受付に同じ規則を適用します。MCPの `verifyAccess` は常に通常の認証処理として実行します。

後段のVM受付で混雑した時点では、前段のSQL更新などがすでにコミットされている場合があります。503は「要求全体が未実行」や「前段をロールバックした」という意味ではありません。NyanQLはこの設定による自動再試行を行いません。利用側もPOST等を無条件に再実行せず、重複実行の影響を確認してください。

この設定は、Goの `password` capability用VM受付が返す専用エラーだけを対象とします。同じ文言をJavaScript例外として投げても混雑には分類しません。JavaScriptが返した認証・認可の判断、チェック拒否、独自のHTTP 503・ヘッダー、一般のスクリプト例外の扱いは維持します。HTTP受付枠の既存503・`Retry-After: 1`、レート制限の429、Argon2計算枠の待機、通常APIとしての実行にも変更はありません。

## JSON-RPC

NyanQLは、通常のHTTP APIに加えて、JSON-RPC 2.0形式でも呼び出せます。

エンドポイントは次のとおりです。

```text
/nyan-rpc
```

呼び出し例です。

```bash
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getItem",
    "params": { "id": 1 },
    "id": 1
  }' \
  "http://localhost:8080/nyan-rpc"
```

`method` が、`api.json` のAPI名として扱われます。`params.api` が指定されていても実行先は変更せず、`nyanAllParams.api` は `method` の完全API名になります。API名は `method` に指定してください。存在しない `method` を `params.api` で補うこともできません。送信された元のJSONは `nyanRequest.json` に保持します。

本体スクリプトの結果はJSONオブジェクトとして返してください。配列を直接返すとJSON-RPCエラーになります。配列データは `({items: [1, 2, 3]})` のようにオブジェクトの項目へ格納します。JSONオブジェクトを表す文字列を返す形式も使用できます。

現在の実装では、JSON-RPCの一括リクエスト、つまりbatch形式には対応していません。

---

<a id="deployment"></a>
## セキュリティ上の注意

NyanQLは信頼できる管理者が用意したSQL・JavaScriptを、サービス実行ユーザーの権限で実行します。config、include先を含むAPI定義、共通JSとその配置先も、信頼できる管理者だけが書き換えられるようにしてください。

通常HTTPは全インターフェースで待ち受けます。localhostへのアクセス例は、他の端末からの到達を制限する設定ではありません。OSのファイアウォール等で到達元を制限し、公開する入口を選んでください。

通常API・JSON-RPCのBasic認証、publicのparamCheck、WebSocketの接続前チェック、MCPのOAuthは別々の保護です。MCP Toolの参照先は通常APIとしても存在するため、MCPだけの設定で全経路が保護されるわけではありません。publicとWS購読には通常APIのBasic認証を適用しないため、必要な認証をparamCheckで行います。CORSやOrigin制限は利用者認証の代わりにはなりません。

MCP/OAuthの公開URLは実際のリクエストのTLS接続とHostから生成し、X-Forwarded-Proto等で自動補正しません。直接TLSで受けるか、proxyからNyanQLまでもTLSを使い公開Hostを保つなど、発行されるissuer/resource URLが公開URLと一致する構成を確認してください。

DB接続の暗号化はHTTPのHTTPS設定とは別です。現在のPostgreSQL接続は `sslmode=disable`、MySQLの接続文字列もTLSを指定しません。別ホストのDBへ接続する場合は、信頼できる隔離された通信経路を用意し、DBユーザーへ必要な権限だけを与えてください。SQLite/DuckDBのファイルとバックアップも公開フォルダから分離します。

- Basic認証のユーザ名とパスワードは、公開環境では必ず変更してください。
- `nyanHostExec` はOSコマンドを実行できるため、外部入力をそのまま渡さないでください。
- CORSは現在 `*` を許可する実装です。公開環境で使う場合は、必要に応じて実装や配置で制御してください。
- HTTPSを使う場合は、`CertPath` と `KeyPath` を指定してください。
- SQLファイルやscriptファイルは、信頼できる人だけが編集できる場所に置いてください。

---

## 予約語

`mcp_principal` と `nyan_guard` はサーバー側の認証・認可コンテキスト用です。通常HTTP・public・JSON-RPC・WebSocket接続前チェックでは、外部パラメータの同名キーを除去します。WebSocketのAPI実行メッセージでは拒否し、MCPでは入力スキーマ検証後に除去して検証済みの情報を設定します。`nyanRequest` の元リクエスト情報には外部入力が記録されますが、その内容を認証済みのprincipalとして信頼しないでください。サーバー内部で設定した引数まで一律に除去するものではありません。

リクエストパラメータ名として、次の名前は避けてください。

- `api`
- `nyan` で始まる名前

`api` は、呼び出すAPI名を指定するために使います。`nyanAllParams` や `nyan_mode` など、`nyan` で始まる名前はNyanQL側の制御用として使われます。

<a id="mcp-api-names"></a>

### MCP/OAuthのAPI名の制約

ここで扱うのはリクエストパラメータ名ではなく、`api.json` のAPI名です。検証対象は、`type: "mcp"` の完全API名（stdio用も含む）と、`oauth` の各役割が参照する完全API名です。任意の通常APIすべてに、同じ名前検査を行うという意味ではありません。

| 条件 | 扱い |
|---|---|
| 名前が空、または前後に空白を含む | 不可。OAuth参照値は前後の空白を除去してから検証します。 |
| 先頭・末尾の `/`、途中の `//`、単独のパス要素 `.`・`..` | 不可。名前は `sub/local_mcp` のように指定します。 |
| `\`・`?`・`#`・改行・タブ、URLパスとしてエスケープが必要な文字 | 不可。空白・日本語・`%` などを含む名前もこの検証で拒否します。 |
| 完全API名が `nyan`・`nyan-rpc`・`favicon.ico` | `/nyan`・`/nyan-rpc`・`/favicon.ico` に対応する予約パスなので不可。 |

条件に違反すると、起動時には設定エラー、ホットリロード時には候補設定の不採用となります。`oauth` の各役割には、存在する `type: "api"` の定義を指定する必要があり、1つのMCP定義内で複数の役割に同じAPI名を使うこともできません。これらの名前検査と、組込みHTTPルート（`/nyan/` 配下など）へのリクエストの振り分けは別の処理です。組込みルートをMCP/OAuthの接続先として上書きする設定にはなりません。

---

## 関連プロジェクト

NyanQLは、Nyanシリーズの1つです。

- NyanQL（にゃんくる）：SQLを中心に、データベースアクセスAPIを作る軽量フレームワーク
- Nyan8（にゃんぱち）：JavaScriptでAPI処理を書くためのサーバ
- NyanPUI（にゃんぷい）：HTMLや画面まわりを扱うための仕組み

NyanQLは、DBアクセスに集中します。画面や複雑なアプリケーション構成が必要な場合は、NyanPUIやNyan8と組み合わせると使いやすくなります。

---

## 開発状況

NyanQLは開発中のソフトウェアです。ただし、SQL実行、2way-SQL、JavaScriptによる処理、トランザクション、WebSocket Pushなど、主要な機能は実装されています。

仕様や設定項目は、今後変わる可能性があります。利用時は、このREADMEと実際の `api.json`、`config.json`、サンプルSQLをあわせて確認してください。

---

## ライセンス

NyanQLはMITライセンスで公開されています。
