# NyanQL

NyanQL（にゃんくる）は、SQL を実行して JSON を返す API サービスです。

内部に保存された SQL ファイルや JavaScript ファイルを API 設定により選択し、実行結果を JSON 形式で返します。さらに、Push 機能を利用すると、ある API の実行結果を WebSocket 経由で別のクライアントに自動配信できます。

NyanQL には以下の機能があります：

- **SQL 実行**：動的パラメータ置換、条件分岐ブロック対応
- **JavaScript スクリプト実行**（`script`）：自由に JSON を生成
- **リクエスト検証**（`check`）：入力パラメータの事前検証
- **WebSocket Push**：別 API へのリアルタイム配信

関連プロジェクト：

- **Nyan8**（にゃんぱち）：JavaScript 実行で JSON 生成
- **NyanPUI**（にゃんぷい）：HTML 生成

---

## 目次

1. [対応データベース](#対応データベース)
2. [インストールと実行](#インストールと実行)
3. [設定ファイル](#設定ファイル)
    - [config.json](#configjson)
    - [api.json](#apijson)
4. [SQL テンプレート構文](#sql-テンプレート構文)
    - [パラメータ置換](#パラメータ置換)
    - [条件分岐ブロック](#条件分岐ブロック)
5. [JavaScript Script / Check](#javascript-script--check)
6. [ファイル操作ユーティリティ](#ファイル操作ユーティリティ)
7. [サーバ情報取得エンドポイント](#サーバ情報取得エンドポイント)
8. [レスポンス形式](#レスポンス形式)
9. [アクセス方法](#アクセス方法)
10. [JSON-RPC サポート](#json-rpc-サポート)
11. [トランザクション](#トランザクション)
12. [予約語](#予約語)

---

## 対応データベース

- MySQL
- PostgreSQL
- SQLite
- DuckDB

---

## インストールと実行

1. GitHub Releases からホスト OS に合わせた ZIP をダウンロード
2. `config.json` と `api.json` を編集
3. ターミナル または ダブルクリックで実行

> リリース: https://github.com/NyanQL/NyanQL/releases

---

## 設定ファイル

### config.json

NyanQL サーバの全体設定を記述します。

```json
{
  "name": "API サーバ名",
  "profile": "サーバの概要説明",
  "version": "v1.0.0",
  "Port": 8080,
  "CertPath": "./cert.pem",
  "KeyPath": "./key.pem",
  "DBType": "postgres",
  "DBUser": "user",
  "DBPassword": "pass",
  "DBName": "dbname",
  "DBHost": "localhost",
  "DBPort": "5432",
  "MaxOpenConnections": 10,
  "MaxIdleConnections": 5,
  "ConnMaxLifetimeSeconds": 300,
  "BasicAuth": {
    "Username": "admin",
    "Password": "secret"
  },
  "log": {
    "Filename": "./logs/nyanql.log",
    "MaxSize": 5,
    "MaxBackups": 3,
    "MaxAge": 7,
    "Compress": true,
    "EnableLogging": true
  },
  "javascript_include": [
    "./javascript/lib/nyanRequestCheck.js",
    "./javascript/common.js"
  ]
}
```

- **Port**: HTTP/HTTPS ポート
- **CertPath/KeyPath**: SSL 証明書（HTTPS 有効化）
- **DBType**: `mysql` | `postgres` | `sqlite` | `duckdb`
- **接続プール**: `MaxOpenConnections` / `MaxIdleConnections` / `ConnMaxLifetimeSeconds`
- **BasicAuth**: ベーシック認証の設定
- **javascript_include**: `check` や `script` 実行前に読み込む JS

<details>
<summary>ログ設定項目の説明</summary>

* **Filename** – 出力先ファイルパス
* **MaxSize** – 1 ファイルの上限サイズ（MB）
* **MaxBackups** – 保持世代数
* **MaxAge** – 保持日数
* **Compress** – 過去ファイルを gzip 圧縮
* **EnableLogging** – false で標準出力のみ

</details>

---

### api.json

各 API エンドポイントごとに実行する SQL/スクリプトを定義します。

```json
{
  "list": {
    "sql": ["./sql/sqlite/list.sql"],
    "description": "当月の一覧を表示します。"
  },
  "check": {
    "check": "./javascript/check.js",
    "sql": ["./sql/sqlite/checkDay.sql"],
    "description": "パラメータ検証と検索を同時に行います。"
  },
  "stamp": {
    "sql": ["./sql/sqlite/insert_stamp.sql"],
    "description": "本日のスタンプを記録します。",
    "push": "list"
  }
}
```

---

## トランザクション

NyanQL は、1つの API 呼び出しの中で複数の SQL を実行する場合、**それらを1つのトランザクションとしてまとめて実行**します。  
これにより、途中でエラーが発生した場合は **それまでの変更がすべてロールバック**され、データの整合性を保てます。

注:
- 1SQL でも「必ずトランザクションにしたい」場合は、`script` を使うか、SQL を分割して複数指定してください。
- `check` はトランザクション開始前に実行されます。`check` が失敗した場合、SQL / script は実行されません。
- 「失敗」とは、`nyanRunSQL()` の実行エラー、またはスクリプト実行時の例外（panic）など、Go 側でエラーとして扱われる状態を指します。

### SQL 配列（api.json の `sql`）のトランザクション

`api.json` の `sql` が **2ファイル以上**指定されている場合、NyanQL は実行開始時に DB トランザクションを開始します。

- **開始**: API 実行の先頭で `BEGIN`
- **実行**: 配列に並んだ SQL を上から順に同一トランザクション内で実行
- **成功**: 全て成功したら `COMMIT`
- **失敗**: Go 側でエラーとして扱われた場合は `ROLLBACK`（以降の SQL は実行されません）

※ `sql` が **1ファイルのみ**の場合は、通常はトランザクションを開始しません（DB の自動コミット動作になります）。

### script（JavaScript）実行時のトランザクション

`api.json` で `script` が指定されている場合、NyanQL はスクリプト実行の先頭でトランザクションを開始し、  
VM に `nyanTx` として渡します。スクリプト内で `nyanRunSQL()` を複数回呼んでも **同一トランザクション内**で実行されます。

- **開始**: `script` 実行開始時に `BEGIN`
- **実行**: `nyanRunSQL()` は `nyanTx` を使って Query/Exec
- **成功**: スクリプトが最後まで成功したら `COMMIT`
- **失敗**: Go 側でエラーとして扱われた場合は `ROLLBACK`

### JSON-RPC のトランザクション

JSON-RPC（`/nyan-rpc`）でも HTTP と同様に、`sql` が複数指定されている場合はトランザクションでまとめて実行されます。

---

## SQL テンプレート構文

### パラメータ置換 

```sql
SELECT count(id) AS this_days_count
FROM stamps
WHERE date = /*date*/'2025-02-15';
```

リクエスト `?date=2024-02-15` で動的に置換されます。

### 条件分岐ブロック

```sql
SELECT id, date FROM stamps
/*BEGIN*/
 WHERE
   /*IF id != null*/ id = /*id*/1 /*END*/
   /*IF date != null*/ AND date = /*date*/'2024-06-25' /*END*/
/*END*/;
```

条件に応じて WHERE 部分が自動展開されます。

---

## JavaScript Script / Check

- **check**: 入力検証用の JS。失敗時に `{ success:false, status:400, error:{ message: ... }}` を返す。
- **script**: 自由に JSON を生成。`nyanRunSQL` や `nyanAllParams` が利用可能。
- **nyan_mode=checkOnly**: HTTP リクエストまたは JSON-RPC で `nyan_mode=checkOnly` パラメータを指定すると、`check` スクリプトのみを実行し、その結果を返します。`script` や SQL の実行は行われません。

---

## ファイル操作ユーティリティ

### `nyanBase64Encode(data: string): string`
文字列を Base64 エンコードして返します。

### `nyanBase64Decode(b64: string): string`
Base64 をデコードして元の文字列を返します。

### `nyanSaveFile(b64: string, destPath: string)`
エンコード済み Base64 をデコードし、`destPath` にファイル保存します。

```js
const raw = "こんにちは！ にゃんくる";
const b64 = nyanBase64Encode(raw);
nyanSaveFile(b64, "./storage/hello.txt");
```

---

## サーバ情報取得エンドポイント

### `GET /nyan`
サーバの基本情報と利用可能な API 一覧を取得します。

**レスポンス例**
```json
{
  "name": "API サーバ名",
  "profile": "サーバの概要説明",
  "version": "v1.0.0",
  "apis": {
    "list": { "description": "当月の一覧を表示します。" },
    "stamp": { "description": "本日のスタンプを記録します。" }
  }
}
```

### `GET /nyan/{API名}`
指定した API の詳細情報（説明、受け入れ可能パラメータ、出力カラム）を取得します。

**レスポンス例**
```json
{
  "api": "list",
  "description": "当月の一覧を表示します。",
  "nyanAcceptedParams": { "date": "2024-06-25" },
  "nyanOutputColumns": ["id", "date"]
}
```

---

## レスポンス形式

### 成功時

```json
{
  "success": true,
  "status": 200,
  "result": [...]
}
```

### エラー時

```json
{
  "success": false,
  "status": 500,
  "error": { "message": "..." }
}
```

---

## アクセス方法

- HTTP: `http://localhost:{Port}/?api=API名`
- HTTPS: `https://localhost:{Port}/?api=API名`
- エンドポイント形式: `/API名` も同様

---

## JSON-RPC サポート

- エンドポイント: `/nyan-rpc`
- JSON-RPC 2.0 準拠(batchは未実装)

---

## 予約語

`api`、`nyan` から始まる名前は予約語です。パラメータに使用しないでください。

