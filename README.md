# NyanQL（にゃんくる）

NyanQL（にゃんくる）は、SQLを書くだけで、データベースにアクセスするAPIサービスを手軽に作るための軽量フレームワークです。

「猫の手も借りたい」くらい忙しい業務システム開発で、APIサーバ作りの手間を小さくし、まずは大事なSQLに集中できるようにすることを目指しています。

NyanQLでは、APIを呼び出すと、`api.json` に紐づけられたSQLファイル、またはJavaScriptファイルが実行されます。SQLの実行結果はJSONで返ります。検索だけでなく、登録・更新・削除、複数SQLのトランザクション、JavaScriptによる複雑な処理、WebSocketによるPush配信にも対応しています。

---

## NyanQLでできること

NyanQLは、主に次のような用途に向いています。

- SQLを中心にして、データベース用のAPIをすばやく作る
- SELECTの結果をJSONとして返すAPIを作る
- INSERT、UPDATE、DELETEなどの更新処理をAPI化する
- 複数のSQLを1つのトランザクションとしてまとめて実行する
- JavaScriptで、SQLだけでは書きにくい一連の処理をまとめる
- WebSocketを使って、API実行後の結果を別の画面へPush配信する
- `/nyan` で、利用できるAPIの情報を取得する

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

ソースからビルドする場合は、Goの開発環境を用意してからビルドしてください。

```bash
git clone https://github.com/NyanQL/NyanQL.git
cd NyanQL
go build -o nyanql
```

### 2. 設定ファイルを用意する

少なくとも次の2つのファイルを用意します。

- `config.json`
- `api.json`

SQLファイルやJavaScriptファイルも、`api.json` から参照できる場所に置いてください。

デフォルトでは、NyanQLは実行ファイルと同じ場所にある `config.json` と `api.json` を読み込みます。別の場所に置きたい場合は、起動時オプションまたは環境変数で指定できます。

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
  "log": {
    "Filename": "./logs/nyanql.log",
    "MaxSize": 5,
    "MaxBackups": 3,
    "MaxAge": 7,
    "Compress": true,
    "EnableLogging": true
  },
  "javascript_include": [
    "./javascript/common.js"
  ]
}
```

主な項目は次のとおりです。

| 項目 | 説明 |
|---|---|
| `name` | `/nyan` で返すサーバ名です。 |
| `profile` | `/nyan` で返すサーバ説明です。 |
| `version` | `/nyan` で返す設定上のバージョンです。 |
| `Port` | NyanQLが待ち受けるポート番号です。 |
| `CertPath`, `KeyPath` | 両方を指定するとHTTPSで起動します。空ならHTTPで起動します。 |
| `DBType` | `mysql`、`postgres`、`sqlite`、`duckdb` のいずれかを指定します。 |
| `DBName` | データベース名、またはSQLite/DuckDBのファイルパスです。 |
| `BasicAuth` | API呼び出し時のBasic認証ユーザ名とパスワードです。 |
| `javascript_include` | `check` や `script` の実行前に読み込む共通JavaScriptです。 |

`config.json` 内の相対パスは、`config.json` がある場所を基準にして扱われます。対象は `CertPath`、`KeyPath`、SQLite/DuckDB の `DBName`、`log.Filename`、`javascript_include` です。

---

## api.json

`api.json` には、API名と、実行するSQLまたはJavaScriptの対応を書きます。

`api.json` 内の相対パスは、`api.json` がある場所を基準にして扱われます。対象は `sql`、`script`、`paramCheck`、`outCheck`、public API の `path` です。

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

`type: "public"` はBasic認証を通さずに配信します。認証や認可が必要なファイル公開では、`paramCheck` を指定してください。`paramCheck` と `outCheck` では、公開エンドポイント名とリクエストされた相対パスを参照できます。

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

URLのパスにAPI名を書いた場合、NyanQLはそのパスをAPI名として扱います。たとえば `/getItem?id=1` は、`api=getItem` として扱われます。

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

### JSONパラメータ

リクエスト値がオブジェクトの場合、NyanQLはJSON文字列に変換して、SQLの1つの値として渡します。PostgreSQLのJSONB列などへ渡すときに使えます。

---

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

`AND` と `OR` を使った条件判定にも対応しています。ただし、複雑な式を自由に評価するものではありません。基本は「値があるか、ないか」を見てSQLの一部を出し分ける機能として使うのが安全です。

---

## `/nyan` でAPI情報を見る

NyanQLでは、APIの一覧や、各APIが受け取るパラメータ情報を確認できます。

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
    }
  }
}
```

### APIごとの詳細を見る

```bash
curl -u admin:secret "http://localhost:8080/nyan/getItem"
```

返り値の例です。

```json
{
  "api": "getItem",
  "description": "商品を1件取得します",
  "nyanAcceptedParams": {
    "id": 1
  },
  "nyanOutputColumns": []
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

const nyanOutputColumns = ["order_id", "order_no"];
```

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

### checkだけを実行する

`nyan_mode=checkOnly` を指定すると、`paramCheck` だけを実行できます。`check` で指定した古い設定も、`paramCheck` として同じように実行されます。

```bash
curl -u admin:secret "http://localhost:8080/getItem?id=1&nyan_mode=checkOnly"
```

入力フォームの事前チェックなどに使えます。

### 出力前チェック：outCheck

`outCheck` を指定すると、SQLやscriptの実行後、または `type: "public"` のファイル送信前にJavaScriptを実行できます。`success: true` かつ `status: 200` の場合だけ本体の実行結果をそのまま返し、それ以外は `outCheck` の結果をJSONとして返します。

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

`script` の実行中は、NyanQLがトランザクションを開始します。`nyanRunSQL()` で実行したSQLは、同じトランザクションの中で処理されます。途中でエラーが起きた場合はロールバックされます。

---

## JavaScriptで使える主な変数と関数

`check` と `script` の中では、次の変数や関数を使えます。

| 名前 | 説明 |
|---|---|
| `nyanAllParams` | リクエストで受け取ったパラメータ全体です。 |
| `nyanAcceptedParamsKeys` | SQLコメントから拾った受け付けパラメータ名です。主にcheckで使います。 |
| `nyanRunSQL(path, params)` | SQLファイルを実行します。scriptでは同じトランザクション内で実行されます。 |
| `nyanGetAPI(url, user, pass)` | 外部APIへGETリクエストを送ります。 |
| `nyanJsonAPI(url, jsonText, user, pass, headers)` | 外部APIへJSONをPOSTします。 |
| `nyanCallAPI(...)` | `nyanJsonAPI` と同じ動きをする別名です。 |
| `nyanCallMe(params)` | `api.json` に定義した別のAPIを内部呼び出しします。 |
| `nyanGetFile(path)` | 実行ファイルの場所を基準にファイルを読みます。存在しない場合は `null` を返します。 |
| `nyanBase64Encode(text)` | 文字列をBase64に変換します。 |
| `nyanBase64Decode(base64)` | Base64を文字列に戻します。 |
| `nyanSaveFile(base64, path)` | Base64文字列をデコードしてファイルに保存します。 |
| `sha256(text)` | SHA-256のハッシュ文字列を返します。 |
| `sha1(text)` | SHA-1のハッシュ文字列を返します。 |
| `nyanHostExec(command)` | OSのコマンドを実行します。利用する場合は十分に注意してください。 |

`nyanHostExec` は、サーバ上でOSコマンドを実行できる強い機能です。公開環境や、外部から入力を受ける処理では、安易に使わないでください。

---

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

現在の実装では、`sql` が1つだけの場合は明示的なトランザクションを開始しません。データベース側の通常の自動コミット動作になります。

---

## scriptでのトランザクション

`script` を使うAPIでは、NyanQLがscript実行の開始時にトランザクションを開始します。

script内で `nyanRunSQL()` を何度呼んでも、同じトランザクションの中で実行されます。scriptが最後まで正常に終わるとコミットされます。scriptの実行でエラーが起きた場合はロールバックされます。

複雑な登録処理をひとまとまりにしたい場合は、複数SQLの配列よりも `script` が向いています。

---

## WebSocketによるPush配信

NyanQLには、APIの実行後に別APIの結果をWebSocketへ配信するPush機能があります。

たとえば、画面Aで「登録API」を呼び出した後、画面Bに「一覧API」の最新結果を送る、という使い方ができます。

### Pushの基本

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

NyanQLのWebSocketサーバでは、URLパスの末尾がチャネル名になります。上の例では、`listItems` がチャネル名です。

### Pushで配信される内容

`push` の参照先がSQL APIの場合、NyanQLはそのSQLを実行し、次のような形に包んで配信します。

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

この設定を書くと、NyanQLは起動時に `connectURL` へ接続します。接続が切れた場合は、時間をあけながら再接続を試みます。

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

scriptが空文字を返した場合、接続先へ返信しません。空でない文字列を返した場合、その文字列をWebSocketのテキストメッセージとして接続先へ送信します。

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

この場合、起動時に `NYANQL_WS_URL` の値を接続先として使います。

---

## 定期実行ジョブ

`api.json` で `type: "schedule"` を指定すると、NyanQLの起動時に定期実行ジョブとして登録されます。

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

`javascript_include` に設定した共通JavaScriptは、scheduleのscript実行時にも毎回読み込まれます。

---

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

`method` が、`api.json` のAPI名として扱われます。

現在の実装では、JSON-RPCの一括リクエスト、つまりbatch形式には対応していません。

---

## セキュリティ上の注意

NyanQLは、SQLやJavaScriptを使って強力なAPIを手軽に作れます。そのぶん、設定や公開範囲には注意が必要です。

- Basic認証のユーザ名とパスワードは、公開環境では必ず変更してください。
- `nyanHostExec` はOSコマンドを実行できるため、外部入力をそのまま渡さないでください。
- CORSは現在 `*` を許可する実装です。公開環境で使う場合は、必要に応じて実装や配置で制御してください。
- HTTPSを使う場合は、`CertPath` と `KeyPath` を指定してください。
- SQLファイルやscriptファイルは、信頼できる人だけが編集できる場所に置いてください。

---

## 予約語

リクエストパラメータ名として、次の名前は避けてください。

- `api`
- `nyan` で始まる名前

`api` は、呼び出すAPI名を指定するために使います。`nyanAllParams` や `nyan_mode` など、`nyan` で始まる名前はNyanQL側の制御用として使われます。

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
