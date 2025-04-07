# NyanQL

NyanQL（にゃんくる）は、SQL を実行して JSON を返す API サービスです。

内部に保存している SQL ファイルや JavaScript ファイルを API 設定により選択し、実行結果を JSON 形式で返します。
また、push 機能を利用することで、ある API の実行結果を WebSocket 経由で別の API クライアントに自動配信することも可能です。
NyanQL には、SQL 実行の他、JavaScript を実行して JSON を生成する機能（script）や、リクエストパラメータの検証用のチェック機能（check）もあります。

NyanQLには、NyanQL(にゃんくる)以外にも、
JavaScriptを実行してJSONを生成するNyan8（にゃんぱち）と、
HTMLを生成するNyanPUI（にゃんぷい）があります。

# 対応データベース
次のデータベースでの利用が可能です。

* MySQL 
* PostgreSQL
* SQLite
* DuckDB

# アプリケーションの実行方法
config.jsonとapi.jsonを編集してください。
クリックまたはターミナルから起動して実行できます。
HostとなるOSに合わせたzipファイルをダウンロードしご利用ください。
https://github.com/NyanQL/NyanQL/releases

# 設定ファイル
APIサーバの設定としてのconfig.jsonとそれぞれのAPIに対する設定となるapi.jsonがあります。
これらを設定し、起動してください。


## 設定ファイル: config.json

`config.json` に NyanQL の設定を記述します。各項目の説明は下記の通りです。
SSL 証明書を指定すると https でアクセス可能になります。
また、javascript_includeで指定したファイルは各APIのcheckもしくはscriptで指定されたjsファイルの前に読み込まれます。
Port:では起動するサーバのport番号を指定してください。

```json
{
  "name": "このAPIサーバの名前",
  "profile": "このAPIサーバの自己紹介",
  "version": "このAPIサーバのバージョン",
  "Port": "ポート番号を数値で記載",
  "CertPath": "SSL証明書のパス",
  "KeyPath": "SSL証明書のキーのパス",
  "DBType": "データベースのタイプ（mysql、postgres、sqliteが使用可能）",
  "DBUser": "DB接続ユーザー",
  "DBPassword": "DB接続パスワード",
  "DBName": "DB名（sqliteの場合はファイルへの相対パス）",
  "DBHost": "DBホスト名",
  "DBPort": "DBに接続するポート番号",
  "MaxOpenConnections": 10,
  "MaxIdleConnections": 5,
  "ConnMaxLifetimeSeconds": 300,
  "BasicAuth": {
    "Username": "ベーシック認証のユーザー名",
    "Password": "ベーシック認証のパスワード"
  },
  "log": {
    "Filename": "./logs/nyanql.log",
    "MaxSize": 5,
    "MaxBackups": 3,
    "MaxAge": 7,
    "Compress": true,
    "EnableLogging": false
  },
  "javascript_include": [
    "./javascript/lib/nyanRequestCheck.js",
    "./javascript/common.js"
  ]
}
```
### DBの指定について
DBType には、使用するデータベースの種類を指定します。
現在サポートされているデータベースは以下の通りです。

* MySQL (mysql)
* PostgreSQL (postgres)
* SQLite (sqlite)
* DuckDB (duckdb)


### DB接続数制御について
NyanQL は、Go言語の database/sql のコネクションプール機能を利用しており、config.json 内の以下の項目で接続数を制御できます。

#### MaxOpenConnections
最大オープン接続数 (アクティブなコネクション数) の上限を指定します。
0 以下を指定した場合は「無制限」となり、必要に応じてコネクションが無制限に作成されます。
実際には無制限に増え続けるとリソースを圧迫する可能性があるため、一般的にはデータベース側やサーバリソースを考慮して適切な上限値を設定することを推奨します。

#### MaxIdleConnections
アイドル（待機）状態として保持できる接続数の上限です。
ここで設定した数を超えると未使用コネクションは破棄されます。0 か省略した場合、Go言語のデフォルトに依存しますが、実質2程度が初期値になります。

#### ConnMaxLifetimeSeconds
コネクションの最大生存期間を秒単位で指定します。
指定した時間を経過すると、そのコネクションは再利用されずにクローズされ、新たに張り直されます。
長時間生きているコネクションによるトラブル（タイムアウトやセッション切れなど）を回避する場合に設定します。

(例)

```json
{
  ...
  "MaxOpenConnections": 10,
  "MaxIdleConnections": 5,
  "ConnMaxLifetimeSeconds": 300,
  ...
}
```

上記設定では、同時にアクティブになる接続は最大10個に制限され、アイドル状態として5個まで保持され、コネクションは300秒（5分）経過すると再生成されます。
もし MaxOpenConnections を 0 にした場合は制限なしになるので、負荷テストなどで必要でない限り、無制限は避けることをおすすめします


### ログ設定について

config.jsonのlogの項目で下記の設定が指定可能です。

* Filename: ログファイルの保存場所を指定します。例: "./logs/nyanql.log"
* MaxSize: ログファイルの最大サイズ（MB単位）。このサイズを超えると新しいログファイルが作成されます。例: 5（5MB）
* MaxBackups: 保持する古いログファイルの最大数。例: 3（最新の3つのログファイルを保持）
* MaxAge: ログファイルを保持する最大日数（日単位）。例: 7（7日間のログファイルを保持し、それを超えると削除）
* Compress: 古いログファイルを圧縮するかどうか。trueに設定すると、古いログファイルがgzip形式で圧縮されます。例: true
* EnableLogging: ログの出力を有効にするかどうか。falseに設定すると、ログは標準出力（コンソール）に出力されます。例: false

## API設定ファイル: api.json

api.json は、各 API エンドポイントごとに実行する SQL ファイルや JavaScript ファイルを定義する設定ファイルです。
エンドポイントは ?api=API名等 パラメータで渡すことも可能です。

### api.json について

```json
{
  "list": {
    "sql": ["./sql/sqlite/list.sql"],
    "description": "当月の一覧を表示します。"
  },
  "check": {
    "sql": ["./sql/sqlite/checkToday.sql"],
    "description": "本日の登録があるか確認します。"
  },
  "stamp": {
    "sql": ["./sql/sqlite/insert_stamp.sql"],
    "description": "本日のスタンプを記録します。",
    "push": "list"
  },
  "target_month_list": {
    "sql": ["./sql/sqlite/target_month_list.sql"],
    "description": "年と月を指定し、一覧を表示します。"
  },
  "check_day": {
    "check": "./javascript/check.js",
    "sql": ["./sql/sqlite/check_day.sql"],
    "description": "日付で検索します"
  }
}

```

#### 各項目について

* API の名前: JSON のキーとして指定します。リクエスト時に ?api=API名 で指定します。これは http(s)://{ドメイン}:{ポート番号}/API名 でもリクエストできます。
* sql: 実行する SQL ファイルのパス（複数指定可能）。複数指定の場合、トランザクション内で順次実行され、最後の SQL の結果が返されます。
  * → sql:が設定されている場合、script:の設定はできません。
* script: JavaScript ファイルのパスを指定すると、そのスクリプトが実行され、JSON を返します。
  * → スクリプト内では成功／失敗の制御や、レスポンスフォーマット（{ success: true, status:200, result: ... }）を自由に定義できます。
  * → script:が指定されている場合、 sql: の指定はできません。
* check: チェック用の JavaScript ファイルのパス。リクエストパラメータの検証や前処理を行い、エラー時はエラーレスポンスを返します。
* push: この API の実行後に、指定した push 対象 API の結果を WebSocket で配信する場合に指定します。
例：stamp API の push に "list" を設定すると、stamp 実行後に list API の結果が push 配信されます。
* description: API の説明。利用者に対して API の目的や使い方を示します。

#### SQLについて
SQLはリクエストされたパラメータを置き換えて実行します。
また条件付きブロックを使用することが可能です。

##### パラメータの置き換えについて

SQLファイルに書かれたSQLのコメントは、get, post, jsonで指定すると、その値が書き換わったものが実行され結果を得られます。
下記例の場合は ?date=2024-02-15 とリクエストをすればその部分が描き変わります。

(例) sqlファイルに記載されたSQL

```sql
SELECT count(id) AS this_days_count 
FROM stamps  
WHERE date = /*date*/'2025-02-15';
```

(例) 実行されるSQL
```sql
SELECT count(id) AS this_days_count 
FROM stamps  
WHERE date = '2024-02-15';
```

これら生成されたSQLはGOで用意された機能によって
SQL インジェクション対策が施され、安全かつ柔軟に動的なクエリの生成が可能となります。

##### 条件分岐によるSQLの生成
NyanQL では、SQL ファイル内に特定のコメント形式を用いることで、リクエストパラメータの有無に応じた動的な SQL クエリの生成が可能です。
この仕組みを使うと、ある条件が満たされた場合のみ、特定の SQL 文をクエリに含めることができます。

条件分岐ブロックの構文
条件分岐ブロックは次の構文で記述します。

* 開始部分: `/*IF 条件*/`
* 終了部分: `/*END*/`

条件内では、リクエストパラメータの有無や値の状態（例: null かどうか）を判定できます。条件に合致する場合、ブロック内の SQL 文が最終的なクエリに展開されます。

(例)

```sql
SELECT id, date FROM stamps
    /*IF id != null*/  WHERE id = /*id*/1 /*END*/
;
```

この例の動作は以下の通りです：

* 条件: `/*IF id != null*/`
→ リクエストパラメータとして id が指定され、かつその値が null でない場合に、IF ブロック内の SQL 文が展開されます。

* パラメータプレースホルダー: `/*id*/`
→ この部分は、リクエストで送られた id の値に置き換えられ、データベースのプレースホルダー（例: ? や $1）として機能します。
※ここでは例として、プレースホルダー部分に 1 が記述されていますが、実際には実行時にリクエストパラメータの値が挿入されます。

* 結果:

リクエストパラメータに id の値が存在する場合
→ クエリは

```sql
SELECT id, date FROM stamps WHERE id = ?;
```

となり、? の部分はリクエストパラメータの値で置換されます。

リクエストパラメータに id が指定されない場合
→ IF ブロックが展開されず、クエリは

```sql
SELECT id, date FROM stamps;
```

のみとなります。

##### 複雑な使用例
外側ブロック (`/*BEGIN*/` ... `/*END*/`)を使用することができます。

```sql
SELECT id, date FROM stamps
/*BEGIN*/
 WHERE
    /*IF id != null*/ id = /*id*/1 /*END*/
    /*IF id != null AND date != null */ AND /*END*/
    /*IF date != null*/ date = /*date*/"2024-06-25" /*END*/
/*END*/
;
```
外側ブロック (`/*BEGIN*/` ... `/*END*/`)
外側ブロックで囲まれた部分は、オプションとして展開されます。
この例では、WHERE 句全体が外側ブロックに含まれているため、内部の条件が一つも展開されなかった場合、WHERE 句自体も出力されません。

### 条件付きブロック (`/*IF 条件*/` ... `/*END*/`)
各 IF ブロックは、リクエストパラメータの存在（nullかどうか）をチェックします。
* ※注意: IF の条件としては、チェックできるのは「パラメータが null か null でないか」という点のみです。
つまり、項目が存在するかしないかを確認するために利用され、その他の複雑な条件比較はサポートされていません。
* AND OR を指定できますが条件は2つまでしか設定できません。

## 条件チェックの目的
各 IF ブロックは、リクエストで送信されたパラメータが存在するか（nullかどうか）だけをチェックします。
たとえば、`/*IF id != null*/` は、「id パラメータが存在すれば」ブロック内の SQL を有効にするためのものです。

# Script と Check の利用方法

## check の使い方
API設定で check を指定すると、指定した JavaScript ファイルが実行され、入力パラメータの検証を行います。
チェックに失敗した場合は、エラーレスポンス (例)（{ success: false, status:500, error: { message: "エラーメッセージ" } }）等が返されます。
チェックスクリプト内では、必要に応じてパラメータの存在確認や形式検証を行い、エラーの場合は適切なレスポンスを生成してください。
?nyan_mode=checkOnly の場合チェックを実行し他結果のみをjsonで返します。

例: check.js

```js
console.log("loaded check.js"); //ログもしくはコンソールに出力されます。

function main() {
    // "date" が存在しない場合はエラーとする
    if (!nyanAllParams.date) {
        return JSON.stringify({ success: false, status: 400, error: { message: "date パラメータが必要です" } });
    }
    // 上記チェックが成功した場合は成功レスポンスを返す
    return JSON.stringify({ success: true, status: 200 });
}

main();

```

## script の使い方
API設定で script を指定すると、対応する JavaScript ファイルが実行され、結果として JSON が返されます。
JavaScript ファイル内では、以下のように書いて、自由にレスポンスの構造（success, status, result など）を制御できます。

### 例: script.js

```js
const nyanAcceptedParams = {"date": "2024-06-25"}; // /nyan/API名にアクセスするとそこで表示される受け入れ可能項目となります。
const nyanOutputColumns = ["date"]; // /nyan/API名にアクセスするとそこで表示される出力予定の項目になります。 
console.log("loaded script.js");

function main() {
    console.log("Received params:", nyanAllParams);
    let data = nyanAllParams;
    data.ids = [2];
    let result = JSON.parse(nyanRunSQL("./sql/sqlite/checkToday.sql", {}));
    console.log("SQL result:", result);
    return JSON.stringify({ success: true, status: 200, result: result, api: nyanAllParams.api });
}

main();

```

# checkとscript共通のjavascript機能
## postやgetやjsonなどで受信されたパラメータの取得
nyanAllParamsに格納されています。

```javascript
console.log(nyanAllParams);
```


## Ajaxの操作
Ajaxの操作が可能です。
取得したデータはJSON.parseでパースしてください。

getでの取得の場合

```javascript
//apiのURL  apiURL
//basic認証のID  apiUser
//basic認証のパスワード apiPass
//javascript内でデータとして扱う場合、JSON.parse()で文字列から変換をする必要があります。
console.log(nyanGetAPI(apiURL,apiUser,apiPass));
```

jsonでの取得の場合

```javascript
//apiのURL  apiURL
//basic認証のID  apiUser
//basic認証のパスワード apiPass
//javascript内でデータとして扱う場合、JSON.parse()で文字列から変換をする必要があります。
const data = {
            api: "create_user",
            username: nyanAllParams.username,
            password: nyanAllParams.password,
            email: nyanAllParams.email,
            salt: saltKey
        };
const result = nyanJsonAPI(
        apiURL,
        JSON.stringify(data),
        apiUser,
        apiPass
    );
const resultData = JSON.parse(result);
```

ヘッダー情報をJSON文字列で渡す例

```js
// ヘッダー情報をJSON文字列で渡す例
let headers = JSON.stringify({
    "X-Custom-Header": "myValue",
    "X-Another-Header": "anotherValue"
});
let result = nyanJsonAPI("https://example.com/api", JSON.stringify(data), "user", "pass", headers);
```

## hostでのコマンド実行と結果の取得
hostでのコマンド実行が可能です。

```javascript
console.log(nyanHostExec("ls"));
```

実行結果は次のような構成になって取得できます。

```json
{"success":true,"exit_code":0,"stdout":"コマンドの実行結果","stderr":""}
```

* success : コマンドの実行が成功したかどうか
* exit_code : コマンドの終了コード
* stdout : 標準出力
* stderr : 標準エラー出力

## ファイルの読み込み

ファイルの読み込みができます。

```js
let text = nyanGetFile("ファイルのパス");
let data = JSON.parse(text);
```



# エラーレスポンスと成功レスポンスのフォーマット

## 成功時

```json
{
  "success": true,
  "status": 200,
  "result": [
    {"message" : "SQL実行結果またはスクリプトの返却値 sql:で指定されたsqlファイルの最後のファイルの結果が配列で格納されます。"},
    {"message":  "scriptやcheckで実行したjsの結果の場合は書いたコードによって配列ではない場合もあります。"}
  ]
}
```

## 例外・エラー時

```json
{
  "success": false,
  "status": 500,
  "error": {
    "message": "エラーメッセージ等"
  }
}
```

# アクセス方法
SSL を利用する場合は、次のように https://localhost:{Port}/?api=API名 の形式でアクセスします。
SSL を利用しない場合は、http://localhost:{Port}/?api=API名 の形式です。
apiをパラメータで指定せず、エンドポイントとして使うこともできます。
http://localhost:{Port}/API名 は http://localhost:{Port}/?api=API名 と同じ挙動をします。

# WebSocket Push の利用方法
stamp API の実行後、設定された push ("list" など) の結果が WebSocket 経由で送信されます。
WebSocket クライアントは、たとえば ws://localhost:{Port}/list に接続することで、push で送信される最新の list API の結果を受信できます。
WebSocketでの接続の場合GETクエリパラメータは利用できませんので /API名の形で接続してください。

# JSON-RPC対応
http(s)://{hostname}:{port}/nyan-rpc にアクセスすると、JSON-RPCのAPIを利用することができます。
Nyan8はJSON-RPC 2.0に準拠したAPIを提供しています。
ただし、現在 6.Batch については未実装です。
JSON-RPC 2.0の仕様については、[こちら](https://www.jsonrpc.org/specification)を参照してください。
以下のようなJSON-RPCリクエストを送信することで、APIを呼び出すことができます。

```json
{
  "jsonrpc": "2.0",
  "method": "api名",
  "params": {
    "param1": "value1",
    "param2": "value2"
  },
  "id": 1
}
```


# このAPIサーバの情報を取得する場合
http(s)://{hostname}:{port}/nyan にアクセスすると、このAPIサーバの情報を取得することができます。
http(s)://{hostname}:{port}/nyan/API名 にアクセスすると、そのAPIの情報を取得することができます。

# 予約語について
apiとnyanから始まるものは予約語となります。 
パラメータなどで使用しないようご注意ください。 NyanQLとその仲間の共通ルールです。
