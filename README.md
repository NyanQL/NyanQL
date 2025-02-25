# NyanQL

NyanQL（にゃんくる）は、SQLを実行してJSONを返すAPIサービスです。
apiで指定した内部に保存しているsqlファイルからsqlを選択し実行した結果をjsonとして返します。

NyanQLには、JavaScriptを実行してJSONを生成するNyan8（にゃんぱち）と、HTMLを生成するNyanPUI（にゃんぷい）があります。
これらは現在公開準備中です。

## 対応データベース

次のデータベースでの利用が可能です。

* MySQL
* PostgreSQL
* SQLite

## 設定ファイル config.json

config.jsonにNyanQLの設定を記述します。各項目の説明は下記の通りです。
SSL証明書を指定すると、httpsでアクセスできるようになります。

### config.json について

```json
{
  "name": "NyanQLの名前",
  "profile": "NyanQLの自己紹介",
  "version": "バージョン",
  "Port": "実行するポート番号",
  "CertPath": "SSL証明書のパス",
  "KeyPath": "SSL証明書のキーのパス",
  "DBType": "データベースのタイプ（mysql、postgres、sqliteが使用可能）",
  "DBUser": "DB接続ユーザー",
  "DBPassword": "DB接続パスワード",
  "DBName": "DB名（sqliteの場合はファイルへの相対パス）",
  "DBHost": "DBホスト名",
  "DBPort": "DBに接続するポート番号",
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
  }
}
``` 

### ログ設定

config.jsonで指定するログ設定の詳細は以下の通りです。

* Filename: ログファイルの保存場所を指定します。例: "./logs/nyanql.log"
* MaxSize: ログファイルの最大サイズ（MB単位）。このサイズを超えると新しいログファイルが作成されます。例: 5（5MB）
* MaxBackups: 保持する古いログファイルの最大数。例: 3（最新の3つのログファイルを保持）
* MaxAge: ログファイルを保持する最大日数（日単位）。例: 7（7日間のログファイルを保持し、それを超えると削除）
* Compress: 古いログファイルを圧縮するかどうか。trueに設定すると、古いログファイルがgzip形式で圧縮されます。例: true
* EnableLogging: ログの出力を有効にするかどうか。falseに設定すると、ログは標準出力（コンソール）に出力されます。例: false

## API設定ファイル: api.json

api.jsonは、APIエンドポイントごとに実行するSQLファイルを定義する設定ファイルです。
各APIエンドポイントに対して、1つまたは複数のSQLファイルを指定できます。複数のSQLファイルを指定すると、それらは順に実行されます。
NyanQLは、複数のSQLファイルを登録してAPIとして利用できます。各APIごとにSQLファイルを指定し、その説明を記述します。
複数のSQLファイルを登録した場合、トランザクションが実行され、最後に実行されたSQLファイルの結果がJSONで返されます。

### api.json について

```json
{
  "target_month_list": {
    "sql": [
      "sql/target_month_list.sql"
    ],
    "description": "指定月のリストを取得するAPI"
  },
  "complex_transaction": {
    "sql": [
      "sql/start_transaction.sql",
      "sql/insert_data.sql",
      "sql/commit_transaction.sql"
    ],
    "description": "複数のSQLファイルを順に実行するAPI"
  }
}
```

#### 各項目について

* APIの名前: キーとなっているこの部分は実行するapiを指定するものになります。
* sql: 実行するSQLファイルのパスを配列で指定します。複数のSQLファイルを指定することで、順次実行されます。
* description: このAPIの説明。APIの目的や機能について簡潔に記述します。

SSL証明書を利用する場合はhttps://localhost:8443/?api=APIの名前、
使用しない場合はhttp://localhost:8080/?api=APIの名前
でアクセスすると、クエリが実行された結果がJSONで返されます。

また、パラメータをURLに含めることで、SQLクエリを動的に制御することが可能です。

### 例:

https://localhost:8443/?api=target_month_list&year=2024&month=7
このURLは、target_month_listというAPIを実行し、年が2024年、月が7月のリストを取得します。

## サンプル

日々のスタンプカード用のサンプルを作成しています。以下に、それぞれのDB用のCREATE TABLE文を示します。

同梱しているapi.jsonとconfig.jsonが指定しているURLは次の通りです。

* https://localhost:8443/?api=list
* https://localhost:8443/?api=check
* https://localhost:8443/?api=stamp
* https://localhost:8443/?api=target_month_list&year=2024&month=7

## DB別 create table 

### MySQL

```sql
CREATE TABLE `stamps`
(
    `id`   int NOT NULL AUTO_INCREMENT,
    `date` date DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `unique_date` (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

### PostgreSQL

```sql
CREATE TABLE stamps
(
    id   SERIAL PRIMARY KEY,
    date DATE,
    UNIQUE (date)
);
```

### SQLite

```sql
CREATE TABLE stamps
(
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE DEFAULT NULL,
    UNIQUE (date)
);
```

# バイナリ実行ファイル

各環境用にビルド済みバイナリファイルを同梱しています。
クリックまたはターミナルから起動して実行できます。

* Windows環境 NyanQL_Windows.exe
* Mac環境 NyanQL_Mac
* Linux環境 NyanQL_Linux_amd64

# このAPIサーバの情報を取得する場合
http(s)://{hostname}:{port}/nyan にアクセスすると、このAPIサーバの情報を取得することができます。
http(s)://{hostname}:{port}/nyan/API名 にアクセスすると、このAPIサーバの指定されたAPIの情報を取得することができます。

# 予約語について

apiとnyanから始まるものは予約語となります。
パラメータなどで使用しないようご注意ください。
NyanQLとその仲間の共通ルールです。
