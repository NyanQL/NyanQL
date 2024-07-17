# NyanQL

* NyanQLとはにゃんくると読みます。
* リクエストを投げると指定されたSQLを実行しjsonを返します。
* NyanQLにはjavascriptを実行しjsonを発行する Nyan8(にゃんぱち)とHTMLを生成するNyanPUI(にゃんぷい)があります。現在公開準備中です。

# 対応しているDB
対応しているDBは次の3種類です。

* mysql
* postgres
* SQLite

# 設定ファイルの準備
config.jsonにNyanQLを起動した場合のポート番号とDB接続情報を設定します。
各項目の説明は下記の通りです。
SSL証明書を利用しない場合はブランクにしてください。

```json
{
  "name": "このにゃんくるの名前",
  "profile": "このにゃんくるの自己紹介",
  "Port": "実行するポート番号", 
  "certPath": "SSL証明書 cartパス",
  "keyPath": "SSL証明書 keyファイル",
  "DBType": "データペースのタイプ mysql postgres sqliteが使用できます",
  "DBUser": "DB接続ユーザー",
  "DBPassword": "DB接続パスワード",
  "DBName": "DB名 sqliteの場合はファイルへの相対パスを記述してください。",
  "DBHost": "DBホスト名",
  "DBPort": "DBに接続するポート番号",
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

## ログ出力について
logの設定について

```json
"log": {
    "Filename": "保存されるログファイルの場所",
    "MaxSize": "数字を記述してください。MB単位です", 
    "MaxBackups": "",
    "MaxAge": "数字を記述してください。7の場合は7日分が保存されそれを経過したものは削除されます。",
    "Compress": true,
    "EnableLogging": false
  }
```



## 実行するSQLファイルの指定
* sqlファイルを複数登録した場合、トランザクションが実行されます。
* また表示されるjsonは最後に実行されたsqlファイルの実行結果となります。
* 最後に実行されるsqlがcreate update delete等の場合、成功すれば {} が表示されます。

```json
{
  "APIの名前": {
    "sql": ["実行するsqlファイルのパス","実行するsqlファイルのパス2"],
    "description": "このAPIの説明"
  },
  "APIの名前2": {
    "sql": ["実行するsqlファイルのパス"],
    "description": "このAPIの説明"
  }

}
```
SSL証明書を利用する場合はhttpsで、使用しない場合はhttpのURLでアクセスください。
https://localhost:8443/?api=APIの名前を記載してアクセスするとqueryが実行された結果がjsonで表示されます。
またパラメータでSQLを動的にすることが可能です。

# サンプルについて
* 日々のスタンプカード用のサンプルを作成しています。
* sqliteが動く環境であればバイナリをクリックすることで実行することができます。
* 以下にそれぞれのDB用のcreate table文を用意しました。
* sqlファイルのパスはapi.jsonで確認することができます。

* https://localhost:8443/?api=list
* https://localhost:8443/?api=check
*  https://localhost:8443/?api=stamp
* https://localhost:8443/?api=target_month_list&year=2024&month=7


## MySQL

```sql
CREATE TABLE `stamps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `date` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_date` (`date`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci 
```

## Postgres

```sql
CREATE TABLE stamps (
  id SERIAL PRIMARY KEY,
  date DATE,
  UNIQUE (date)
);

```

## SQLite

```sql
CREATE TABLE stamps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date DATE DEFAULT NULL,
  UNIQUE (date)
);
```

# バイナリー実行ファイル

* 各環境用にビルド済みバイナリーファイルを同梱しています。
* クリックもしくはターミナルから起動し実行することが可能です。
* （配布する各環境用のバイナリーはzip.shを実行し作成予定です）

# 予約語について

* nyanから始まるものについて大文字、小文字、混在のパターン全てで予約後となりますのでパラメータ等で使用しないようお願いします。
* NyanQLとその仲間の共通のルールです。
