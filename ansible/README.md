# NyanQL VPS deployment

`stamp.necomori.asia`（VPS `153.126.182.172`）へNyanQL MCP ServerをデプロイするためのAnsibleです。Nginxは使用せず、NyanQL自身が標準HTTPS port `443`でTLSを終端します。

## 構築されるもの

- SSH: `2222/tcp`
- ACME HTTP-01 challenge: `80/tcp`
- NyanQL HTTPS / MCP: `443/tcp`
- swap file: 10 GB
- Git、SQLite、Go 1.26.5
- 非rootの`nyanql`ユーザーで動くsystemd service
- OAuth migration `001`、`002`、`003`（offline access / refresh token rotation）
- Certbotによる `stamp.necomori.asia` 用のLet's Encrypt証明書
- 12時間ごとの自動renewと、更新後の証明書コピー・NyanQL再起動

HTTP-01 challengeと自動更新のため、DNSとport 80の到達性を維持し、renew timerを止めないでください。
旧IP証明書 `nyanql-ip` は初回移行では削除しませんが、renew対象とdeploy hookは
`stamp.necomori.asia` のlineageだけに限定されるため、稼働中のドメイン証明書を上書きしません。
ドメインでの動作確認後に整理する場合だけ、playbookへ
`-e nyanql_remove_legacy_ip_certificate=true` を追加してください。

## 初回準備

inventoryの実体はGit管理されません。exampleをコピーして、秘密鍵のパスを必要に応じて修正します。

実行前に `stamp.necomori.asia` のDNS A recordが `153.126.182.172` を指していることを確認してください。SSH inventoryは引き続きIP addressを使用します。

```bash
cd /Users/neko/github/Nyan/NyanQL/ansible
cp inventory.example.ini inventory.ini
```

SSH確認:

```bash
ssh -p 2222 -i /Users/neko/.ssh/id_rsa ubuntu@153.126.182.172
```

## 実行

```bash
cd /Users/neko/github/Nyan/NyanQL/ansible
ansible-playbook deploy.yml --ask-become-pass
```

次の値を対話入力します。

- Let's Encrypt account email
- NyanQL Basic Auth username / password
- 初期OAuth username / password

passwordは画面に表示されません。`CHANGE_ME`および12文字未満のpasswordはplaybookが拒否します。Basic Auth usernameに`:`は使用できず、OAuth usernameは3〜128文字です。入力検証で失敗した場合は、失敗したtask名から対象の入力（email、Basic Auth、OAuth）を判別できますが、passwordそのものはログへ出力されません。OAuthユーザーはDBにユーザーが一件もない初回だけ作成され、passwordはArgon2id hashとして保存されます。

Basic認証またはOAuthユーザーを後から変更する場合は、認証情報をコマンドラインやファイルへ保存せず、専用playbookの対話プロンプトから入力します。

```bash
cd /Users/neko/github/Nyan/NyanQL/ansible
ansible-playbook rotate-auth.yml --ask-become-pass
```

`rotate-auth.yml`は指定したOAuthユーザー以外を無効化し、既存の認可リクエスト、認可コード、アクセストークン、リフレッシュトークンを失効させます。現在の接続セッションは再認証が必要になります。sudoを一時的にpasswordなしで許可している間は、`--ask-become-pass`を省略できます。

CIなど非対話環境では、平文をGit管理せずAnsible Vaultまたは安全なsecret injectionを使用してください。`--extra-vars`でも変数を渡せますが、コマンド履歴へpasswordを残さない運用が必要です。

必要な変数名:

```yaml
letsencrypt_email: operator@example.com
nyanql_basic_username: operator
nyanql_basic_password: use-a-secret-manager
nyanql_oauth_username: neko
nyanql_oauth_password: use-a-secret-manager
```

Vaultの例:

```bash
ansible-vault create vault.yml
ansible-playbook deploy.yml --ask-become-pass --ask-vault-pass -e @vault.yml
```

`vault.yml`もこのディレクトリの`.gitignore`対象です。

## デプロイ処理

1. OS package、10 GB swap、UFW、SSH portを整備
2. 公式archiveからchecksum検証付きでGoを導入
3. VPSの管理対象source directoryから旧構成の`.go`ファイルを除去し、`main.go`、Go module、JavaScript、SQLを転送
4. `api.vps.json`をremoteへstageし、証明書発行成功まで稼働中の`api.json`は維持
5. secretを埋めた`config.json`をremoteだけで生成
6. SQLiteの未適用migrationだけを、10秒のlock待機とfail-fast付きで実行し、旧`oauth_users` schemaとの互換性を検証
7. VPS内で`go mod download`と`go build`を実行
8. port 80の最小ACME webroot serviceを起動
9. 次のHTTP-01 webroot方式でドメイン証明書を発行

```text
certbot certonly --webroot \
  --webroot-path /var/lib/nyanql/acme \
  --domains stamp.necomori.asia \
  --cert-name stamp.necomori.asia
```

10. 証明書を`/etc/nyanql/tls`へroot所有でコピー
11. stageした`api.vps.json`をremoteの`api.json`へ配置し、NyanQLを非root systemd serviceとして起動
12. loopback限定endpointで初期OAuthユーザーを作成し、trusted HTTPSでwell-known metadataとMCP `initialize`を確認

OAuth bootstrapのpasswordやAuthorization headerはAnsibleログへ出力されません。Basic Authorization headerを含むcurl設定はVPSの`/tmp`にデプロイユーザー専用mode `0600`で一時作成し、JSON payloadはファイルへ保存せずcurlの標準入力へ渡します。一時設定は送信の成否にかかわらず直後に削除します。失敗時には秘密値の代わりにcurl終了コードとHTTP statusだけを表示します。`400`はOAuth入力、`401`はBasic Auth、`403`はloopback制限、`429`はrate limit、`500`はJavaScriptまたはSQLite schemaを確認してください。

ローカルの`stamps.db`はremote DBが存在しない初回だけseedとして転送されます。以後のデプロイでVPS上のデータを上書きしません。

OAuth migration `001`〜`003` のいずれかを適用する直前には、SQLite online backupを `/var/lib/nyanql/backups/stamps-before-oauth-v3.db` に作成します。既存バイナリは新しいバイナリを配置する直前に `/opt/nyanql/bin/NyanQL.previous` へ保存します。

## ロールバック

アプリケーションだけを一つ前へ戻す場合:

```bash
sudo systemctl stop nyanql
sudo install -o root -g root -m 0755 /opt/nyanql/bin/NyanQL.previous /opt/nyanql/bin/NyanQL
sudo systemctl start nyanql
```

OAuth migration前のDBへ戻す必要がある場合は、先に現DBを別名で保存し、サービス停止中に復元します。migration後に追加されたデータとOAuth認証情報は失われるため、DB rollbackは障害時だけ実施してください。

```bash
sudo systemctl stop nyanql
sudo -u nyanql sqlite3 /var/lib/nyanql/stamps.db ".backup /var/lib/nyanql/backups/stamps-before-manual-rollback.db"
sudo install -o nyanql -g nyanql -m 0640 /var/lib/nyanql/backups/stamps-before-oauth-v3.db /var/lib/nyanql/stamps.db
sudo systemctl start nyanql
```

## 動作・運用確認

```bash
ssh -p 2222 -i /Users/neko/.ssh/id_rsa ubuntu@153.126.182.172
sudo systemctl status nyanql
sudo systemctl status nyanql-acme-webroot
sudo systemctl status nyanql-certbot-renew.timer
sudo journalctl -u nyanql -n 100 --no-pager
sudo /opt/certbot/bin/certbot certificates
```

外部からの確認:

```bash
curl -fsS https://stamp.necomori.asia/.well-known/oauth-protected-resource/mcp
curl -fsS https://stamp.necomori.asia/.well-known/oauth-authorization-server
```

更新テストは本番CAへ不要な要求を送らないよう、まずdry-runを使います。

```bash
sudo /opt/certbot/bin/certbot renew --cert-name stamp.necomori.asia --dry-run
```

## ChatGPT Developer modeへ接続

ChatGPT webでDeveloper modeを有効にし、Appsの作成画面を開きます。Businessではadmin/owner、Enterprise/Eduでは権限を付与された利用者が作成できます。Proはcustom appで利用できるactionがread/fetchに制限される場合があります。

作成画面では次を指定します。標準HTTPS portのため、公開URLに `:443` は記載しません。

- MCP endpoint: `https://stamp.necomori.asia/mcp`
- Authentication: OAuth
- Client registration: Dynamic Client Registration（DCR）
- Default scope: `stamps:read`
- Base scope: `offline_access`
- Authorization URL: `https://stamp.necomori.asia/oauth/authorize`
- Token URL: `https://stamp.necomori.asia/oauth/token`
- Registration URL: `https://stamp.necomori.asia/oauth/register`
- Authorization server base: `https://stamp.necomori.asia`
- Resource: `https://stamp.necomori.asia/mcp`
- Token endpoint authentication: `none`
- OpenID Connect: 無効

`Scan Tools`を実行するとNyanQLの認可画面へ遷移します。Ansible実行時に登録したOAuth username / passwordでログインし、`list_stamps` の権限を許可してからAppを作成します。作成後は新しいchatでdraft appを選び、スタンプ一覧取得を試します。

認可サーバは `offline_access`、90日有効のrefresh token、使用ごとのrotation、reuse検知を実装しています。access tokenは1時間で更新されます。接続に失敗した場合は、まずDNS A record、上記curl、証明書chain、port `443`の到達性を確認してください。port `2255` は旧構成であり、公開・登録には使用しません。

DCR endpointはOAuth仕様上、client登録前には認証できません。本構成ではChatGPT callback形式の厳格な検証、接続元IP単位のrate limit、client上限、認証情報を持たない未使用clientの定期清掃で登録枯渇を緩和します。公開運用では登録件数とHTTP `429` / `503`を監視してください。

## 公式資料

- [OpenAI: Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt)
- [OpenAI: Authentication](https://developers.openai.com/plugins/build/auth)
- [OpenAI: Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
- [Let's Encrypt: Challenge Types](https://letsencrypt.org/docs/challenge-types/)
- [Certbot: Webroot](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot)
