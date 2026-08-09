# NyanQL MCP Server / JavaScript OAuth 設計書

## 1. 文書の目的

NyanQLをChatGPTのDeveloper modeから利用できるMCP Serverとして公開し、OAuth 2.1による認証を行うための設計を定義する。

本設計では、次の方針を必須条件とする。

- MCP Serverの公開内容とOAuthのHTTP endpointは `api.json` で宣言する。
- OAuthの判断、状態遷移、SQLite操作はJavaScriptで実装する。
- OAuth専用のGoルーター、Go製OAuthストア、Go製OAuth状態機械は作成しない。
- Goの実装は既存の `main.go` だけに追加し、新しい `.go` ファイルは作成しない。
- Goのテストは既存の `main_test.go` に追加し、新しいGoテストファイルは作成しない。
- Nginxを経由せず、NyanQL自身がTLSを終端する。
- 既存の `paramCheck` / `outCheck` スキーマ機能をMCP Tool定義に再利用する。

本設計は `docs/paramcheck-outcheck-schema-design.md` とは別の設計書であり、同文書の仕様を変更しない。

## 2. 対象環境

初回のVPS動作確認では、次の接続先を使用する。

| 項目 | 値 |
|---|---|
| VPS | `153.126.182.172` |
| Public hostname | `stamp.necomori.asia` |
| NyanQL HTTPS port | `443` |
| MCP endpoint | `https://stamp.necomori.asia/mcp` |
| Authorization Server issuer | `https://stamp.necomori.asia` |
| Protected Resource Metadata | `https://stamp.necomori.asia/.well-known/oauth-protected-resource/mcp` |
| Authorization Server Metadata | `https://stamp.necomori.asia/.well-known/oauth-authorization-server` |

TLS証明書と秘密鍵のパスは、VPS用の `config.json` に設定する。証明書の発行・更新はデプロイ処理で管理し、NyanQLは `certPath` / `keyPath` に指定された証明書を直接使用する。

TLS証明書はLet's Encryptの標準ドメイン証明書を使用する。`stamp.necomori.asia` のDNS A recordを `153.126.182.172` へ向け、Certbotで `--webroot`、`--domains stamp.necomori.asia` を指定して発行・自動更新する。HTTP-01 challenge用のport 80は常時到達可能にする。更新後は証明書と秘密鍵をNyanQL専用の読取権限へコピーし、サービスを再起動するdeploy hookを実行する。

VPSではSSH `2222/tcp`、HTTP-01 `80/tcp`、NyanQL HTTPS `443/tcp` だけを許可し、旧構成の `2255/tcp` は閉じる。NyanQLは専用の非root systemd userで実行し、`CAP_NET_BIND_SERVICE` だけを付与してport 443へ直接bindする。SQLite DB、実 `config.json`、TLS秘密鍵はそのuser以外から読めない権限にする。標準HTTPS portのため、issuerやresourceを含む公開URLに `:443` は記載しない。

## 3. 設計原則

### 3.1 Goと `main.go` の関係

「Go」は実装言語およびNyanQLのネイティブ実行基盤を表す。「`main.go`」はGoソースファイルの名前を表す。

本設計ではGoコードを機能別の別ファイルへ分割しない。MCP transport、汎用HTTP bridge、JavaScript向け暗号関数を含むすべてのGo変更を `main.go` に収める。コンパイル後は従来どおり単一のNyanQLバイナリになる。

`main.go` 内ではコメントと関数単位で責務を分離する。

```go
// -----------------------------------------------------------------------------
// Configured HTTP API
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// MCP Streamable HTTP
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// MCP Tool Adapter
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// JavaScript Request / Response Bridge
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Generic Cryptographic Functions for JavaScript
// -----------------------------------------------------------------------------
```

ファイルを分割しないことと、OAuthの責務をGoへ移さないことは別の条件である。`main.go` に置くのは汎用実行基盤だけとし、OAuthのパス、テーブル、状態遷移、判定ルールをハードコードしない。

### 3.2 責務の分離

| 層 | 担当するもの | 担当しないもの |
|---|---|---|
| `api.json` | HTTP path、method、公開範囲、MCP endpoint、ToolとAPIの対応、scope、security scheme | パスワードやtokenなどの秘密情報 |
| JavaScript | DCR、ログイン、同意、PKCE、認可コード、token発行・失効、Bearer検証、scope/audience判定 | MCP wire protocol、TLS終端 |
| SQLite / SQL | user、client、認可リクエスト、認可コード、token、同意情報の永続化 | HTTP routing、MCP protocol |
| `main.go` | 汎用HTTP routing、MCP transport、既存API呼び出し、JS実行、HTTP応答反映、安全な暗号プリミティブ | OAuth固有ルート、OAuth用DBストア、OAuth状態機械 |
| `main_test.go` | Go基盤、MCP、JS OAuthフローの結合テスト | 本番用秘密情報 |

## 4. 全体構成

### 4.1 MCP Tool呼び出し

```text
ChatGPT
   │ POST /mcp
   ▼
MCP Streamable HTTP（main.go）
   │
   ├─ initialize / tools/list
   │    └─ api.jsonと既存スキーマからTool定義を生成
   │
   └─ tools/call
        │
        ├─ api.jsonで指定された内部guard APIを実行
        │    └─ JavaScriptがSQLiteのtokenを検証
        │
        ├─ 許可: 既存NyanQL APIを実行
        └─ 拒否: MCP auth errorとchallengeを返す
```

### 4.2 OAuth endpoint

```text
Browser / ChatGPT
   │ /.well-known または /oauth/*
   ▼
Configured HTTP API（main.go）
   │ api.jsonからscriptとHTTP設定を取得
   ▼
JavaScript
   │ OAuthパラメーターを検証
   ▼
SQLite
   │ client / code / tokenを照合・更新
   ▼
JavaScriptが {status, headers, body} を返す
   ▼
main.goが汎用HTTPレスポンスとして反映
```

`main.go` は `/oauth/authorize` や `/oauth/token` の意味を解釈しない。`api.json` で宣言されたHTTP APIとしてJavaScriptを実行するだけとする。

## 5. `api.json` の拡張

### 5.1 汎用HTTP設定

通常APIへ、任意の `http` 設定を追加できるようにする。

```json
{
  "sample_http_api": {
    "script": "./javascript/sample.js",
    "http": {
      "path": "/sample",
      "methods": ["GET", "POST"],
      "access": "anonymous",
      "responseMode": "raw",
      "allowedOrigins": ["https://chatgpt.com"],
      "rateLimit": {
        "requests": 30,
        "window": "1m"
      }
    },
    "runtime": {
      "capabilities": ["sql", "crypto"]
    }
  }
}
```

`http` の仕様は次のとおりとする。

| フィールド | 内容 |
|---|---|
| `path` | 公開する絶対URL path |
| `methods` | 許可するHTTP method。未指定時は既存APIの動作を維持する |
| `access` | `basic`、`anonymous`、`internal` |
| `responseMode` | `nyan` または `raw` |
| `allowedRemoteIPs` | 任意。直接接続元IPの完全一致allowlist。管理用endpointをloopbackだけに制限する用途 |
| `allowedOrigins` | 任意。`Origin` headerがあるブラウザリクエストを許可するoriginの完全一致allowlist |
| `rateLimit` | 任意。接続元IPごとの固定window制限を `requests` とGo duration形式の `window` で指定 |

既定値は既存APIとの互換性を優先する。

- `http` 未指定: 従来どおりAPI名をpathに使用し、Basic認証とNyanQLレスポンス形式を使用する。
- `access: basic`: Basic認証を要求する。
- `access: anonymous`: Basic認証なしで公開する。明示指定を必須とする。
- `access: internal`: HTTPでは公開せず、明示allowlistされたMCP Tool、MCP guard、JavaScript内部呼び出しだけを許可する。
- `responseMode: nyan`: 従来のNyanQLレスポンス形式を使用する。
- `responseMode: raw`: JavaScriptのHTTPレスポンスエンベロープを使用する。

### 5.2 MCP Server設定

MCP Serverは `type: "mcp"` として明示する。

```json
{
  "server_mcp_http": {
    "type": "mcp",
    "path": "/mcp",
    "transport": "streamable_http",
    "protocolVersions": ["2025-11-25"],
    "resource": "https://stamp.necomori.asia/mcp",
    "allowedOrigins": [
      "https://chatgpt.com",
      "https://platform.openai.com"
    ],
    "rateLimit": {"requests": 120, "window": "1m"},
    "maxConcurrent": 8,
    "guard": {
      "api": "oauth_verify_access"
    },
    "tools": [
      {
        "name": "list_stamps",
        "api": "list",
        "title": "スタンプ一覧を取得",
        "securitySchemes": [
          {
            "type": "oauth2",
            "scopes": ["stamps:read"]
          }
        ],
        "annotations": {
          "readOnlyHint": true,
          "destructiveHint": false,
          "openWorldHint": false
        }
      }
    ]
  }
}
```

MCP Toolは必ず `tools` で明示的に許可する。全NyanQL APIを自動公開してはならない。これにより、更新SQL、管理API、`nyanHostExec` を利用するAPI、OAuth内部APIの意図しない公開を防ぐ。

Toolの `description` はTool設定に明記された値を優先し、省略時は参照先APIの `description` を使用する。

### 5.3 OAuth endpoint設定

初回実装では次のendpointをVPS用の `api.vps.json` に宣言し、デプロイ時にサーバー上の `api.json` として配置する。ローカル開発用 `api.json` は変更しない。

```json
{
  "oauth_protected_resource_metadata": {
    "script": "./javascript/oauth/protected_resource_metadata.js",
    "http": {
      "path": "/.well-known/oauth-protected-resource/mcp",
      "methods": ["GET"],
      "access": "anonymous",
      "responseMode": "raw"
    }
  },
  "oauth_authorization_server_metadata": {
    "script": "./javascript/oauth/authorization_server_metadata.js",
    "http": {
      "path": "/.well-known/oauth-authorization-server",
      "methods": ["GET"],
      "access": "anonymous",
      "responseMode": "raw"
    }
  },
  "oauth_register": {
    "script": "./javascript/oauth/register.js",
    "http": {
      "path": "/oauth/register",
      "methods": ["POST"],
      "access": "anonymous",
      "responseMode": "raw"
    },
    "runtime": {
      "capabilities": ["sql", "crypto"]
    }
  },
  "oauth_authorize": {
    "script": "./javascript/oauth/authorize.js",
    "http": {
      "path": "/oauth/authorize",
      "methods": ["GET", "POST"],
      "access": "anonymous",
      "responseMode": "raw"
    },
    "runtime": {
      "capabilities": ["sql", "crypto", "password"]
    }
  },
  "oauth_token": {
    "script": "./javascript/oauth/token.js",
    "http": {
      "path": "/oauth/token",
      "methods": ["POST"],
      "access": "anonymous",
      "responseMode": "raw"
    },
    "runtime": {
      "capabilities": ["sql", "crypto"]
    }
  },
  "oauth_revoke": {
    "script": "./javascript/oauth/revoke.js",
    "http": {
      "path": "/oauth/revoke",
      "methods": ["POST"],
      "access": "anonymous",
      "responseMode": "raw"
    },
    "runtime": {
      "capabilities": ["sql", "crypto"]
    }
  },
  "oauth_bootstrap_user": {
    "script": "./javascript/oauth/bootstrap_user.js",
    "http": {
      "path": "/oauth/admin/users",
      "methods": ["POST"],
      "access": "basic",
      "responseMode": "raw"
    },
    "runtime": {
      "capabilities": ["sql", "password"]
    }
  },
  "oauth_verify_access": {
    "script": "./javascript/oauth/verify_access.js",
    "http": {
      "access": "internal"
    },
    "runtime": {
      "capabilities": ["sql", "crypto"]
    }
  }
}
```

endpointの名前やpathを `main.go` にハードコードしない。MCP Serverから内部guardを呼ぶ場合も、`guard.api` に指定されたAPI名を使用する。

## 6. 既存スキーマ機能との接続

MCP Toolの `inputSchema` / `outputSchema` は `api.json` に重複記載しない。

入力スキーマの取得優先順位は既存設計に従う。

1. `paramCheck` の `nyanInputSchema`
2. SQL解析による生成
3. scriptの `nyanAcceptedParams`
4. 空スキーマ `{}`

出力スキーマの取得優先順位も既存設計に従う。

1. `outCheck` の `nyanOutputSchema`
2. SQL解析による生成
3. 空スキーマ `{}`

通常のNyanQL APIでは、引き続きJSON Schemaによる実行時検証を行わない。MCP `tools/call` だけは、MCP Toolとして公開した入力契約を守るため、取得したスキーマで引数を検証してから既存APIを呼び出す。この検証は従来のHTTP APIやJSON-RPC APIの挙動を変更しない。

MCP Toolの正常結果は、既存NyanQLの正常レスポンス全体を `structuredContent` として返す。必要に応じて、同じ内容の簡潔な表現をMCP `content` に追加する。

## 7. JavaScript HTTP bridge

### 7.1 `nyanRequest`

`responseMode: raw` のscriptには、HTTP情報を次のような読取専用オブジェクトとして渡す。

```js
const nyanRequest = {
  method: "POST",
  path: "/oauth/token",
  query: {},
  form: {},
  json: null,
  headers: {},
  cookies: {},
  body: "",
  remoteAddress: ""
};
```

要件は次のとおりとする。

- header名は小文字へ正規化する。
- bodyサイズに上限を設ける。
- `Authorization`、password、code、token、client secretをログへ出力しない。
- metadataのissuerやresourceを受信した `Host` headerから動的生成しない。
- OAuth guardへ渡す `Authorization` headerは、通常の業務scriptへ無条件に公開しない。

### 7.2 raw HTTPレスポンス

JavaScriptは最後の評価値として、次のJSON文字列を返す。

```js
JSON.stringify({
  status: 302,
  headers: {
    "Location": "https://example.invalid/callback?code=...&state=...",
    "Cache-Control": "no-store"
  },
  body: ""
});
```

`main.go` はこの値を汎用HTTPレスポンスとして検証・反映する。

- status codeの範囲を検証する。
- header名と値にCR/LFを許可しない。
- `Connection`、`Transfer-Encoding` などのhop-by-hop headerをscriptから設定させない。
- `Content-Length` はGo側で決定する。
- bodyサイズに上限を設ける。
- scriptエラーの内部詳細を公開レスポンスへ含めない。
- OAuth token responseにはJavaScript側で `Cache-Control: no-store` と `Pragma: no-cache` を設定する。

## 8. JavaScript runtime capability

OAuth endpointへ、既存のすべてのホスト関数を無条件に公開してはならない。

`runtime.capabilities` により、scriptごとに利用できる機能を明示する。

| capability | 内容 |
|---|---|
| `sql` | 現在のtransactionを使用するSQL実行 |
| `crypto` | 安全な乱数、SHA-256、base64url、constant-time比較 |
| `password` | Argon2id password hash / verify |

`sql` を許可する場合は `runtime.sqlFiles` に、そのscriptが実行できるSQLファイルを明示的に列挙する。Go側は正規化した絶対pathで照合し、allowlist外のSQLファイルを拒否する。生のDB connectionやtransactionをJavaScript globalへ公開しない。

OAuth scriptには原則として次を公開しない。

- `nyanHostExec`
- 任意ファイル書き込み
- 任意ファイル読み込み
- SSRF対策のない任意HTTPアクセス

既存APIの後方互換性を維持するため、capability未指定時の扱いは既存APIと新しい公開HTTP APIで分ける。既存APIは従来の関数を維持し、新しく `http` を明示したAPIは必要なcapabilityだけを許可する。

## 9. 汎用暗号プリミティブ

goja上のJavaScriptには、OAuthで利用できる安全な乱数源とWeb Crypto APIが存在しない。そのため、暗号処理の低レベルプリミティブだけを `main.go` から提供する。

対象は次のとおりとする。

- CSPRNGによるbase64url乱数生成
- SHA-256 digestのhex / base64url出力
- constant-time文字列またはbyte列比較
- Argon2id PHC文字列によるpassword hash / verify

次のルールを適用する。

- `Math.random()` を認可コード、token、client IDへ使用しない。
- Argon2idの最低パラメーターをJavaScript側から弱められないようにする。
- 乱数生成サイズへ上限と下限を設ける。
- hash比較には通常の文字列比較を使用しない。

これらはOAuth状態機械ではない。どの値を生成し、どのDBレコードへ保存し、どの条件で認可するかはJavaScriptが決定する。

## 10. OAuth 2.1実装

### 10.1 初回対応範囲

- OAuth Authorization Server Metadata
- Protected Resource Metadata
- Dynamic Client Registration（DCR）
- public client
- Authorization Code Grant
- PKCE S256
- opaque access token
- `offline_access`
- refresh token grant
- refresh token rotationとreuse検知
- per-tool scope
- token revocation

初回実装ではCIMDを広告しない。`client_id_metadata_document_supported: true` は設定しない。

refresh tokenは90日の絶対有効期限を持つopaque tokenとし、使用ごとに必ずrotationする。使用済みrefresh tokenが再提示された場合はtoken family全体と、そのfamilyから発行したaccess tokenを失効する。

### 10.2 Protected Resource Metadata

`/.well-known/oauth-protected-resource/mcp` は最低限、次を返す。

```json
{
  "resource": "https://stamp.necomori.asia/mcp",
  "authorization_servers": [
    "https://stamp.necomori.asia"
  ],
  "scopes_supported": [
    "stamps:read",
    "offline_access"
  ]
}
```

`resource` はauthorize、token、access token保存、Bearer検証のすべてで完全一致させる。

### 10.3 Authorization Server Metadata

`/.well-known/oauth-authorization-server` は、実装済みの機能だけを広告する。

```json
{
  "issuer": "https://stamp.necomori.asia",
  "authorization_endpoint": "https://stamp.necomori.asia/oauth/authorize",
  "token_endpoint": "https://stamp.necomori.asia/oauth/token",
  "registration_endpoint": "https://stamp.necomori.asia/oauth/register",
  "revocation_endpoint": "https://stamp.necomori.asia/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["none"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["stamps:read", "offline_access"]
}
```

### 10.4 Dynamic Client Registration

`/oauth/register` は次を検証する。

- `redirect_uris`
- `grant_types`
- `response_types`
- `token_endpoint_auth_method`
- 許可していないURI schemeや不正なURI

ChatGPTのredirect URIは `https://chatgpt.com/connector/oauth/{callback_id}` という構造を登録時の許可ポリシーで検証し、受信した完全なURIを保存する。`{callback_id}` は安全な単一path segmentだけを許可する。設定されたprefixは登録可否の判定にだけ使用し、authorize/token時は保存済みの完全なredirect URIと完全一致で照合する。hostだけの一致や未検証の任意HTTPS URIを許可してはならない。

public clientとして登録し、`token_endpoint_auth_method` は `none` とする。client secretは発行しない。登録済みgrant typeは `authorization_code` と `refresh_token`、scopeは業務scopeと `offline_access` を返す。

DCRには登録client数の上限を設定する。認可画面では `client_name` を未検証の表示名として扱い、client IDと完全なredirect URIも利用者へ表示する。authorize時にも現在のredirect URI許可ポリシーを再評価し、旧ポリシーでDBへ残ったURIを使用できないようにする。

### 10.5 Authorization endpoint

`/oauth/authorize` は次を検証する。

- `response_type=code`
- 登録済み `client_id`
- 登録済み `redirect_uri` との完全一致
- 許可された `scope`
- canonical MCP resourceとの完全一致
- `code_challenge`
- `code_challenge_method=S256`
- `state` の保持

ログイン・同意完了後、短寿命かつ一回限りの認可コードを発行する。認可コードはuser、client、redirect URI、resource、scope、PKCE challengeに束縛する。

### 10.6 Token endpoint

`/oauth/token` は `application/x-www-form-urlencoded` を受け付ける。Authorization Code Grantでは次を検証する。

- `grant_type=authorization_code`
- 認可コード
- `client_id`
- `redirect_uri`
- `code_verifier`
- `resource`

認可コードは同じSQLite transaction内で一回だけ消費し、その後access tokenを作成する。使用済み、期限切れ、resource不一致、PKCE不一致のコードは拒否する。

認可scopeに `offline_access` が含まれる場合はaccess tokenとrefresh tokenを同時に発行する。Refresh Token Grantでは `refresh_token`、`client_id`、任意の `resource` と `scope` を検証し、resourceはcanonical MCP resource、scopeは元のgrantの部分集合だけを許可する。新しいaccess tokenのscopeは要求された縮小scopeとし、rotation後のrefresh tokenは元のgrant scopeを保持する。

refresh処理はSQLite transactionの最初のSQLでwrite lockを取得して同一tokenの並行交換を直列化し、条件付き更新で旧tokenを一回だけ消費する。使用済みtokenの再提示を検知した場合は、同じtransactionでtoken family、全refresh token、familyに紐づく全access tokenを失効する。

access tokenとrefresh tokenは十分な長さのランダムなopaque tokenとし、SQLiteにはSHA-256ハッシュだけを保存する。access tokenは1時間、refresh token familyは90日を初期値とし、設定可能な安全範囲をJavaScriptで制限する。

### 10.7 MCP guard

MCP `tools/call` 時に、`guard.api` で指定された内部APIを呼び出す。

入力には次を含める。

- Authorization header
- canonical resource
- Tool名
- Toolの `securitySchemes`
- 要求されたscope

JavaScript guardは、次を検証する。

- Bearer tokenの存在
- token hashの一致
- 有効期限
- 失効状態
- resource / audience
- userとclientの有効状態
- Toolに必要なscope

guardの戻り値は汎用判定形式とする。

```json
{
  "allow": false,
  "status": 401,
  "headers": {
    "WWW-Authenticate": "Bearer resource_metadata=\"https://stamp.necomori.asia/.well-known/oauth-protected-resource/mcp\", error=\"invalid_token\", error_description=\"Authentication is required\""
  },
  "mcpMeta": {
    "mcp/www_authenticate": [
      "Bearer resource_metadata=\"https://stamp.necomori.asia/.well-known/oauth-protected-resource/mcp\", error=\"invalid_token\", error_description=\"Authentication is required\""
    ]
  }
}
```

`main.go` は `allow`、HTTP status、headers、MCP metadataを反映するだけとし、tokenやscopeの意味を解釈しない。

## 11. SQLite設計

OAuthデータは、NyanQLが接続している同一SQLiteデータベース内の専用テーブルへ保存する。Go製の別AuthStoreは作成しない。

初回実装で使用するテーブルは次のとおりとする。

| テーブル | 目的 |
|---|---|
| `oauth_users` | username、Argon2id password hash、有効状態 |
| `oauth_clients` | client ID、client name、認証方式、有効状態 |
| `oauth_client_redirect_uris` | clientごとの完全一致redirect URI |
| `oauth_authorization_requests` | ログイン・同意前の短寿命リクエスト |
| `oauth_authorization_codes` | 認可コードhash、PKCE、resource、scope、期限、使用日時 |
| `oauth_access_tokens` | token hash、user、client、resource、scope、refresh family、期限、失効日時 |
| `oauth_refresh_token_families` | user、client、resource、元scope、絶対期限、family失効日時 |
| `oauth_refresh_tokens` | token hash、family、親token、scope、期限、消費日時、失効日時 |
| `oauth_consents` | userがclientへ許可したscope |

共通要件は次のとおりとする。

- codeとtokenの平文を保存しない。
- 日時はUTCで保存する。
- client ID、code hash、token hashに必要なunique制約を付ける。
- 期限と失効状態を毎回確認する。
- 認可コードの消費は条件付き更新または `RETURNING` を使い、同時使用を一件だけ成功させる。
- schema作成は `sql/oauth/001_init.sql` の明示migrationとして管理する。
- redirect URI許可ポリシー導入前に発行された可能性がある一時情報とtokenは、`sql/oauth/002_reset_pre_policy_credentials.sql` を一度だけ適用して無効化する。
- refresh token family、rotation履歴、access tokenとの関連は `sql/oauth/003_add_refresh_tokens.sql` で追加する。
- 消費済みrefresh tokenはfamilyが有効な間は削除せず、reuse検知に使う。
- 期限切れ・失効済みデータはcapability制限されたJavaScript scheduleから定期清掃する。ChatGPTがconnector instanceごとにDCR clientを再利用するため、DCR clientの自動削除期限は10年とし、有効な認証情報が残るclientは削除しない。

初回VPS環境は単一の業務利用者を前提とする。OAuth上はuserを保持するが、既存のスタンプテーブル自体はuser IDで分離されていない。複数利用者へ拡張する場合は、Toolへ渡すprincipalと業務テーブルのuser IDを結び付ける別設計を先に行う。

## 12. MCP protocol

### 12.1 初回対象version

ChatGPT Developer modeでの初回動作確認はMCP `2025-11-25` を受入基準とする。

実装対象は次のとおりとする。

- Streamable HTTP
- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`
- `MCP-Protocol-Version`
- JSON-RPC error
- Tool `securitySchemes`
- Tool `annotations`
- Tool結果の `structuredContent`、`content`、`isError`、`_meta`

`MCP-Session-Id` は発行しない。2025-11-25では任意であり、OAuthとSQLiteを明示的な状態源とするため、MCP transport自体はsessionlessにする。

MCP `2026-07-28` はwire形式とライフサイクルに破壊的変更があるため、初回実装の対象外とする。将来対応する場合も新しいGoファイルは作らず、`main.go` 内のversion adapterとして追加する。

### 12.2 ChatGPT認証UI

ChatGPTのTool単位の認証導線に必要な次の三点をすべて実装する。

1. Protected Resource Metadata
2. Toolごとの `securitySchemes`
3. 認証失敗結果の `_meta["mcp/www_authenticate"]`

`initialize` と `tools/list` ではToolの発見を可能にし、保護対象の `tools/call` でguardを実行する。認証が必要なToolを匿名実行させてはならない。

## 13. `main.go` の変更範囲

### 13.1 追加する汎用処理

- `APIConfig` の `http`、`runtime`、MCP設定
- 設定のdecode、validation、deep clone、snapshot反映
- 設定されたHTTP pathのdispatch
- HTTP methodとaccessの検証
- `nyanRequest` の構築
- raw HTTPレスポンスの検証と出力
- MCP Streamable HTTP
- MCP Tool設定の解決
- 既存APISchemaのMCP Toolへの変換
- MCP引数検証
- 既存NyanQL APIの内部実行
- guard API実行と判定結果の反映
- JavaScript用の汎用暗号・password関数
- 機密値のログredaction

### 13.2 追加しないOAuth固有処理

- OAuth endpoint pathの定数
- OAuth専用router
- OAuth専用Go handler
- OAuth用Go DB store
- client登録処理
- redirect URIのOAuth固有判定
- PKCEの状態遷移
- 認可コード発行
- access/refresh token発行
- scopeやaudienceのOAuth固有判定
- OAuthテーブルを直接操作するGoコード
- ChatGPT callback URLのハードコード

MCP protocolに必要な `initialize`、`tools/list`、`tools/call` はGo基盤に含めるが、OAuthの `authorize`、`token`、`register` は含めない。

## 14. セキュリティ要件

- OAuth、MCP、well-known endpointは有効なTLSでのみ公開する。
- redirect URIは完全一致で検証する。
- PKCEはS256のみ許可する。
- `resource` をauthorizeとtokenの両方で要求し、canonical MCP URLと完全一致させる。
- codeとtokenは十分に長いCSPRNG値とする。
- codeは短寿命・一回限りとする。
- access tokenは短寿命、refresh tokenは期限付き・rotation必須とし、期限・失効・scope・resourceを毎回検証する。
- refresh tokenのreuse時はfamilyに属するaccess tokenとrefresh tokenをすべて失効する。
- passwordはArgon2idで保存する。
- code、token、password、Authorization header、client secretをログへ記録しない。
- 公開endpointへrate limitを設定できる構造とする。
- HTTP `Origin` がある場合は許可originを検証する。サーバー間通信で `Origin` がないことだけを理由に拒否しない。
- 許可originは `api.vps.json` の完全一致allowlistで宣言し、ChatGPT固有originをGoへハードコードしない。
- OAuth VMではhost command、任意ファイル操作、任意HTTPアクセスを許可しない。
- `api.json` のMCP Toolは明示allowlistとする。
- Hot reload時に不正な新設定があれば、動作中の正常なsnapshotを維持する。
- API設定の未知フィールドとセキュリティ設定の誤った階層をfail closedで拒否する。
- SQL結果は行数とJSON容量、MCP/HTTP応答はbody容量に上限を設ける。

## 15. ファイル構成

Goファイルは増やさない。

```text
main.go
main_test.go
api.json
api.vps.json
config.json
config.vps.json.example
docs/
  paramcheck-outcheck-schema-design.md
  nyanql-mcp-oauth-design.md
javascript/
  oauth/
    protected_resource_metadata.js
    authorization_server_metadata.js
    register.js
    authorize.js
    token.js
    revoke.js
    bootstrap_user.js
    verify_access.js
    cleanup.js
sql/
  oauth/
    001_init.sql
    002_reset_pre_policy_credentials.sql
    003_add_refresh_tokens.sql
    ...
```

VPS向けに別名の設定を管理する場合は、秘密情報を含まない `api.vps.json` を転送時に `api.json` とする。TLS pathなどを含むVPS用設定もテンプレートから `config.json` として配置する。パスワード、token、秘密鍵の内容はGitへ保存しない。

## 16. 実装フェーズ

### フェーズ1: 汎用HTTP bridge

- `http` / `runtime` 設定
- `nyanRequest`
- rawレスポンス
- anonymous / basic / internal
- header、body、method検証
- capability制限
- ログredaction

完了条件:

- OAuth固有処理なしで、JavaScriptからJSON、HTML、302、400、401を返せる。
- 既存APIのBasic認証とレスポンスが変わらない。
- internal APIへHTTPアクセスできない。

### フェーズ2: MCP基盤

- MCP 2025-11-25 Streamable HTTP
- initialize / initialized
- tools/list / tools/call
- Tool allowlist
- 既存スキーマ接続
- MCP引数検証
- 既存API実行
- security schemes / annotations

完了条件:

- MCP Inspectorから接続できる。
- 設定したToolだけが表示される。
- `paramCheck` / `outCheck` / SQL由来のスキーマが反映される。
- 無効な引数で既存APIを実行しない。

### フェーズ3: JavaScript OAuth / SQLite

- SQLite migration
- 初期userの安全な登録方法
- metadata
- DCR
- authorize
- PKCE
- token
- offline access / refresh token rotation / reuse検知
- revoke
- MCP guard
- 期限切れOAuthデータのschedule清掃

完了条件:

- codeを再利用できない。
- redirect URI、resource、PKCE、scope不一致を拒否する。
- tokenの平文がSQLiteとログに残らない。
- 期限切れ・失効tokenを拒否する。
- refresh tokenの並行交換は一件だけ成功し、reuse検知時はfamily全体を失効する。

### フェーズ4: ローカル結合テスト

- `go test ./...`
- `go test -race ./...`
- MCP Inspector
- DCRからBearer付きTool実行までのend-to-endテスト

### フェーズ5: VPS反映

- `api.vps.json` をVPSの `api.json` として配置
- `config.json` に直接TLSの証明書pathを設定
- SQLite migrationを番号順に適用
- systemd再起動
- well-known、DCR、authorize、token、MCPを順番に確認

### フェーズ6: ChatGPT Developer mode確認

- MCP URLとして `https://stamp.necomori.asia/mcp` を登録
- Tool metadataを確認
- OAuthログイン画面を確認
- callbackからtoken交換まで確認
- 認証済みTool呼び出しを確認
- scope不足、失効、再認可を確認

## 17. テスト項目

すべてのGoテストは既存の `main_test.go` に追加する。

最低限、次を自動テストする。

- `http` 未指定APIの後方互換性
- anonymous / basic / internalの分離
- method違反の405
- raw responseのstatus、header、body
- CRLF headerとhop-by-hop headerの拒否
- bodyサイズ制限
- SQL結果とMCP応答のサイズ制限
- Origin完全一致と拒否
- 未知フィールドおよび誤った設定階層の拒否
- OAuth scope-tokenの文字制限
- capability未許可関数の利用拒否
- MCP initialize
- MCP tools/list
- Tool allowlist
- schema優先順位とMCPへの反映
- MCP引数検証
- MCP tools/callから既存API実行
- guardの許可・拒否
- `_meta["mcp/www_authenticate"]`
- DCR入力検証
- redirect URI完全一致
- PKCE S256成功・失敗
- resource一致・不一致
- code一回消費
- token期限・失効・scope
- offline_access時のrefresh token発行とhashのみの保存
- refresh token rotation、縮小scope、client/resource binding
- 使用済みrefresh tokenのreuseによるfamily全体の失効
- 同一refresh tokenの並行交換
- refresh tokenの明示失効と清掃
- DCR redirect URI許可範囲とclient数上限
- 期限切れOAuthデータの清掃
- code、token、Authorizationがログに出ないこと
- api.json hot reload時のsnapshot整合性

## 18. 初回対象外

- CIMD
- `private_key_jwt`
- OpenID Connect / ID Token
- MCP 2026-07-28
- Nginx経由のTLS終端
- JWT access token
- 外部IdPとの接続
- OAuthデータ専用の別Go DB接続
- 全APIのMCP自動公開
- 通常HTTP APIへのJSON Schema実行時検証

refresh tokenを無期限にする構成、rotationなしで再利用できる構成は対象外とする。

## 19. 完了条件

本機能は、次のすべてを満たした時点で完了とする。

- 新しい `.go` ファイルが作成されていない。
- Go変更が `main.go`、Goテスト変更が `main_test.go` に限定されている。
- `main.go` にOAuth専用router、store、状態機械が存在しない。
- OAuth endpointとTool公開設定が `api.json` に存在する。
- OAuthの処理とSQLite操作がJavaScript / SQLに存在する。
- `offline_access` とrefresh token rotationによりChatGPTがaccess token期限後も接続を更新できる。
- 既存APIのBasic認証とレスポンス形式が維持されている。
- MCP Inspectorで認証前後のTool呼び出しを確認できる。
- VPS上でNyanQL自身のTLSによりMCP endpointへ接続できる。
- ChatGPT Developer modeでOAuth認証を完了し、認証済みToolを実行できる。
- `go test ./...` と `go test -race ./...` が成功する。

## 20. 参考仕様

- OpenAI Authentication: <https://developers.openai.com/plugins/build/auth>
- OpenAI Developer mode and MCP apps in ChatGPT: <https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt>
- OpenAI Build an MCP server: <https://developers.openai.com/plugins/build/mcp-server>
- OpenAI Connect and test your plugin: <https://developers.openai.com/plugins/deploy/connect-chatgpt>
- MCP 2025-11-25 Authorization: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- MCP 2025-11-25 Streamable HTTP: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
- RFC 9728 OAuth 2.0 Protected Resource Metadata: <https://www.rfc-editor.org/rfc/rfc9728.html>
- RFC 8707 Resource Indicators for OAuth 2.0: <https://www.rfc-editor.org/rfc/rfc8707.html>
- RFC 7591 OAuth 2.0 Dynamic Client Registration: <https://www.rfc-editor.org/rfc/rfc7591.html>
- Let's Encrypt Challenge Types: <https://letsencrypt.org/docs/challenge-types/>
- Certbot Webroot: <https://eff-certbot.readthedocs.io/en/stable/using.html#webroot>
