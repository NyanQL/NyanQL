# NyanQL `paramCheck` / `outCheck` スキーマ設計メモ

## 1. 文書の目的

NyanQLの各APIについて、入力と正常終了時出力の構造を機械的に取得できるようにするため、今回合意した仕様と実装方針を記録する。

この情報は、次の用途で再利用できる内部形式を目指す。

- `/nyan/{API名}` でのAPI情報表示
- 将来のOpenAPI出力
- 将来のMCP Toolの `inputSchema` / `outputSchema`

この文書の段階では実装を行わず、実装を安全な単位へ分割する。

## 2. 基本方針

- `api.json` の構造は変更しない。
- `api.json` に `inputSchema` や `outputSchema` は追加しない。
- 実装コードは既存の `main.go` 内に収め、新しいGoソースファイルは追加しない。
- テストコードは既存の `main_test.go` に追加する。
- 利用者向けの説明はREADME、設計判断と実装フェーズはこの文書に記録する。
- 入力スキーマは `paramCheck` JavaScript内の `nyanInputSchema` から取得する。
- 出力スキーマは `outCheck` JavaScript内の `nyanOutputSchema` から取得する。
- JavaScript内のスキーマはJSON Schema Draft 2020-12向けの情報として扱う。
- 利用者が記載したスキーマオブジェクトをNyanQL側で変更しない。
- `$schema` が省略されていてもNyanQL側から自動追加しない。
- スキーマ取得のためにJavaScriptを実行しない。
- 明示スキーマがない場合はSQL解析へフォールバックし、入力だけは既存の `nyanAcceptedParams` も候補にする。
- スキーマを取得できなくても、既存APIの起動や実行を失敗させない。
- `paramCheck` / `outCheck` による従来のチェック処理は変更しない。

## 3. 今回の対象

### 3.1 対象に含めるもの

- `nyanInputSchema` の静的抽出
- `nyanOutputSchema` の静的抽出
- SQLからの入力スキーマ生成
- SQLからの出力スキーマ生成
- 既存の `nyanAcceptedParams` への入力スキーマのフォールバック
- `/nyan/{API名}` の取得時にスキーマと取得元を都度解決
- `/nyan/{API名}` での `inputSchema` / `outputSchema` / `schemaSource` 出力
- include配下のAPIへの適用
- SQL、script、paramCheck、outCheck変更の次回詳細取得への即時反映
- 後方互換テストとREADME更新

### 3.2 今回の対象外

- JSON Schema Draft 2020-12のメタスキーマによる完全検証
- JSON Schemaを使った入力値の実行時検証
- JSON Schemaを使った出力値の実行時検証
- GETパラメータのスキーマに基づく型変換
- JSON Schema検証ライブラリの追加
- OpenAPI文書そのものの生成
- MCP Server / MCP Toolそのものの生成
- 動的に生成されるJavaScriptスキーマ
- SQL式からの完全な型推論
- DB固有型の完全なJSON Schema変換
- SQL、script、paramCheck、outCheckファイル自体のホットリロード監視

構造検証や業務チェックが必要な場合は、従来どおり `paramCheck` / `outCheck` のJavaScriptで実装できる。

## 4. JavaScriptでの明示スキーマ

### 4.1 入力スキーマ

`paramCheck` ファイルのトップレベルへ記述する。

```js
const nyanInputSchema = {
  type: "object",
  properties: {
    id: {
      type: "integer",
      minimum: 1,
      description: "取得する商品ID",
      examples: [1]
    }
  },
  required: ["id"],
  additionalProperties: false
};
```

### 4.2 出力スキーマ

`outCheck` ファイルのトップレベルへ記述する。

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
```

出力スキーマは `result` だけではなく、NyanQLの正常レスポンス全体を表す。

## 5. ASTによる静的抽出

現在利用しているgojaに含まれる `github.com/dop251/goja/parser` と `github.com/dop251/goja/ast` を使用する。新しい外部依存は追加しない。

JavaScriptファイル全体を実行せず、トップレベルにある次の宣言を構文木から探す。

```js
const nyanInputSchema = { ... };
const nyanOutputSchema = { ... };
```

### 5.1 静的に許可する値

- オブジェクトリテラル
- 配列リテラル
- 文字列
- 数値（負数を含む）
- 真偽値
- `null`

ASTからGoのJSON互換値へ変換し、`json.Encoder`でJSONオブジェクトとして出力する。

元のJavaScriptの次の情報は保持しない。

- コメント
- インデントや改行
- プロパティの記述順
- キーの引用符の有無

スキーマとしてのオブジェクト構造と値は保持する。

### 5.2 対象外とする動的定義

次のような定義はJavaScript実行が必要になるため、初期実装では許可しない。

```js
const nyanInputSchema = createSchema();
```

```js
const schemaType = "object";
const nyanInputSchema = {type: schemaType};
```

```js
const nyanInputSchema = {
  ...commonSchema,
  type: "object"
};
```

```js
const nyanInputSchema = condition ? schemaA : schemaB;
```

制限するのはスキーマ定義部分だけであり、その後の `paramCheck` / `outCheck` 本体では従来どおり動的なJavaScriptを使用できる。

### 5.3 宣言なしと不正な宣言の違い

- スキーマ宣言がない場合はエラーにせず、次の取得元へフォールバックする。
- 宣言はあるが動的な値、非オブジェクト、重複宣言などで解釈できない場合は設定エラーにする。
- 動的な式を文字列化して出力しない。
- 解釈できない明示宣言を無視してSQLへ暗黙フォールバックしない。

例:

```js
const nyanInputSchema = createSchema();
```

想定エラー:

```text
nyanInputSchema must be a static object literal; function calls are not supported
```

API設定の読み込みは妨げない。対象の `/nyan/{API名}` を取得した時点でスキーマ解決エラーを返し、ファイル修正後の次回取得で再度解決する。

## 6. スキーマ取得優先順位

### 6.1 入力スキーマ

1. `paramCheck` ファイル内の `nyanInputSchema`
2. SQLファイルの解析による自動生成
3. APIのscript内にある既存の `nyanAcceptedParams`
4. 空スキーマ `{}`

`paramCheck` が存在しても、`nyanInputSchema` が存在しなければSQL解析へ進む。

### 6.2 出力スキーマ

1. `outCheck` ファイル内の `nyanOutputSchema`
2. SQLファイルの解析による自動生成
3. 空スキーマ `{}`

`outCheck` が存在しても、`nyanOutputSchema` が存在しなければSQL解析へ進む。

### 6.3 取得元

内部および `/nyan/{API名}` では次の値を使用する。

- `paramCheck`
- `outCheck`
- `sql`
- `scriptLegacy`
- `unknown`

`scriptLegacy` は入力をscript内の `nyanAcceptedParams` から取得した場合だけ使用する。出力の取得元は `outCheck`、`sql`、`unknown` のいずれかになる。

## 7. SQLからの入力スキーマ生成

### 7.1 型推測

| SQL記述 | 生成するスキーマ |
|---|---|
| `/*id*/1` | `type: "integer"`, `examples: [1]` |
| `/*price*/1.5` | `type: "number"`, `examples: [1.5]` |
| `/*name*/'cat'` | `type: "string"`, `examples: ["cat"]` |
| `/*enabled*/true` | `type: "boolean"`, `examples: [true]` |
| `IN (/*ids*/1)` | 配列、`items.type: "integer"` |
| `IN (/*codes*/'A')` | 配列、`items.type: "string"` |

2way-SQLコメント後の値は、APIの既定値ではなくSQL単体実行用のテスト値である。そのため `default` ではなく `examples` として扱う。

### 7.2 必須判定

- `/*IF ...*/` の外側にあるパラメータは必須とする。
- `/*IF ...*/` の内側にだけあるパラメータは任意とする。
- IF条件式にだけ登場するパラメータは、型不明の任意プロパティとして扱う。
- `/*BEGIN*/` は任意条件を意味しないため、BEGIN内という理由だけでは任意にしない。
- 同じパラメータが任意位置と必須位置の両方にあれば必須とする。

### 7.3 複数SQL

- 入力パラメータはすべてのSQLファイルから統合する。
- 同名パラメータの型を安全に統合できない場合は、型を勝手に確定せず空スキーマ `{}` へ寄せる。
- 自動生成した入力スキーマは `additionalProperties: true` とする。

## 8. SQLからの出力スキーマ生成

### 8.1 SELECT / RETURNING

- `SELECT` または `RETURNING` の列名を取得する。
- 初期実装では明示された `AS` 別名を優先する。
- 静的解析で型を確定しない。各列のスキーマは `{}` とする。
- すべての列名を安全に特定できる場合だけ、行オブジェクトを `additionalProperties: false` とする。
- `SELECT *` や解析不能な列がある場合は、実際の正常出力を過度に制限しないスキーマへフォールバックする。

結果セットを返す場合は、NyanQLの正常レスポンス全体を次の形で表す。

```json
{
  "type": "object",
  "properties": {
    "success": {"const": true},
    "status": {"const": 200},
    "result": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {},
          "name": {}
        },
        "required": ["id", "name"],
        "additionalProperties": false
      }
    }
  },
  "required": ["success", "status", "result"],
  "additionalProperties": false
}
```

### 8.2 更新SQL

行を返さない `INSERT` / `UPDATE` / `DELETE` などは、現行NyanQLの `result: {}` に合わせる。

```json
{
  "type": "object",
  "properties": {
    "success": {"const": true},
    "status": {"const": 200},
    "result": {
      "type": "object",
      "additionalProperties": false
    }
  },
  "required": ["success", "status", "result"],
  "additionalProperties": false
}
```

`RETURNING` がある場合は結果セットとして扱う。

### 8.3 複数SQL

現在のNyanQLは複数SQLを順番に実行し、最後に実行したSQLの結果をレスポンスに使用する。そのため、自動出力スキーマも最後のSQLを基準に生成する。

## 9. 既存入力定数からのフォールバック

既存機能を維持する。

```js
const nyanAcceptedParams = {
  id: 1
};
```

- `nyanAcceptedParams` はAPI本体の `script` から取得する。
- 明示入力スキーマまたはSQL入力スキーマが存在する場合は、`nyanAcceptedParams` よりそちらを優先する。
- 明示的な `nyanInputSchema` がある場合、`/nyan/{API名}` では `nyanAcceptedParams` を省略する。それ以外で値を取得できた場合は引き続き表示する。
- 新しいAST抽出を共通化できる場合でも、既存の有効な記述を壊さないことをテストする。

既存入力定数から新しいスキーマへ変換する際は、安全に判断できる値だけ型と `examples` に使用する。判断できない場合は `{}` とする。

旧形式の `nyanOutputColumns` は廃止する。script APIの出力スキーマを公開する場合は、`outCheck` に `nyanOutputSchema` を定義する。

## 10. 空スキーマ

明示スキーマ、SQL、入力の既存定数のどれからも取得できない場合は空スキーマ `{}` を使用する。出力には既存定数のフォールバックを設けない。

```json
{
  "api": "sample",
  "description": "サンプルAPI",
  "inputSchema": {},
  "outputSchema": {},
  "schemaSource": {
    "input": "unknown",
    "output": "unknown"
  }
}
```

空スキーマは「構造を特定できない」ことを表す。今回NyanQLはスキーマによる実行時検証を行わないため、API実行には影響しない。

## 11. 推奨内部構造

概念例:

```go
type APISchema struct {
    Input        map[string]interface{}
    Output       map[string]interface{}
    InputSource  string
    OutputSource string
}
```

`APIConfigSnapshot` にはAPI定義だけを保持し、スキーマは保持しない。`/nyan/{API名}` の詳細取得時に、スナップショットから対象の `APIConfig` を選び、その設定が参照するファイルを読み直して `APISchema` を構築する。

- API定義の選択にはリクエスト開始時のスナップショットを使用する。
- スキーマ本体はリクエストごとに関連ファイルから解決する。
- include配下のAPIも完全API名から対象の `APIConfig` を選ぶ。
- 明示スキーマの抽出失敗は対象の詳細取得だけをエラーにする。
- `/nyan/` の一覧取得ではスキーマ解決を行わない。

## 12. `/nyan/{API名}` の変更

既存の入力情報と共存させながら、次を追加する。

```json
{
  "api": "getItem",
  "description": "商品を1件取得します",
  "nyanAcceptedParams": {
    "id": 1
  },
  "inputSchema": {
    "type": "object"
  },
  "outputSchema": {
    "type": "object"
  },
  "schemaSource": {
    "input": "paramCheck",
    "output": "sql"
  }
}
```

- `inputSchema` / `outputSchema` はJSON文字列ではなくJSONオブジェクトとして返す。
- `$schema` は利用者が記載した場合だけ含め、省略時に自動追加しない。
- 明示的な `nyanInputSchema` がある場合は旧形式の `nyanAcceptedParams` を省略する。明示スキーマがない場合は、取得できた `nyanAcceptedParams` を維持する。
- mount配下のAPIは `/nyan/sub/getItem` のように完全API名で取得する。
- `/nyan/` のフラットな `apis` 一覧は変更しない。

## 13. ホットリロードの扱い

初期実装では、現在と同じく次だけを監視する。

- ルート `api.json`
- includeされたすべてのJSONファイル

次のファイル自体は監視しない。

- SQL
- script
- paramCheck
- outCheck

これらのファイル自体を監視対象には追加しないが、スキーマは `/nyan/{API名}` の取得ごとに読み直す。そのため、スキーマ記述の変更は次回の詳細取得から反映され、NyanQLの再起動や `api.json` の更新は不要である。

## 14. 後方互換性

- `paramCheck`、互換エイリアスの `check`、`outCheck` の実行順や結果を変更しない。
- APIの入力値や出力値を新しいスキーマで検証しない。
- 既存レスポンス形式を変更しない。ただし `/nyan/{API名}` には新しいフィールドを追加する。
- スキーマ宣言がない既存APIをエラーにしない。
- SQL解析で情報を取得できなくても既存APIをエラーにしない。
- includeを使用しないAPIとinclude配下APIの両方を同じルールで扱う。
- スキーマ解決に失敗してもAPI設定、schedule、ws_clientの読み込みには影響させず、対象のAPI詳細だけをエラーにする。

## 15. 実装フェーズ

一度にAPI実行経路まで変更せず、次の順で1フェーズずつ実装する。

すべてのフェーズで、実装関数と構造体は `main.go`、テストは `main_test.go` に追加する。スキーマ機能専用の新しい `.go` ファイルは作成しない。

### フェーズ1: 静的AST値変換

目的:

- goja parserでJavaScriptをASTへ変換する。
- ASTの静的リテラルをGoのJSON互換値へ変換する。
- まだAPI設定読み込みや `/nyan` へ接続しない。

実装対象:

- オブジェクト、配列、文字列、数値、真偽値、`null` の変換
- 負数の変換
- 動的式、spread、参照、関数呼び出しの拒否
- エラーにファイル名、定数名、対象箇所を含める

完了条件:

- ネストしたスキーマを抽出できる。
- JavaScript本体を実行しない。
- 動的定義を明確なエラーにできる。
- 既存テストとraceテストが成功する。

### フェーズ2: スキーマ定数の抽出

目的:

- `paramCheck` / `outCheck` ファイルから対象定数を取得する。
- 宣言なしと不正宣言を区別する。

実装対象:

- トップレベルの `const nyanInputSchema`
- トップレベルの `const nyanOutputSchema`
- 重複宣言、非オブジェクト、動的右辺のエラー
- `$schema` を含む利用者オブジェクトの無変更保持
- 宣言がない場合を「未定義」として返す

完了条件:

- 明示入力・出力スキーマをJSON互換mapとして取得できる。
- `$schema` を追加・削除・変更しない。
- 宣言なしはエラーにならない。
- 動的な明示宣言はエラーになる。

### フェーズ3: SQL入力スキーマ生成

目的:

- SQLプレースホルダーから入力スキーマを生成する。

実装対象:

- integer、number、string、booleanの推測
- `IN (...)` の配列推測
- テスト値を `examples` として保持
- IFブロック内外の必須判定
- IF条件だけにあるパラメータ
- 複数SQLの統合
- 型競合時の安全なフォールバック

完了条件:

- 仕様例の入力スキーマを生成できる。
- 任意パラメータを `required` に含めない。
- `additionalProperties: true` になる。
- `default` を生成しない。

### フェーズ4: SQL出力スキーマ生成

目的:

- SQLの実際のレスポンス形式に合わせた出力スキーマを生成する。

実装対象:

- SELECT列の `AS` 別名抽出
- RETURNING列の抽出
- 更新SQLの `result: {}`
- 列型を `{}` とする安全な生成
- `SELECT *` や解析不能SQLのフォールバック
- 複数SQLでは最後のSQLを採用

完了条件:

- SELECTの列名が `result.items.properties` に入る。
- 安全に列名を確定できない場合に過度な制約を生成しない。
- 更新SQLが現行レスポンスと一致する。

### フェーズ5: フォールバック解決

目的:

- 優先順位に従ってAPIごとの最終スキーマを構築する。
- API詳細取得時に優先順位どおり解決できるようにする。

実装対象:

- 明示スキーマ、SQL、既存入力定数、空スキーマの順序
- 既存 `nyanAcceptedParams` の取得と変換
- `APISchema` と取得元
- include配下の完全API名
- `/nyan/{API名}` ごとの都度読込

完了条件:

- API詳細取得時に入力・出力スキーマと取得元が存在する。
- スキーマなしAPIは `unknown` と `{}` になる。
- 不正な明示スキーマは対象の詳細取得だけを失敗させる。
- ファイル修正が次回の詳細取得へ反映される。

### フェーズ6: `/nyan/{API名}` への公開

目的:

- リクエスト時に解決したスキーマをAPI詳細として返す。

実装対象:

- `inputSchema`
- `outputSchema`
- `schemaSource.input`
- `schemaSource.output`
- 既存入力フィールドとの共存
- mountを含む完全API名

完了条件:

- スキーマがJSONオブジェクトとして返る。
- `$schema` を自動追加しない。
- 明示入力スキーマがない場合は、既存の `nyanAcceptedParams` が維持される。
- `nyanOutputColumns` は返らない。
- `/nyan/` の `apis` 一覧は変わらない。

### フェーズ7: README・統合テスト・最終監査

目的:

- 利用方法と制約を文書化し、既存機能への影響がないことを確認する。

実装対象:

- READMEの明示スキーマ例
- SQLフォールバックの説明
- 動的スキーマが対象外であることの説明
- SQL、script、paramCheck、outCheckが監視対象外であることの説明
- include配下APIの統合テスト
- 起動、ホットリロード、後方互換テスト

完了条件:

- `gofmt` を実行している。
- `go test ./...` が成功する。
- `go test -race ./...` が成功する。
- READMEと実装が一致する。
- 未解決事項を完了報告に記載する。

## 16. 将来拡張

初期実装後、必要性を確認して次を別仕様として検討する。

1. 同一ファイル内の静的 `const` 参照
2. 静的 `const` オブジェクトのspread
3. JSON Schemaライブラリを使った実行時検証
4. GETパラメータの型変換規則
5. NyanQL内部パラメータを除外した入力検証
6. SQL、script、paramCheck、outCheckの依存ファイル監視
7. OpenAPI 3.1文書生成
8. MCP Tool定義生成

任意の関数実行による動的スキーマ生成は、副作用、無限ループ、環境依存、依存ファイル追跡、スキーマの非決定性を解決できる場合に限って検討する。
