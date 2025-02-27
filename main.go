package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dop251/goja"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/cors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Name              string          `json:"name"`
	Profile           string          `json:"profile"`
	Version           string          `json:"version"`
	Port              int             `json:"Port"`
	CertPath          string          `json:"CertPath"`
	KeyPath           string          `json:"KeyPath"`
	DatabaseType      string          `json:"DBType"`
	DBUsername        string          `json:"DBUser"`
	DBPassword        string          `json:"DBPassword"`
	DBName            string          `json:"DBName"`
	DBHost            string          `json:"DBHost"`
	DBPort            string          `json:"DBPort"`
	BasicAuth         BasicAuthConfig `json:"BasicAuth"`
	Log               LogConfig       `json:"log"`
	JavascriptInclude []string        `json:"javascript_include,omitempty"` // 新規フィールド
}

// BasicAuthConfig represents basic authentication configuration
type BasicAuthConfig struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

// LogConfig represents logging configuration
type LogConfig struct {
	Filename      string `json:"Filename"`
	MaxSize       int    `json:"MaxSize"`
	MaxBackups    int    `json:"MaxBackups"`
	MaxAge        int    `json:"MaxAge"`
	Compress      bool   `json:"Compress"`
	EnableLogging bool   `json:"EnableLogging"`
}

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Error interface{} `json:"error"`
}

type APIConfig struct {
	SQL         []string `json:"sql,omitempty"`    // SQL ファイルのパス。存在しなければ nil または空スライス
	Script      []string `json:"script,omitempty"` // 任意の JavaScript ファイルを配列で指定可能
	Check       string   `json:"check,omitempty"`  // 単一のチェック用 JavaScript ファイル。必要に応じて省略可能
	Description string   `json:"description"`      // 説明文。ここは必須とするか、必要ならomitemptyを付けてもよい
}

var config Config
var db *sql.DB
var sqlFiles map[string]APIConfig
var dbType string
var reParams = regexp.MustCompile(`(?s)\/\*\s*([^*\/]+)\s*\*\/\s*(?:'([^']*)'|([^\s,;]+))`)

type DetailResponse struct {
	API                string                 `json:"api"`
	Description        string                 `json:"description"`
	NyanAcceptedParams map[string]interface{} `json:"nyanAcceptedParams"`
}

func main() {
	// 現在の作業ディレクトリを取得
	execDir, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir = filepath.Dir(execDir) // 実行ファイルのディレクトリを取得

	configFilePath := filepath.Join(execDir, "config.json")
	configFile, err := os.Open(configFilePath)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode config JSON: %v", err)
	}

	// Adjust relative paths in the configuration
	adjustPaths(execDir, &config)

	// Display version
	log.Printf("Starting application version: %s", config.Version)

	// Configure logger
	setupLogger(execDir)

	// Connect to the database
	db, err = connectDB(config)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	loadSQLFiles(execDir)

	// Set up CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	// /nyan エンドポイントの登録（Basic Auth も適用）
	http.Handle("/nyan/", corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic Auth はまとめて掛けたい場合、ここでラップ
		basicAuth(handleNyanOrDetail, config)(w, r)
	})))

	// Wrap handler with CORS and basic auth
	http.Handle("/", corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basicAuth(handleRequest, config)(w, r)
	})))

	if config.CertPath != "" && config.KeyPath != "" {
		log.Printf("Server starting on HTTPS port %d\n", config.Port)
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", config.Port), config.CertPath, config.KeyPath, nil))
	} else {
		log.Printf("Server starting on HTTP port %d\n", config.Port)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
	}
}

func adjustPaths(execDir string, config *Config) {
	if config.CertPath != "" && !filepath.IsAbs(config.CertPath) {
		config.CertPath = filepath.Join(execDir, config.CertPath)
	}
	if config.KeyPath != "" && !filepath.IsAbs(config.KeyPath) {
		config.KeyPath = filepath.Join(execDir, config.KeyPath)
	}
	if config.DatabaseType == "sqlite" && config.DBName != "" && !filepath.IsAbs(config.DBName) {
		config.DBName = filepath.Join(execDir, config.DBName)
	}
}

func loadSQLFiles(execDir string) {
	apiFilePath := filepath.Join(execDir, "api.json")
	data, err := ioutil.ReadFile(apiFilePath)
	if err != nil {
		log.Fatalf("Failed to read SQL files config: %v", err)
	}
	if err := json.Unmarshal(data, &sqlFiles); err != nil {
		log.Fatalf("Failed to decode SQL files JSON: %v", err)
	}

	// Update SQL file paths to be absolute if they are relative
	for apiKey, apiConfig := range sqlFiles {
		for i, sqlPath := range apiConfig.SQL {
			if !filepath.IsAbs(sqlPath) {
				sqlFiles[apiKey].SQL[i] = filepath.Join(execDir, sqlPath)
			}
		}
	}
}

func setupLogger(execDir string) {
	logFilePath := filepath.Join(execDir, config.Log.Filename)
	if config.Log.EnableLogging {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    config.Log.MaxSize,
			MaxBackups: config.Log.MaxBackups,
			MaxAge:     config.Log.MaxAge,
			Compress:   config.Log.Compress,
		})
	} else {
		log.SetOutput(os.Stdout)
	}
}

func connectDB(config Config) (*sql.DB, error) {
	var driverName, dsn string
	switch config.DatabaseType {
	case "mysql":
		driverName = "mysql"
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", config.DBUsername, config.DBPassword, config.DBHost, config.DBPort, config.DBName)
	case "postgres":
		driverName = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", config.DBHost, config.DBPort, config.DBUsername, config.DBPassword, config.DBName)
	case "sqlite":
		driverName = "sqlite3"
		dsn = config.DBName
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.DatabaseType)
	}
	dbType = driverName
	return sql.Open(driverName, dsn)
}

// リクエストの処理
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}

	contentType := r.Header.Get("Content-Type")
	var params map[string]interface{}

	if contentType == "application/json" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			sendJSONError(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			sendJSONError(w, "Error parsing JSON data", http.StatusBadRequest)
			return
		}
		log.Printf("Received JSON: %v", data)
		params = data
	} else {
		if err := r.ParseForm(); err != nil {
			sendJSONError(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		params = make(map[string]interface{})
		for key, values := range r.Form {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	}

	// URLパスが "/" 以外の場合、apiパラメータとして扱う
	if r.URL.Path != "/" {
		// 先頭の "/" を除去して api 名を取得
		apiName := strings.TrimPrefix(r.URL.Path, "/")
		if apiName != "" {
			// すでに "api" が指定されていなければ、URLパスの値を設定
			if _, exists := params["api"]; !exists {
				params["api"] = apiName
			}
		}
	}

	apiKey, ok := params["api"].(string)
	if !ok || apiKey == "" {
		sendJSONError(w, "API key is required and must be a string", http.StatusBadRequest)
		return
	}

	apiConfig, exists := sqlFiles[apiKey]
	if !exists {
		sendJSONError(w, "SQL files not found", http.StatusNotFound)
		return
	}
	log.Print(apiConfig.SQL)

	// チェック用の JavaScript ファイルが指定されている場合、goja を使って事前チェックを実施
	if apiConfig.Check != "" {
		success, statusCode, errorObj, err := runCheckScript(apiConfig.Check, params)
		if err != nil {
			log.Printf("Check script error: %v", err)
			sendJSONError(w, err.Error(), statusCode)
			return
		}
		if !success {
			// errorObj が nil ならデフォルトメッセージを返す
			if errorObj == nil {
				errorObj = "Request check failed"
			}
			sendJSONError(w, errorObj, statusCode)
			return
		}
	}

	var tx *sql.Tx
	var err error
	if len(apiConfig.SQL) > 1 {
		tx, err = db.Begin()
		if err != nil {
			log.Printf("Failed to start transaction: %v", err)
			sendJSONError(w, "Failed to start transaction", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()
		log.Print("Transaction started")
	}

	var lastJSON []byte
	for _, sqlPath := range apiConfig.SQL {
		query, err := ioutil.ReadFile(sqlPath)
		if err != nil {
			log.Printf("Failed to read SQL file: %v", err)
			sendJSONError(w, "Error reading SQL file", http.StatusInternalServerError)
			return
		}
		log.Print(string(query))
		queryStr, args := prepareQueryWithParams(string(query), params)

		if isSelectQuery(queryStr) {
			var rows *sql.Rows
			if tx != nil {
				rows, err = tx.Query(queryStr, args...)
			} else {
				rows, err = db.Query(queryStr, args...)
			}
			if err != nil {
				log.Printf("Failed to execute SQL query: %v", err)
				sendJSONError(w, "Error executing SQL query", http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			lastJSON, err = RowsToJSON(rows)
			if err != nil {
				log.Printf("Failed to convert rows to JSON: %v", err)
				sendJSONError(w, "Error formatting results", http.StatusInternalServerError)
				return
			}
		} else {
			var result sql.Result
			if tx != nil {
				result, err = tx.Exec(queryStr, args...)
			} else {
				result, err = db.Exec(queryStr, args...)
			}
			if err != nil {
				log.Printf("Failed to execute SQL query: %v", err)
				sendJSONError(w, "Error executing SQL query", http.StatusInternalServerError)
				return
			}
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				log.Printf("Failed to retrieve rows affected: %v", err)
				sendJSONError(w, "Error retrieving rows affected", http.StatusInternalServerError)
				return
			}
			log.Printf("Rows affected: %d", rowsAffected)
			lastJSON = []byte("{}")
		}
	}

	if tx != nil {
		log.Print("End transaction. Commit")
		if err := tx.Commit(); err != nil {
			log.Printf("Failed to commit transaction: %v", err)
			sendJSONError(w, "Failed to commit transaction", http.StatusInternalServerError)
			return
		}
	}
	lastJSONString := string(lastJSON)
	if lastJSONString == "null" {
		lastJSON = []byte("[]")
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(lastJSON)
}

func isSelectQuery(query string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToUpper(query)), "SELECT")
}

// SQLのパラメータ適用
func prepareQueryWithParams(query string, params map[string]interface{}) (string, []interface{}) {
	// 改善版の正規表現:
	// ・コメント内からパラメータ名（任意の文字列）を抽出
	// ・続く値は、単一引用符または二重引用符で囲まれているか、
	//   またはスペースとカンマ以外の文字列として扱う
	re := regexp.MustCompile(`\/\*([^*]+)\*\/\s*(?:'([^']*)'|"([^"]*)"|([^\s,]+))`)

	// 同じパラメータ名ごとに一度だけ引数に登録するためのマッピング
	mapping := make(map[string]string)
	args := []interface{}{}
	placeholderCounter := 1

	// 正規表現でマッチした部分を置換する
	replacedQuery := re.ReplaceAllStringFunc(query, func(match string) string {
		// グループ: [全体, param名, 値(シングル), 値(ダブル), 値(非引用)]
		groups := re.FindStringSubmatch(match)
		paramName := strings.TrimSpace(groups[1])

		// 既に同じパラメータが置換済みの場合は、そのプレースホルダーを返す
		if placeholder, exists := mapping[paramName]; exists {
			return placeholder
		}

		// 初回の場合は引数リストに追加
		value, ok := params[paramName]
		if !ok {
			log.Printf("Parameter %s not found in provided parameters", paramName)
			value = nil
		}
		args = append(args, value)

		var placeholder string
		if dbType == "postgres" {
			placeholder = fmt.Sprintf("$%d", placeholderCounter)
		} else {
			placeholder = "?"
		}
		mapping[paramName] = placeholder
		placeholderCounter++
		return placeholder
	})

	log.Print(replacedQuery)
	return replacedQuery, args
}

func RowsToJSON(rows *sql.Rows) ([]byte, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))

	for rows.Next() {
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		results = append(results, entry)
	}
	return json.Marshal(results)
}

func basicAuth(next http.HandlerFunc, config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !checkPassword(user, pass, config) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			sendJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func checkPassword(user, pass string, config Config) bool {
	return user == config.BasicAuth.Username && pass == config.BasicAuth.Password
}

// /nyan 用のハンドラー
// NyanResponse は JSON レスポンスの順序を保証するための構造体です。
type NyanResponse struct {
	Name    string               `json:"name"`
	Profile string               `json:"profile"`
	Version string               `json:"version"`
	Apis    map[string]APIConfig `json:"apis"`
}

func handleNyan(w http.ResponseWriter, r *http.Request) {
	// config.jsonから必要な情報を抽出
	response := NyanResponse{
		Name:    config.Name,
		Profile: config.Profile,
		Version: config.Version,
		Apis:    sqlFiles, // sqlFiles は api.json の内容が格納されている変数
	}

	// JSON として出力（構造体を利用することで、フィールドの順序が保証される）
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
	}
}

// nyanとdetailの切り分け
func handleNyanOrDetail(w http.ResponseWriter, r *http.Request) {
	// 先頭の "/nyan" を除去し、残りのサブパスを判定する
	subPath := strings.TrimPrefix(r.URL.Path, "/nyan")

	// /nyan のみ (実際には /nyan にアクセスすると net/http が /nyan/ にリダイレクトする場合が多い)
	// /nyan/ でアクセスされた場合、subPath は "/" になる
	if subPath == "" || subPath == "/" {
		// => /nyan/ の場合は既存の機能 (handleNyan)
		handleNyan(w, r)
	} else {
		// => /nyan/以降に何か続いている場合 (/nyan/apiName)
		handleNyanDetail(w, r)
	}
}

// /nyan/{API名} の詳細を返すハンドラー
// /nyan/{API名} の詳細を返すハンドラー
func handleNyanDetail(w http.ResponseWriter, r *http.Request) {
	type detailResponse struct {
		API                string                 `json:"api"`
		Description        string                 `json:"description"`
		NyanAcceptedParams map[string]interface{} `json:"nyanAcceptedParams"`
		// ← ここを追加
		NyanOutputColumns []string `json:"nyanOutputColumns,omitempty"`
	}

	apiName := strings.TrimPrefix(r.URL.Path, "/nyan/")
	if apiName == "" {
		sendJSONError(w, "API name is required", http.StatusBadRequest)
		return
	}

	apiConfig, exists := sqlFiles[apiName]
	if !exists {
		sendJSONError(w, "API not found", http.StatusNotFound)
		return
	}

	// 1) パラメータを解析
	paramsMap, err := parseSQLParams(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to parse SQL comments: %v", err)
		sendJSONError(w, "Failed to parse SQL comments", http.StatusInternalServerError)
		return
	}

	// 2) 最後のSQLファイルがあればSELECTカラムを解析
	var outputCols []string
	if len(apiConfig.SQL) > 0 {
		lastFile := apiConfig.SQL[len(apiConfig.SQL)-1]
		cols, err := parseSelectColumns(lastFile)
		if err != nil {
			log.Printf("Failed to parse columns from last SQL file: %v", err)
		} else {
			outputCols = cols
		}
	}

	// 3) レスポンスを作成
	resp := detailResponse{
		API:                apiName,
		Description:        apiConfig.Description,
		NyanAcceptedParams: paramsMap,
		NyanOutputColumns:  outputCols,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SQLのパース
func parseSQLParams(filePaths []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, filePath := range filePaths {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %v", filePath, err)
		}
		content := string(data)

		// コメント + デフォルト値を全て取得
		matches := reParams.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			// m[1] = paramName
			// m[2] = '...' (シングルクオート文字列) の中身
			// m[3] = クオートなし
			paramName := strings.TrimSpace(m[1])

			var rawValue string
			if m[2] != "" {
				// シングルクオートの中身を使用する
				rawValue = m[2]
			} else {
				// クオートなしの値
				rawValue = m[3]
			}

			// 既に同じparamNameがあった場合は上書き or スキップ 等、要件に合わせて調整
			result[paramName] = convertToNumberIfPossible(rawValue)
		}
	}
	return result, nil
}

// convertToNumberIfPossible は、文字列が数値なら int/float64 に、
// それ以外は string として返します。
func convertToNumberIfPossible(s string) interface{} {
	if isInteger(s) {
		if i, err := strconv.Atoi(s); err == nil {
			return i
		}
	}
	if isFloat(s) {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return s // 数字でなければ文字列として扱う
}

func isInteger(s string) bool {
	// 先頭に + - がついた整数をざっくり判定
	return regexp.MustCompile(`^[+-]?\d+$`).MatchString(s)
}

func isFloat(s string) bool {
	// 小数点を含む数値をざっくり判定 (指数部や厳密な形式は非考慮)
	return regexp.MustCompile(`^[+-]?\d+(\.\d+)?$`).MatchString(s)
}

// parseSelectColumns は、指定したファイルを読み込み
// 例: "SELECT count(id) AS today_count, name FROM stamps" のような文から
// ["today_count", "name"] を取り出す簡易実装です。
// parseSelectColumns は、SELECT～FROM の間を取り出し、トップレベルの列区切りカンマで分割し、
// "AS エイリアス" があればエイリアスを抽出して返す簡易実装です。
func parseSelectColumns(sqlFilePath string) ([]string, error) {
	data, err := ioutil.ReadFile(sqlFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", sqlFilePath, err)
	}
	content := string(data)

	// 大文字小文字を無視して「SELECT」「FROM」の位置を探す
	upper := strings.ToUpper(content)
	selectIdx := strings.Index(upper, "SELECT")
	if selectIdx == -1 {
		return nil, nil // SELECT がなければ空
	}
	fromIdx := strings.Index(upper, "FROM")
	if fromIdx == -1 || fromIdx < selectIdx {
		// FROM がない、または SELECT より前にある場合は対象外
		return nil, nil
	}

	// SELECT と FROM の間を取り出し、前後の空白を削除
	selectPart := strings.TrimSpace(content[selectIdx+len("SELECT") : fromIdx])
	if selectPart == "" {
		return nil, nil
	}

	// "SELECT * FROM" のように一発で終わる場合
	if selectPart == "*" {
		return []string{"*"}, nil
	}

	// トップレベルの列区切りとなるカンマを見つけて分割
	colExprs := splitTopLevelColumns(selectPart)

	var aliases []string
	for _, expr := range colExprs {
		// 大文字小文字無視で " AS " を探して、あればエイリアス部分を抽出
		upperExpr := strings.ToUpper(expr)
		asIdx := strings.Index(upperExpr, " AS ")
		if asIdx >= 0 {
			aliasPart := strings.TrimSpace(expr[asIdx+4:])
			aliases = append(aliases, aliasPart)
		} else {
			// AS がなければ式全体を格納してもいいが、ここでは式全体をとりあえず返す
			// 例: "COUNT(stamps.date)" -> "COUNT(stamps.date)"
			trimmed := strings.TrimSpace(expr)
			aliases = append(aliases, trimmed)
		}
	}
	return aliases, nil
}

// splitTopLevelColumns は、SELECT ... FROM の間の文字列を受け取り、
// トップレベルのカンマ(関数呼び出しやCASE式などの中ではない)で分割したスライスを返す。
func splitTopLevelColumns(selectPart string) []string {
	var result []string
	var sb strings.Builder

	depth := 0 // ( ) の深さ
	inSingleQuote := false

	runes := []rune(selectPart)

	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		switch ch {
		case '\'':
			// シングルクオートの開始 or 終了
			inSingleQuote = !inSingleQuote
			sb.WriteRune(ch)
		case '(':
			if !inSingleQuote {
				depth++
			}
			sb.WriteRune(ch)
		case ')':
			if !inSingleQuote && depth > 0 {
				depth--
			}
			sb.WriteRune(ch)
		case ',':
			// depth=0 かつ inSingleQuote=false のときだけ、トップレベルの列区切り
			if depth == 0 && !inSingleQuote {
				// 列1つ分を確定
				col := strings.TrimSpace(sb.String())
				result = append(result, col)
				sb.Reset()
			} else {
				sb.WriteRune(ch)
			}
		default:
			sb.WriteRune(ch)
		}
	}
	// 最後に残っている要素を追加
	rest := strings.TrimSpace(sb.String())
	if rest != "" {
		result = append(result, rest)
	}
	return result
}

// sendJSONErrorをinterface{}を受け取るように定義（1箇所だけ定義する）
func sendJSONError(w http.ResponseWriter, errPayload interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errPayload})
}

func runCheckScript(apiCheckScriptPath string, params map[string]interface{}) (bool, int, interface{}, error) {
	var combinedScript strings.Builder

	// config.json の javascript_include に指定されたすべてのファイルを読み込む
	for _, includePath := range config.JavascriptInclude {
		content, err := ioutil.ReadFile(includePath)
		if err != nil {
			return false, 500, nil, fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// api.json で指定されたチェック用 JavaScript ファイルをそのまま読み込む
	checkContent, err := ioutil.ReadFile(apiCheckScriptPath)
	if err != nil {
		return false, 500, nil, fmt.Errorf("failed to read check script %s: %v", apiCheckScriptPath, err)
	}
	combinedScript.Write(checkContent)
	combinedScript.WriteString("\n")

	// デバッグ用: 合体したスクリプトの内容をログ出力
	log.Printf("Combined check script:\n%s", combinedScript.String())

	// goja VM を作成し、パラメータをセットする
	vm := goja.New()
	vm.Set("nyanAllParams", params)

	// 合体したスクリプトを実行する
	value, err := vm.RunString(combinedScript.String())
	if err != nil {
		return false, 500, nil, fmt.Errorf("check script error: %v", err)
	}

	// 返り値が undefined または null ならエラー
	if goja.IsUndefined(value) || value == nil {
		return false, 500, nil, fmt.Errorf("check script returned no value")
	}

	// 戻り値のオブジェクトから success, status, error を取得
	obj := value.ToObject(vm)
	successVal := obj.Get("success")
	statusVal := obj.Get("status")
	errorVal := obj.Get("error")
	if goja.IsUndefined(successVal) || goja.IsUndefined(statusVal) {
		return false, 500, nil, fmt.Errorf("check script did not return proper object with success and status")
	}

	success := successVal.ToBoolean()
	statusCode := int(statusVal.ToInteger())

	// errorVal を明示的にネイティブな map に変換する
	var errorObj interface{}
	if !goja.IsUndefined(errorVal) && errorVal != nil {
		var m map[string]interface{}
		if err := vm.ExportTo(errorVal, &m); err != nil {
			// 変換できなかった場合は文字列化
			errorObj = errorVal.String()
		} else {
			errorObj = m
		}
	}

	return success, statusCode, errorObj, nil
}
