package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
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
	"reflect"
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
	Script      string   `json:"script,omitempty"` // 任意の JavaScript ファイルを配列で指定可能
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
	configFile, err := os.Open(configFilePath) // 既に err が宣言されているので "=" を使用
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
		// Basic Auth を適用
		basicAuth(handleNyanOrDetail, config)(w, r)
	})))

	// その他のリクエストに対しても Basic Auth を適用
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

// SQLファイルの読み込み
func loadSQLFiles(execDir string) {
	apiFilePath := filepath.Join(execDir, "api.json")
	data, err := ioutil.ReadFile(apiFilePath)
	if err != nil {
		log.Fatalf("Failed to read SQL files config: %v", err)
	}
	if err := json.Unmarshal(data, &sqlFiles); err != nil {
		log.Fatalf("Failed to decode SQL files JSON: %v", err)
	}

	// ここで "script" と "sql" の両方が設定されている場合にエラーとして起動を停止
	for apiKey, apiConfig := range sqlFiles {
		// script があり、かつ sql のエントリ数が > 0 ならエラー
		if len(apiConfig.Script) > 0 && len(apiConfig.SQL) > 0 {
			log.Fatalf(
				"Configuration error in api.json for API '%s': If 'script' is set, 'sql' cannot be specified. Please remove one of them.",
				apiKey,
			)
		}
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

// ロガーの設定
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
	// favicon.ico は無視
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}

	// リクエストパラメータを取得（JSON or フォーム）
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
		if err := r.ParseForm(); err != nil {
			sendJSONError(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		params = make(map[string]interface{})
		for key, values := range r.Form {
			// 複数の値があればそのままスライスとして設定
			if len(values) > 1 {
				params[key] = values
			} else {
				val := values[0]
				// 値がJSON配列の形式かチェック
				if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
					var arr []interface{}
					if err := json.Unmarshal([]byte(val), &arr); err == nil {
						params[key] = arr
						continue
					}
				}
				// カンマ区切りの文字列なら分割
				if strings.Contains(val, ",") {
					splitVals := strings.Split(val, ",")
					for i := range splitVals {
						splitVals[i] = strings.TrimSpace(splitVals[i])
					}
					params[key] = splitVals
				} else {
					params[key] = val
				}
			}
		}
	}

	// URLパスが "/" 以外の場合、api パラメータとして扱う
	if r.URL.Path != "/" {
		apiName := strings.TrimPrefix(r.URL.Path, "/")
		if apiName != "" {
			if _, exists := params["api"]; !exists {
				params["api"] = apiName
			}
		}
	}

	// APIキー（名前）を取得
	apiKey, ok := params["api"].(string)
	if !ok || apiKey == "" {
		sendJSONError(w, "API key is required and must be a string", http.StatusBadRequest)
		return
	}

	// api.json から API 設定を取得
	apiConfig, exists := sqlFiles[apiKey]
	if !exists {
		sendJSONError(w, "SQL files not found", http.StatusNotFound)
		return
	}

	// 置換対象パラメータキーの配列を取得
	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}

	// リクエストパラメータから nyan_mode を取得（snake_case）
	nyanMode, _ := params["nyan_mode"].(string)

	// nyan_mode が "checkOnly" かつチェック用スクリプトが未設定の場合は 404 エラー
	if nyanMode == "checkOnly" && apiConfig.Check == "" {
		sendJSONError(w, "No check script for this API", http.StatusNotFound)
		return
	}

	// チェック用 JavaScript の実行（チェック用スクリプトが指定されている場合）
	if apiConfig.Check != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(apiConfig.Check, params, acceptedKeys)
		if err != nil {
			log.Printf("Check script error: %v", err)
			sendJSONError(w, err.Error(), statusCode)
			return
		}
		if !success {
			if errorObj == nil {
				errorObj = "Request check failed"
			}
			response := map[string]interface{}{
				"success": success,
				"status":  statusCode,
				"error":   errorObj,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
			return
		}
		// nyan_mode が "checkOnly" の場合はチェック結果のみを返す
		if nyanMode == "checkOnly" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
		// もし script の設定がある場合は、チェック成功なら script を実行してその結果を返す
		if apiConfig.Script != "" {
			scriptResult, err := runScript([]string{apiConfig.Script}, params)
			if err != nil {
				log.Printf("Script execution error: %v", err)
				sendJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(scriptResult))
			return
		}

		// チェックが成功し、なおかつ SQL も script も未設定の場合はチェック結果を返す
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
	}

	// SQL 実行へ進む場合
	var tx *sql.Tx
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
	// パラメータ置換用の正規表現
	re := regexp.MustCompile(`\/\*([^*]+)\*\/\s*(?:'([^']*)'|"([^"]*)"|([^\s,;)]+))`)

	// 同じパラメータ名ごとに一度だけ引数に登録するためのマッピング
	mapping := make(map[string]string)
	args := []interface{}{}
	placeholderCounter := 1

	// 正規表現でマッチした部分を置換
	replacedQuery := re.ReplaceAllStringFunc(query, func(match string) string {
		// マッチしたグループの取得
		groups := re.FindStringSubmatch(match)
		paramName := strings.TrimSpace(groups[1])

		// すでに置換済みならそのプレースホルダーを返す
		if placeholder, exists := mapping[paramName]; exists {
			return placeholder
		}

		// パラメータ値の取得
		value, ok := params[paramName]
		if !ok {
			log.Printf("Parameter %s not found in provided parameters", paramName)
			value = nil
		}

		// reflect を用いてスライスかどうかを判定
		rv := reflect.ValueOf(value)
		if rv.IsValid() && rv.Kind() == reflect.Slice {
			// スライスの場合、要素ごとにプレースホルダーを生成
			placeholders := []string{}
			for i := 0; i < rv.Len(); i++ {
				args = append(args, rv.Index(i).Interface())
				if dbType == "postgres" {
					placeholders = append(placeholders, fmt.Sprintf("$%d", placeholderCounter))
				} else {
					placeholders = append(placeholders, "?")
				}
				placeholderCounter++
			}
			placeholder := strings.Join(placeholders, ",")
			mapping[paramName] = placeholder
			return placeholder
		} else {
			// スライスでない場合は従来通り単一のプレースホルダーを生成
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
		}
	})

	log.Print("Replaced Query: ", replacedQuery)
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
func handleNyanDetail(w http.ResponseWriter, r *http.Request) {
	type detailResponse struct {
		API                string                 `json:"api"`
		Description        string                 `json:"description"`
		NyanAcceptedParams map[string]interface{} `json:"nyanAcceptedParams"`
		NyanOutputColumns  []string               `json:"nyanOutputColumns,omitempty"`
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

	// SQLファイルからパラメータ解析
	paramsMap, err := parseSQLParams(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to parse SQL comments: %v", err)
		sendJSONError(w, "Failed to parse SQL comments", http.StatusInternalServerError)
		return
	}

	var acceptedParamsFromScript map[string]interface{}
	var outputColumns []string

	// script が指定されている場合は、スクリプトから定数を抽出
	if apiConfig.Script != "" {
		acceptedParamsFromScript, outputColumns, err = parseScriptConstants(apiConfig.Script)
		if err != nil {
			log.Printf("Failed to parse script constants: %v", err)
			// 必須でなければログ出力のみ、もしくはエラー応答とするか検討してください
		} else {
			// スクリプトから得た acceptedParams を SQL で解析した内容とマージ（スクリプト側優先）
			for k, v := range acceptedParamsFromScript {
				paramsMap[k] = v
			}
		}
	}

	resp := detailResponse{
		API:                apiName,
		Description:        apiConfig.Description,
		NyanAcceptedParams: paramsMap,
		NyanOutputColumns:  outputColumns,
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

// runCheckScript のシグネチャを変更し、元の JSON 文字列も返すようにする
func runCheckScript(apiCheckScriptPath string, params map[string]interface{}, acceptedParamsKeys []string) (bool, int, interface{}, string, error) {
	var combinedScript strings.Builder

	// config.json の javascript_include に指定されたすべてのファイルを読み込む
	for _, includePath := range config.JavascriptInclude {
		content, err := ioutil.ReadFile(includePath)
		if err != nil {
			return false, 500, nil, "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// api.json で指定されたチェック用 JavaScript ファイルをそのまま読み込む
	checkContent, err := ioutil.ReadFile(apiCheckScriptPath)
	if err != nil {
		return false, 500, nil, "", fmt.Errorf("failed to read check script %s: %v", apiCheckScriptPath, err)
	}
	combinedScript.Write(checkContent)
	combinedScript.WriteString("\n")

	log.Printf("Combined check script:\n%s", combinedScript.String())

	vm := goja.New()
	// パラメータと、置換対象パラメータのキー配列をセット
	vm.Set("nyanAllParams", params)
	vm.Set("nyanAcceptedParamsKeys", acceptedParamsKeys)

	// 必要な console, nyanGetAPI, nyanJsonAPI などの登録（省略可。前述の例を参照）
	// console.log を登録
	vm.Set("console", map[string]interface{}{
		"log": func(call goja.FunctionCall) goja.Value {
			args := []string{}
			// JSON.stringify を取得して、オブジェクトの場合に文字列化する
			jsonStringifyVal := vm.Get("JSON").ToObject(vm).Get("stringify")
			jsonStringify, ok := goja.AssertFunction(jsonStringifyVal)
			if !ok {
				log.Println("JSON.stringify is not a function")
				return goja.Undefined()
			}
			for _, arg := range call.Arguments {
				exported := arg.Export()
				switch exported.(type) {
				case map[string]interface{}, []interface{}:
					s, err := jsonStringify(goja.Undefined(), arg)
					if err == nil {
						args = append(args, s.String())
					} else {
						args = append(args, arg.String())
					}
				default:
					args = append(args, arg.String())
				}
			}
			log.Println("[JS:check]", strings.Join(args, " "))
			return goja.Undefined()
		},
	})

	// nyanGetAPI の登録（引数はオプション対応）
	vm.Set("nyanGetAPI", func(call goja.FunctionCall) goja.Value {
		var url, username, password string
		if len(call.Arguments) >= 1 {
			url = call.Argument(0).String()
		}
		if len(call.Arguments) >= 2 {
			username = call.Argument(1).String()
		}
		if len(call.Arguments) >= 3 {
			password = call.Argument(2).String()
		}
		result, err := getAPI(url, username, password)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(result)
	})

	// nyanJsonAPI の登録（引数はオプション対応）
	vm.Set("nyanJsonAPI", func(call goja.FunctionCall) goja.Value {
		var url, jsonData, username, password string
		if len(call.Arguments) >= 1 {
			url = call.Argument(0).String()
		}
		if len(call.Arguments) >= 2 {
			jsonData = call.Argument(1).String()
		}
		if len(call.Arguments) >= 3 {
			username = call.Argument(2).String()
		}
		if len(call.Arguments) >= 4 {
			password = call.Argument(3).String()
		}
		result, err := jsonAPI(url, []byte(jsonData), username, password)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(result)
	})

	value, err := vm.RunString(combinedScript.String())
	if err != nil {
		return false, 500, nil, "", fmt.Errorf("check script error: %v", err)
	}

	jsonStr := value.String()
	var result struct {
		Success bool        `json:"success"`
		Status  int         `json:"status"`
		Error   interface{} `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return false, 500, nil, jsonStr, fmt.Errorf("failed to unmarshal check result: %v", err)
	}

	return result.Success, result.Status, result.Error, jsonStr, nil
}

func getAPI(url, username, password string) (string, error) {
	// HTTPクライアントの生成
	client := &http.Client{}

	// リクエストの生成
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// BASIC認証ヘッダーの設定
	if username != "" {
		req.SetBasicAuth(username, password)
	}

	// リクエストの送信
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// レスポンスの読み取り
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}
	return string(body), nil
}

// POSTリクエストを行うGo関数
func jsonAPI(url string, jsonData []byte, username, password string) (string, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// Basic認証のセットアップ
	basicAuth := username + ":" + password
	basicAuthEncoded := base64.StdEncoding.EncodeToString([]byte(basicAuth))
	req.Header.Set("Authorization", "Basic "+basicAuthEncoded)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// パラメータの取得
func getAcceptedParamsKeys(sqlPaths []string) ([]string, error) {
	paramsMap, err := parseSQLParams(sqlPaths)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for k := range paramsMap {
		keys = append(keys, k)
	}
	return keys, nil
}

// runScript は、config.JavascriptInclude で指定されたファイルと、
// apiConfig.Script に指定されたスクリプト群を連結して実行し、結果の文字列を返します。
func runScript(scriptPaths []string, params map[string]interface{}) (string, error) {
	var combinedScript strings.Builder

	// config.JavascriptInclude に指定されたファイルを全て読み込む
	for _, includePath := range config.JavascriptInclude {
		content, err := ioutil.ReadFile(includePath)
		if err != nil {
			return "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// apiConfig.Script に指定された各スクリプトファイルを読み込む
	for _, scriptPath := range scriptPaths {
		content, err := ioutil.ReadFile(scriptPath)
		if err != nil {
			return "", fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// Goja の VM を作成し、パラメータをセット
	vm := goja.New()
	vm.Set("nyanAllParams", params)

	//console
	vm.Set("console", map[string]interface{}{
		"log": func(call goja.FunctionCall) goja.Value {
			args := []string{}
			// JSON.stringify を取得して、オブジェクトの場合に文字列化する
			jsonStringifyVal := vm.Get("JSON").ToObject(vm).Get("stringify")
			jsonStringify, ok := goja.AssertFunction(jsonStringifyVal)
			if !ok {
				log.Println("JSON.stringify is not a function")
				return goja.Undefined()
			}
			for _, arg := range call.Arguments {
				exported := arg.Export()
				switch exported.(type) {
				case map[string]interface{}, []interface{}:
					s, err := jsonStringify(goja.Undefined(), arg)
					if err == nil {
						args = append(args, s.String())
					} else {
						args = append(args, arg.String())
					}
				default:
					args = append(args, arg.String())
				}
			}
			log.Println("[JS:script]", strings.Join(args, " "))
			return goja.Undefined()
		},
	})

	// nyanGetAPI の登録（引数はオプション対応）
	vm.Set("nyanGetAPI", func(call goja.FunctionCall) goja.Value {
		var url, username, password string
		if len(call.Arguments) >= 1 {
			url = call.Argument(0).String()
		}
		if len(call.Arguments) >= 2 {
			username = call.Argument(1).String()
		}
		if len(call.Arguments) >= 3 {
			password = call.Argument(2).String()
		}
		result, err := getAPI(url, username, password)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(result)
	})

	// nyanJsonAPI の登録（引数はオプション対応）
	vm.Set("nyanJsonAPI", func(call goja.FunctionCall) goja.Value {
		var url, jsonData, username, password string
		if len(call.Arguments) >= 1 {
			url = call.Argument(0).String()
		}
		if len(call.Arguments) >= 2 {
			jsonData = call.Argument(1).String()
		}
		if len(call.Arguments) >= 3 {
			username = call.Argument(2).String()
		}
		if len(call.Arguments) >= 4 {
			password = call.Argument(3).String()
		}
		result, err := jsonAPI(url, []byte(jsonData), username, password)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(result)
	})

	vm.Set("nyanRunSQL", func(call goja.FunctionCall) goja.Value {
		return nyanRunSQLHandler(vm, call)
	})

	// 連結したスクリプトを実行
	value, err := vm.RunString(combinedScript.String())
	if err != nil {
		return "", fmt.Errorf("script execution error: %v", err)
	}
	return value.String(), nil
}

// parseScriptConstants は、指定されたスクリプトファイルから
// const nyanAcceptedParams と const nyanOutputColumns の値を抽出して返します。
func parseScriptConstants(scriptPath string) (map[string]interface{}, []string, error) {
	data, err := ioutil.ReadFile(scriptPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
	}
	content := string(data)

	var acceptedParams map[string]interface{}
	var outputColumns []string

	// 改善した正規表現：末尾のセミコロンは含めず、括弧の中身のみをキャプチャ
	reAcceptedParams := regexp.MustCompile(`(?s)const\s+nyanAcceptedParams\s*=\s*({[\s\S]*?})\s*;`)
	if match := reAcceptedParams.FindStringSubmatch(content); match != nil && len(match) > 1 {
		jsonStr := match[1]
		if err := json.Unmarshal([]byte(jsonStr), &acceptedParams); err != nil {
			return nil, nil, fmt.Errorf("failed to parse nyanAcceptedParams: %v", err)
		}
	}

	// 改善した正規表現：[] の中身を正しくキャプチャ（改行や空白も含む）
	reOutputColumns := regexp.MustCompile(`(?s)const\s+nyanOutputColumns\s*=\s*(\[[\s\S]*?\])\s*;`)
	if match := reOutputColumns.FindStringSubmatch(content); match != nil && len(match) > 1 {
		jsonStr := match[1]
		if err := json.Unmarshal([]byte(jsonStr), &outputColumns); err != nil {
			return nil, nil, fmt.Errorf("failed to parse nyanOutputColumns: %v", err)
		}
	}

	log.Print(outputColumns)

	return acceptedParams, outputColumns, nil
}

// nyanRunSQLHandler は、JavaScript から呼ばれた nyanRunSQL の処理を実装します。
func nyanRunSQLHandler(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	// 第一引数: SQL ファイルのパス
	if len(call.Arguments) < 1 {
		panic(vm.ToValue("nyanRunSQL requires at least the SQL file path as argument"))
	}
	sqlFilePath := call.Argument(0).String()

	// 第二引数: オプションのパラメータオブジェクト（存在しなければ空のマップ）
	var params map[string]interface{}
	if len(call.Arguments) >= 2 {
		if obj, ok := call.Argument(1).Export().(map[string]interface{}); ok {
			params = obj
		} else {
			params = make(map[string]interface{})
		}
	} else {
		params = make(map[string]interface{})
	}

	// SQL ファイルを読み込む
	sqlContent, err := ioutil.ReadFile(sqlFilePath)
	if err != nil {
		panic(vm.ToValue(fmt.Sprintf("failed to read SQL file %s: %v", sqlFilePath, err)))
	}

	// SQL 内のパラメータを置換
	queryStr, args := prepareQueryWithParams(string(sqlContent), params)

	// SELECT クエリなら結果を JSON に変換して返す
	if isSelectQuery(queryStr) {
		rows, err := db.Query(queryStr, args...)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error executing SQL query: %v", err)))
		}
		defer rows.Close()
		jsonBytes, err := RowsToJSON(rows)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error converting rows to JSON: %v", err)))
		}
		return vm.ToValue(string(jsonBytes))
	} else {
		// SELECT 以外の場合は、影響を受けた行数を返す
		res, err := db.Exec(queryStr, args...)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error executing SQL query: %v", err)))
		}
		affected, err := res.RowsAffected()
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error retrieving rows affected: %v", err)))
		}
		response := map[string]interface{}{
			"rowsAffected": affected,
		}
		jsonResp, _ := json.Marshal(response)
		return vm.ToValue(string(jsonResp))
	}
}
