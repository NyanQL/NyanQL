package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dop251/goja"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	_ "github.com/duckdb/duckdb-go/v2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/cors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

type Config struct {
	Name                   string          `json:"name"`
	Profile                string          `json:"profile"`
	Version                string          `json:"version"`
	Port                   int             `json:"Port"`
	CertPath               string          `json:"CertPath"`
	KeyPath                string          `json:"KeyPath"`
	DatabaseType           string          `json:"DBType"`
	DBUsername             string          `json:"DBUser"`
	DBPassword             string          `json:"DBPassword"`
	DBName                 string          `json:"DBName"`
	DBHost                 string          `json:"DBHost"`
	DBPort                 string          `json:"DBPort"`
	MaxOpenConnections     int             `json:"MaxOpenConnections"`
	MaxIdleConnections     int             `json:"MaxIdleConnections"`
	ConnMaxLifetimeSeconds int             `json:"ConnMaxLifetimeSeconds"`
	BasicAuth              BasicAuthConfig `json:"BasicAuth"`
	Log                    LogConfig       `json:"log"`
	JavascriptInclude      []string        `json:"javascript_include,omitempty"`
}

type BasicAuthConfig struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

type LogConfig struct {
	Filename      string `json:"Filename"`
	MaxSize       int    `json:"MaxSize"`
	MaxBackups    int    `json:"MaxBackups"`
	MaxAge        int    `json:"MaxAge"`
	Compress      bool   `json:"Compress"`
	EnableLogging bool   `json:"EnableLogging"`
}

type APIConfig struct {
	SQL         []string `json:"sql,omitempty"`
	Script      string   `json:"script,omitempty"`
	Check       string   `json:"check,omitempty"`
	Push        string   `json:"push,omitempty"`
	Description string   `json:"description"`
}

type Hub struct {
	mu      sync.Mutex
	clients map[string]map[*websocket.Conn]bool // チャネル名ごとのクライアント一覧
}

type SQLResponse struct {
	Success bool            `json:"success"`
	Status  int             `json:"status"`
	Result  json.RawMessage `json:"result"`
}

type JSONErrorResponse struct {
	Success bool `json:"success"`
	Status  int  `json:"status"`
	Error   struct {
		Message string `json:"message"`
	} `json:"error"`
}

// APIDetails は、各 API の説明情報のみを保持する構造体です。
type APIDetails struct {
	Description string `json:"description"`
}

// NyanResponse は /nyan にアクセスしたときに返すサーバ情報です。
// Apis には、API名をキーとして、各 API の説明のみが含まれます。
type NyanResponse struct {
	Name    string                `json:"name"`
	Profile string                `json:"profile"`
	Version string                `json:"version"`
	Apis    map[string]APIDetails `json:"apis"`
}

// ExecResult はコマンド実行結果を表す構造体です。
type ExecResult struct {
	Success  bool   `json:"success"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type JSONRPCRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	ID      interface{}            `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *JSONRPCError    `json:"error,omitempty"`
	ID      interface{}      `json:"id,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var config Config
var db *sql.DB
var sqlFiles map[string]APIConfig
var dbType string

// reParams は、/*id*/ のようなプレースホルダーを抽出する正規表現
var reParams = regexp.MustCompile(`(?s)/\*\s*([^*\/]+)\s*\*/\s*(?:'([^']*)'|"([^"]*)"|([^\s,;)]+))`)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 必要に応じてオリジンチェックを追加
	},
}

var hub *Hub

// main
func main() {
	execDir, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir = filepath.Dir(execDir)

	configFilePath := filepath.Join(execDir, "config.json")
	configFile, err := os.Open(configFilePath)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()
	if err = json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to decode config JSON: %v", err)
	}
	adjustPaths(execDir, &config)
	log.Printf("Starting application version: %s", config.Version)
	setupLogger(execDir)

	db, err = connectDB(config)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	loadSQLFiles(execDir)

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	hub = NewHub()

	http.Handle("/nyan-rpc", corsHandler.Handler(http.HandlerFunc(basicAuth(handleJSONRPC, config))))

	http.Handle("/nyan/", corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basicAuth(handleNyanOrDetail, config)(w, r)
	})))

	http.Handle("/", corsHandler.Handler(http.HandlerFunc(unifiedHandler)))

	if config.CertPath != "" && config.KeyPath != "" {
		log.Printf("Server starting on HTTPS port %d\n", config.Port)
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", config.Port), config.CertPath, config.KeyPath, nil))
	} else {
		log.Printf("Server starting on HTTP port %d\n", config.Port)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
	}
}

func (h *Hub) AddClient(channel string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients == nil {
		h.clients = make(map[string]map[*websocket.Conn]bool)
	}
	if _, ok := h.clients[channel]; !ok {
		h.clients[channel] = make(map[*websocket.Conn]bool)
	}
	h.clients[channel][conn] = true
}

func (h *Hub) RemoveClient(channel string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if clients, ok := h.clients[channel]; ok {
		delete(clients, conn)
		if len(clients) == 0 {
			delete(h.clients, channel)
		}
	}
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]map[*websocket.Conn]bool),
	}
}

func unifiedHandler(w http.ResponseWriter, r *http.Request) {
	// WebSocketアップグレード要求なら認証後、handleWebSocketに処理を委譲
	if isWebSocketRequest(r) {
		// ここで必要ならBasicAuthの認証を実施
		// もしくはWebSocket用に別の認証方式を採用する
		handleWebSocket(w, r)
		return
	}
	// 通常のHTTPリクエストならBasicAuthを適用して処理
	basicAuth(handleRequest, config)(w, r)
}

// WebSocketリクエストかどうかを判定する関数例
func isWebSocketRequest(r *http.Request) bool {
	upgrade := r.Header.Get("Upgrade")
	return strings.ToLower(upgrade) == "websocket"
}

// WebSocketアップグレードと接続管理を行う関数
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// ここでは、例えばURLパスの末尾をチャネル名として利用する例
	parts := strings.Split(r.URL.Path, "/")
	channel := "default" // デフォルトチャネル
	if len(parts) > 1 && parts[len(parts)-1] != "" {
		channel = parts[len(parts)-1]
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocketアップグレードエラー: %v", err)
		return
	}
	hub.AddClient(channel, conn)
	defer hub.RemoveClient(channel, conn)

	// シンプルな読み込みループ（ここで受信したメッセージを必要に応じて処理可能）
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		// 受信メッセージのログ出力例
		log.Printf("Received on channel [%s]: %s", channel, msg)
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
	for apiKey, apiConfig := range sqlFiles {
		if len(apiConfig.Script) > 0 && len(apiConfig.SQL) > 0 {
			log.Fatalf("Configuration error in api.json for API '%s': If 'script' is set, 'sql' cannot be specified.", apiKey)
		}
	}

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
		// MySQLの場合
		driverName = "mysql"
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
			config.DBUsername, config.DBPassword,
			config.DBHost, config.DBPort, config.DBName)

	case "postgres":
		// PostgreSQLの場合
		driverName = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			config.DBHost, config.DBPort, config.DBUsername, config.DBPassword, config.DBName)

	case "sqlite":
		// SQLiteの場合
		driverName = "sqlite3"
		// DBNameにファイルパスが入っていると仮定
		dsn = config.DBName

	case "duckdb":
		// DuckDBの場合
		driverName = "duckdb"
		// DBNameにファイルパスが入っていると仮定
		dsn = config.DBName

	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.DatabaseType)
	}

	// グローバル変数などでDB種類を後から参照する場合があればセット
	dbType = driverName

	// ここでDB接続をオープン。実際にはまだ物理コネクションは張られない可能性あり
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB: %w", err)
	}

	// 最大オープン接続数を設定 (0以下なら制限なし)
	if config.MaxOpenConnections > 0 {
		db.SetMaxOpenConns(config.MaxOpenConnections)
	}

	// 最大アイドル接続数を設定
	if config.MaxIdleConnections > 0 {
		db.SetMaxIdleConns(config.MaxIdleConnections)
	}

	// コネクションの最大寿命を設定 (秒指定をDurationに変換)
	if config.ConnMaxLifetimeSeconds > 0 {
		db.SetConnMaxLifetime(time.Duration(config.ConnMaxLifetimeSeconds) * time.Second)
	}

	// 実際に接続が有効かどうか確かめるためPingを打つ(任意)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping DB: %w", err)
	}

	return db, nil
}

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
			if len(values) > 1 {
				params[key] = values
			} else {
				val := values[0]
				if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
					var arr []interface{}
					if err := json.Unmarshal([]byte(val), &arr); err == nil {
						params[key] = arr
						continue
					}
				}
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
	if r.URL.Path != "/" {
		apiName := strings.TrimPrefix(r.URL.Path, "/")
		if apiName != "" {
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
	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}
	nyanMode, _ := params["nyan_mode"].(string)
	if nyanMode == "checkOnly" && apiConfig.Check == "" {
		sendJSONError(w, "No check script for this API", http.StatusNotFound)
		return
	}
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
		if nyanMode == "checkOnly" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
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
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
	}

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
		// まず、外側ブロック（-- BEGIN -- ～ -- END --）を処理
		processed := processWhereBlock(string(query), params)
		// 次に、従来のIFブロック（/*IF ...*/ ... /*END*/）も処理
		processed = processConditionals(processed, params)
		log.Print("Processed SQL: ", processed)
		queryStr, args := prepareQueryWithParams(processed, params)
		log.Print("Final Query: ", queryStr)
		if isSelectQuery(queryStr) || isReturningQuery(queryStr) {
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

	// push 処理
	performPush(apiConfig, params)

	// SQL実行結果を固定順序の構造体で返す
	type SQLResponse struct {
		Success bool            `json:"success"`
		Status  int             `json:"status"`
		Result  json.RawMessage `json:"result"`
	}
	response := SQLResponse{
		Success: true,
		Status:  200,
		Result:  lastJSON,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
	}
}

func isSelectQuery(query string) bool {
	u := strings.TrimSpace(strings.ToUpper(query))
	if strings.HasPrefix(u, "SELECT") {
		return true
	}
	// CTE で始まる場合は SELECT かどうかをざっくり判定
	if strings.HasPrefix(u, "WITH") {
		// 最初の文の中に SELECT が含まれていれば結果セットを返す想定
		// （単純化: INSERT/UPDATE/DELETE の CTE を誤判定したくなければ、より厳密にパースする）
		// まずセミコロンまでを見る（無ければ全文）
		semi := strings.Index(u, ";")
		head := u
		if semi >= 0 {
			head = u[:semi]
		}
		// 代表的なデータ修正文より SELECT が先に現れるなら SELECT とみなす
		sel := strings.Index(head, "SELECT")
		ins := strings.Index(head, "INSERT")
		upd := strings.Index(head, "UPDATE")
		del := strings.Index(head, "DELETE")

		// SELECT が存在し、かつ INSERT/UPDATE/DELETE より前に出る場合を SELECT とみなす
		firstMut := -1
		for _, i := range []int{ins, upd, del} {
			if i >= 0 && (firstMut == -1 || i < firstMut) {
				firstMut = i
			}
		}
		return sel >= 0 && (firstMut == -1 || sel < firstMut)
	}
	return false
}


func prepareQueryWithParams(query string, params map[string]interface{}) (string, []interface{}) {
    re := regexp.MustCompile(`(?s)/\*\s*([^*\/]+)\s*\*/\s*(?:'([^']*)'|"([^"]*)"|([^\s,;)]+))`)

    var args []interface{}
    placeholderCounter := 1

    replacedQuery := re.ReplaceAllStringFunc(query, func(match string) string {
        groups := re.FindStringSubmatch(match)
        paramName := strings.TrimSpace(groups[1])

        // パラメータ取得
        value, ok := params[paramName]
        if !ok {
            args = append(args, nil)
            if dbType == "postgres" {
                place := fmt.Sprintf("$%d", placeholderCounter)
                placeholderCounter++
                return place
            }
            return "?"
        }

        rv := reflect.ValueOf(value)
        if !rv.IsValid() {
            args = append(args, nil)
            if dbType == "postgres" {
                place := fmt.Sprintf("$%d", placeholderCounter)
                placeholderCounter++
                return place
            }
            return "?"
        }

        // --- JSONB/文字列系の特別扱い ---
        // []byte は 1つの値として扱う
        if b, ok := value.([]byte); ok {
            args = append(args, string(b))
            place := "?"
            if dbType == "postgres" {
                place = fmt.Sprintf("$%d", placeholderCounter)
            }
            placeholderCounter++
            return place
        }

        // json.RawMessage も 1つの値として扱う
        if jm, ok := value.(json.RawMessage); ok {
            args = append(args, string(jm))
            place := "?"
            if dbType == "postgres" {
                place = fmt.Sprintf("$%d", placeholderCounter)
            }
            placeholderCounter++
            return place
        }

        // map や struct は JSON に変換して 1値として扱う
        kind := rv.Kind()
        if kind == reflect.Map || kind == reflect.Struct {
            jb, err := json.Marshal(value)
            if err != nil {
                args = append(args, value)
            } else {
                args = append(args, string(jb))
            }
            place := "?"
            if dbType == "postgres" {
                place = fmt.Sprintf("$%d", placeholderCounter)
            }
            placeholderCounter++
            return place
        }

        // --- 通常のスライスは IN (...) 展開 ---
        if kind == reflect.Slice {
            n := rv.Len()
            if n == 0 {
                return "NULL"
            }
            placeholders := make([]string, 0, n)
            for i := 0; i < n; i++ {
                args = append(args, rv.Index(i).Interface())
                var p string
                if dbType == "postgres" {
                    p = fmt.Sprintf("$%d", placeholderCounter)
                } else {
                    p = "?"
                }
                placeholders = append(placeholders, p)
                placeholderCounter++
            }
            return strings.Join(placeholders, ",")
        }

        // --- 通常の単一値 ---
        args = append(args, value)
        place := "?"
        if dbType == "postgres" {
            place = fmt.Sprintf("$%d", placeholderCounter)
        }
        placeholderCounter++
        return place
    })

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
			val := values[i]

			switch v := val.(type) {
			case []byte:
				// JSON っぽいならパースを試みる（先頭が { または [ または "n"=null）
				s := string(v)
				if len(s) > 0 && (s[0] == '{' || s[0] == '[' || s == "null") {
					var any interface{}
					if err := json.Unmarshal(v, &any); err == nil {
						entry[col] = any
						continue
					}
				}
				// それ以外は文字列として扱う
				entry[col] = s
			default:
				entry[col] = v
			}
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

// handleNyan は、サーバ情報と各 API のキーと説明のみを返します。
func handleNyan(w http.ResponseWriter, r *http.Request) {
	// sqlFiles は map[string]APIConfig になっているので、必要な情報のみ抽出します。
	filteredApis := make(map[string]APIDetails)
	for key, apiConf := range sqlFiles {
		filteredApis[key] = APIDetails{
			Description: apiConf.Description,
		}
	}

	response := NyanResponse{
		Name:    config.Name,
		Profile: config.Profile,
		Version: config.Version,
		Apis:    filteredApis,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleNyanOrDetail(w http.ResponseWriter, r *http.Request) {
	subPath := strings.TrimPrefix(r.URL.Path, "/nyan")
	if subPath == "" || subPath == "/" {
		handleNyan(w, r)
	} else {
		handleNyanDetail(w, r)
	}
}

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
	paramsMap, err := parseSQLParams(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to parse SQL comments: %v", err)
		sendJSONError(w, "Failed to parse SQL comments", http.StatusInternalServerError)
		return
	}
	var acceptedParamsFromScript map[string]interface{}
	var outputColumns []string
	if apiConfig.Script != "" {
		acceptedParamsFromScript, outputColumns, err = parseScriptConstants(apiConfig.Script)
		if err != nil {
			log.Printf("Failed to parse script constants: %v", err)
		} else {
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

func parseSQLParams(filePaths []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, filePath := range filePaths {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %v", filePath, err)
		}
		content := string(data)
		matches := reParams.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			paramName := strings.TrimSpace(m[1])
			var rawValue string
			if m[2] != "" {
				rawValue = m[2]
			} else {
				rawValue = m[3]
			}
			result[paramName] = convertToNumberIfPossible(rawValue)
		}
	}
	return result, nil
}

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
	return s
}

func isInteger(s string) bool {
	return regexp.MustCompile(`^[+-]?\d+$`).MatchString(s)
}

func isFloat(s string) bool {
	return regexp.MustCompile(`^[+-]?\d+(\.\d+)?$`).MatchString(s)
}

func splitTopLevelColumns(selectPart string) []string {
	var result []string
	var sb strings.Builder
	depth := 0
	inSingleQuote := false
	runes := []rune(selectPart)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		switch ch {
		case '\'':
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
			if depth == 0 && !inSingleQuote {
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
	rest := strings.TrimSpace(sb.String())
	if rest != "" {
		result = append(result, rest)
	}
	return result
}

func sendJSONError(w http.ResponseWriter, message interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := JSONErrorResponse{
		Success: false,
		Status:  statusCode,
	}

	switch msg := message.(type) {
	case string:
		response.Error.Message = msg
	case error:
		response.Error.Message = msg.Error()
	default:
		// その他の場合はJSONに変換して文字列化
		b, err := json.Marshal(msg)
		if err != nil {
			response.Error.Message = "An unknown error occurred"
		} else {
			response.Error.Message = string(b)
		}
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode JSON error response: %v", err)
	}
}

// 従来形式の IF ブロック処理（/*IF ...*/ ... /*END*/）
func processConditionalsOnce(query string, params map[string]interface{}) string {
	reIf := regexp.MustCompile(`(?s)/\*IF\s+(.*?)\*/(.*?)/\*END\*/`)
	query = reIf.ReplaceAllStringFunc(query, func(block string) string {
		parts := reIf.FindStringSubmatch(block)
		if len(parts) < 3 {
			return ""
		}
		condition := strings.TrimSpace(parts[1])
		content := parts[2]
		if strings.Contains(condition, "!=") {
			condParts := strings.Split(condition, "!=")
			if len(condParts) == 2 {
				paramName := strings.TrimSpace(condParts[0])
				expected := strings.TrimSpace(condParts[1])
				if expected == "null" {
					if val, exists := params[paramName]; exists && !isEmpty(val) {
						return content
					}
				}
			}
		} else if strings.Contains(condition, "==") {
			condParts := strings.Split(condition, "==")
			if len(condParts) == 2 {
				paramName := strings.TrimSpace(condParts[0])
				expected := strings.TrimSpace(condParts[1])
				if expected == "null" {
					if val, exists := params[paramName]; !exists || isEmpty(val) {
						return content
					}
				}
			}
		}
		return ""
	})
	reBegin := regexp.MustCompile(`(?s)/\*BEGIN\*/(.*?)/\*END\*/`)
	query = reBegin.ReplaceAllStringFunc(query, func(block string) string {
		parts := reBegin.FindStringSubmatch(block)
		if len(parts) < 2 {
			return ""
		}
		content := parts[1]
		if strings.TrimSpace(content) != "" {
			return content
		}
		return ""
	})
	return query
}

func processConditionals(query string, params map[string]interface{}) string {
	prev := ""
	for query != prev {
		prev = query
		query = processConditionalsOnce(query, params)
	}
	return query
}

func isReturningQuery(query string) bool {
	upper := strings.ToUpper(query)
	return strings.Contains(upper, "RETURNING")
}

func nyanRunSQLHandler(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	// 第一引数: SQLファイルのパス
	if len(call.Arguments) < 1 {
		panic(vm.ToValue("nyanRunSQL requires at least the SQL file path as argument"))
	}
	sqlFilePath := call.Argument(0).String()

	// 第二引数: パラメータオブジェクト（存在しなければ空のマップ）
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

	// SQLファイルの読み込み
	sqlContent, err := ioutil.ReadFile(sqlFilePath)
	if err != nil {
		panic(vm.ToValue(fmt.Sprintf("failed to read SQL file %s: %v", sqlFilePath, err)))
	}
	normalizedSQL := normalizeSQL(string(sqlContent))
	log.Print(normalizedSQL)

	// 外側ブロックと IF ブロックの処理
	processedSQL := processWhereBlock(normalizedSQL, params)
	processedSQL = processConditionals(processedSQL, params)
	log.Print("Processed SQL: ", processedSQL)

	// パラメータ置換
	queryStr, args := prepareQueryWithParams(processedSQL, params)
	log.Print("Final Query: ", queryStr)

	// トランザクションが存在するか確認
	var execer interface {
		Query(query string, args ...interface{}) (*sql.Rows, error)
		Exec(query string, args ...interface{}) (sql.Result, error)
	}
	if txVal := vm.Get("nyanTx"); txVal != nil && txVal.Export() != nil {
		if tx, ok := txVal.Export().(*sql.Tx); ok {
			execer = tx
		}
	}
	if execer == nil {
		execer = db
	}

	// SQL の実行
	// SELECT 文、または RETURNING 句を含む場合は Query を使用して結果セットを取得
	if isSelectQuery(queryStr) || isReturningQuery(queryStr) {
        rows, err := execer.Query(queryStr, args...)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error executing SQL query: %v", err)))
		}
		defer rows.Close()
		jsonBytes, err := RowsToJSON(rows)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error converting rows to JSON: %v", err)))
		}
		// 返却する前に JSON 文字列を Go の値にパースする
		var result interface{}
		if err := json.Unmarshal(jsonBytes, &result); err != nil {
			panic(vm.ToValue(fmt.Sprintf("error parsing JSON: %v", err)))
		}
		return vm.ToValue(result)
	} else {
	    // それ以外の場合は Exec を使用して結果を取得
        result, err := execer.Exec(queryStr, args...)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error executing SQL query: %v", err)))
		}
		affected, err := result.RowsAffected()
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("error retrieving rows affected: %v", err)))
		}
		response := map[string]interface{}{
			"rowsAffected": affected,
		}
		jsonResp, _ := json.Marshal(response)
		var res interface{}
		if err := json.Unmarshal(jsonResp, &res); err != nil {
			panic(vm.ToValue(fmt.Sprintf("error parsing JSON: %v", err)))
		}
		return vm.ToValue(res)
	}
}



func runCheckScript(apiCheckScriptPath string, params map[string]interface{}, acceptedParamsKeys []string) (bool, int, interface{}, string, error) {
	var combinedScript strings.Builder
	for _, includePath := range config.JavascriptInclude {
		content, err := ioutil.ReadFile(includePath)
		if err != nil {
			return false, 500, nil, "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}
	checkContent, err := ioutil.ReadFile(apiCheckScriptPath)
	if err != nil {
		return false, 500, nil, "", fmt.Errorf("failed to read check script %s: %v", apiCheckScriptPath, err)
	}
	combinedScript.Write(checkContent)
	combinedScript.WriteString("\n")
	log.Printf("Combined check script:\n%s", combinedScript.String())
	vm := goja.New()
	registerNyanFuncs(vm, params, acceptedParamsKeys)


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
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}
	return string(body), nil
}

// POSTリクエストを行うGo関数
func jsonAPI(url string, jsonData []byte, username, password string, headers map[string]string) (string, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// BASIC認証のセットアップ（usernameが空でなければ）
	if username != "" {
		basicAuth := username + ":" + password
		basicAuthEncoded := base64.StdEncoding.EncodeToString([]byte(basicAuth))
		req.Header.Set("Authorization", "Basic "+basicAuthEncoded)
	}

	req.Header.Set("Content-Type", "application/json")

	// 追加のヘッダーが指定されていれば設定（複数指定可能）
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

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

func getAcceptedParamsKeys(sqlPaths []string) ([]string, error) {
	paramsMap, err := parseSQLParams(sqlPaths)
	if err != nil {
		return nil, err
	}
	var keys []string
	for k := range paramsMap {
		keys = append(keys, k)
	}
	return keys, nil
}

// runScript は、指定された JavaScript ファイル群を結合して実行します。
// この関数の先頭で DB トランザクションを開始し、グローバル変数 "nyanTx" として VM に渡します。
// スクリプト内で複数の nyanRunSQLHandler 呼び出しがあった場合、すべて同一トランザクション下で実行されます。
// スクリプトの実行が成功すればコミット、エラーがあればロールバックします。
func runScript(scriptPaths []string, params map[string]interface{}) (string, error) {
	// トランザクション開始
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %v", err)
	}
	// コミット済みかどうかのフラグ（defer で rollback するため）
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	// javascript_include に指定されたファイルと scriptPaths の内容を結合
	var combinedScript strings.Builder
	for _, includePath := range config.JavascriptInclude {
		content, err := ioutil.ReadFile(includePath)
		if err != nil {
			return "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}
	for _, scriptPath := range scriptPaths {
		content, err := ioutil.ReadFile(scriptPath)
		if err != nil {
			return "", fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// JavaScript VM の生成
	vm := goja.New()
	registerNyanFuncs(vm, params, nil)

	// スクリプト実行
	value, err := vm.RunString(combinedScript.String())
	if err != nil {
		return "", fmt.Errorf("script execution error: %v", err)
	}

	// トランザクションコミット
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %v", err)
	}
	committed = true

	return value.String(), nil
}

// evaluateCondition は、条件文字列（例："id != null OR date != null" や "id != null AND date != null"）を解析して評価します。
// まず "OR" で分割し、各部分についてさらに "AND" で分割、すべてが成立すればそのOR部分は成立とみなし、
// いずれかが成立すれば全体でtrueを返します。
func evaluateCondition(cond string, params map[string]interface{}) bool {
	orParts := strings.Split(cond, "OR")
	for _, orPart := range orParts {
		orPart = strings.TrimSpace(orPart)
		andParts := strings.Split(orPart, "AND")
		allTrue := true
		for _, andPart := range andParts {
			andPart = strings.TrimSpace(andPart)
			if !checkOneCondition(andPart, params) {
				allTrue = false
				break
			}
		}
		if allTrue {
			return true
		}
	}
	return false
}

// checkOneCondition は、単一の条件（例："id != null" または "id == null"）を評価します。
func checkOneCondition(cond string, params map[string]interface{}) bool {
	cond = strings.TrimSpace(cond)
	if strings.ToUpper(cond) == "BEGIN" {
		return true
	}
	if strings.Contains(cond, "!=") {
		parts := strings.SplitN(cond, "!=", 2)
		if len(parts) != 2 {
			return false
		}
		paramName := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		if strings.ToLower(expected) == "null" {
			if val, exists := params[paramName]; exists && !isEmpty(val) {
				return true
			}
		}
	} else if strings.Contains(cond, "==") {
		parts := strings.SplitN(cond, "==", 2)
		if len(parts) != 2 {
			return false
		}
		paramName := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		if strings.ToLower(expected) == "null" {
			if val, exists := params[paramName]; !exists || isEmpty(val) {
				return true
			}
		}
	}
	return false
}

// isEmpty は、値が nil、空文字、または空のスライスの場合に true を返します。
func isEmpty(val interface{}) bool {
	if val == nil {
		return true
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case []interface{}:
		return len(v) == 0
	case []string:
		return len(v) == 0
	}
	return false
}

// processWhereBlock は、SQL全文から外側ブロック (/*BEGIN*/ ～ /*END*/) を抽出し、
// ブロック内のIFブロック（/*IF ...*/ ... /*END*/）を処理して、外側ブロックを置き換えます。
func processWhereBlock(sqlText string, params map[string]interface{}) string {
	beginIdx := strings.Index(sqlText, "/*BEGIN*/")
	endIdx := strings.LastIndex(sqlText, "/*END*/")
	if beginIdx == -1 || endIdx == -1 || beginIdx >= endIdx {
		return sqlText
	}
	// 外側ブロック内の内容を抽出
	blockContent := sqlText[beginIdx+len("/*BEGIN*/") : endIdx]
	// ブロック内のIFブロックを処理する（normalize も必要に応じて行う）
	processedBlock := processCommentConditionals(blockContent, params)
	// 外側ブロック全体を置き換える
	result := sqlText[:beginIdx] + processedBlock + sqlText[endIdx+len("/*END*/"):]
	return result
}

// processCommentConditionals は、IFブロック（/*IF ...*/ ... /*END*/）を処理します。
func processCommentConditionals(block string, params map[string]interface{}) string {
	// 正規表現で非貪欲にIFブロックをマッチさせる
	re := regexp.MustCompile(`(?s)/\*IF\s+(.*?)\*/(.*?)\s*/\*END\*/`)
	processed := re.ReplaceAllStringFunc(block, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 3 {
			return ""
		}
		cond := strings.TrimSpace(submatches[1])
		content := strings.TrimSpace(submatches[2])
		// 特別条件 "BEGIN" なら無条件に出力
		if strings.ToUpper(cond) == "BEGIN" || evaluateCondition(cond, params) {
			return content
		}
		return ""
	})
	return processed
}

// 余分な空白文字（改行、タブ、連続するスペース）を1つのスペースに正規化する関数
func normalizeSQL(sqlText string) string {
	// \s+ は空白文字（スペース、タブ、改行など）の連続にマッチする
	return regexp.MustCompile(`\s+`).ReplaceAllString(sqlText, " ")
}

func executeAPIConfig(apiConfig APIConfig) ([]byte, error) {
	// ここでは、SQLが設定されている場合、最初のSQLファイルを実行する例です
	if len(apiConfig.SQL) > 0 {
		query, err := ioutil.ReadFile(apiConfig.SQL[0])
		if err != nil {
			return nil, fmt.Errorf("failed to read SQL file: %v", err)
		}
		// パラメータが必要な場合は適宜設定してください
		rows, err := db.Query(string(query))
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %v", err)
		}
		defer rows.Close()
		return RowsToJSON(rows)
	}
	// Scriptが設定されている場合は runScript を使う例
	if apiConfig.Script != "" {
		result, err := runScript([]string{apiConfig.Script}, make(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		return []byte(result), nil
	}
	return nil, fmt.Errorf("no executable configuration found")
}

func (h *Hub) Broadcast(channel string, message []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	clients, ok := h.clients[channel]
	if !ok {
		log.Printf("Channel [%s] に接続しているクライアントがありません", channel)
		return
	}
	for conn := range clients {
		if conn == nil {
			// nil の接続があればスキップ
			continue
		}
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Printf("チャネル [%s] への送信エラー: %v", channel, err)
		}
	}
}

// execCommand は指定されたコマンドを実行し、その結果を返します。
func execCommand(commandLine string) (*ExecResult, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", commandLine)
	} else {
		cmd = exec.Command("sh", "-c", commandLine)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	result := &ExecResult{
		Success:  false,
		ExitCode: 0,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		return result, fmt.Errorf("failed to exec: %w", err)
	}

	result.Success = true
	return result, nil
}

// nyanHostExecWrapper は、nyanHostExec の実装部分を切り出した関数です。
// コマンドを実行し、JSON タグに沿ったマップとして結果を返します。
func nyanHostExecWrapper(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	if len(call.Arguments) < 1 {
		panic(vm.ToValue("exec: No command provided"))
	}
	// コマンドライン文字列を取得
	commandLine := call.Argument(0).String()
	// コマンドを実行する
	result, err := execCommand(commandLine)
	if err != nil {
		panic(vm.ToValue(err.Error()))
	}
	// 構造体を JSON にシリアライズし、再度 Unmarshal してマップに変換することで、
	// JSON タグに基づいたキーが反映される
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		panic(vm.ToValue(err.Error()))
	}
	var out interface{}
	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		panic(vm.ToValue(err.Error()))
	}
	return vm.ToValue(out)
}

func adjustPaths(execDir string, config *Config) {
	if config.CertPath != "" && !filepath.IsAbs(config.CertPath) {
		config.CertPath = filepath.Join(execDir, config.CertPath)
	}
	if config.KeyPath != "" && !filepath.IsAbs(config.KeyPath) {
		config.KeyPath = filepath.Join(execDir, config.KeyPath)
	}
	// sqlite と duckdb の場合、DBName が相対パスなら絶対パスに変換
	if (config.DatabaseType == "sqlite" || config.DatabaseType == "duckdb") && config.DBName != "" && !filepath.IsAbs(config.DBName) {
		config.DBName = filepath.Join(execDir, config.DBName)
	}
}

// nyanGetFile
func nyanGetFile(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		// 引数のチェック
		if len(call.Arguments) < 1 {
			panic(vm.NewTypeError("nyanGetFileには1つの引数（ファイルパス）が必要です"))
		}
		relativePath := call.Arguments[0].String()

		// 実行中のバイナリのディレクトリからの相対パスに解決
		exePath, err := os.Executable()
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		exeDir := filepath.Dir(exePath)
		fullPath := filepath.Join(exeDir, relativePath)

		// ディレクトリ指定なら null
		if fi, err := os.Stat(fullPath); err == nil && fi.IsDir() {
			return goja.Null()
		}

		// 読み込み。存在しないなら null、その他はエラーを投げる
		content, err := os.ReadFile(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				return goja.Null()
			}
			// 権限など他のエラーはJS例外に（従来の動作）
			panic(vm.ToValue(err.Error()))
		}

		// 読み込んだ内容を文字列で返す（バイナリは Base64 を使う nyanReadFileB64 を推奨）
		return vm.ToValue(string(content))
	}
}

// parseScriptConstants は、指定されたスクリプトファイルから定数をパースします。
func parseScriptConstants(scriptPath string) (map[string]interface{}, []string, error) {
    data, err := ioutil.ReadFile(scriptPath)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
    }
    content := string(data)

    // 戻り値用の変数
    var acceptedParams map[string]interface{} = map[string]interface{}{}
    var outputColumns []string

    // const nyanAcceptedParams = {...};
    reAcceptedParams := regexp.MustCompile(`(?s)const\s+nyanAcceptedParams\s*=\s*({[\s\S]*?})\s*;`)
    if match := reAcceptedParams.FindStringSubmatch(content); len(match) >= 2 {
        jsonStr := match[1]
        if err := json.Unmarshal([]byte(jsonStr), &acceptedParams); err != nil {
            return nil, nil, fmt.Errorf("failed to parse nyanAcceptedParams: %v", err)
        }
    }

    // const nyanOutputColumns = [...];
    reOutputColumns := regexp.MustCompile(`(?s)const\s+nyanOutputColumns\s*=\s*(\[[\s\S]*?\])\s*;`)
    if match := reOutputColumns.FindStringSubmatch(content); len(match) >= 2 {
        jsonStr := match[1]
        if err := json.Unmarshal([]byte(jsonStr), &outputColumns); err != nil {
            return nil, nil, fmt.Errorf("failed to parse nyanOutputColumns: %v", err)
        }
    }

    return acceptedParams, outputColumns, nil
}

func respondJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	if data == nil {
		data = map[string]interface{}{}
	}
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}

	w.Header().Set("Content-Type", "application/json")
	// JSON-RPCのエラーコードとHTTPステータスを対応付け(例)
	var httpStatus int
	switch code {
	case -32601:
		httpStatus = http.StatusNotFound
	case -32602:
		httpStatus = http.StatusBadRequest
	case -32603, -32001:
		httpStatus = http.StatusInternalServerError
	case -32700:
		httpStatus = http.StatusBadRequest // JSONパースエラー
	default:
		httpStatus = http.StatusInternalServerError
	}
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(resp)
}

func handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	// 1) リクエストボディを読み込み、JSONRPCRequestにパースする
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		respondJSONRPCError(w, nil, -32700, "Parse error (failed to read body)", err.Error())
		return
	}
	defer r.Body.Close()

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		respondJSONRPCError(w, nil, -32700, "Parse error (invalid JSON)", err.Error())
		return
	}

	// 2) JSON-RPCの基本チェック
	if rpcReq.JSONRPC != "2.0" {
		respondJSONRPCError(w, rpcReq.ID, -32600, "Invalid Request: 'jsonrpc' must be '2.0'", nil)
		return
	}
	if rpcReq.Method == "" {
		respondJSONRPCError(w, rpcReq.ID, -32601, "Method not found (empty)", nil)
		return
	}

	// 3) 既存のハンドリングと同様に、api.json から対象設定を取得
	//    JSON-RPCでは、"method" を api キーとして扱う
	allParams := make(map[string]interface{})
	for k, v := range rpcReq.Params {
		allParams[k] = v
	}
	if _, ok := allParams["api"]; !ok {
		allParams["api"] = rpcReq.Method
	}
	apiKey, ok := allParams["api"].(string)
	if !ok || apiKey == "" {
		respondJSONRPCError(w, rpcReq.ID, -32602, "API key is required and must be a string", nil)
		return
	}

	apiConfig, exists := sqlFiles[apiKey]
	fmt.Print(apiConfig);
	if !exists {
		respondJSONRPCError(w, rpcReq.ID, -32601, "SQL files not found", nil)
		return
	}

	// 4) チェックスクリプトが設定されていれば実行
	nyanMode, _ := allParams["nyan_mode"].(string)
	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}
	if apiConfig.Check != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(apiConfig.Check, allParams, acceptedKeys)
		if err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "Check script error", err.Error())
			return
		}
		if !success {
			errData := map[string]interface{}{
				"message": "Request check failed",
				"detail":  errorObj,
			}
			respondJSONRPCError(w, rpcReq.ID, -32602, "Invalid params", errData)
			return
		}
		// nyan_mode=checkOnly ならチェック結果のみ返す
		if nyanMode == "checkOnly" {
			var checkResult map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &checkResult); err != nil {
				respondJSONRPCError(w, rpcReq.ID, -32603, "Failed to parse check result", err.Error())
				return
			}
			// statusCode はチェックスクリプトが返した値を使用
			rpcResp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  checkResult,
				ID:      rpcReq.ID,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(rpcResp)
			return
		}
	}

	// 5) メインの処理: Script または SQL の実行
	var finalResult map[string]interface{}
	if apiConfig.Script != "" {
		scriptResult, err := runScript([]string{apiConfig.Script}, allParams)
		if err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "Script execution error", err.Error())
			return
		}
		if err := json.Unmarshal([]byte(scriptResult), &finalResult); err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "Failed to parse script result as JSON", err.Error())
			return
		}
	} else if len(apiConfig.SQL) > 0 {
		var tx *sql.Tx
		if len(apiConfig.SQL) > 1 {
			tx, err = db.Begin()
			if err != nil {
				respondJSONRPCError(w, rpcReq.ID, -32603, "Failed to start transaction", err.Error())
				return
			}
			defer tx.Rollback()
		}
		var lastJSON []byte
		for _, sqlPath := range apiConfig.SQL {
			query, err := ioutil.ReadFile(sqlPath)
			if err != nil {
				respondJSONRPCError(w, rpcReq.ID, -32603, "Error reading SQL file", err.Error())
				return
			}
			processed := processWhereBlock(string(query), allParams)
			processed = processConditionals(processed, allParams)
			queryStr, args := prepareQueryWithParams(processed, allParams)
			if isSelectQuery(queryStr) || isReturningQuery(queryStr) {
				var rows *sql.Rows
				if tx != nil {
					rows, err = tx.Query(queryStr, args...)
				} else {
					rows, err = db.Query(queryStr, args...)
				}
				if err != nil {
					respondJSONRPCError(w, rpcReq.ID, -32603, "Error executing SQL query", err.Error())
					return
				}
				defer rows.Close()
				lastJSON, err = RowsToJSON(rows)
				if err != nil {
					respondJSONRPCError(w, rpcReq.ID, -32603, "Error formatting SQL results", err.Error())
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
					respondJSONRPCError(w, rpcReq.ID, -32603, "Error executing SQL query", err.Error())
					return
				}
				rowsAffected, err := result.RowsAffected()
				if err != nil {
					respondJSONRPCError(w, rpcReq.ID, -32603, "Error retrieving rows affected", err.Error())
					return
				}
				log.Printf("Rows affected: %d", rowsAffected)
				lastJSON = []byte("{}")
			}
		}
		if tx != nil {
			if err := tx.Commit(); err != nil {
				respondJSONRPCError(w, rpcReq.ID, -32603, "Failed to commit transaction", err.Error())
				return
			}
		}
		if string(lastJSON) == "null" {
			lastJSON = []byte("[]")
		}
		finalResult = map[string]interface{}{
			"success": true,
			"status":  200,
			"result":  json.RawMessage(lastJSON),
		}
	} else {
		respondJSONRPCError(w, rpcReq.ID, -32603, "No script or SQL defined for this method", nil)
		return
	}

	// 6) Push処理（必要な場合）
	performPush(apiConfig, allParams)

	// 7) 最終レスポンスの返却
	statusCode := 200
	if st, ok := finalResult["status"].(float64); ok {
		statusCode = int(st)
		delete(finalResult, "status")
	}
	rpcResp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  finalResult,
		ID:      rpcReq.ID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(rpcResp); err != nil {
		log.Printf("Failed to encode JSON-RPC response: %v", err)
	}
}

func performPush(apiConfig APIConfig, allParams map[string]interface{}) {
	if apiConfig.Push != "" {
		pushConfig, exists := sqlFiles[apiConfig.Push]
		if exists {
			var pushResult []byte
			var err error
			if pushConfig.Script != "" {
				s, err := runScript([]string{pushConfig.Script}, allParams)
				if err != nil {
					log.Printf("Push script error: %v", err)
				} else {
					pushResult = []byte(s)
				}
			} else {
				pushResult, err = executeAPIConfig(pushConfig)
				if err != nil {
					log.Printf("Push API execution error: %v", err)
				} else {
					type SQLResponse struct {
						Success bool            `json:"success"`
						Status  int             `json:"status"`
						Result  json.RawMessage `json:"result"`
					}
					response := SQLResponse{
						Success: true,
						Status:  200,
						Result:  pushResult,
					}
					pushResult, err = json.Marshal(response)
					if err != nil {
						log.Printf("Push response JSON marshal error: %v", err)
					}
				}
			}
			if pushResult != nil {
				log.Printf("Broadcasting push result to channel [%s]: %s", apiConfig.Push, pushResult)
				hub.Broadcast(apiConfig.Push, pushResult)
			}
		} else {
			log.Printf("Push API config [%s] not found", apiConfig.Push)
		}
	}
}

// saveBase64ToFile decodes a Base64 string and writes it to destPath.
// If destPath is relative, it is treated as relative to the executable directory.
func saveBase64ToFile(destPath, b64 string) error {
	// 1) パス解決（実行ファイルのディレクトリ基準）
	if !filepath.IsAbs(destPath) {
		exe, _ := os.Executable()
		destPath = filepath.Join(filepath.Dir(exe), destPath)
	}
	// 2) デコード
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	// 3) 中間ディレクトリ自動生成
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	// 4) 書き込み（既存なら上書き）
	return os.WriteFile(destPath, data, 0o644)
}

func registerNyanFuncs(vm *goja.Runtime, params map[string]interface{}, acceptedParamsKeys []string) {
	vm.Set("nyanAllParams", params)
	vm.Set("nyanAcceptedParamsKeys", acceptedParamsKeys)
	vm.Set("console", map[string]interface{}{
		"log": func(call goja.FunctionCall) goja.Value {
			var args []string
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
	vm.Set("nyanJsonAPI", func(call goja.FunctionCall) goja.Value {
		url := call.Argument(0).String()
		jsonData := call.Argument(1).String()
		username := call.Argument(2).String()
		password := call.Argument(3).String()

		// 第5引数：ヘッダー情報（オブジェクトまたはJSON文字列）
		var headers map[string]string
		if len(call.Arguments) >= 5 {
			// まずは、GojaのExportを使って直接オブジェクトとして取り出す
			if obj, ok := call.Argument(4).Export().(map[string]interface{}); ok {
				headers = make(map[string]string)
				for key, value := range obj {
					if s, ok := value.(string); ok {
						headers[key] = s
					} else {
						// 文字列以外なら fmt.Sprintで文字列化
						headers[key] = fmt.Sprint(value)
					}
				}
			} else {
				// オブジェクトとして取得できなければ、JSON文字列として処理する
				headerJSON := call.Argument(4).String()
				if err := json.Unmarshal([]byte(headerJSON), &headers); err != nil {
					panic(vm.ToValue("Invalid header JSON: " + err.Error()))
				}
			}
		}

		result, err := jsonAPI(url, []byte(jsonData), username, password, headers)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(result)
	})
	// VM にホストコマンド実行関数 nyanHostExec を登録
	vm.Set("nyanHostExec", func(call goja.FunctionCall) goja.Value {
		return nyanHostExecWrapper(vm, call)
	})
	vm.Set("nyanRunSQL", func(call goja.FunctionCall) goja.Value {
		return nyanRunSQLHandler(vm, call)
	})
	vm.Set("nyanGetFile", nyanGetFile(vm))
	vm.Set("nyanBase64Encode", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("nyanBase64Encode(data) : data が必要です"))
		}
		// ①第一引数を文字列として取得（Uint8Array などにしたい場合は要調整）
		src := call.Argument(0).String()
		// ②Base64 へ
		b64 := base64.StdEncoding.EncodeToString([]byte(src))
		return vm.ToValue(b64)
	})
	vm.Set("nyanBase64Decode", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("nyanBase64Decode(b64) : b64 が必要です"))
		}
		b64 := call.Argument(0).String()
		bin, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			panic(vm.ToValue("base64 decode error: " + err.Error()))
		}
		// 戻り値は UTF-8 文字列を想定（バイナリを扱う場合は Uint8Array などへ変換を）
		return vm.ToValue(string(bin))
	})
	vm.Set("nyanSaveFile", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic(vm.ToValue("nyanSaveFile(base64, path) requires 2 arguments"))
		}
		b64   := call.Argument(0).String()
		path  := call.Argument(1).String()
		if err := saveBase64ToFile(path, b64); err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return goja.Undefined() // 成功時は undefined を返すだけ
	})

	vm.Set("sha256", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("nyanSHA256(input) requires 1 argument"))
		}
		input := call.Argument(0).String()
		return vm.ToValue(sha256Hash(input))
	})

	vm.Set("sha1", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("nyanSHA1(input) requires 1 argument"))
		}
		input := call.Argument(0).String()
		return vm.ToValue(sha1Hash(input))
	})
}

func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func sha1Hash(input string) string {
	hash := sha1.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}
