package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
	"strings"
)

type Config struct {
	Name         string          `json:"name"`
	Profile      string          `json:"profile"`
	Version      string          `json:"version"`
	Port         int             `json:"Port"`
	CertPath     string          `json:"CertPath"`
	KeyPath      string          `json:"KeyPath"`
	DatabaseType string          `json:"DBType"`
	DBUsername   string          `json:"DBUser"`
	DBPassword   string          `json:"DBPassword"`
	DBName       string          `json:"DBName"`
	DBHost       string          `json:"DBHost"`
	DBPort       string          `json:"DBPort"`
	BasicAuth    BasicAuthConfig `json:"BasicAuth"`
	Log          LogConfig       `json:"log"`
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
	Error string `json:"error"`
}

type APIConfig struct {
	SQL         []string `json:"sql"`
	Description string   `json:"description"`
}

var config Config
var db *sql.DB
var sqlFiles map[string]APIConfig
var dbType string

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

func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
