package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

	"github.com/dop251/goja"
	_ "github.com/duckdb/duckdb-go/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/cors"
)

type Config struct {
	Name                   string             `json:"name"`
	Profile                string             `json:"profile"`
	Version                string             `json:"version"`
	Port                   int                `json:"Port"`
	CertPath               string             `json:"CertPath"`
	KeyPath                string             `json:"KeyPath"`
	DatabaseType           string             `json:"DBType"`
	DBUsername             string             `json:"DBUser"`
	DBPassword             string             `json:"DBPassword"`
	DBName                 string             `json:"DBName"`
	DBHost                 string             `json:"DBHost"`
	DBPort                 string             `json:"DBPort"`
	MaxOpenConnections     int                `json:"MaxOpenConnections"`
	MaxIdleConnections     int                `json:"MaxIdleConnections"`
	ConnMaxLifetimeSeconds int                `json:"ConnMaxLifetimeSeconds"`
	BasicAuth              BasicAuthConfig    `json:"BasicAuth"`
	Log                    LogConfig          `json:"log"`
	JavascriptInclude      []string           `json:"javascript_include,omitempty"`
	APIHotReload           APIHotReloadConfig `json:"APIHotReload"`
}

type APIHotReloadConfig struct {
	Enabled  bool   `json:"Enabled"`
	Interval string `json:"Interval"`
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
	SQL         []string      `json:"sql,omitempty"`
	Script      string        `json:"script,omitempty"`
	Path        string        `json:"path,omitempty"`
	ParamCheck  string        `json:"paramCheck,omitempty"`
	Check       string        `json:"check,omitempty"` // Deprecated: use ParamCheck. Kept as a compatibility alias.
	OutCheck    string        `json:"outCheck,omitempty"`
	Push        string        `json:"push,omitempty"`
	Trigger     TriggerConfig `json:"trigger,omitempty"`
	Description string        `json:"description"`
	Type        string        `json:"type,omitempty"`
	ConnectURL  string        `json:"connectURL,omitempty"`
}

type TriggerConfig struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (apiConfig *APIConfig) UnmarshalJSON(data []byte) error {
	type apiConfigJSON struct {
		SQL             []string      `json:"sql,omitempty"`
		Script          string        `json:"script,omitempty"`
		Path            string        `json:"path,omitempty"`
		ParamCheck      string        `json:"paramCheck,omitempty"`
		ParamCheckLower string        `json:"paramcheck,omitempty"`
		Check           string        `json:"check,omitempty"`
		OutCheck        string        `json:"outCheck,omitempty"`
		OutCheckLower   string        `json:"outcheck,omitempty"`
		Push            string        `json:"push,omitempty"`
		Trigger         TriggerConfig `json:"trigger,omitempty"`
		Description     string        `json:"description"`
		Type            string        `json:"type,omitempty"`
		ConnectURL      string        `json:"connectURL,omitempty"`
	}

	var raw apiConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	apiConfig.SQL = raw.SQL
	apiConfig.Script = raw.Script
	apiConfig.Path = raw.Path
	apiConfig.ParamCheck = raw.ParamCheck
	if apiConfig.ParamCheck == "" {
		apiConfig.ParamCheck = raw.ParamCheckLower
	}
	if apiConfig.ParamCheck == "" {
		apiConfig.ParamCheck = raw.Check
	}
	apiConfig.Check = ""
	apiConfig.OutCheck = raw.OutCheck
	if apiConfig.OutCheck == "" {
		apiConfig.OutCheck = raw.OutCheckLower
	}
	apiConfig.Push = raw.Push
	apiConfig.Trigger = raw.Trigger
	apiConfig.Description = raw.Description
	apiConfig.Type = raw.Type
	apiConfig.ConnectURL = raw.ConnectURL

	return nil
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
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var config Config
var db *sql.DB
var sqlFilesMu sync.RWMutex
var sqlFiles map[string]APIConfig
var dbType string
var buildVersion = "v0.0.20"

type serviceFilePath struct {
	Path   string
	Source string
}

type serviceFilePaths struct {
	API    serviceFilePath
	Config serviceFilePath
}

const (
	apiTypeAPI                       = "api"
	apiTypeWSClient                  = "ws_client"
	apiTypePublic                    = "public"
	apiTypeSchedule                  = "schedule"
	defaultAPIHotReloadCheckInterval = time.Second
)

// reParams は、/*id*/ のようなプレースホルダーを抽出する正規表現
var reParams = regexp.MustCompile(`(?s)/\*\s*([^*\/]+)\s*\*/\s*(?:'([^']*)'|"([^"]*)"|([^\s,;)]+))`)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 必要に応じてオリジンチェックを追加
	},
}

var hub *Hub

func resolveServiceFilePaths(execDir string, args []string) (serviceFilePaths, error) {
	flags := flag.NewFlagSet("NyanQL", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apiFlag := flags.String("api", "", "path to api.json")
	configFlag := flags.String("config", "", "path to config.json")
	if err := flags.Parse(args); err != nil {
		return serviceFilePaths{}, err
	}

	apiPath, apiSource := chooseServiceFilePath(*apiFlag, "NYAN_API_PATH", filepath.Join(execDir, "api.json"), "--api")
	configPath, configSource := chooseServiceFilePath(*configFlag, "NYAN_CONFIG_PATH", filepath.Join(execDir, "config.json"), "--config")

	resolvedAPIPath, err := resolveExistingServiceFilePath(apiPath, "api", apiSource)
	if err != nil {
		return serviceFilePaths{}, err
	}
	resolvedConfigPath, err := resolveExistingServiceFilePath(configPath, "config", configSource)
	if err != nil {
		return serviceFilePaths{}, err
	}

	return serviceFilePaths{
		API:    serviceFilePath{Path: resolvedAPIPath, Source: apiSource},
		Config: serviceFilePath{Path: resolvedConfigPath, Source: configSource},
	}, nil
}

func chooseServiceFilePath(cliValue, envName, defaultPath, cliSource string) (string, string) {
	if strings.TrimSpace(cliValue) != "" {
		return cliValue, cliSource
	}
	if envValue := strings.TrimSpace(os.Getenv(envName)); envValue != "" {
		return envValue, envName
	}
	return defaultPath, "default"
}

func resolveExistingServiceFilePath(pathValue, label, source string) (string, error) {
	resolvedPath, err := filepath.Abs(pathValue)
	if err != nil {
		return "", fmt.Errorf("%s file path could not be resolved: %s (source: %s): %w", label, pathValue, source, err)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%s file not found: %s (source: %s)", label, resolvedPath, source)
		}
		return "", fmt.Errorf("%s file cannot be accessed: %s (source: %s): %w", label, resolvedPath, source, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s file is a directory: %s (source: %s)", label, resolvedPath, source)
	}
	return resolvedPath, nil
}

// main
func main() {
	execDir, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir = filepath.Dir(execDir)

	paths, err := resolveServiceFilePaths(execDir, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	configFile, err := os.Open(paths.Config.Path)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()
	applyConfigDefaults(&config)
	if err = json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to decode config JSON: %v", err)
	}
	apiHotReloadInterval, err := parseAPIHotReloadInterval(config.APIHotReload.Interval)
	if err != nil {
		log.Fatalf("Invalid APIHotReload.Interval: %v", err)
	}
	configBaseDir := filepath.Dir(paths.Config.Path)
	apiBaseDir := filepath.Dir(paths.API.Path)
	adjustPaths(configBaseDir, &config)
	setupLogger(configBaseDir)
	log.Printf("Binary version: %s", buildVersion)
	log.Printf("Go runtime version: %s", runtime.Version())
	log.Printf("Config file: %s (source: %s)", paths.Config.Path, paths.Config.Source)
	log.Printf("API file: %s (source: %s)", paths.API.Path, paths.API.Source)
	log.Printf("Config version: %s", config.Version)

	db, err = connectDB(config)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	initialSQLFiles, initialAPIHash, err := readSQLFiles(paths.API.Path, apiBaseDir)
	if err != nil {
		log.Fatalf("Failed to load API file: %v", err)
	}
	setSQLFiles(initialSQLFiles)
	if err := startWebSocketClients(apiBaseDir); err != nil {
		log.Printf("Failed to start WebSocket clients: %v", err)
	}
	if err := startScheduleJobs(apiBaseDir); err != nil {
		log.Printf("Failed to start schedule jobs: %v", err)
	}
	if config.APIHotReload.Enabled {
		log.Printf("API hot reload enabled: file=%s check_interval=%s", paths.API.Path, apiHotReloadInterval)
		go watchAPIFile(paths.API.Path, apiBaseDir, apiHotReloadInterval, initialAPIHash)
	} else {
		log.Printf("API hot reload disabled")
	}

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
	if apiKey, requestedPath, apiConfig, ok := findPublicAPIForPath(r.URL.Path); ok {
		handlePublicRequest(w, r, apiKey, requestedPath, apiConfig)
		return
	}
	// 通常のHTTPリクエストならBasicAuthを適用して処理
	basicAuth(handleRequest, config)(w, r)
}

func findPublicAPIForPath(requestPath string) (string, string, APIConfig, bool) {
	var matchedKey string
	var matchedPath string
	var matchedConfig APIConfig
	for apiKey, apiConfig := range currentSQLFiles() {
		if getAPIType(apiConfig) != apiTypePublic {
			continue
		}
		routePath := "/" + strings.Trim(strings.TrimSpace(apiKey), "/")
		if routePath == "/" {
			continue
		}
		if requestPath == routePath || strings.HasPrefix(requestPath, routePath+"/") {
			if len(routePath) <= len(matchedPath) {
				continue
			}
			matchedKey = apiKey
			matchedPath = routePath
			matchedConfig = apiConfig
		}
	}
	if matchedKey == "" {
		return "", "", APIConfig{}, false
	}
	if requestPath == matchedPath {
		return matchedKey, "", matchedConfig, true
	}
	return matchedKey, strings.TrimPrefix(requestPath, matchedPath+"/"), matchedConfig, true
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

func parseAPIHotReloadInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultAPIHotReloadCheckInterval, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if interval <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return interval, nil
}

func applyConfigDefaults(target *Config) {
	target.APIHotReload.Enabled = true
	target.APIHotReload.Interval = defaultAPIHotReloadCheckInterval.String()
}

func readSQLFiles(apiFilePath, apiBaseDir string) (map[string]APIConfig, [sha256.Size]byte, error) {
	data, err := os.ReadFile(apiFilePath)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("read api file: %w", err)
	}
	files, err := decodeSQLFiles(data, apiBaseDir)
	if err != nil {
		return nil, sha256.Sum256(data), err
	}
	return files, sha256.Sum256(data), nil
}

func decodeSQLFiles(data []byte, apiBaseDir string) (map[string]APIConfig, error) {
	var files map[string]APIConfig
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, fmt.Errorf("decode api JSON: %w", err)
	}
	if files == nil {
		return nil, fmt.Errorf("decode api JSON: top-level value must be an object")
	}
	for apiKey, apiConfig := range files {
		if len(apiConfig.Script) > 0 && len(apiConfig.SQL) > 0 {
			return nil, fmt.Errorf("configuration error for API %q: if script is set, sql cannot be specified", apiKey)
		}
	}

	for apiKey, apiConfig := range files {
		for i, sqlPath := range apiConfig.SQL {
			if !filepath.IsAbs(sqlPath) {
				apiConfig.SQL[i] = filepath.Join(apiBaseDir, sqlPath)
			}
		}
		apiConfig.Script = resolvePathFromBase(apiBaseDir, apiConfig.Script)
		apiConfig.ParamCheck = resolvePathFromBase(apiBaseDir, apiConfig.ParamCheck)
		apiConfig.OutCheck = resolvePathFromBase(apiBaseDir, apiConfig.OutCheck)
		if apiConfig.Path != "" && !filepath.IsAbs(apiConfig.Path) {
			apiConfig.Path = filepath.Join(apiBaseDir, apiConfig.Path)
		}
		files[apiKey] = apiConfig
	}
	return files, nil
}

func currentSQLFiles() map[string]APIConfig {
	sqlFilesMu.RLock()
	files := sqlFiles
	sqlFilesMu.RUnlock()
	return files
}

func setSQLFiles(files map[string]APIConfig) {
	sqlFilesMu.Lock()
	sqlFiles = files
	sqlFilesMu.Unlock()
}

func backgroundSQLFiles(files map[string]APIConfig) map[string]APIConfig {
	background := make(map[string]APIConfig)
	for name, apiConfig := range files {
		switch getAPIType(apiConfig) {
		case apiTypeSchedule, apiTypeWSClient:
			background[name] = apiConfig
		}
	}
	return background
}

func reloadSQLFilesIfChanged(apiFilePath, apiBaseDir string, lastObservedHash [sha256.Size]byte) ([sha256.Size]byte, bool, error) {
	data, err := os.ReadFile(apiFilePath)
	if err != nil {
		return lastObservedHash, false, fmt.Errorf("read api file: %w", err)
	}
	observedHash := sha256.Sum256(data)
	if observedHash == lastObservedHash {
		return lastObservedHash, false, nil
	}

	candidate, err := decodeSQLFiles(data, apiBaseDir)
	if err != nil {
		return observedHash, false, err
	}
	current := currentSQLFiles()
	if !reflect.DeepEqual(backgroundSQLFiles(current), backgroundSQLFiles(candidate)) {
		return observedHash, false, fmt.Errorf("schedule or ws_client definitions changed; restart is required")
	}
	if reflect.DeepEqual(current, candidate) {
		return observedHash, false, nil
	}

	setSQLFiles(candidate)
	return observedHash, true, nil
}

func watchAPIFile(apiFilePath, apiBaseDir string, interval time.Duration, initialHash [sha256.Size]byte) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastObservedHash := initialHash
	lastReloadError := ""
	for range ticker.C {
		observedHash, reloaded, err := reloadSQLFilesIfChanged(apiFilePath, apiBaseDir, lastObservedHash)
		lastObservedHash = observedHash
		if err != nil {
			if err.Error() != lastReloadError {
				log.Printf("API hot reload failed: %v; current API configuration remains active", err)
			}
			lastReloadError = err.Error()
			continue
		}
		lastReloadError = ""
		if reloaded {
			log.Printf("API hot reload succeeded: api_count=%d", len(currentSQLFiles()))
		}
	}
}

func resolvePathFromBase(baseDir, pathValue string) string {
	if strings.TrimSpace(pathValue) == "" || filepath.IsAbs(pathValue) {
		return pathValue
	}
	return filepath.Join(baseDir, pathValue)
}

func getAPIType(apiConfig APIConfig) string {
	t := strings.TrimSpace(apiConfig.Type)
	if t == "" {
		return apiTypeAPI
	}
	return t
}

func getParamCheckScriptPath(apiConfig APIConfig) string {
	if apiConfig.ParamCheck != "" {
		return apiConfig.ParamCheck
	}
	return apiConfig.Check
}

func cloneParams(params map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func runOutCheckScript(apiConfig APIConfig, params map[string]interface{}, statusCode int, contentType string, body []byte) (bool, int, string, error) {
	outCheckPath := strings.TrimSpace(apiConfig.OutCheck)
	if outCheckPath == "" {
		return false, statusCode, "", nil
	}

	checkParams := cloneParams(params)
	bodyString := string(body)
	bodyBase64 := base64.StdEncoding.EncodeToString(body)
	checkParams["nyan_output"] = map[string]interface{}{
		"status":          statusCode,
		"contentType":     contentType,
		"headers":         map[string]string{},
		"body":            bodyString,
		"bodyBase64":      bodyBase64,
		"bodyLength":      len(body),
		"bodyLengthBytes": len(body),
	}
	checkParams["nyan_output_status"] = statusCode
	checkParams["nyan_output_content_type"] = contentType
	checkParams["nyan_output_body"] = bodyString
	checkParams["nyan_output_body_base64"] = bodyBase64

	success, checkStatusCode, _, jsonStr, err := runCheckScript(outCheckPath, checkParams, nil)
	if err != nil {
		return true, http.StatusInternalServerError, "", err
	}
	if checkStatusCode < 100 || checkStatusCode > 599 {
		return true, http.StatusInternalServerError, "", fmt.Errorf("outCheck response status is out of range: %d", checkStatusCode)
	}
	if success && checkStatusCode == http.StatusOK {
		return false, statusCode, "", nil
	}
	return true, checkStatusCode, jsonStr, nil
}

func isCheckOnlyMode(params map[string]interface{}) bool {
	if params == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(fmt.Sprint(params["nyan_mode"])), "checkOnly")
}

func collectRequestParams(r *http.Request) (map[string]interface{}, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading request body: %v", err)
		}
		var data map[string]interface{}
		if len(strings.TrimSpace(string(body))) == 0 {
			data = map[string]interface{}{}
		} else if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("error parsing JSON data: %v", err)
		}
		log.Printf("Received JSON: %v", data)
		return data, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("error parsing form data: %v", err)
	}
	params := make(map[string]interface{})
	for key, values := range r.Form {
		if len(values) > 1 {
			params[key] = values
			continue
		}
		val := values[0]
		trimmedVal := strings.TrimSpace(val)
		if (strings.HasPrefix(trimmedVal, "{") && strings.HasSuffix(trimmedVal, "}")) ||
			(strings.HasPrefix(trimmedVal, "[") && strings.HasSuffix(trimmedVal, "]")) {
			var parsed interface{}
			if err := json.Unmarshal([]byte(trimmedVal), &parsed); err == nil {
				params[key] = parsed
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
	return params, nil
}

func handlePublicRequest(w http.ResponseWriter, r *http.Request, apiKey string, requestedPath string, apiConfig APIConfig) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	publicPath := strings.TrimSpace(apiConfig.Path)
	if publicPath == "" {
		sendJSONError(w, "public path is missing", http.StatusInternalServerError)
		return
	}

	params, err := collectRequestParams(r)
	if err != nil {
		sendJSONError(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}
	params["api"] = apiKey
	params["nyan_public_endpoint"] = apiKey
	params["nyan_public_path"] = requestedPath

	checkScriptPath := getParamCheckScriptPath(apiConfig)
	if checkScriptPath == "" && isCheckOnlyMode(params) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true,"status":200,"result":null}`))
		return
	}
	if checkScriptPath != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(checkScriptPath, params, nil)
		if err != nil {
			log.Printf("Public paramCheck script error: %v", err)
			sendJSONError(w, err.Error(), statusCode)
			return
		}
		allowed := success && statusCode == http.StatusOK
		if isCheckOnlyMode(params) || !allowed {
			if !success && errorObj != nil {
				log.Printf("Public paramCheck rejected %s/%s: %v", apiKey, requestedPath, errorObj)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
	}

	if requestedPath == "" || !filepath.IsLocal(requestedPath) {
		http.NotFound(w, r)
		return
	}
	filePath := filepath.Join(publicPath, requestedPath)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		sendJSONError(w, "failed to read public file", http.StatusInternalServerError)
		return
	}
	if fileInfo.IsDir() {
		http.NotFound(w, r)
		return
	}

	if strings.TrimSpace(apiConfig.OutCheck) == "" {
		http.ServeFile(w, r, filePath)
		return
	}
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		sendJSONError(w, "failed to read public file", http.StatusInternalServerError)
		return
	}
	contentType := http.DetectContentType(fileContent)
	if handled, outStatusCode, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, contentType, fileContent); handled {
		if err != nil {
			log.Printf("Public outCheck script error: %v", err)
			sendJSONError(w, err.Error(), outStatusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(outStatusCode)
		w.Write([]byte(outJSON))
		return
	}
	http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), bytes.NewReader(fileContent))
}

// connectURL が env:XXXX 形式なら環境変数 XXXX で解決する。空や未設定はエラー。
func resolveConnectURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("connectURL is empty")
	}
	if strings.HasPrefix(raw, "env:") {
		key := strings.TrimPrefix(raw, "env:")
		if key == "" {
			return "", fmt.Errorf("connectURL env: prefix is empty")
		}
		val := os.Getenv(key)
		if val == "" {
			return "", fmt.Errorf("environment variable %s is empty", key)
		}
		return val, nil
	}
	return raw, nil
}

type wsClientConfig struct {
	name        string
	scriptPath  string
	connectURL  string
	description string
}

type scheduleJobConfig struct {
	name        string
	scriptPath  string
	trigger     TriggerConfig
	description string
	schedule    cronSchedule
}

type cronSchedule struct {
	minutes     cronField
	hours       cronField
	days        cronField
	months      cronField
	weekdays    cronField
	dayStar     bool
	weekdayStar bool
}

type cronField map[int]bool

func parseCronSchedule(expr string) (cronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return cronSchedule{}, fmt.Errorf("cron expression must have 5 fields")
	}

	minutes, _, err := parseCronField(fields[0], 0, 59, false)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("minute field: %w", err)
	}
	hours, _, err := parseCronField(fields[1], 0, 23, false)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("hour field: %w", err)
	}
	days, dayStar, err := parseCronField(fields[2], 1, 31, false)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("day field: %w", err)
	}
	months, _, err := parseCronField(fields[3], 1, 12, false)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("month field: %w", err)
	}
	weekdays, weekdayStar, err := parseCronField(fields[4], 0, 7, true)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("weekday field: %w", err)
	}

	return cronSchedule{
		minutes:     minutes,
		hours:       hours,
		days:        days,
		months:      months,
		weekdays:    weekdays,
		dayStar:     dayStar,
		weekdayStar: weekdayStar,
	}, nil
}

func parseCronField(field string, minValue, maxValue int, normalizeSunday bool) (cronField, bool, error) {
	values := make(cronField)
	isStar := field == "*"
	for _, part := range strings.Split(field, ",") {
		if part == "" {
			return nil, false, fmt.Errorf("empty list item")
		}

		step := 1
		base := part
		if strings.Contains(part, "/") {
			stepParts := strings.Split(part, "/")
			if len(stepParts) != 2 || stepParts[0] == "" || stepParts[1] == "" {
				return nil, false, fmt.Errorf("invalid step %q", part)
			}
			base = stepParts[0]
			parsedStep, err := strconv.Atoi(stepParts[1])
			if err != nil || parsedStep <= 0 {
				return nil, false, fmt.Errorf("invalid step %q", part)
			}
			step = parsedStep
		}

		start, end, err := cronRange(base, minValue, maxValue)
		if err != nil {
			return nil, false, err
		}
		for value := start; value <= end; value += step {
			normalized := value
			if normalizeSunday && normalized == 7 {
				normalized = 0
			}
			values[normalized] = true
		}
	}

	return values, isStar, nil
}

func cronRange(base string, minValue, maxValue int) (int, int, error) {
	if base == "*" {
		return minValue, maxValue, nil
	}
	if strings.Contains(base, "-") {
		rangeParts := strings.Split(base, "-")
		if len(rangeParts) != 2 || rangeParts[0] == "" || rangeParts[1] == "" {
			return 0, 0, fmt.Errorf("invalid range %q", base)
		}
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range start %q", base)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range end %q", base)
		}
		if start > end {
			return 0, 0, fmt.Errorf("range start is greater than end %q", base)
		}
		if start < minValue || end > maxValue {
			return 0, 0, fmt.Errorf("range %q is out of bounds %d-%d", base, minValue, maxValue)
		}
		return start, end, nil
	}

	value, err := strconv.Atoi(base)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid value %q", base)
	}
	if value < minValue || value > maxValue {
		return 0, 0, fmt.Errorf("value %q is out of bounds %d-%d", base, minValue, maxValue)
	}
	return value, value, nil
}

func (s cronSchedule) next(after time.Time) time.Time {
	next := after.Truncate(time.Minute).Add(time.Minute)
	limit := next.AddDate(5, 0, 0)
	for next.Before(limit) {
		if s.matches(next) {
			return next
		}
		next = next.Add(time.Minute)
	}
	return time.Time{}
}

func (s cronSchedule) matches(t time.Time) bool {
	weekday := int(t.Weekday())
	dayMatches := s.days[t.Day()]
	weekdayMatches := s.weekdays[weekday]
	switch {
	case !s.dayStar && !s.weekdayStar:
		if !dayMatches && !weekdayMatches {
			return false
		}
	case !dayMatches || !weekdayMatches:
		return false
	}

	return s.minutes[t.Minute()] &&
		s.hours[t.Hour()] &&
		s.months[int(t.Month())]
}

func startScheduleJobs(execDir string) error {
	var firstErr error
	for name, apiConfig := range currentSQLFiles() {
		if getAPIType(apiConfig) != apiTypeSchedule {
			continue
		}

		scriptPath := strings.TrimSpace(apiConfig.Script)
		triggerType := strings.TrimSpace(apiConfig.Trigger.Type)
		triggerValue := strings.TrimSpace(apiConfig.Trigger.Value)

		if scriptPath == "" {
			err := fmt.Errorf("schedule %s: script is missing", name)
			log.Print(err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if triggerType != "cron" {
			err := fmt.Errorf("schedule %s: unsupported trigger type %q", name, triggerType)
			log.Print(err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		schedule, err := parseCronSchedule(triggerValue)
		if err != nil {
			err = fmt.Errorf("schedule %s: invalid cron trigger %q: %w", name, triggerValue, err)
			log.Print(err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		scriptAbs := scriptPath
		if !filepath.IsAbs(scriptPath) {
			scriptAbs = filepath.Join(execDir, scriptPath)
		}

		cfg := scheduleJobConfig{
			name:        name,
			scriptPath:  scriptAbs,
			trigger:     apiConfig.Trigger,
			description: apiConfig.Description,
			schedule:    schedule,
		}

		log.Printf("Starting schedule job %s with cron %q", cfg.name, cfg.trigger.Value)
		go runScheduleJob(cfg)
	}

	return firstErr
}

func runScheduleJob(cfg scheduleJobConfig) {
	for {
		next := cfg.schedule.next(time.Now())
		if next.IsZero() {
			log.Printf("Schedule job %s has no next run time", cfg.name)
			return
		}

		log.Printf("Schedule job %s next run at %s", cfg.name, next.Format(time.RFC3339))
		timer := time.NewTimer(time.Until(next))
		<-timer.C

		params := map[string]interface{}{
			"nyan_job_name":              cfg.name,
			"nyan_schedule_trigger_type": cfg.trigger.Type,
			"nyan_schedule_trigger":      cfg.trigger.Value,
			"nyan_schedule_time":         next.Format(time.RFC3339),
		}
		result, err := runScript([]string{cfg.scriptPath}, params)
		if err != nil {
			log.Printf("Schedule job %s failed: %v", cfg.name, err)
			continue
		}
		log.Printf("Schedule job %s completed: %s", cfg.name, result)
	}
}

// startWebSocketClients は api.json に定義された ws_client を起動する。
func startWebSocketClients(execDir string) error {
	var firstErr error
	for name, apiConfig := range currentSQLFiles() {
		if getAPIType(apiConfig) != apiTypeWSClient {
			continue
		}

		scriptPath := strings.TrimSpace(apiConfig.Script)
		connectURLRaw := strings.TrimSpace(apiConfig.ConnectURL)

		if scriptPath == "" {
			err := fmt.Errorf("ws_client %s: script is missing", name)
			log.Print(err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if connectURLRaw == "" {
			err := fmt.Errorf("ws_client %s: connectURL is missing", name)
			log.Print(err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		connectURL, err := resolveConnectURL(connectURLRaw)
		if err != nil {
			log.Printf("ws_client %s: %v", name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		scriptAbs := scriptPath
		if !filepath.IsAbs(scriptPath) {
			scriptAbs = filepath.Join(execDir, scriptPath)
		}

		cfg := wsClientConfig{
			name:        name,
			scriptPath:  scriptAbs,
			connectURL:  connectURL,
			description: apiConfig.Description,
		}

		log.Printf("Starting WebSocket client %s -> %s", cfg.name, cfg.connectURL)
		go runWebSocketClient(cfg)
	}

	return firstErr
}

// 常時接続を維持し、切断時は指数バックオフで再接続する。
func runWebSocketClient(cfg wsClientConfig) {
	backoff := time.Second
	for {
		err := connectAndListenWebSocket(cfg)
		if err != nil {
			log.Printf("WebSocket client %s disconnected: %v", cfg.name, err)
		}

		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func connectAndListenWebSocket(cfg wsClientConfig) error {
	conn, _, err := websocket.DefaultDialer.Dial(cfg.connectURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	log.Printf("WebSocket client %s connected", cfg.name)

	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}

		if msgType == websocket.CloseMessage {
			return fmt.Errorf("close message received: %s", string(data))
		}

		log.Printf("ws_client %s received %s: %s", cfg.name, websocketMessageTypeLabel(msgType), string(data))

		allParams := map[string]interface{}{
			"api":             cfg.name,
			"ws_client":       cfg.name,
			"ws_message_type": websocketMessageTypeLabel(msgType),
			"ws_message_text": string(data),
			"ws_connect_url":  cfg.connectURL,
			"ws_description":  cfg.description,
		}

		if msgType == websocket.BinaryMessage {
			allParams["ws_message_base64"] = base64.StdEncoding.EncodeToString(data)
		}

		if msgType == websocket.TextMessage {
			var decoded interface{}
			if err := json.Unmarshal(data, &decoded); err == nil {
				allParams["ws_message_json"] = decoded
			}
		}

		result, err := runScript([]string{cfg.scriptPath}, allParams)
		if err != nil {
			log.Printf("ws_client %s script error: %v", cfg.name, err)
			continue
		}

		trimmed := strings.TrimSpace(result)
		if trimmed == "" {
			continue
		}

		if err := conn.WriteMessage(websocket.TextMessage, []byte(trimmed)); err != nil {
			return fmt.Errorf("send error: %w", err)
		}
	}
}

func websocketMessageTypeLabel(t int) string {
	switch t {
	case websocket.TextMessage:
		return "text"
	case websocket.BinaryMessage:
		return "binary"
	case websocket.CloseMessage:
		return "close"
	case websocket.PingMessage:
		return "ping"
	case websocket.PongMessage:
		return "pong"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func setupLogger(configBaseDir string) {
	logFilePath := resolvePathFromBase(configBaseDir, config.Log.Filename)
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

	params, err := collectRequestParams(r)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
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
	apiConfig, exists := currentSQLFiles()[apiKey]
	if !exists {
		sendJSONError(w, "SQL files not found", http.StatusNotFound)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		sendJSONError(w, fmt.Sprintf("API %s is not an HTTP/WebSocket endpoint", apiKey), http.StatusBadRequest)
		return
	}
	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}
	nyanMode, _ := params["nyan_mode"].(string)
	checkScriptPath := getParamCheckScriptPath(apiConfig)
	if nyanMode == "checkOnly" && checkScriptPath == "" {
		sendJSONError(w, "No check script for this API", http.StatusNotFound)
		return
	}
	if checkScriptPath != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(checkScriptPath, params, acceptedKeys)
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
			performPush(apiConfig, params)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			performPush(apiConfig, params)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
	}

	if apiConfig.Script != "" {
		scriptResult, err := runScript([]string{apiConfig.Script}, params)
		if err != nil {
			log.Printf("Script execution error: %v", err)
			sendJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := []byte(scriptResult)
		if handled, outStatusCode, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, "application/json", body); handled {
			if err != nil {
				log.Printf("outCheck script error: %v", err)
				sendJSONError(w, err.Error(), outStatusCode)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(outStatusCode)
			w.Write([]byte(outJSON))
			return
		}
		performPush(apiConfig, params)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
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
		query, err := os.ReadFile(sqlPath)
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
	body, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		sendJSONError(w, "Error formatting results", http.StatusInternalServerError)
		return
	}
	if handled, outStatusCode, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, "application/json", body); handled {
		if err != nil {
			log.Printf("outCheck script error: %v", err)
			sendJSONError(w, err.Error(), outStatusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(outStatusCode)
		w.Write([]byte(outJSON))
		return
	}
	performPush(apiConfig, params)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
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
	var args []interface{}
	placeholderCounter := 1
	var builder strings.Builder

	for i := 0; i < len(query); {
		start := strings.Index(query[i:], "/*")
		if start == -1 {
			builder.WriteString(query[i:])
			break
		}
		start += i
		commentEnd := strings.Index(query[start+2:], "*/")
		if commentEnd == -1 {
			builder.WriteString(query[i:])
			break
		}
		commentEnd += start + 2
		paramName := strings.TrimSpace(query[start+2 : commentEnd])
		if paramName == "" || strings.ContainsAny(paramName, "*/") || strings.HasPrefix(strings.ToUpper(paramName), "IF ") || strings.EqualFold(paramName, "END") || strings.EqualFold(paramName, "BEGIN") {
			builder.WriteString(query[i : commentEnd+2])
			i = commentEnd + 2
			continue
		}

		_, defaultEnd := findPlaceholderDefault(query, commentEnd+2)
		if defaultEnd == -1 {
			builder.WriteString(query[i : commentEnd+2])
			i = commentEnd + 2
			continue
		}
		builder.WriteString(query[i:start])

		value, ok := params[paramName]
		if !ok {
			args = append(args, nil)
			builder.WriteString(nextPlaceholder(&placeholderCounter))
			i = defaultEnd
			continue
		}

		rv := reflect.ValueOf(value)
		if !rv.IsValid() {
			args = append(args, nil)
			builder.WriteString(nextPlaceholder(&placeholderCounter))
			i = defaultEnd
			continue
		}

		// --- JSONB/文字列系の特別扱い ---
		// []byte は 1つの値として扱う
		if b, ok := value.([]byte); ok {
			args = append(args, string(b))
			builder.WriteString(nextPlaceholder(&placeholderCounter))
			i = defaultEnd
			continue
		}

		// json.RawMessage も 1つの値として扱う
		if jm, ok := value.(json.RawMessage); ok {
			args = append(args, string(jm))
			builder.WriteString(nextPlaceholder(&placeholderCounter))
			i = defaultEnd
			continue
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
			builder.WriteString(nextPlaceholder(&placeholderCounter))
			i = defaultEnd
			continue
		}

		// --- 通常のスライスは IN (...) 展開 ---
		if kind == reflect.Slice {
			n := rv.Len()
			if n == 0 {
				builder.WriteString("NULL")
				i = defaultEnd
				continue
			}
			placeholders := make([]string, 0, n)
			for i := 0; i < n; i++ {
				args = append(args, rv.Index(i).Interface())
				placeholders = append(placeholders, nextPlaceholder(&placeholderCounter))
			}
			builder.WriteString(strings.Join(placeholders, ","))
			i = defaultEnd
			continue
		}

		// --- 通常の単一値 ---
		args = append(args, value)
		builder.WriteString(nextPlaceholder(&placeholderCounter))
		i = defaultEnd
	}

	return builder.String(), args
}

func nextPlaceholder(counter *int) string {
	if dbType == "postgres" {
		place := fmt.Sprintf("$%d", *counter)
		*counter = *counter + 1
		return place
	}
	*counter = *counter + 1
	return "?"
}

func findPlaceholderDefault(query string, offset int) (int, int) {
	i := offset
	for i < len(query) && (query[i] == ' ' || query[i] == '\t' || query[i] == '\r' || query[i] == '\n') {
		i++
	}
	if i >= len(query) {
		return i, -1
	}
	switch query[i] {
	case '\'', '"':
		end := scanQuotedSQLValue(query, i)
		return i, end
	case '{':
		end := scanBalancedSQLValue(query, i, '{', '}')
		return i, end
	case '[':
		end := scanBalancedSQLValue(query, i, '[', ']')
		return i, end
	default:
		j := i
		for j < len(query) && !strings.ContainsRune(" \t\r\n,;)", rune(query[j])) {
			j++
		}
		if j == i {
			return i, -1
		}
		return i, j
	}
}

func scanQuotedSQLValue(s string, start int) int {
	quote := s[start]
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == quote {
			return i + 1
		}
	}
	return len(s)
}

func scanBalancedSQLValue(s string, start int, open byte, close byte) int {
	depth := 0
	inQuote := byte(0)
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			continue
		}
		if ch == open {
			depth++
			continue
		}
		if ch == close {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
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
	// API定義から必要な情報のみ抽出します。
	filteredApis := make(map[string]APIDetails)
	for key, apiConf := range currentSQLFiles() {
		if getAPIType(apiConf) != apiTypeAPI {
			continue
		}
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
	apiConfig, exists := currentSQLFiles()[apiName]
	if !exists {
		sendJSONError(w, "API not found", http.StatusNotFound)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
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
		data, err := os.ReadFile(filePath)
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
	sqlContent, err := os.ReadFile(sqlFilePath)
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
		content, err := os.ReadFile(includePath)
		if err != nil {
			return false, 500, nil, "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}
	checkContent, err := os.ReadFile(apiCheckScriptPath)
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
	jsonStr, err := checkResultToJSONString(value)
	if err != nil {
		return false, 500, nil, "", err
	}
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

func checkResultToJSONString(value goja.Value) (string, error) {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return "", fmt.Errorf("check script must return JSON")
	}
	exported := value.Export()
	if jsonStr, ok := exported.(string); ok {
		return jsonStr, nil
	}
	b, err := json.Marshal(exported)
	if err != nil {
		return "", fmt.Errorf("failed to marshal check result: %v", err)
	}
	return string(b), nil
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
	body, err := io.ReadAll(resp.Body)
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

	body, err := io.ReadAll(resp.Body)
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
// スクリプト内で複数の nyanRunSQL 呼び出しがあった場合、すべて同一トランザクション下で実行されます。
// スクリプトの実行が成功すればコミット、エラーがあればロールバックします。
func runScript(scriptPaths []string, params map[string]interface{}) (string, error) {
	// トランザクション開始
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %v", err)
	}

	committed := false
	defer func() {
		// committed=false のままなら rollback（成功時や commit 後は rollback しない）
		if !committed {
			if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
				log.Printf("transaction rollback error: %v", rbErr)
			}
		}
	}()

	// javascript_include に指定されたファイルと scriptPaths の内容を結合
	var combinedScript strings.Builder

	for _, includePath := range config.JavascriptInclude {
		content, err := os.ReadFile(includePath)
		if err != nil {
			return "", fmt.Errorf("failed to read javascript include file %s: %v", includePath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}
	for _, scriptPath := range scriptPaths {
		content, err := os.ReadFile(scriptPath)
		if err != nil {
			return "", fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
		}
		combinedScript.Write(content)
		combinedScript.WriteString("\n")
	}

	// JavaScript VM の生成
	vm := goja.New()

	// 既存の関数群を登録
	registerNyanFuncs(vm, params, nil)

	// ★重要：トランザクションを VM に渡す（nyanRunSQLHandler がこれを拾って tx で実行する）
	vm.Set("nyanTx", tx)

	// スクリプト実行
	value, err := vm.RunString(combinedScript.String())
	if err != nil {
		// committed は false のままなので defer rollback が動く
		return "", fmt.Errorf("script execution error: %v", err)
	}

	// トランザクションコミット
	if err := tx.Commit(); err != nil {
		// committed は false のままなので defer rollback が動く（ErrTxDone 以外はログ）
		return "", fmt.Errorf("failed to commit transaction: %v", err)
	}

	committed = true
	return value.String(), nil
}

// callNyanAPIFromVM は、JavaScript VM から api.json の API を check/script/sql 含めて実行します。
func callNyanAPIFromVM(apiName string, allParams map[string]interface{}) (string, error) {
	if strings.TrimSpace(apiName) == "" {
		return "", fmt.Errorf("api name is required")
	}

	apiConfig, exists := currentSQLFiles()[apiName]
	if !exists {
		return "", fmt.Errorf("API config not found: %s", apiName)
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		return "", fmt.Errorf("API %s is not an HTTP/WebSocket endpoint", apiName)
	}

	params := map[string]interface{}{}
	for k, v := range allParams {
		params[k] = v
	}
	params["api"] = apiName

	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}
	nyanMode, _ := params["nyan_mode"].(string)
	checkScriptPath := getParamCheckScriptPath(apiConfig)
	if nyanMode == "checkOnly" && checkScriptPath == "" {
		return "", fmt.Errorf("No check script for API %s", apiName)
	}

	if checkScriptPath != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(checkScriptPath, params, acceptedKeys)
		if err != nil {
			return "", fmt.Errorf("check script error: %v", err)
		}
		if !success {
			if errorObj == nil {
				errorObj = "Request check failed"
			}
			response := map[string]interface{}{
				"success": false,
				"status":  statusCode,
				"error":   errorObj,
			}
			b, err := json.Marshal(response)
			if err != nil {
				return "", fmt.Errorf("failed to marshal check response for API %s: %v", apiName, err)
			}
			return string(b), nil
		}
		if nyanMode == "checkOnly" {
			performPush(apiConfig, params)
			return jsonStr, nil
		}
		if apiConfig.Script != "" {
			result, err := runScript([]string{apiConfig.Script}, params)
			if err != nil {
				return "", fmt.Errorf("failed to run API %s: %v", apiName, err)
			}
			if handled, _, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, "application/json", []byte(result)); handled {
				if err != nil {
					return "", fmt.Errorf("outCheck script error: %v", err)
				}
				return outJSON, nil
			}
			performPush(apiConfig, params)
			return result, nil
		}
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			performPush(apiConfig, params)
			return jsonStr, nil
		}
	}

	if apiConfig.Script != "" {
		result, err := runScript([]string{apiConfig.Script}, params)
		if err != nil {
			return "", fmt.Errorf("failed to run API %s: %v", apiName, err)
		}
		if handled, _, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, "application/json", []byte(result)); handled {
			if err != nil {
				return "", fmt.Errorf("outCheck script error: %v", err)
			}
			return outJSON, nil
		}
		performPush(apiConfig, params)
		return result, nil
	}

	if len(apiConfig.SQL) == 0 {
		return "", fmt.Errorf("No script or SQL defined for API %s", apiName)
	}

	var tx *sql.Tx
	if len(apiConfig.SQL) > 1 {
		tx, err = db.Begin()
		if err != nil {
			return "", fmt.Errorf("failed to start transaction for API %s: %v", apiName, err)
		}
		defer tx.Rollback()
	}

	var lastJSON []byte
	for _, sqlPath := range apiConfig.SQL {
		query, err := os.ReadFile(sqlPath)
		if err != nil {
			return "", fmt.Errorf("failed to read SQL file for API %s: %v", apiName, err)
		}
		processed := processWhereBlock(string(query), params)
		processed = processConditionals(processed, params)
		queryStr, args := prepareQueryWithParams(processed, params)

		if isSelectQuery(queryStr) || isReturningQuery(queryStr) {
			var rows *sql.Rows
			if tx != nil {
				rows, err = tx.Query(queryStr, args...)
			} else {
				rows, err = db.Query(queryStr, args...)
			}
			if err != nil {
				return "", fmt.Errorf("failed to execute SQL query for API %s: %v", apiName, err)
			}

			lastJSON, err = RowsToJSON(rows)
			closeErr := rows.Close()
			if err != nil {
				return "", fmt.Errorf("failed to format SQL result for API %s: %v", apiName, err)
			}
			if closeErr != nil {
				return "", fmt.Errorf("failed to close SQL rows for API %s: %v", apiName, closeErr)
			}
		} else {
			var result sql.Result
			if tx != nil {
				result, err = tx.Exec(queryStr, args...)
			} else {
				result, err = db.Exec(queryStr, args...)
			}
			if err != nil {
				return "", fmt.Errorf("failed to execute SQL statement for API %s: %v", apiName, err)
			}
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return "", fmt.Errorf("failed to get rows affected for API %s: %v", apiName, err)
			}
			log.Printf("Rows affected: %d", rowsAffected)
			lastJSON = []byte("{}")
		}
	}

	if tx != nil {
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("failed to commit transaction for API %s: %v", apiName, err)
		}
	}

	if string(lastJSON) == "null" {
		lastJSON = []byte("[]")
	}

	response := SQLResponse{
		Success: true,
		Status:  200,
		Result:  json.RawMessage(lastJSON),
	}
	b, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal SQL response for API %s: %v", apiName, err)
	}
	if handled, _, outJSON, err := runOutCheckScript(apiConfig, params, http.StatusOK, "application/json", b); handled {
		if err != nil {
			return "", fmt.Errorf("outCheck script error: %v", err)
		}
		return outJSON, nil
	}
	performPush(apiConfig, params)
	return string(b), nil
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
	if isEmptyConditionalSQLBlock(processedBlock) {
		processedBlock = ""
	}
	// 外側ブロック全体を置き換える
	result := sqlText[:beginIdx] + processedBlock + sqlText[endIdx+len("/*END*/"):]
	return result
}

func isEmptyConditionalSQLBlock(block string) bool {
	trimmed := strings.TrimSpace(block)
	if trimmed == "" {
		return true
	}
	re := regexp.MustCompile(`(?i)\b(WHERE|AND|OR)\b`)
	withoutConnectors := re.ReplaceAllString(trimmed, "")
	return strings.TrimSpace(withoutConnectors) == ""
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
	// 行コメントを削除してから空白を正規化する
	lines := strings.Split(sqlText, "\n")
	for i, line := range lines {
		inSingleQuote := false
		for j := 0; j+1 < len(line); j++ {
			if line[j] == '\'' {
				inSingleQuote = !inSingleQuote
				continue
			}
			if !inSingleQuote && line[j] == '-' && line[j+1] == '-' {
				lines[i] = line[:j]
				break
			}
		}
	}
	withoutLineComments := strings.Join(lines, "\n")
	// \s+ は空白文字（スペース、タブ、改行など）の連続にマッチする
	return regexp.MustCompile(`\s+`).ReplaceAllString(withoutLineComments, " ")
}

func executeAPIConfig(apiConfig APIConfig) ([]byte, error) {
	// ここでは、SQLが設定されている場合、最初のSQLファイルを実行する例です
	if len(apiConfig.SQL) > 0 {
		query, err := os.ReadFile(apiConfig.SQL[0])
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

func adjustPaths(configBaseDir string, config *Config) {
	if config.CertPath != "" && !filepath.IsAbs(config.CertPath) {
		config.CertPath = filepath.Join(configBaseDir, config.CertPath)
	}
	if config.KeyPath != "" && !filepath.IsAbs(config.KeyPath) {
		config.KeyPath = filepath.Join(configBaseDir, config.KeyPath)
	}
	// sqlite と duckdb の場合、DBName が相対パスなら絶対パスに変換
	if (config.DatabaseType == "sqlite" || config.DatabaseType == "duckdb") && config.DBName != "" && !filepath.IsAbs(config.DBName) {
		config.DBName = filepath.Join(configBaseDir, config.DBName)
	}
	for i, includePath := range config.JavascriptInclude {
		config.JavascriptInclude[i] = resolvePathFromBase(configBaseDir, includePath)
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
	data, err := os.ReadFile(scriptPath)
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

func respondJSONRPCResultJSON(w http.ResponseWriter, id interface{}, statusCode int, jsonStr string) {
	var result interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		respondJSONRPCError(w, id, -32603, "Failed to parse check result", err.Error())
		return
	}
	rpcResp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(rpcResp); err != nil {
		log.Printf("Failed to encode JSON-RPC response: %v", err)
	}
}

func handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	// 1) リクエストボディを読み込み、JSONRPCRequestにパースする
	body, err := io.ReadAll(r.Body)
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

	apiConfig, exists := currentSQLFiles()[apiKey]
	fmt.Print(apiConfig)
	if !exists {
		respondJSONRPCError(w, rpcReq.ID, -32601, "SQL files not found", nil)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		respondJSONRPCError(w, rpcReq.ID, -32601, "Method not found", nil)
		return
	}

	// 4) チェックスクリプトが設定されていれば実行
	nyanMode, _ := allParams["nyan_mode"].(string)
	acceptedKeys, err := getAcceptedParamsKeys(apiConfig.SQL)
	if err != nil {
		log.Printf("Failed to get accepted params keys: %v", err)
		acceptedKeys = []string{}
	}
	checkScriptPath := getParamCheckScriptPath(apiConfig)
	if checkScriptPath != "" {
		success, statusCode, errorObj, jsonStr, err := runCheckScript(checkScriptPath, allParams, acceptedKeys)
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
	var finalBody []byte
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
		finalBody = []byte(scriptResult)
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
			query, err := os.ReadFile(sqlPath)
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
		finalBody, err = json.Marshal(finalResult)
		if err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "Failed to marshal SQL result", err.Error())
			return
		}
	} else {
		respondJSONRPCError(w, rpcReq.ID, -32603, "No script or SQL defined for this method", nil)
		return
	}

	statusCode := 200
	if st, ok := finalResult["status"].(float64); ok {
		statusCode = int(st)
	} else if st, ok := finalResult["status"].(int); ok {
		statusCode = st
	}
	if handled, outStatusCode, outJSON, err := runOutCheckScript(apiConfig, allParams, statusCode, "application/json", finalBody); handled {
		if err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "outCheck script error", err.Error())
			return
		}
		respondJSONRPCResultJSON(w, rpcReq.ID, outStatusCode, outJSON)
		return
	}

	// 6) Push処理（必要な場合）
	performPush(apiConfig, allParams)

	// 7) 最終レスポンスの返却
	if st, ok := finalResult["status"].(float64); ok {
		statusCode = int(st)
		delete(finalResult, "status")
	} else if _, ok := finalResult["status"].(int); ok {
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
		pushConfig, exists := currentSQLFiles()[apiConfig.Push]
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
	jsonAPIFunc := func(call goja.FunctionCall) goja.Value {
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
	}
	vm.Set("nyanJsonAPI", jsonAPIFunc)
	vm.Set("nyanCallAPI", jsonAPIFunc)
	// VM にホストコマンド実行関数 nyanHostExec を登録
	vm.Set("nyanHostExec", func(call goja.FunctionCall) goja.Value {
		return nyanHostExecWrapper(vm, call)
	})
	vm.Set("nyanRunSQL", func(call goja.FunctionCall) goja.Value {
		return nyanRunSQLHandler(vm, call)
	})
	vm.Set("nyanGetFile", nyanGetFile(vm))
	vm.Set("nyanCallMe", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("nyanCallMe(params) requires an object argument"))
		}

		var params map[string]interface{}

		raw := call.Argument(0).Export()
		if raw != nil {
			if m, ok := raw.(map[string]interface{}); ok {
				params = m
			} else if obj, ok := call.Argument(0).(*goja.Object); ok {
				exported := obj.Export()
				if m, ok := exported.(map[string]interface{}); ok {
					params = m
				}
			}
		}
		if params == nil {
			panic(vm.ToValue("nyanCallMe(params) requires an object argument"))
		}

		v, ok := params["api"]
		if !ok {
			panic(vm.ToValue("nyanCallMe(params) requires params.api"))
		}
		apiName, ok := v.(string)
		if !ok || strings.TrimSpace(apiName) == "" {
			panic(vm.ToValue("nyanCallMe(params) requires params.api as non-empty string"))
		}
		apiName = strings.TrimSpace(apiName)
		params["api"] = apiName

		result, err := callNyanAPIFromVM(apiName, params)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		var parsed interface{}
		if err := json.Unmarshal([]byte(result), &parsed); err == nil {
			return vm.ToValue(parsed)
		}
		return vm.ToValue(result)
	})
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
		b64 := call.Argument(0).String()
		path := call.Argument(1).String()
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
