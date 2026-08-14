package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
	_ "github.com/duckdb/duckdb-go/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/cors"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/argon2"
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
	SQL                        []string             `json:"sql,omitempty"`
	Script                     string               `json:"script,omitempty"`
	Path                       string               `json:"path,omitempty"`
	ParamCheck                 string               `json:"paramCheck,omitempty"`
	Check                      string               `json:"check,omitempty"` // Deprecated: use ParamCheck. Kept as a compatibility alias.
	OutCheck                   string               `json:"outCheck,omitempty"`
	Push                       string               `json:"push,omitempty"`
	Trigger                    TriggerConfig        `json:"trigger,omitempty"`
	Description                string               `json:"description"`
	Title                      string               `json:"title,omitempty"`
	Type                       string               `json:"type,omitempty"`
	ConnectURL                 string               `json:"connectURL,omitempty"`
	HTTP                       *HTTPAPIConfig       `json:"http,omitempty"`
	Runtime                    APIRuntimeConfig     `json:"runtime,omitempty"`
	Transport                  string               `json:"transport,omitempty"`
	ProtocolVersions           []string             `json:"protocolVersions,omitempty"`
	Resource                   string               `json:"resource,omitempty"`
	Guard                      MCPGuardConfig       `json:"guard,omitempty"`
	Tools                      []MCPToolConfig      `json:"tools,omitempty"`
	Instructions               string               `json:"instructions,omitempty"`
	AllowedOrigins             []string             `json:"allowedOrigins,omitempty"`
	RateLimit                  *HTTPRateLimitConfig `json:"rateLimit,omitempty"`
	MaxConcurrent              int                  `json:"maxConcurrent,omitempty"`
	RedirectURIAllowedPrefixes []string             `json:"redirectURIAllowedPrefixes,omitempty"`
	OAuth                      MCPOAuthConfig       `json:"oauth,omitempty"`
	SecuritySchemes            []MCPSecurityScheme  `json:"securitySchemes,omitempty"`
	Annotations                MCPToolAnnotations   `json:"annotations,omitempty"`
	Scopes                     []string             `json:"scopes,omitempty"`
}

type HTTPAPIConfig struct {
	Path             string               `json:"path,omitempty"`
	Methods          []string             `json:"methods,omitempty"`
	Access           string               `json:"access,omitempty"`
	ResponseMode     string               `json:"responseMode,omitempty"`
	AllowedRemoteIPs []string             `json:"allowedRemoteIPs,omitempty"`
	AllowedOrigins   []string             `json:"allowedOrigins,omitempty"`
	RateLimit        *HTTPRateLimitConfig `json:"rateLimit,omitempty"`
}

type HTTPRateLimitConfig struct {
	Requests int    `json:"requests"`
	Window   string `json:"window"`
}

type APIRuntimeConfig struct {
	Capabilities []string               `json:"capabilities,omitempty"`
	SQLFiles     []string               `json:"sqlFiles,omitempty"`
	Settings     map[string]interface{} `json:"settings,omitempty"`
}

type MCPGuardConfig struct {
	API string `json:"api,omitempty"`
}

type MCPOAuthConfig struct {
	AuthorizationServerMetadata string `json:"authorizationServerMetadata,omitempty"`
	ProtectedResourceMetadata   string `json:"protectedResourceMetadata,omitempty"`
	Authorize                   string `json:"authorize,omitempty"`
	Token                       string `json:"token,omitempty"`
	Register                    string `json:"register,omitempty"`
	AdminUser                   string `json:"adminUser,omitempty"`
	VerifyAccess                string `json:"verifyAccess,omitempty"`
}

type MCPSecurityScheme struct {
	Type   string   `json:"type"`
	Scopes []string `json:"scopes,omitempty"`
}

type MCPToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

type MCPToolConfig struct {
	Name            string              `json:"name"`
	API             string              `json:"api"`
	Title           string              `json:"title,omitempty"`
	Description     string              `json:"description,omitempty"`
	SecuritySchemes []MCPSecurityScheme `json:"securitySchemes,omitempty"`
	Annotations     MCPToolAnnotations  `json:"annotations,omitempty"`
}

type TriggerConfig struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (apiConfig *APIConfig) UnmarshalJSON(data []byte) error {
	type apiConfigJSON struct {
		SQL                        []string             `json:"sql,omitempty"`
		Script                     string               `json:"script,omitempty"`
		Path                       string               `json:"path,omitempty"`
		ParamCheck                 string               `json:"paramCheck,omitempty"`
		ParamCheckLower            string               `json:"paramcheck,omitempty"`
		Check                      string               `json:"check,omitempty"`
		OutCheck                   string               `json:"outCheck,omitempty"`
		OutCheckLower              string               `json:"outcheck,omitempty"`
		Push                       string               `json:"push,omitempty"`
		Trigger                    TriggerConfig        `json:"trigger,omitempty"`
		Description                string               `json:"description"`
		Title                      string               `json:"title,omitempty"`
		Type                       string               `json:"type,omitempty"`
		ConnectURL                 string               `json:"connectURL,omitempty"`
		HTTP                       *HTTPAPIConfig       `json:"http,omitempty"`
		Runtime                    APIRuntimeConfig     `json:"runtime,omitempty"`
		Transport                  string               `json:"transport,omitempty"`
		ProtocolVersions           []string             `json:"protocolVersions,omitempty"`
		Resource                   string               `json:"resource,omitempty"`
		Guard                      MCPGuardConfig       `json:"guard,omitempty"`
		Tools                      []string             `json:"tools,omitempty"`
		Instructions               string               `json:"instructions,omitempty"`
		AllowedOrigins             []string             `json:"allowedOrigins,omitempty"`
		RateLimit                  *HTTPRateLimitConfig `json:"rateLimit,omitempty"`
		MaxConcurrent              int                  `json:"maxConcurrent,omitempty"`
		RedirectURIAllowedPrefixes []string             `json:"redirectURIAllowedPrefixes,omitempty"`
		OAuth                      MCPOAuthConfig       `json:"oauth,omitempty"`
		SecuritySchemes            []MCPSecurityScheme  `json:"securitySchemes,omitempty"`
		Annotations                MCPToolAnnotations   `json:"annotations,omitempty"`
		Scopes                     []string             `json:"scopes,omitempty"`
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
	apiConfig.Title = raw.Title
	apiConfig.Type = raw.Type
	apiConfig.ConnectURL = raw.ConnectURL
	apiConfig.HTTP = raw.HTTP
	apiConfig.Runtime = raw.Runtime
	apiConfig.Transport = raw.Transport
	apiConfig.ProtocolVersions = raw.ProtocolVersions
	apiConfig.Resource = raw.Resource
	apiConfig.Guard = raw.Guard
	apiConfig.Tools = make([]MCPToolConfig, len(raw.Tools))
	for index, apiName := range raw.Tools {
		apiConfig.Tools[index] = MCPToolConfig{Name: apiName, API: apiName}
	}
	apiConfig.Instructions = raw.Instructions
	apiConfig.AllowedOrigins = raw.AllowedOrigins
	apiConfig.RateLimit = raw.RateLimit
	apiConfig.MaxConcurrent = raw.MaxConcurrent
	apiConfig.RedirectURIAllowedPrefixes = raw.RedirectURIAllowedPrefixes
	apiConfig.OAuth = raw.OAuth
	apiConfig.SecuritySchemes = raw.SecuritySchemes
	apiConfig.Annotations = raw.Annotations
	apiConfig.Scopes = raw.Scopes

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

// APIFileState represents the observed state of a file used to build an API
// configuration snapshot.
type APIFileState struct {
	Path   string
	Exists bool
	Hash   [sha256.Size]byte
	Error  string
}

const (
	schemaSourceParamCheck   = "paramCheck"
	schemaSourceOutCheck     = "outCheck"
	schemaSourceSQL          = "sql"
	schemaSourceScriptLegacy = "scriptLegacy"
	schemaSourceUnknown      = "unknown"
)

type APISchema struct {
	Input        map[string]interface{}
	Output       map[string]interface{}
	InputSource  string
	OutputSource string
}

// APIConfigSnapshot is an immutable, internally consistent view of the API
// configuration. Maps and slices reachable from a published snapshot must not
// be modified.
type APIConfigSnapshot struct {
	Definitions map[string]APIConfig
	APIs        map[string]APIDetails
	Sources     map[string]string
	Files       map[string]APIFileState
	Schedules   map[string]scheduleJobConfig
	WSClients   map[string]wsClientConfig
}

type apiConfigLoadResult struct {
	Snapshot  *APIConfigSnapshot
	Schedules map[string]scheduleJobConfig
	WSClients map[string]wsClientConfig
	Hash      [sha256.Size]byte
}

type includeDefinition struct {
	Type string `json:"type"`
	Path string `json:"path"`
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
var apiSnapshot atomic.Pointer[APIConfigSnapshot]
var backgroundRuntimes *backgroundRuntimeManager
var dbType string
var buildVersion = "v0.0.21"

type serviceFilePath struct {
	Path   string
	Source string
}

type serviceFilePaths struct {
	API       serviceFilePath
	Config    serviceFilePath
	MCPServer string
}

const (
	apiTypeAPI                       = "api"
	apiTypeInclude                   = "include"
	apiTypeWSClient                  = "ws_client"
	apiTypePublic                    = "public"
	apiTypeSchedule                  = "schedule"
	apiTypeMCP                       = "mcp"
	defaultAPIHotReloadCheckInterval = time.Second
	configuredHTTPAccessBasic        = "basic"
	configuredHTTPAccessAnonymous    = "anonymous"
	configuredHTTPAccessInternal     = "internal"
	configuredHTTPResponseNyan       = "nyan"
	configuredHTTPResponseRaw        = "raw"
	mcpProtocolVersion20250326       = "2025-03-26"
	mcpProtocolVersion20250618       = "2025-06-18"
	mcpProtocolVersion20251125       = "2025-11-25"
	maxConfiguredHTTPBodyBytes       = 1 << 20
	maxConfiguredHTTPResponseBytes   = 4 << 20
	maxSQLJSONRows                   = 10000
	maxSQLJSONBytes                  = maxConfiguredHTTPResponseBytes
	maxRestrictedScriptRuntime       = 15 * time.Second
	maxWebSocketMessageBytes         = 1 << 20
	maxWebSocketConnections          = 128
)

type configuredHTTPRateBucket struct {
	StartedAt time.Time
	Window    time.Duration
	Count     int
}

var configuredHTTPRateBuckets = struct {
	sync.Mutex
	Buckets     map[string]configuredHTTPRateBucket
	LastCleanup time.Time
}{Buckets: make(map[string]configuredHTTPRateBucket)}

var mcpConcurrencyLimiters = struct {
	sync.Mutex
	Limiters map[string]chan struct{}
}{Limiters: make(map[string]chan struct{})}

var restrictedPasswordExecutions = make(chan struct{}, 1)
var errRestrictedRuntimeBusy = errors.New("restricted JavaScript runtime is busy")
var websocketConnectionSlots = make(chan struct{}, maxWebSocketConnections)

// reParams は、/*id*/ のようなプレースホルダーを抽出する正規表現
var reParams = regexp.MustCompile(`(?s)/\*\s*([^*\/]+)\s*\*/\s*(?:'([^']*)'|"([^"]*)"|([^\s,;)]+))`)
var reSQLSchemaConditionParam = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:==|!=)\s*null`)

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
	mcpServerFlag := flags.String("mcp-server", "", "MCP API name selected for stdio mode")
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
		API:       serviceFilePath{Path: resolvedAPIPath, Source: apiSource},
		Config:    serviceFilePath{Path: resolvedConfigPath, Source: configSource},
		MCPServer: strings.TrimSpace(*mcpServerFlag),
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
	initialLoad, err := loadAPIConfigFile(paths.API.Path)
	if err != nil {
		log.Fatalf("Failed to load API file: %v", err)
	}
	if err := validateConfiguredServerTransportSecurity(initialLoad.Snapshot, config); err != nil {
		log.Fatalf("Invalid server transport configuration: %v", err)
	}
	setAPISnapshot(initialLoad.Snapshot)
	if paths.MCPServer != "" {
		mcpName, mcpConfig, selectErr := selectMCPStdioServer(initialLoad.Snapshot, paths.MCPServer)
		if selectErr != nil {
			log.Fatal(selectErr)
		}
		if err := serveMCPStdio(os.Stdin, os.Stdout, initialLoad.Snapshot, mcpName, mcpConfig); err != nil {
			log.Fatal(err)
		}
		return
	}
	backgroundRuntimes = newBackgroundRuntimeManager()
	backgroundRuntimes.reconcile(initialLoad.Snapshot.Schedules, initialLoad.Snapshot.WSClients)
	if config.APIHotReload.Enabled {
		log.Printf("API hot reload enabled: file=%s check_interval=%s", paths.API.Path, apiHotReloadInterval)
		go watchAPIFile(paths.API.Path, apiHotReloadInterval, initialLoad.Snapshot.Files)
	} else {
		log.Printf("API hot reload disabled")
	}

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "MCP-Protocol-Version", "MCP-Session-Id", "Last-Event-ID"},
		ExposedHeaders: []string{"WWW-Authenticate", "MCP-Protocol-Version", "Retry-After"},
	})

	hub = NewHub()

	http.Handle("/nyan-rpc", corsHandler.Handler(http.HandlerFunc(basicAuth(handleJSONRPC, config))))

	http.Handle("/nyan/", corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basicAuth(handleNyanOrDetail, config)(w, r)
	})))

	http.Handle("/", corsHandler.Handler(http.HandlerFunc(unifiedHandler)))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.Port),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	if config.CertPath != "" && config.KeyPath != "" {
		log.Printf("Server starting on HTTPS port %d\n", config.Port)
		log.Fatal(server.ListenAndServeTLS(config.CertPath, config.KeyPath))
	} else {
		log.Printf("Server starting on HTTP port %d\n", config.Port)
		log.Fatal(server.ListenAndServe())
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
	snapshot := currentAPISnapshot()
	if mcpName, mcpConfig, oauthAPI, role, ok := findMCPOAuthAPIForRequest(snapshot, r); ok {
		handleMCPOAuthHTTPRequest(snapshot, w, r, mcpName, mcpConfig, oauthAPI, role)
		return
	}
	if apiName, apiConfig, ok := findMCPServerForRequestInSnapshot(snapshot, r); ok {
		handleMCPRequestWithSnapshot(snapshot, w, r, apiName, apiConfig)
		return
	}
	if apiName, apiConfig, ok := findConfiguredHTTPAPIForPathInSnapshot(snapshot, r.URL.Path); ok {
		handleConfiguredHTTPRequestWithSnapshot(snapshot, w, r, apiName, apiConfig)
		return
	}
	// WebSocketアップグレード要求なら認証後、handleWebSocketに処理を委譲
	if isWebSocketRequest(r) {
		if !webSocketEndpointConfigured(snapshot, r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if !validateWebSocketOrigin(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		handleWebSocket(w, r)
		return
	}
	if apiKey, requestedPath, apiConfig, ok := findPublicAPIForPathInSnapshot(snapshot, r.URL.Path); ok {
		handlePublicRequestWithSnapshot(snapshot, w, r, apiKey, requestedPath, apiConfig)
		return
	}
	// 通常のHTTPリクエストならBasicAuthを適用して処理
	basicAuth(func(w http.ResponseWriter, r *http.Request) {
		handleRequestWithSnapshot(snapshot, w, r)
	}, config)(w, r)
}

func webSocketEndpointConfigured(snapshot *APIConfigSnapshot, requestPath string) bool {
	if snapshot == nil {
		return false
	}
	apiName := strings.Trim(requestPath, "/")
	if apiName != "" && !strings.Contains(apiName, "/") {
		if apiConfig, exists := snapshot.Definitions[apiName]; exists && getAPIType(apiConfig) == apiTypeAPI && apiConfig.HTTP == nil {
			return true
		}
	}
	for _, apiConfig := range snapshot.Definitions {
		if getAPIType(apiConfig) != apiTypeWSClient {
			continue
		}
		connectURL, err := url.Parse(apiConfig.ConnectURL)
		if err == nil && connectURL.Path == requestPath {
			return true
		}
	}
	return false
}

func validateWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || (originURL.Scheme != "http" && originURL.Scheme != "https") || originURL.Path != "" {
		return false
	}
	return strings.EqualFold(originURL.Host, r.Host)
}

type configuredAPIDispatchContextKey struct{}

type configuredHTTPResponse struct {
	Status  int                    `json:"status"`
	Headers map[string]interface{} `json:"headers"`
	Body    interface{}            `json:"body"`
}

func findConfiguredHTTPAPIForPathInSnapshot(snapshot *APIConfigSnapshot, requestPath string) (string, APIConfig, bool) {
	if snapshot == nil {
		return "", APIConfig{}, false
	}
	for apiName, apiConfig := range snapshot.Definitions {
		if getAPIType(apiConfig) != apiTypeAPI || apiConfig.HTTP == nil {
			continue
		}
		if configuredHTTPAccess(apiConfig) == configuredHTTPAccessInternal {
			continue
		}
		if apiConfig.HTTP.Path == requestPath {
			return apiName, apiConfig, true
		}
	}
	return "", APIConfig{}, false
}

func findMCPServerForRequestInSnapshot(snapshot *APIConfigSnapshot, r *http.Request) (string, APIConfig, bool) {
	if snapshot == nil {
		return "", APIConfig{}, false
	}
	queryAPI := strings.TrimSpace(r.URL.Query().Get("api"))
	for apiName, apiConfig := range snapshot.Definitions {
		if getAPIType(apiConfig) != apiTypeMCP || apiConfig.Transport != "streamable_http" {
			continue
		}
		endpointPath, err := canonicalAPIEndpointPath(apiName)
		if err == nil && (r.URL.Path == endpointPath || (r.URL.Path == "/" && queryAPI == apiName)) {
			return apiName, apiConfig, true
		}
	}
	return "", APIConfig{}, false
}

func findMCPOAuthAPIForRequest(snapshot *APIConfigSnapshot, r *http.Request) (string, APIConfig, string, string, bool) {
	if snapshot == nil {
		return "", APIConfig{}, "", "", false
	}
	queryAPI := strings.TrimSpace(r.URL.Query().Get("api"))
	for mcpName, mcp := range snapshot.Definitions {
		if getAPIType(mcp) != apiTypeMCP || mcp.Transport != "streamable_http" || !mcpOAuthConfigured(mcp.OAuth) {
			continue
		}
		roles := []struct{ api, role string }{
			{mcp.OAuth.AuthorizationServerMetadata, "authorizationServerMetadata"},
			{mcp.OAuth.ProtectedResourceMetadata, "protectedResourceMetadata"},
			{mcp.OAuth.Authorize, "oauthAuthorize"}, {mcp.OAuth.Token, "oauthToken"},
			{mcp.OAuth.Register, "oauthRegister"}, {mcp.OAuth.AdminUser, "oauthAdminUser"},
		}
		for _, candidate := range roles {
			if candidate.api == "" {
				continue
			}
			endpointPath, err := canonicalAPIEndpointPath(candidate.api)
			if err == nil && (r.URL.Path == endpointPath || (r.URL.Path == "/" && queryAPI == candidate.api)) {
				return mcpName, mcp, candidate.api, candidate.role, true
			}
		}
	}
	return "", APIConfig{}, "", "", false
}

func handleConfiguredHTTPRequestWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, apiName string, apiConfig APIConfig) {
	if !configuredHTTPOriginAllowed(r, apiConfig) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if !configuredHTTPMethodAllowed(apiConfig, r.Method) {
		w.Header().Set("Allow", strings.Join(configuredHTTPMethods(apiConfig), ", "))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !configuredHTTPRemoteAllowed(apiConfig, r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if allowed, retryAfter := configuredHTTPRateLimitAllows(apiName, apiConfig, r.RemoteAddr, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		sendJSONError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if configuredHTTPResponseMode(apiConfig) == configuredHTTPResponseNyan {
			clonedRequest := r.Clone(context.WithValue(r.Context(), configuredAPIDispatchContextKey{}, true))
			clonedURL := *r.URL
			clonedURL.Path = "/" + strings.TrimPrefix(apiName, "/")
			clonedRequest.URL = &clonedURL
			handleRequestWithSnapshot(snapshot, w, clonedRequest)
			return
		}
		handleRawScriptHTTPRequestWithSnapshot(snapshot, w, r, apiName, apiConfig)
	}

	if configuredHTTPAccess(apiConfig) == configuredHTTPAccessBasic {
		basicAuth(handler, config)(w, r)
		return
	}
	handler(w, r)
}

func configuredHTTPOriginAllowed(r *http.Request, apiConfig APIConfig) bool {
	if apiConfig.HTTP == nil {
		return strings.TrimSpace(r.Header.Get("Origin")) == ""
	}
	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}
	return requestOriginAllowed(r.Header.Get("Origin"), requestScheme+"://"+r.Host, apiConfig.HTTP.AllowedOrigins)
}

func configuredHTTPRemoteAllowed(apiConfig APIConfig, remoteAddress string) bool {
	if apiConfig.HTTP == nil || len(apiConfig.HTTP.AllowedRemoteIPs) == 0 {
		return true
	}
	host := remoteAddress
	if parsedHost, _, err := net.SplitHostPort(remoteAddress); err == nil {
		host = parsedHost
	}
	remoteIP := net.ParseIP(strings.TrimSpace(host))
	if remoteIP == nil {
		return false
	}
	for _, allowed := range apiConfig.HTTP.AllowedRemoteIPs {
		if allowedIP := net.ParseIP(allowed); allowedIP != nil && allowedIP.Equal(remoteIP) {
			return true
		}
	}
	return false
}

func configuredHTTPMethods(apiConfig APIConfig) []string {
	if apiConfig.HTTP == nil || len(apiConfig.HTTP.Methods) == 0 {
		return []string{http.MethodGet, http.MethodPost}
	}
	return append([]string(nil), apiConfig.HTTP.Methods...)
}

func configuredHTTPMethodAllowed(apiConfig APIConfig, method string) bool {
	for _, allowed := range configuredHTTPMethods(apiConfig) {
		if method == allowed || (method == http.MethodHead && allowed == http.MethodGet) {
			return true
		}
	}
	return false
}

func handleRawScriptHTTPRequestWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, apiName string, apiConfig APIConfig) {
	requestContext, params, err := buildScriptHTTPRequest(w, r, apiName)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			sendJSONError(w, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	params["nyan_request"] = requestContext

	scriptResult, err := runScriptWithRuntimeWithSnapshot(snapshot, []string{apiConfig.Script}, params, apiConfig.Runtime, true)
	if err != nil {
		if errors.Is(err, errRestrictedRuntimeBusy) {
			w.Header().Set("Retry-After", "1")
			sendJSONError(w, "configured API is busy", http.StatusServiceUnavailable)
			return
		}
		log.Printf("configured HTTP API %s failed: %v", apiName, err)
		sendJSONError(w, "configured API execution failed", http.StatusInternalServerError)
		return
	}
	response, err := parseConfiguredHTTPResponse(scriptResult)
	if err != nil {
		log.Printf("configured HTTP API %s returned an invalid response: %v", apiName, err)
		sendJSONError(w, "configured API returned an invalid response", http.StatusInternalServerError)
		return
	}
	if err := writeConfiguredHTTPResponse(w, r, response); err != nil {
		log.Printf("configured HTTP API %s response rejected: %v", apiName, err)
		sendJSONError(w, "configured API returned an invalid response", http.StatusInternalServerError)
	}
}

func buildScriptHTTPRequest(w http.ResponseWriter, r *http.Request, apiName string) (map[string]interface{}, map[string]interface{}, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxConfiguredHTTPBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}

	query := urlValuesToInterfaceMap(r.URL.Query())
	form := map[string]interface{}{}
	var jsonBody interface{}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch contentType {
	case "application/json":
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &jsonBody); err != nil {
				return nil, nil, err
			}
		}
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, nil, err
		}
		form = urlValuesToInterfaceMap(values)
	}

	headers := make(map[string]interface{}, len(r.Header))
	for name, values := range r.Header {
		if strings.EqualFold(name, "Authorization") {
			continue
		}
		key := strings.ToLower(name)
		if len(values) == 1 {
			headers[key] = values[0]
		} else {
			headers[key] = append([]string(nil), values...)
		}
	}
	cookies := make(map[string]interface{})
	for _, cookie := range r.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	requestContext := map[string]interface{}{
		"method":        r.Method,
		"path":          r.URL.Path,
		"query":         query,
		"form":          form,
		"json":          jsonBody,
		"headers":       headers,
		"cookies":       cookies,
		"body":          string(body),
		"remoteAddress": r.RemoteAddr,
	}
	params := make(map[string]interface{})
	mergeInterfaceMaps(params, query)
	mergeInterfaceMaps(params, form)
	if jsonObject, ok := jsonBody.(map[string]interface{}); ok {
		mergeInterfaceMaps(params, jsonObject)
	}
	params["api"] = apiName
	return requestContext, params, nil
}

func configuredHTTPRateLimitAllows(apiName string, apiConfig APIConfig, remoteAddress string, now time.Time) (bool, time.Duration) {
	if apiConfig.HTTP == nil || apiConfig.HTTP.RateLimit == nil {
		return true, 0
	}
	return configuredRateLimitAllows("http:"+apiName, apiConfig.HTTP.RateLimit, remoteAddress, now)
}

func configuredRateLimitAllows(bucketName string, rateLimit *HTTPRateLimitConfig, remoteAddress string, now time.Time) (bool, time.Duration) {
	if rateLimit == nil {
		return true, 0
	}
	window, err := time.ParseDuration(rateLimit.Window)
	if err != nil || window <= 0 || rateLimit.Requests <= 0 {
		return false, time.Second
	}
	host := remoteAddress
	if parsedHost, _, splitErr := net.SplitHostPort(remoteAddress); splitErr == nil {
		host = parsedHost
	}
	key := bucketName + "\x00" + host + "\x00" + strconv.Itoa(rateLimit.Requests) + "\x00" + window.String()

	configuredHTTPRateBuckets.Lock()
	defer configuredHTTPRateBuckets.Unlock()
	if configuredHTTPRateBuckets.LastCleanup.IsZero() || now.Sub(configuredHTTPRateBuckets.LastCleanup) >= time.Minute {
		for bucketKey, bucket := range configuredHTTPRateBuckets.Buckets {
			if now.Sub(bucket.StartedAt) >= bucket.Window*2 {
				delete(configuredHTTPRateBuckets.Buckets, bucketKey)
			}
		}
		configuredHTTPRateBuckets.LastCleanup = now
	}
	bucket, exists := configuredHTTPRateBuckets.Buckets[key]
	if !exists || now.Sub(bucket.StartedAt) >= window || now.Before(bucket.StartedAt) {
		configuredHTTPRateBuckets.Buckets[key] = configuredHTTPRateBucket{StartedAt: now, Window: window, Count: 1}
		return true, 0
	}
	if bucket.Count >= rateLimit.Requests {
		return false, window - now.Sub(bucket.StartedAt)
	}
	bucket.Count++
	configuredHTTPRateBuckets.Buckets[key] = bucket
	return true, 0
}

func urlValuesToInterfaceMap(values url.Values) map[string]interface{} {
	result := make(map[string]interface{}, len(values))
	for key, items := range values {
		if len(items) == 1 {
			result[key] = items[0]
		} else {
			result[key] = append([]string(nil), items...)
		}
	}
	return result
}

func mergeInterfaceMaps(destination, source map[string]interface{}) {
	for key, value := range source {
		destination[key] = value
	}
}

func parseConfiguredHTTPResponse(scriptResult string) (configuredHTTPResponse, error) {
	var response configuredHTTPResponse
	decoder := json.NewDecoder(strings.NewReader(scriptResult))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return configuredHTTPResponse{}, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return configuredHTTPResponse{}, fmt.Errorf("response contains more than one JSON value")
		}
		return configuredHTTPResponse{}, fmt.Errorf("response contains trailing data: %w", err)
	}
	if response.Status == 0 {
		response.Status = http.StatusOK
	}
	if response.Status < 100 || response.Status > 599 {
		return configuredHTTPResponse{}, fmt.Errorf("status code is out of range: %d", response.Status)
	}
	return response, nil
}

func writeConfiguredHTTPResponse(w http.ResponseWriter, r *http.Request, response configuredHTTPResponse) error {
	validatedHeaders := make(map[string][]string, len(response.Headers))
	for name, rawValue := range response.Headers {
		if !isHTTPToken(name) {
			return fmt.Errorf("invalid response header name %q", name)
		}
		canonicalName := http.CanonicalHeaderKey(name)
		if isForbiddenScriptResponseHeader(canonicalName) {
			return fmt.Errorf("response header %q is not allowed", canonicalName)
		}
		values, err := configuredHTTPHeaderValues(rawValue)
		if err != nil {
			return fmt.Errorf("response header %q: %w", canonicalName, err)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("response header %q contains a newline", canonicalName)
			}
		}
		validatedHeaders[canonicalName] = append(validatedHeaders[canonicalName], values...)
	}
	body, err := configuredHTTPResponseBody(response.Body)
	if err != nil {
		return err
	}
	if len(body) > maxConfiguredHTTPResponseBytes {
		return fmt.Errorf("response body is too large")
	}
	for name, values := range validatedHeaders {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(response.Status)
	if r.Method != http.MethodHead && response.Status != http.StatusNoContent && response.Status != http.StatusNotModified {
		_, err = w.Write(body)
	}
	return err
}

func configuredHTTPHeaderValues(value interface{}) ([]string, error) {
	switch value := value.(type) {
	case string:
		return []string{value}, nil
	case []interface{}:
		values := make([]string, len(value))
		for index, item := range value {
			stringValue, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("header values must be strings")
			}
			values[index] = stringValue
		}
		return values, nil
	case []string:
		return append([]string(nil), value...), nil
	default:
		return nil, fmt.Errorf("header value must be a string or string array")
	}
}

func configuredHTTPResponseBody(value interface{}) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	if body, ok := value.(string); ok {
		return []byte(body), nil
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal response body: %w", err)
	}
	return body, nil
}

func isForbiddenScriptResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "content-length", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

// -----------------------------------------------------------------------------
// MCP Streamable HTTP
// -----------------------------------------------------------------------------

type MCPJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *MCPJSONRPCError `json:"error,omitempty"`
}

type MCPJSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type MCPGuardDecision struct {
	Allow     bool                   `json:"allow"`
	Status    int                    `json:"status"`
	Headers   map[string]interface{} `json:"headers"`
	MCPMeta   map[string]interface{} `json:"mcpMeta"`
	Principal interface{}            `json:"principal"`
}

type mcpRuntimeURLs struct {
	Origin                      string
	Issuer                      string
	Resource                    string
	AuthorizationServerMetadata string
	ProtectedResourceMetadata   string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	RegistrationEndpoint        string
	AdminUserEndpoint           string
}

type rejectingJSONSchemaLoader struct{}

func (rejectingJSONSchemaLoader) Load(location string) (interface{}, error) {
	return nil, fmt.Errorf("external JSON Schema resource is not allowed: %s", location)
}

func handleMCPRequestWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, serverName string, serverConfig APIConfig) {
	runtimeURLs, err := deriveMCPRuntimeURLs(r, serverName, serverConfig)
	if err != nil {
		http.Error(w, "invalid Host", http.StatusMisdirectedRequest)
		return
	}
	if !requestOriginAllowed(r.Header.Get("Origin"), runtimeURLs.Origin, serverConfig.AllowedOrigins) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	writeMCPCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if allowed, retryAfter := configuredRateLimitAllows("mcp:"+serverName, serverConfig.RateLimit, r.RemoteAddr, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	release, acquired := acquireMCPExecutionSlot(serverName, configuredMCPMaxConcurrent(serverConfig))
	if !acquired {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "server is busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	if !mcpAcceptsJSONAndEventStream(r.Header.Get("Accept")) {
		http.Error(w, "Accept must allow application/json and text/event-stream", http.StatusNotAcceptable)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxConfiguredHTTPBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] == '[' {
		writeMCPError(w, nil, -32600, "Invalid Request", nil)
		return
	}
	if err := validateNoDuplicateJSONKeys(trimmedBody); err != nil {
		writeMCPError(w, nil, -32600, "Invalid Request", nil)
		return
	}

	var request MCPJSONRPCRequest
	if err := json.Unmarshal(trimmedBody, &request); err != nil {
		writeMCPError(w, nil, -32700, "Parse error", nil)
		return
	}
	if request.JSONRPC != "2.0" || strings.TrimSpace(request.Method) == "" {
		writeMCPError(w, request.ID, -32600, "Invalid Request", nil)
		return
	}
	var protocolVersion string
	if request.Method == "initialize" {
		requestedVersion, ok := mcpInitializeProtocolVersion(request)
		if !ok {
			writeMCPError(w, request.ID, -32602, "Invalid params", nil)
			return
		}
		protocolVersion = negotiateMCPProtocolVersion(requestedVersion, serverConfig.ProtocolVersions)
	} else {
		var ok bool
		protocolVersion, ok = mcpSubsequentRequestProtocolVersion(
			r.Header.Get("MCP-Protocol-Version"),
			serverConfig.ProtocolVersions,
		)
		if !ok {
			http.Error(w, "unsupported or missing MCP-Protocol-Version", http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("MCP-Protocol-Version", protocolVersion)

	if len(request.ID) == 0 {
		handleMCPNotification(w, request)
		return
	}

	switch request.Method {
	case "initialize":
		handleMCPInitialize(w, request, serverName, serverConfig, protocolVersion)
	case "ping":
		writeMCPResult(w, request.ID, map[string]interface{}{})
	case "tools/list":
		handleMCPToolsList(snapshot, w, request, serverConfig)
	case "tools/call":
		handleMCPToolCall(snapshot, w, r, request, serverName, serverConfig, runtimeURLs)
	default:
		writeMCPError(w, request.ID, -32601, "Method not found", nil)
	}
}

func deriveMCPRuntimeURLs(r *http.Request, serverName string, serverConfig APIConfig) (mcpRuntimeURLs, error) {
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, "\\/?#@\r\n\t ") {
		return mcpRuntimeURLs{}, fmt.Errorf("invalid Host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil && strings.Count(host, ":") > 0 && net.ParseIP(strings.Trim(host, "[]")) == nil {
		return mcpRuntimeURLs{}, fmt.Errorf("invalid Host")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origin := scheme + "://" + strings.ToLower(host)
	pathFor := func(name string) string {
		if name == "" {
			return ""
		}
		endpointPath, _ := canonicalAPIEndpointPath(name)
		return origin + endpointPath
	}
	return mcpRuntimeURLs{
		Origin: origin, Issuer: origin, Resource: pathFor(serverName),
		AuthorizationServerMetadata: pathFor(serverConfig.OAuth.AuthorizationServerMetadata),
		ProtectedResourceMetadata:   pathFor(serverConfig.OAuth.ProtectedResourceMetadata),
		AuthorizationEndpoint:       pathFor(serverConfig.OAuth.Authorize),
		TokenEndpoint:               pathFor(serverConfig.OAuth.Token), RegistrationEndpoint: pathFor(serverConfig.OAuth.Register),
		AdminUserEndpoint: pathFor(serverConfig.OAuth.AdminUser),
	}, nil
}

func writeMCPCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, MCP-Protocol-Version")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Protocol-Version, Retry-After")
}

func handleMCPOAuthHTTPRequest(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, serverName string, serverConfig APIConfig, apiName, role string) {
	runtimeURLs, err := deriveMCPRuntimeURLs(r, serverName, serverConfig)
	if err != nil {
		http.Error(w, "invalid Host", http.StatusMisdirectedRequest)
		return
	}
	if !requestOriginAllowed(r.Header.Get("Origin"), runtimeURLs.Origin, serverConfig.AllowedOrigins) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if role == "oauthAdminUser" {
		remoteHost := r.RemoteAddr
		if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
			remoteHost = host
		}
		remoteIP := net.ParseIP(strings.TrimSpace(remoteHost))
		if remoteIP == nil || !remoteIP.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || !timingSafeStringEqual(username, config.BasicAuth.Username) || !timingSafeStringEqual(password, config.BasicAuth.Password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="NyanQL OAuth administration", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	if role == "authorizationServerMetadata" || role == "protectedResourceMetadata" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		scopes := snapshot.Definitions[serverConfig.OAuth.VerifyAccess].Scopes
		if role == "authorizationServerMetadata" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": runtimeURLs.Issuer, "authorization_endpoint": runtimeURLs.AuthorizationEndpoint,
				"token_endpoint": runtimeURLs.TokenEndpoint, "registration_endpoint": runtimeURLs.RegistrationEndpoint,
				"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
				"token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": scopes,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"resource": runtimeURLs.Resource, "authorization_servers": []string{runtimeURLs.Issuer},
				"scopes_supported": scopes, "bearer_methods_supported": []string{"header"},
			})
		}
		return
	}
	if !mcpOAuthMethodAllowed(role, r.Method) {
		w.Header().Set("Allow", mcpOAuthAllowedMethods(role))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := validateMCPOAuthContentType(role, r); err != nil {
		http.Error(w, "unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	if allowed, retryAfter := configuredRateLimitAllows("mcp:"+serverName+":oauth:"+role, mcpOAuthRateLimit(serverConfig, role), r.RemoteAddr, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retryAfter.Seconds())))))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	params, err := mcpOAuthRequestParams(w, r)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "too large") {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return
	}
	release, acquired := acquireMCPExecutionSlot(serverName+":oauth:"+role, mcpOAuthMaxConcurrent(serverConfig, role))
	if !acquired {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "OAuth endpoint is busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	value, err := invokeMCPOAuthHook(snapshot, serverName, serverConfig, runtimeURLs, role, params)
	if err != nil {
		log.Printf("OAuth hook %s failed: %v", apiName, err)
		http.Error(w, "OAuth hook failed", http.StatusInternalServerError)
		return
	}
	response, ok := value.(map[string]interface{})
	if !ok {
		http.Error(w, "OAuth hook returned an invalid response", http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if raw, exists := response["status"]; exists {
		if number, ok := raw.(json.Number); ok {
			parsed, _ := strconv.Atoi(number.String())
			status = parsed
		} else if number, ok := raw.(float64); ok {
			status = int(number)
		}
	}
	if status < 100 || status > 599 {
		http.Error(w, "OAuth hook returned an invalid status", http.StatusInternalServerError)
		return
	}
	if headers, ok := response["headers"].(map[string]interface{}); ok {
		for name, raw := range headers {
			if !isHTTPToken(name) || isForbiddenScriptResponseHeader(name) {
				http.Error(w, "OAuth hook returned an invalid header", http.StatusInternalServerError)
				return
			}
			values, err := configuredHTTPHeaderValues(raw)
			if err != nil {
				http.Error(w, "OAuth hook returned an invalid header", http.StatusInternalServerError)
				return
			}
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n") {
					http.Error(w, "OAuth hook returned an invalid header", http.StatusInternalServerError)
					return
				}
				w.Header().Add(http.CanonicalHeaderKey(name), value)
			}
		}
	}
	if rawContentType, exists := response["contentType"]; exists {
		contentType, ok := rawContentType.(string)
		if !ok {
			http.Error(w, "OAuth hook returned an invalid content type", http.StatusInternalServerError)
			return
		}
		if _, _, err := mime.ParseMediaType(contentType); err != nil || strings.ContainsAny(contentType, "\r\n") {
			http.Error(w, "OAuth hook returned an invalid content type", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
	}
	body, err := configuredHTTPResponseBody(response["body"])
	if err != nil || len(body) > maxConfiguredHTTPResponseBytes {
		http.Error(w, "OAuth hook returned an invalid body", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func mcpOAuthMethodAllowed(role, method string) bool {
	if role == "oauthAuthorize" {
		return method == http.MethodGet || method == http.MethodPost
	}
	return method == http.MethodPost
}

func mcpOAuthAllowedMethods(role string) string {
	if role == "oauthAuthorize" {
		return "GET, POST, OPTIONS"
	}
	return "POST, OPTIONS"
}

func validateMCPOAuthContentType(role string, r *http.Request) error {
	if r.Method != http.MethodPost {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	switch role {
	case "oauthRegister", "oauthAdminUser":
		if mediaType != "application/json" {
			return fmt.Errorf("JSON is required")
		}
	case "oauthAuthorize", "oauthToken":
		if mediaType != "application/x-www-form-urlencoded" {
			return fmt.Errorf("form data is required")
		}
	}
	return nil
}

func mcpOAuthRateLimit(serverConfig APIConfig, role string) *HTTPRateLimitConfig {
	requests := 60
	switch role {
	case "oauthAdminUser", "oauthRegister":
		requests = 10
	case "oauthAuthorize":
		requests = 30
	}
	if serverConfig.RateLimit != nil && serverConfig.RateLimit.Requests < requests {
		return serverConfig.RateLimit
	}
	return &HTTPRateLimitConfig{Requests: requests, Window: "1m"}
}

func mcpOAuthMaxConcurrent(serverConfig APIConfig, role string) int {
	limit := configuredMCPMaxConcurrent(serverConfig)
	switch role {
	case "oauthAdminUser":
		return min(limit, 1)
	case "oauthAuthorize":
		return min(limit, 2)
	default:
		return limit
	}
}

func mcpOAuthRequestParams(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	params := map[string]interface{}{
		"method": r.Method, "request_path": r.URL.Path, "query": urlValuesToInterfaceMap(r.URL.Query()),
		"authorization": r.Header.Get("Authorization"),
		"headers":       map[string]interface{}{"Authorization": r.Header.Get("Authorization"), "Content-Type": r.Header.Get("Content-Type"), "Accept": r.Header.Get("Accept"), "Origin": r.Header.Get("Origin")},
	}
	cookies := map[string]interface{}{}
	for _, cookie := range r.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	params["cookies"] = cookies
	if r.Method != http.MethodPost {
		return params, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxConfiguredHTTPBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("request body is too large")
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		if err := validateNoDuplicateJSONKeys(body); err != nil {
			return nil, fmt.Errorf("invalid JSON")
		}
		var value interface{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid JSON")
		}
		params["body"] = value
	} else {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("invalid form")
		}
		params["form"] = urlValuesToInterfaceMap(values)
	}
	return params, nil
}

func selectMCPStdioServer(snapshot *APIConfigSnapshot, requestedName string) (string, APIConfig, error) {
	if snapshot == nil {
		return "", APIConfig{}, fmt.Errorf("API configuration is not loaded")
	}
	definition, exists := snapshot.Definitions[requestedName]
	if !exists || getAPIType(definition) != apiTypeMCP {
		return "", APIConfig{}, fmt.Errorf("MCP API %q is not configured", requestedName)
	}
	if definition.Transport != "stdio" {
		return "", APIConfig{}, fmt.Errorf("MCP API %q does not use stdio", requestedName)
	}
	return requestedName, definition, nil
}

type mcpStdioLifecycle int

const (
	mcpStdioCreated mcpStdioLifecycle = iota
	mcpStdioWaitingForInitialized
	mcpStdioReady
)

func serveMCPStdio(input io.Reader, output io.Writer, snapshot *APIConfigSnapshot, serverName string, serverConfig APIConfig) error {
	if serverConfig.Transport != "stdio" {
		return fmt.Errorf("MCP API %q does not use stdio", serverName)
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxConfiguredHTTPBodyBytes+1)
	state := mcpStdioCreated
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		response, respond := handleMCPStdioMessage(snapshot, serverName, serverConfig, &state, line)
		if !respond {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if len(encoded) > maxConfiguredHTTPResponseBytes {
			return fmt.Errorf("stdio MCP response is too large")
		}
		encoded = append(encoded, '\n')
		if _, err := output.Write(encoded); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdio MCP input failed: %w", err)
	}
	return nil
}

func handleMCPStdioMessage(snapshot *APIConfigSnapshot, serverName string, serverConfig APIConfig, state *mcpStdioLifecycle, message []byte) (map[string]interface{}, bool) {
	trimmed := bytes.TrimSpace(message)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return mcpStdioError(nil, -32700, "Parse error"), true
	}
	if trimmed[0] != '{' || validateNoDuplicateJSONKeys(trimmed) != nil {
		return mcpStdioError(nil, -32600, "Invalid Request"), true
	}
	var request MCPJSONRPCRequest
	if json.Unmarshal(trimmed, &request) != nil || request.JSONRPC != "2.0" || strings.TrimSpace(request.Method) == "" {
		return mcpStdioError(nil, -32600, "Invalid Request"), true
	}
	notification := len(request.ID) == 0
	if request.Method == "notifications/initialized" {
		if !notification {
			return mcpStdioError(request.ID, -32600, "notifications/initialized must be a notification"), true
		}
		if *state == mcpStdioWaitingForInitialized {
			*state = mcpStdioReady
		}
		return nil, false
	}
	if notification {
		return nil, false
	}
	if request.Method == "initialize" {
		if *state != mcpStdioCreated {
			return mcpStdioError(request.ID, -32600, "MCP server is already initialized"), true
		}
		version, ok := mcpInitializeProtocolVersion(request)
		if !ok || !containsMCPProtocolVersion(serverConfig.ProtocolVersions, version) {
			return mcpStdioError(request.ID, -32602, "unsupported or missing protocolVersion"), true
		}
		*state = mcpStdioWaitingForInitialized
		return mcpStdioResult(request.ID, mcpInitializeResult(serverName, serverConfig, version)), true
	}
	if *state != mcpStdioReady {
		return mcpStdioError(request.ID, -32002, "MCP server is not initialized"), true
	}
	switch request.Method {
	case "ping":
		return mcpStdioResult(request.ID, map[string]interface{}{}), true
	case "tools/list":
		tools := make([]map[string]interface{}, 0, len(serverConfig.Tools))
		for _, toolConfig := range serverConfig.Tools {
			tool, err := buildMCPToolDefinition(snapshot, toolConfig)
			if err != nil {
				return mcpStdioError(request.ID, -32603, "Internal error"), true
			}
			delete(tool, "securitySchemes")
			delete(tool, "_meta")
			tools = append(tools, tool)
		}
		return mcpStdioResult(request.ID, map[string]interface{}{"tools": tools}), true
	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if len(request.Params) == 0 || json.Unmarshal(request.Params, &params) != nil || params.Name == "" {
			return mcpStdioError(request.ID, -32602, "Invalid params"), true
		}
		tool, exists := findMCPToolConfig(serverConfig.Tools, params.Name)
		if !exists {
			return mcpStdioError(request.ID, -32602, "Unknown tool"), true
		}
		if params.Arguments == nil {
			params.Arguments = map[string]interface{}{}
		}
		result, err := executeMCPToolForStdio(snapshot, tool, params.Arguments)
		if err != nil {
			return mcpStdioResult(request.ID, mcpToolErrorResult(err.Error(), nil)), true
		}
		return mcpStdioResult(request.ID, result), true
	default:
		return mcpStdioError(request.ID, -32601, "Method not found"), true
	}
}

func mcpInitializeResult(serverName string, serverConfig APIConfig, protocolVersion string) map[string]interface{} {
	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = serverName
	}
	version := strings.TrimSpace(config.Version)
	if version == "" {
		version = buildVersion
	}
	result := map[string]interface{}{"protocolVersion": protocolVersion, "capabilities": map[string]interface{}{"tools": map[string]interface{}{"listChanged": false}}, "serverInfo": map[string]interface{}{"name": name, "version": version}}
	if serverConfig.Instructions != "" {
		result["instructions"] = serverConfig.Instructions
	}
	return result
}

func executeMCPToolForStdio(snapshot *APIConfigSnapshot, tool MCPToolConfig, arguments map[string]interface{}) (map[string]interface{}, error) {
	apiConfig := snapshot.Definitions[tool.API]
	schema, err := resolveAPISchema(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("Tool schema could not be resolved")
	}
	if err := validateJSONSchemaValue(normalizedMCPInputSchema(schema.Input), arguments); err != nil {
		return nil, fmt.Errorf("Tool arguments did not match the input schema")
	}
	scopes := apiConfig.Scopes
	if len(apiConfig.SecuritySchemes) > 0 {
		scopes = mcpRequiredScopes(apiConfig.SecuritySchemes)
	}
	params := cloneParams(arguments)
	for _, key := range []string{"api", "nyan_guard", "nyan_mode", "nyan_request", "mcp_principal"} {
		delete(params, key)
	}
	params["mcp_principal"] = map[string]interface{}{"user_id": "local-process", "username": "local-process", "client_id": "stdio", "transport": "stdio", "scope": strings.Join(scopes, " "), "scopes": scopes}
	resultJSON, err := callNyanAPIFromVMWithSnapshot(snapshot, tool.API, params)
	if err != nil {
		return nil, fmt.Errorf("Tool execution failed")
	}
	if len(resultJSON) > maxConfiguredHTTPResponseBytes/2 {
		return nil, fmt.Errorf("Tool result is too large")
	}
	var structured interface{}
	if json.Unmarshal([]byte(resultJSON), &structured) != nil {
		return nil, fmt.Errorf("Tool returned invalid JSON")
	}
	if schema.OutputSource != schemaSourceUnknown && validateJSONSchemaValue(schema.Output, structured) != nil {
		return nil, fmt.Errorf("Tool result did not match its output schema")
	}
	result := map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": resultJSON}}}
	if object, ok := structured.(map[string]interface{}); ok {
		result["structuredContent"] = object
		if success, ok := object["success"].(bool); ok && !success {
			result["isError"] = true
		}
	}
	return result, nil
}

func mcpStdioResult(id json.RawMessage, result interface{}) map[string]interface{} {
	return map[string]interface{}{"jsonrpc": "2.0", "id": rawMCPID(id), "result": result}
}
func mcpStdioError(id json.RawMessage, code int, message string) map[string]interface{} {
	return map[string]interface{}{"jsonrpc": "2.0", "id": rawMCPID(id), "error": map[string]interface{}{"code": code, "message": message}}
}
func rawMCPID(id json.RawMessage) interface{} {
	if len(id) == 0 {
		return nil
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil
	}
	return value
}

func configuredMCPMaxConcurrent(serverConfig APIConfig) int {
	if serverConfig.MaxConcurrent > 0 {
		return serverConfig.MaxConcurrent
	}
	return 16
}

func acquireMCPExecutionSlot(serverName string, limit int) (func(), bool) {
	key := serverName + "\x00" + strconv.Itoa(limit)
	mcpConcurrencyLimiters.Lock()
	limiter := mcpConcurrencyLimiters.Limiters[key]
	if limiter == nil {
		limiter = make(chan struct{}, limit)
		mcpConcurrencyLimiters.Limiters[key] = limiter
	}
	mcpConcurrencyLimiters.Unlock()
	select {
	case limiter <- struct{}{}:
		return func() { <-limiter }, true
	default:
		return func() {}, false
	}
}

func validateMCPOrigin(r *http.Request, resource string, allowedOrigins []string) bool {
	return requestOriginAllowed(r.Header.Get("Origin"), resourceOrigin(resource), allowedOrigins)
}

func requestOriginAllowed(rawOrigin, sameOrigin string, allowedOrigins []string) bool {
	origin := strings.TrimSpace(rawOrigin)
	if origin == "" {
		return true
	}
	canonicalOrigin, err := canonicalHTTPOrigin(origin)
	if err != nil {
		return false
	}
	if canonicalSameOrigin, err := canonicalHTTPOrigin(sameOrigin); err == nil && canonicalOrigin == canonicalSameOrigin {
		return true
	}
	for _, allowedOrigin := range allowedOrigins {
		if canonicalOrigin == allowedOrigin {
			return true
		}
	}
	return false
}

func resourceOrigin(resource string) string {
	resourceURL, err := url.Parse(resource)
	if err != nil || resourceURL.Scheme == "" || resourceURL.Host == "" {
		return ""
	}
	return strings.ToLower(resourceURL.Scheme) + "://" + strings.ToLower(resourceURL.Host)

}

func canonicalHTTPOrigin(origin string) (string, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(origin))
	if err != nil || parsed == nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("origin must be an absolute HTTP(S) origin")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("origin must not contain user information, path, query, or fragment")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func mcpAcceptsJSONAndEventStream(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return false
	}
	accept = strings.ToLower(accept)
	return strings.Contains(accept, "application/json") && strings.Contains(accept, "text/event-stream")
}

func mcpInitializeProtocolVersion(request MCPJSONRPCRequest) (string, bool) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(request.Params) == 0 || json.Unmarshal(request.Params, &params) != nil {
		return "", false
	}
	version := strings.TrimSpace(params.ProtocolVersion)
	return version, version != ""
}

func isImplementedMCPProtocolVersion(version string) bool {
	switch version {
	case mcpProtocolVersion20250618, mcpProtocolVersion20251125:
		return true
	default:
		return false
	}
}

func containsMCPProtocolVersion(versions []string, candidate string) bool {
	for _, version := range versions {
		if version == candidate {
			return true
		}
	}
	return false
}

func preferredMCPProtocolVersion(versions []string) string {
	for _, candidate := range []string{
		mcpProtocolVersion20251125,
		mcpProtocolVersion20250618,
	} {
		if containsMCPProtocolVersion(versions, candidate) {
			return candidate
		}
	}
	return ""
}

func negotiateMCPProtocolVersion(requested string, configured []string) string {
	if containsMCPProtocolVersion(configured, requested) {
		return requested
	}
	return preferredMCPProtocolVersion(configured)
}

func mcpSubsequentRequestProtocolVersion(header string, configured []string) (string, bool) {
	version := strings.TrimSpace(header)
	if version == "" {
		// MCP Streamable HTTP defines 2025-03-26 as the compatibility default
		// when a subsequent request does not carry the version header.
		version = mcpProtocolVersion20250326
	}
	return version, containsMCPProtocolVersion(configured, version)
}

func handleMCPNotification(w http.ResponseWriter, request MCPJSONRPCRequest) {
	switch request.Method {
	case "notifications/initialized", "notifications/cancelled":
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

func handleMCPInitialize(w http.ResponseWriter, request MCPJSONRPCRequest, serverName string, serverConfig APIConfig, protocolVersion string) {
	if protocolVersion == "" {
		writeMCPError(w, request.ID, -32602, "Invalid params", nil)
		return
	}
	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = serverName
	}
	version := strings.TrimSpace(config.Version)
	if version == "" {
		version = buildVersion
	}
	result := map[string]interface{}{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"listChanged": false,
			},
		},
		"serverInfo": map[string]interface{}{
			"name":    name,
			"version": version,
		},
	}
	if strings.TrimSpace(serverConfig.Instructions) != "" {
		result["instructions"] = serverConfig.Instructions
	}
	writeMCPResult(w, request.ID, result)
}

func handleMCPToolsList(snapshot *APIConfigSnapshot, w http.ResponseWriter, request MCPJSONRPCRequest, serverConfig APIConfig) {
	if len(request.Params) > 0 {
		var params struct {
			Cursor string `json:"cursor"`
		}
		if err := json.Unmarshal(request.Params, &params); err != nil || params.Cursor != "" {
			writeMCPError(w, request.ID, -32602, "Invalid params", nil)
			return
		}
	}
	tools := make([]map[string]interface{}, 0, len(serverConfig.Tools))
	for _, toolConfig := range serverConfig.Tools {
		tool, err := buildMCPToolDefinition(snapshot, toolConfig)
		if err != nil {
			log.Printf("failed to build MCP tool %s: %v", toolConfig.Name, err)
			writeMCPError(w, request.ID, -32603, "Internal error", nil)
			return
		}
		tools = append(tools, tool)
	}
	writeMCPResult(w, request.ID, map[string]interface{}{"tools": tools})
}

func buildMCPToolDefinition(snapshot *APIConfigSnapshot, toolConfig MCPToolConfig) (map[string]interface{}, error) {
	apiConfig, exists := snapshot.Definitions[toolConfig.API]
	if !exists {
		return nil, fmt.Errorf("API %q was not found", toolConfig.API)
	}
	apiSchema, err := resolveAPISchema(apiConfig)
	if err != nil {
		return nil, err
	}
	inputSchema := normalizedMCPInputSchema(apiSchema.Input)
	if schemaType, ok := inputSchema["type"].(string); !ok || schemaType != "object" {
		return nil, fmt.Errorf("input schema for API %q must have type object", toolConfig.API)
	}
	if _, err := compileJSONSchema(inputSchema); err != nil {
		return nil, fmt.Errorf("invalid input schema for API %q: %w", toolConfig.API, err)
	}
	title := apiConfig.Title
	if title == "" {
		title = toolConfig.API
	}
	description := apiConfig.Description
	tool := map[string]interface{}{
		"name":        toolConfig.API,
		"title":       title,
		"description": description,
		"inputSchema": inputSchema,
	}
	if apiSchema.OutputSource != schemaSourceUnknown {
		if _, err := compileJSONSchema(apiSchema.Output); err != nil {
			return nil, fmt.Errorf("invalid output schema for API %q: %w", toolConfig.API, err)
		}
		tool["outputSchema"] = cloneJSONCompatibleValue(apiSchema.Output)
	}
	if annotations := mcpAnnotationsMap(apiConfig.Annotations); len(annotations) > 0 {
		tool["annotations"] = annotations
	}
	securitySchemes := apiConfig.SecuritySchemes
	if len(securitySchemes) == 0 && len(apiConfig.Scopes) > 0 {
		securitySchemes = []MCPSecurityScheme{{Type: "oauth2", Scopes: append([]string(nil), apiConfig.Scopes...)}}
	}
	if len(securitySchemes) > 0 {
		securitySchemes := cloneMCPSecuritySchemes(securitySchemes)
		tool["securitySchemes"] = securitySchemes
		tool["_meta"] = map[string]interface{}{"securitySchemes": cloneJSONCompatibleValue(securitySchemes)}
	}
	return tool, nil
}

func normalizedMCPInputSchema(schema map[string]interface{}) map[string]interface{} {
	if len(schema) == 0 {
		return map[string]interface{}{
			"type":                 "object",
			"properties":           map[string]interface{}{},
			"additionalProperties": true,
		}
	}
	return cloneJSONCompatibleValue(schema).(map[string]interface{})
}

func mcpAnnotationsMap(annotations MCPToolAnnotations) map[string]interface{} {
	result := make(map[string]interface{})
	if annotations.ReadOnlyHint != nil {
		result["readOnlyHint"] = *annotations.ReadOnlyHint
	}
	if annotations.DestructiveHint != nil {
		result["destructiveHint"] = *annotations.DestructiveHint
	}
	if annotations.OpenWorldHint != nil {
		result["openWorldHint"] = *annotations.OpenWorldHint
	}
	return result
}

func cloneMCPSecuritySchemes(schemes []MCPSecurityScheme) []map[string]interface{} {
	result := make([]map[string]interface{}, len(schemes))
	for index, scheme := range schemes {
		entry := map[string]interface{}{"type": scheme.Type}
		if len(scheme.Scopes) > 0 {
			entry["scopes"] = append([]string(nil), scheme.Scopes...)
		}
		result[index] = entry
	}
	return result
}

func handleMCPToolCall(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, request MCPJSONRPCRequest, serverName string, serverConfig APIConfig, runtimeURLs mcpRuntimeURLs) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if len(request.Params) == 0 || json.Unmarshal(request.Params, &params) != nil || strings.TrimSpace(params.Name) == "" {
		writeMCPError(w, request.ID, -32602, "Invalid params", nil)
		return
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}
	toolConfig, ok := findMCPToolConfig(serverConfig.Tools, params.Name)
	if !ok {
		writeMCPError(w, request.ID, -32602, "Unknown tool", nil)
		return
	}
	apiConfig := snapshot.Definitions[toolConfig.API]
	requiredScopes := apiConfig.Scopes
	if len(apiConfig.SecuritySchemes) > 0 {
		requiredScopes = mcpRequiredScopes(apiConfig.SecuritySchemes)
	}
	principal := interface{}(map[string]interface{}{"anonymous": true, "transport": "streamable_http"})
	if mcpOAuthConfigured(serverConfig.OAuth) {
		verifiedPrincipal, authenticated, forbidden := validateMCPAccessToken(snapshot, serverName, serverConfig, runtimeURLs, r.Header.Get("Authorization"), toolConfig.API, requiredScopes)
		if !authenticated {
			status := http.StatusUnauthorized
			errorCode := "invalid_token"
			if forbidden {
				status, errorCode = http.StatusForbidden, "insufficient_scope"
			}
			challenge := mcpOAuthChallenge(runtimeURLs, requiredScopes, errorCode, "Authentication or authorization is required")
			w.Header().Set("WWW-Authenticate", challenge)
			writeMCPResultWithStatus(w, request.ID, mcpToolErrorResult("Authentication or authorization is required", map[string]interface{}{"mcp/www_authenticate": []string{challenge}}), status)
			return
		}
		principal = verifiedPrincipal
	}
	apiSchema, err := resolveAPISchema(apiConfig)
	if err != nil {
		log.Printf("failed to resolve MCP tool schema for %s: %v", toolConfig.Name, err)
		writeMCPError(w, request.ID, -32603, "Internal error", nil)
		return
	}
	inputSchema := normalizedMCPInputSchema(apiSchema.Input)
	if schemaType, ok := inputSchema["type"].(string); !ok || schemaType != "object" {
		writeMCPError(w, request.ID, -32603, "Internal error", nil)
		return
	}
	if err := validateJSONSchemaValue(inputSchema, params.Arguments); err != nil {
		writeMCPResult(w, request.ID, mcpToolErrorResult("Tool arguments did not match the input schema", nil))
		return
	}

	executionParams := cloneParams(params.Arguments)
	for _, reservedName := range []string{"api", "nyan_guard", "nyan_mode", "nyan_request", "mcp_principal"} {
		delete(executionParams, reservedName)
	}
	if principal != nil {
		executionParams["mcp_principal"] = cloneJSONCompatibleValue(principal)
	}
	resultJSON, err := callNyanAPIFromVMWithSnapshot(snapshot, toolConfig.API, executionParams)
	if err != nil {
		log.Printf("MCP tool %s execution failed: %v", toolConfig.Name, err)
		writeMCPResult(w, request.ID, mcpToolErrorResult("Tool execution failed", nil))
		return
	}
	if len(resultJSON) > maxConfiguredHTTPResponseBytes/2 {
		writeMCPResult(w, request.ID, mcpToolErrorResult("Tool result is too large", nil))
		return
	}
	var result interface{}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		writeMCPResult(w, request.ID, mcpToolErrorResult("Tool returned invalid JSON", nil))
		return
	}
	if apiSchema.OutputSource != schemaSourceUnknown {
		if err := validateJSONSchemaValue(apiSchema.Output, result); err != nil {
			log.Printf("MCP tool %s output schema validation failed: %v", toolConfig.Name, err)
			writeMCPResult(w, request.ID, mcpToolErrorResult("Tool result did not match its output schema", nil))
			return
		}
	}
	toolResult := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": resultJSON},
		},
	}
	if resultObject, ok := result.(map[string]interface{}); ok {
		toolResult["structuredContent"] = resultObject
		if success, exists := resultObject["success"].(bool); exists && !success {
			toolResult["isError"] = true
		}
	}
	writeMCPResult(w, request.ID, toolResult)
}

func findMCPToolConfig(tools []MCPToolConfig, name string) (MCPToolConfig, bool) {
	for _, tool := range tools {
		if tool.API == name {
			return tool, true
		}
	}
	return MCPToolConfig{}, false
}

func mcpToolRequiresAuthorization(tool MCPToolConfig) bool {
	if len(tool.SecuritySchemes) == 0 {
		return true
	}
	for _, scheme := range tool.SecuritySchemes {
		if scheme.Type == "oauth2" {
			return true
		}
	}
	return false
}

func runMCPGuard(snapshot *APIConfigSnapshot, r *http.Request, serverConfig APIConfig, toolConfig MCPToolConfig) (MCPGuardDecision, error) {
	guardConfig, exists := snapshot.Definitions[serverConfig.Guard.API]
	if !exists || guardConfig.Script == "" {
		return MCPGuardDecision{}, fmt.Errorf("guard API is unavailable")
	}
	headers := map[string]interface{}{}
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		headers["authorization"] = authorization
	}
	requestContext := map[string]interface{}{
		"method":        r.Method,
		"path":          r.URL.Path,
		"query":         urlValuesToInterfaceMap(r.URL.Query()),
		"form":          map[string]interface{}{},
		"json":          nil,
		"headers":       headers,
		"cookies":       map[string]interface{}{},
		"body":          "",
		"remoteAddress": r.RemoteAddr,
	}
	params := map[string]interface{}{
		"api":                  serverConfig.Guard.API,
		"nyan_request":         requestContext,
		"mcp_resource":         serverConfig.Resource,
		"mcp_tool":             toolConfig.Name,
		"mcp_security_schemes": cloneMCPSecuritySchemes(toolConfig.SecuritySchemes),
		"mcp_required_scopes":  mcpRequiredScopes(toolConfig.SecuritySchemes),
	}
	result, err := runScriptWithRuntimeWithSnapshot(snapshot, []string{guardConfig.Script}, params, guardConfig.Runtime, true)
	if err != nil {
		return MCPGuardDecision{}, err
	}
	var decision MCPGuardDecision
	if err := json.Unmarshal([]byte(result), &decision); err != nil {
		return MCPGuardDecision{}, fmt.Errorf("decode guard result: %w", err)
	}
	if decision.Status == 0 {
		if decision.Allow {
			decision.Status = http.StatusOK
		} else {
			decision.Status = http.StatusUnauthorized
		}
	}
	if decision.Status < 100 || decision.Status > 599 {
		return MCPGuardDecision{}, fmt.Errorf("guard returned invalid status %d", decision.Status)
	}
	if decision.Allow && (decision.Status < 200 || decision.Status > 299) {
		return MCPGuardDecision{}, fmt.Errorf("guard allowed access with non-success status %d", decision.Status)
	}
	if !decision.Allow && decision.Status < 400 {
		return MCPGuardDecision{}, fmt.Errorf("guard denied access with non-error status %d", decision.Status)
	}
	return decision, nil
}

func validateMCPAccessToken(snapshot *APIConfigSnapshot, serverName string, serverConfig APIConfig, runtimeURLs mcpRuntimeURLs, authorization, tool string, requiredScopes []string) (interface{}, bool, bool) {
	value, err := invokeMCPOAuthHook(snapshot, serverName, serverConfig, runtimeURLs, "oauthValidateAccessToken", map[string]interface{}{
		"authorization": authorization, "tool": tool, "required_scopes": requiredScopes,
	})
	if err != nil {
		return nil, false, false
	}
	result, ok := value.(map[string]interface{})
	if !ok {
		return nil, false, false
	}
	authenticated, _ := result["authenticated"].(bool)
	forbidden, _ := result["forbidden"].(bool)
	principal := result["principal"]
	if allow, exists := result["allow"].(bool); exists {
		authenticated = allow
		if status, ok := result["status"].(json.Number); ok {
			forbidden = status.String() == strconv.Itoa(http.StatusForbidden)
		} else if status, ok := result["status"].(float64); ok {
			forbidden = int(status) == http.StatusForbidden
		}
		if principalMap, ok := principal.(map[string]interface{}); ok {
			if scopes, exists := result["scopes"]; exists {
				principalMap["scopes"] = scopes
				if scopeList, ok := scopes.([]interface{}); ok {
					parts := make([]string, 0, len(scopeList))
					for _, scope := range scopeList {
						if text, ok := scope.(string); ok {
							parts = append(parts, text)
						}
					}
					principalMap["scope"] = strings.Join(parts, " ")
				}
			}
		}
	}
	return principal, authenticated && principal != nil, forbidden
}

func mcpOAuthChallenge(runtimeURLs mcpRuntimeURLs, scopes []string, errorCode, description string) string {
	escape := func(value string) string {
		value = strings.ReplaceAll(value, `\`, `\\`)
		return strings.ReplaceAll(value, `"`, `\"`)
	}
	return fmt.Sprintf(`Bearer resource_metadata="%s", scope="%s", error="%s", error_description="%s"`,
		escape(runtimeURLs.ProtectedResourceMetadata), escape(strings.Join(scopes, " ")), escape(errorCode), escape(description))
}

func mcpOAuthAPIForRole(serverConfig APIConfig, role string) string {
	switch role {
	case "oauthAuthorize":
		return serverConfig.OAuth.Authorize
	case "oauthToken":
		return serverConfig.OAuth.Token
	case "oauthRegister":
		return serverConfig.OAuth.Register
	case "oauthAdminUser":
		return serverConfig.OAuth.AdminUser
	case "oauthValidateAccessToken":
		return serverConfig.OAuth.VerifyAccess
	default:
		return ""
	}
}

func invokeMCPOAuthHook(snapshot *APIConfigSnapshot, serverName string, serverConfig APIConfig, runtimeURLs mcpRuntimeURLs, role string, extra map[string]interface{}) (interface{}, error) {
	apiName := mcpOAuthAPIForRole(serverConfig, role)
	definition, exists := snapshot.Definitions[apiName]
	if !exists || getAPIType(definition) != apiTypeAPI || definition.Script == "" {
		return nil, fmt.Errorf("OAuth API is unavailable")
	}
	endpointPath, _ := canonicalAPIEndpointPath(apiName)
	params := map[string]interface{}{
		"oauth_hook": role, "endpoint": serverName, "mcp_api": serverName, "oauth_api": apiName,
		"issuer": runtimeURLs.Issuer, "resource": runtimeURLs.Resource, "path": endpointPath,
		"authorization_server_metadata_url": runtimeURLs.AuthorizationServerMetadata,
		"protected_resource_metadata_url":   runtimeURLs.ProtectedResourceMetadata,
		"authorization_endpoint":            runtimeURLs.AuthorizationEndpoint, "token_endpoint": runtimeURLs.TokenEndpoint,
		"registration_endpoint": runtimeURLs.RegistrationEndpoint, "admin_user_endpoint": runtimeURLs.AdminUserEndpoint,
		"scopes":                        append([]string(nil), snapshot.Definitions[serverConfig.OAuth.VerifyAccess].Scopes...),
		"redirect_uri_allowed_prefixes": append([]string(nil), serverConfig.RedirectURIAllowedPrefixes...),
	}
	for key, value := range extra {
		params[key] = value
	}
	requestContext := map[string]interface{}{
		"method": extra["method"], "path": extra["request_path"], "query": extra["query"],
		"form": extra["form"], "json": extra["body"], "headers": extra["headers"], "cookies": extra["cookies"],
	}
	params["nyan_request"] = requestContext
	runtimeConfig := definition.Runtime
	if runtimeConfig.Settings == nil {
		runtimeConfig.Settings = map[string]interface{}{}
	} else {
		runtimeConfig.Settings = cloneJSONCompatibleValue(runtimeConfig.Settings).(map[string]interface{})
	}
	runtimeConfig.Settings["issuer"] = runtimeURLs.Issuer
	runtimeConfig.Settings["resource"] = runtimeURLs.Resource
	runtimeConfig.Settings["authorizationEndpoint"] = runtimeURLs.AuthorizationEndpoint
	runtimeConfig.Settings["tokenEndpoint"] = runtimeURLs.TokenEndpoint
	runtimeConfig.Settings["registrationEndpoint"] = runtimeURLs.RegistrationEndpoint
	runtimeConfig.Settings["protectedResourceMetadata"] = runtimeURLs.ProtectedResourceMetadata
	runtimeConfig.Settings["authorizationCookiePath"], _ = canonicalAPIEndpointPath(serverConfig.OAuth.Authorize)
	runtimeConfig.Settings["scopes"] = append([]string(nil), snapshot.Definitions[serverConfig.OAuth.VerifyAccess].Scopes...)
	runtimeConfig.Settings["redirectURIAllowedPrefixes"] = append([]string(nil), serverConfig.RedirectURIAllowedPrefixes...)
	result, err := runScriptWithRuntimeWithSnapshot(snapshot, []string{definition.Script}, params, runtimeConfig, true)
	if err != nil {
		return nil, err
	}
	var value interface{}
	decoder := json.NewDecoder(strings.NewReader(result))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode OAuth hook result: %w", err)
	}
	return value, nil
}

func mcpRequiredScopes(schemes []MCPSecurityScheme) []string {
	seen := make(map[string]struct{})
	var scopes []string
	for _, scheme := range schemes {
		if scheme.Type != "oauth2" {
			continue
		}
		for _, scope := range scheme.Scopes {
			if _, exists := seen[scope]; exists {
				continue
			}
			seen[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func applyMCPGuardHeaders(w http.ResponseWriter, headers map[string]interface{}) {
	for name, rawValue := range headers {
		if !isHTTPToken(name) || isForbiddenScriptResponseHeader(http.CanonicalHeaderKey(name)) {
			continue
		}
		values, err := configuredHTTPHeaderValues(rawValue)
		if err != nil {
			continue
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				continue
			}
			w.Header().Add(http.CanonicalHeaderKey(name), value)
		}
	}
}

func mcpToolErrorResult(message string, metadata map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": message},
		},
		"isError": true,
	}
	if len(metadata) > 0 {
		result["_meta"] = cloneJSONCompatibleValue(metadata)
	}
	return result
}

func compileJSONSchema(schema map[string]interface{}) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(rejectingJSONSchemaLoader{})
	const schemaLocation = "urn:nyanql:mcp-schema"
	if err := compiler.AddResource(schemaLocation, cloneJSONCompatibleValue(schema)); err != nil {
		return nil, err
	}
	return compiler.Compile(schemaLocation)
}

func validateJSONSchemaValue(schema map[string]interface{}, value interface{}) error {
	compiled, err := compileJSONSchema(schema)
	if err != nil {
		return err
	}
	return compiled.Validate(value)
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	writeMCPResultWithStatus(w, id, result, http.StatusOK)
}

func writeMCPResultWithStatus(w http.ResponseWriter, id json.RawMessage, result interface{}, status int) {
	writeMCPJSONRPCResponseWithStatus(w, MCPJSONRPCResponse{
		JSONRPC: "2.0",
		ID:      normalizedMCPID(id),
		Result:  result,
	}, status)
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, code int, message string, data interface{}) {
	writeMCPJSONRPCResponse(w, MCPJSONRPCResponse{
		JSONRPC: "2.0",
		ID:      normalizedMCPID(id),
		Error: &MCPJSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	})
}

func normalizedMCPID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return append(json.RawMessage(nil), id...)
}

func writeMCPJSONRPCResponse(w http.ResponseWriter, response MCPJSONRPCResponse) {
	writeMCPJSONRPCResponseWithStatus(w, response, http.StatusOK)
}

func writeMCPJSONRPCResponseWithStatus(w http.ResponseWriter, response MCPJSONRPCResponse, status int) {
	body, err := json.Marshal(response)
	if err != nil {
		log.Printf("failed to encode MCP response: %v", err)
		http.Error(w, "failed to encode MCP response", http.StatusInternalServerError)
		return
	}
	if len(body) > maxConfiguredHTTPResponseBytes {
		response = MCPJSONRPCResponse{
			JSONRPC: "2.0",
			ID:      response.ID,
			Error: &MCPJSONRPCError{
				Code:    -32603,
				Message: "Response is too large",
			},
		}
		body, err = json.Marshal(response)
		if err != nil {
			http.Error(w, "failed to encode MCP response", http.StatusInternalServerError)
			return
		}
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body = append(body, '\n')
	if _, err := w.Write(body); err != nil {
		log.Printf("failed to encode MCP response: %v", err)
	}
}

func findPublicAPIForPath(requestPath string) (string, string, APIConfig, bool) {
	return findPublicAPIForPathInSnapshot(currentAPISnapshot(), requestPath)
}

func findPublicAPIForPathInSnapshot(snapshot *APIConfigSnapshot, requestPath string) (string, string, APIConfig, bool) {
	var matchedKey string
	var matchedPath string
	var matchedConfig APIConfig
	for apiKey, apiConfig := range snapshot.Definitions {
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
	select {
	case websocketConnectionSlots <- struct{}{}:
		defer func() { <-websocketConnectionSlots }()
	default:
		http.Error(w, "too many WebSocket connections", http.StatusServiceUnavailable)
		return
	}
	channel := strings.TrimPrefix(r.URL.Path, "/")
	if channel == "" {
		channel = "default"
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocketアップグレードエラー: %v", err)
		return
	}
	defer conn.Close()
	hub.AddClient(channel, conn)
	defer hub.RemoveClient(channel, conn)
	conn.SetReadLimit(maxWebSocketMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	})
	pingDone := make(chan struct{})
	pingStopped := make(chan struct{})
	defer func() {
		close(pingDone)
		<-pingStopped
	}()
	go func() {
		defer close(pingStopped)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					_ = conn.Close()
					return
				}
			case <-pingDone:
				return
			}
		}
	}()

	// シンプルな読み込みループ（ここで受信したメッセージを必要に応じて処理可能）
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		log.Printf("Received WebSocket message on channel [%s]: bytes=%d", channel, len(msg))
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

func normalizeAPIFilePath(apiFilePath string) (string, error) {
	absPath, err := filepath.Abs(apiFilePath)
	if err != nil {
		return "", fmt.Errorf("resolve api file path %q: %w", apiFilePath, err)
	}
	return filepath.Clean(absPath), nil
}

func loadAPIConfigFile(apiFilePath string) (*apiConfigLoadResult, error) {
	result, _, err := loadAPIConfigFileAttempt(apiFilePath)
	return result, err
}

func loadAPIConfigFileAttempt(apiFilePath string) (*apiConfigLoadResult, map[string]APIFileState, error) {
	normalizedPath, err := normalizeAPIFilePath(apiFilePath)
	if err != nil {
		return nil, nil, err
	}
	identity, state, data, err := inspectAPIFile(normalizedPath)
	discovered := map[string]APIFileState{identity: state}
	if err != nil {
		return nil, discovered, fmt.Errorf("read api file %s: %w", normalizedPath, err)
	}
	result, files, err := loadAPIConfigDataAttempt(normalizedPath, data)
	return result, files, err
}

func loadAPIConfigData(apiFilePath string, data []byte) (*apiConfigLoadResult, error) {
	result, _, err := loadAPIConfigDataAttempt(apiFilePath, data)
	return result, err
}

func loadAPIConfigDataAttempt(apiFilePath string, data []byte) (*apiConfigLoadResult, map[string]APIFileState, error) {
	normalizedPath, err := normalizeAPIFilePath(apiFilePath)
	if err != nil {
		return nil, nil, err
	}
	files, sources, fileStates, err := expandAPIConfigGraph(normalizedPath, data)
	if err != nil {
		return nil, fileStates, err
	}
	if err := validateConfiguredAPIExtensions(files); err != nil {
		return nil, fileStates, err
	}
	schedules, err := buildScheduleJobConfigs(files, filepath.Dir(normalizedPath))
	if err != nil {
		return nil, fileStates, err
	}
	wsClients, err := buildWSClientConfigs(files, filepath.Dir(normalizedPath))
	if err != nil {
		return nil, fileStates, err
	}
	hash := sha256.Sum256(data)
	snapshot := newLoadedAPIConfigSnapshot(files, sources, fileStates, schedules, wsClients)
	result := &apiConfigLoadResult{
		Snapshot:  snapshot,
		Schedules: snapshot.Schedules,
		WSClients: snapshot.WSClients,
		Hash:      hash,
	}
	return result, fileStates, nil
}

func readSQLFiles(apiFilePath, _ string) (map[string]APIConfig, [sha256.Size]byte, error) {
	result, err := loadAPIConfigFile(apiFilePath)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return result.Snapshot.Definitions, result.Hash, nil
}

func decodeSQLFiles(data []byte, apiBaseDir string) (map[string]APIConfig, error) {
	rawFiles, err := decodeRawAPIDefinitions(data)
	if err != nil {
		return nil, err
	}
	files := make(map[string]APIConfig, len(rawFiles))
	for apiKey, rawDefinition := range rawFiles {
		definitionType, err := rawAPIDefinitionType(rawDefinition)
		if err != nil {
			return nil, fmt.Errorf("decode api JSON: definition %q: %w", apiKey, err)
		}
		if definitionType == apiTypeInclude {
			return nil, fmt.Errorf("decode api JSON: include definition %q requires an API file path", apiKey)
		}
		apiConfig, err := decodeAPIConfigDefinition(apiKey, rawDefinition, apiBaseDir)
		if err != nil {
			return nil, err
		}
		files[apiKey] = apiConfig
	}
	return files, nil
}

func decodeRawAPIDefinitions(data []byte) (map[string]json.RawMessage, error) {
	if err := validateNoDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("decode api JSON: %w", err)
	}
	trimmedData := bytes.TrimSpace(data)
	if len(trimmedData) == 0 || trimmedData[0] != '{' {
		return nil, fmt.Errorf("decode api JSON: top-level value must be an object")
	}
	var rawFiles map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawFiles); err != nil {
		return nil, fmt.Errorf("decode api JSON: %w", err)
	}
	if rawFiles == nil {
		return nil, fmt.Errorf("decode api JSON: top-level value must be an object")
	}
	for apiKey, rawDefinition := range rawFiles {
		trimmed := bytes.TrimSpace(rawDefinition)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("decode api JSON: definition %q must be an object", apiKey)
		}
	}
	return rawFiles, nil
}

func rawAPIDefinitionType(rawDefinition json.RawMessage) (string, error) {
	var typeOnly struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rawDefinition, &typeOnly); err != nil {
		return "", err
	}
	return strings.TrimSpace(typeOnly.Type), nil
}

func decodeAPIConfigDefinition(apiKey string, rawDefinition json.RawMessage, apiBaseDir string) (APIConfig, error) {
	if err := validateAPIConfigKnownFields(apiKey, rawDefinition); err != nil {
		return APIConfig{}, err
	}
	var apiConfig APIConfig
	if err := json.Unmarshal(rawDefinition, &apiConfig); err != nil {
		return APIConfig{}, fmt.Errorf("decode api JSON: definition %q: %w", apiKey, err)
	}
	if len(apiConfig.Script) > 0 && len(apiConfig.SQL) > 0 {
		return APIConfig{}, fmt.Errorf("configuration error for API %q: if script is set, sql cannot be specified", apiKey)
	}
	for i, sqlPath := range apiConfig.SQL {
		if !filepath.IsAbs(sqlPath) {
			apiConfig.SQL[i] = filepath.Join(apiBaseDir, sqlPath)
		}
	}
	apiConfig.Script = resolvePathFromBase(apiBaseDir, apiConfig.Script)
	apiConfig.ParamCheck = resolvePathFromBase(apiBaseDir, apiConfig.ParamCheck)
	apiConfig.OutCheck = resolvePathFromBase(apiBaseDir, apiConfig.OutCheck)
	apiConfig.Transport = strings.TrimSpace(apiConfig.Transport)
	apiConfig.Resource = strings.TrimSpace(apiConfig.Resource)
	apiConfig.Title = strings.TrimSpace(apiConfig.Title)
	for i := range apiConfig.AllowedOrigins {
		apiConfig.AllowedOrigins[i] = strings.TrimSpace(apiConfig.AllowedOrigins[i])
	}
	apiConfig.Guard.API = strings.TrimSpace(apiConfig.Guard.API)
	apiConfig.OAuth.AuthorizationServerMetadata = strings.TrimSpace(apiConfig.OAuth.AuthorizationServerMetadata)
	apiConfig.OAuth.ProtectedResourceMetadata = strings.TrimSpace(apiConfig.OAuth.ProtectedResourceMetadata)
	apiConfig.OAuth.Authorize = strings.TrimSpace(apiConfig.OAuth.Authorize)
	apiConfig.OAuth.Token = strings.TrimSpace(apiConfig.OAuth.Token)
	apiConfig.OAuth.Register = strings.TrimSpace(apiConfig.OAuth.Register)
	apiConfig.OAuth.AdminUser = strings.TrimSpace(apiConfig.OAuth.AdminUser)
	apiConfig.OAuth.VerifyAccess = strings.TrimSpace(apiConfig.OAuth.VerifyAccess)
	for index := range apiConfig.RedirectURIAllowedPrefixes {
		apiConfig.RedirectURIAllowedPrefixes[index] = strings.TrimSpace(apiConfig.RedirectURIAllowedPrefixes[index])
	}
	for index := range apiConfig.Scopes {
		apiConfig.Scopes[index] = strings.TrimSpace(apiConfig.Scopes[index])
	}
	for index := range apiConfig.SecuritySchemes {
		apiConfig.SecuritySchemes[index].Type = strings.ToLower(strings.TrimSpace(apiConfig.SecuritySchemes[index].Type))
		for scopeIndex := range apiConfig.SecuritySchemes[index].Scopes {
			apiConfig.SecuritySchemes[index].Scopes[scopeIndex] = strings.TrimSpace(apiConfig.SecuritySchemes[index].Scopes[scopeIndex])
		}
	}
	if apiConfig.RateLimit != nil {
		apiConfig.RateLimit.Window = strings.TrimSpace(apiConfig.RateLimit.Window)
	}
	for i := range apiConfig.ProtocolVersions {
		apiConfig.ProtocolVersions[i] = strings.TrimSpace(apiConfig.ProtocolVersions[i])
	}
	if getAPIType(apiConfig) == apiTypeMCP && len(apiConfig.ProtocolVersions) == 0 {
		apiConfig.ProtocolVersions = []string{mcpProtocolVersion20251125, mcpProtocolVersion20250618}
	}
	for i := range apiConfig.Runtime.Capabilities {
		apiConfig.Runtime.Capabilities[i] = strings.TrimSpace(apiConfig.Runtime.Capabilities[i])
	}
	for i := range apiConfig.Runtime.SQLFiles {
		apiConfig.Runtime.SQLFiles[i] = resolvePathFromBase(apiBaseDir, strings.TrimSpace(apiConfig.Runtime.SQLFiles[i]))
	}
	if apiConfig.HTTP != nil {
		apiConfig.HTTP.Path = strings.TrimSpace(apiConfig.HTTP.Path)
		apiConfig.HTTP.Access = strings.ToLower(strings.TrimSpace(apiConfig.HTTP.Access))
		apiConfig.HTTP.ResponseMode = strings.ToLower(strings.TrimSpace(apiConfig.HTTP.ResponseMode))
		if apiConfig.HTTP.RateLimit != nil {
			apiConfig.HTTP.RateLimit.Window = strings.TrimSpace(apiConfig.HTTP.RateLimit.Window)
		}
		for i := range apiConfig.HTTP.AllowedRemoteIPs {
			apiConfig.HTTP.AllowedRemoteIPs[i] = strings.TrimSpace(apiConfig.HTTP.AllowedRemoteIPs[i])
		}
		for i := range apiConfig.HTTP.AllowedOrigins {
			apiConfig.HTTP.AllowedOrigins[i] = strings.TrimSpace(apiConfig.HTTP.AllowedOrigins[i])
		}
		for i := range apiConfig.HTTP.Methods {
			apiConfig.HTTP.Methods[i] = strings.ToUpper(strings.TrimSpace(apiConfig.HTTP.Methods[i]))
		}
	}
	for toolIndex := range apiConfig.Tools {
		tool := &apiConfig.Tools[toolIndex]
		tool.Name = strings.TrimSpace(tool.Name)
		tool.API = strings.TrimSpace(tool.API)
		tool.Title = strings.TrimSpace(tool.Title)
		for schemeIndex := range tool.SecuritySchemes {
			scheme := &tool.SecuritySchemes[schemeIndex]
			scheme.Type = strings.ToLower(strings.TrimSpace(scheme.Type))
			for scopeIndex := range scheme.Scopes {
				scheme.Scopes[scopeIndex] = strings.TrimSpace(scheme.Scopes[scopeIndex])
			}
		}
	}
	if apiConfig.Path != "" && !filepath.IsAbs(apiConfig.Path) {
		apiConfig.Path = filepath.Join(apiBaseDir, apiConfig.Path)
	}
	return apiConfig, nil
}

func validateAPIConfigKnownFields(apiKey string, rawDefinition json.RawMessage) error {
	topLevel, err := decodeKnownJSONObject(rawDefinition, "definition "+strconv.Quote(apiKey), stringSet(
		"sql", "script", "path", "paramCheck", "paramcheck", "check", "outCheck", "outcheck",
		"push", "trigger", "title", "description", "type", "connectURL", "http", "runtime", "transport",
		"protocolVersions", "tools", "instructions", "allowedOrigins", "redirectURIAllowedPrefixes",
		"rateLimit", "maxConcurrent", "oauth", "securitySchemes", "annotations", "scopes",
	))
	if err != nil {
		return fmt.Errorf("decode api JSON: %w", err)
	}
	if raw, exists := topLevel["trigger"]; exists {
		if _, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".trigger", stringSet("type", "value")); err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
	}
	if raw, exists := topLevel["http"]; exists {
		httpFields, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".http", stringSet(
			"path", "methods", "access", "responseMode", "allowedRemoteIPs", "allowedOrigins", "rateLimit",
		))
		if err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
		if rateLimit, exists := httpFields["rateLimit"]; exists {
			if _, err := decodeKnownJSONObject(rateLimit, "definition "+strconv.Quote(apiKey)+".http.rateLimit", stringSet("requests", "window")); err != nil {
				return fmt.Errorf("decode api JSON: %w", err)
			}
		}
	}
	if raw, exists := topLevel["runtime"]; exists {
		if _, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".runtime", stringSet("capabilities", "sqlFiles", "settings")); err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
	}
	if raw, exists := topLevel["oauth"]; exists {
		if _, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".oauth", stringSet(
			"authorizationServerMetadata", "protectedResourceMetadata", "authorize", "token", "register", "adminUser", "verifyAccess",
		)); err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
	}
	if raw, exists := topLevel["rateLimit"]; exists {
		if _, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".rateLimit", stringSet("requests", "window")); err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
	}
	if raw, exists := topLevel["tools"]; exists {
		var tools []string
		if err := json.Unmarshal(raw, &tools); err != nil {
			return fmt.Errorf("decode api JSON: definition %q.tools must be an array of API names: %w", apiKey, err)
		}
	}
	if raw, exists := topLevel["annotations"]; exists {
		if _, err := decodeKnownJSONObject(raw, "definition "+strconv.Quote(apiKey)+".annotations", stringSet("readOnlyHint", "destructiveHint", "openWorldHint")); err != nil {
			return fmt.Errorf("decode api JSON: %w", err)
		}
	}
	if raw, exists := topLevel["securitySchemes"]; exists {
		var schemes []json.RawMessage
		if err := json.Unmarshal(raw, &schemes); err != nil {
			return fmt.Errorf("decode api JSON: definition %q.securitySchemes must be an array: %w", apiKey, err)
		}
		for index, scheme := range schemes {
			if _, err := decodeKnownJSONObject(scheme, fmt.Sprintf("definition %q.securitySchemes[%d]", apiKey, index), stringSet("type", "scopes")); err != nil {
				return fmt.Errorf("decode api JSON: %w", err)
			}
		}
	}
	return nil
}

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func decodeKnownJSONObject(raw json.RawMessage, contextName string, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be an object", contextName)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", contextName, err)
	}
	for field := range fields {
		if _, exists := allowed[field]; !exists {
			return nil, fmt.Errorf("%s contains unsupported field %q", contextName, field)
		}
	}
	return fields, nil
}

func validateConfiguredAPIExtensions(definitions map[string]APIConfig) error {
	routes := make(map[string]string)
	oauthOwners := make(map[string]string)
	reservedRoutes := map[string]struct{}{
		"/nyan-rpc": {},
		"/nyan":     {},
		"/nyan/":    {},
	}

	for _, apiName := range sortedAPIConfigNames(definitions) {
		apiConfig := definitions[apiName]
		if err := validateAPIConfigFieldPlacement(apiName, apiConfig); err != nil {
			return err
		}
		if apiConfig.HTTP != nil {
			if err := validateConfiguredHTTPAPI(apiName, apiConfig); err != nil {
				return err
			}
			if configuredHTTPAccess(apiConfig) != configuredHTTPAccessInternal {
				routePath := apiConfig.HTTP.Path
				if _, reserved := reservedRoutes[routePath]; reserved {
					return fmt.Errorf("configuration error for API %q: HTTP path %q is reserved", apiName, routePath)
				}
				if previous, exists := routes[routePath]; exists {
					return fmt.Errorf("configuration error for API %q: HTTP path %q conflicts with %q", apiName, routePath, previous)
				}
				routes[routePath] = apiName
			}
		}
		if getAPIType(apiConfig) == apiTypeMCP {
			if err := validateMCPServerConfig(apiName, apiConfig, definitions); err != nil {
				return err
			}
			if apiConfig.Transport == "streamable_http" {
				routePath, _ := canonicalAPIEndpointPath(apiName)
				if previous, exists := routes[routePath]; exists {
					return fmt.Errorf("configuration error for MCP server %q: path %q conflicts with %q", apiName, routePath, previous)
				}
				routes[routePath] = apiName
				if mcpOAuthConfigured(apiConfig.OAuth) {
					publicOAuth := []string{apiConfig.OAuth.AuthorizationServerMetadata, apiConfig.OAuth.ProtectedResourceMetadata, apiConfig.OAuth.Authorize, apiConfig.OAuth.Token, apiConfig.OAuth.Register}
					if apiConfig.OAuth.AdminUser != "" {
						publicOAuth = append(publicOAuth, apiConfig.OAuth.AdminUser)
					}
					for _, oauthAPI := range publicOAuth {
						if owner, exists := oauthOwners[oauthAPI]; exists && owner != apiName {
							return fmt.Errorf("configuration error: OAuth API %q is owned by MCP servers %q and %q", oauthAPI, owner, apiName)
						}
						oauthOwners[oauthAPI] = apiName
						oauthPath, _ := canonicalAPIEndpointPath(oauthAPI)
						if previous, exists := routes[oauthPath]; exists && previous != apiName {
							return fmt.Errorf("configuration error: OAuth path %q conflicts with %q", oauthPath, previous)
						}
						routes[oauthPath] = apiName
					}
				}
			}
		}
	}

	for apiName, apiConfig := range definitions {
		if getAPIType(apiConfig) != apiTypePublic {
			continue
		}
		publicRoute := "/" + strings.Trim(strings.TrimSpace(apiName), "/")
		for routePath, routeOwner := range routes {
			if routePath == publicRoute || strings.HasPrefix(routePath, publicRoute+"/") || strings.HasPrefix(publicRoute, routePath+"/") {
				return fmt.Errorf("configuration error: configured HTTP path %q for %q conflicts with public API %q", routePath, routeOwner, apiName)
			}
		}
	}
	return nil
}

func validateAPIConfigFieldPlacement(apiName string, apiConfig APIConfig) error {
	definitionType := getAPIType(apiConfig)
	hasMCPFields := apiConfig.Transport != "" || len(apiConfig.ProtocolVersions) > 0 || len(apiConfig.Tools) > 0 ||
		apiConfig.Instructions != "" || len(apiConfig.AllowedOrigins) > 0 || apiConfig.RateLimit != nil ||
		apiConfig.MaxConcurrent != 0 || len(apiConfig.RedirectURIAllowedPrefixes) > 0 || mcpOAuthConfigured(apiConfig.OAuth)
	if definitionType != apiTypeMCP && hasMCPFields {
		return fmt.Errorf("configuration error for API %q: MCP fields are only allowed when type is %q", apiName, apiTypeMCP)
	}
	if definitionType == apiTypeMCP {
		if apiConfig.Path != "" || apiConfig.Resource != "" || apiConfig.Guard.API != "" {
			return fmt.Errorf("configuration error for MCP server %q: path, resource, and guard are not supported; endpoints and OAuth are API-name based", apiName)
		}
		if apiConfig.HTTP != nil {
			return fmt.Errorf("configuration error for MCP server %q: http settings are not allowed; use the MCP top-level path and allowedOrigins fields", apiName)
		}
		if apiConfig.Script != "" || len(apiConfig.SQL) > 0 || apiConfig.ParamCheck != "" || apiConfig.OutCheck != "" || apiConfig.Push != "" || apiConfig.ConnectURL != "" || apiConfig.Trigger.Type != "" || apiConfig.Trigger.Value != "" || len(apiConfig.Runtime.Capabilities) > 0 || len(apiConfig.Runtime.SQLFiles) > 0 || len(apiConfig.Runtime.Settings) > 0 {
			return fmt.Errorf("configuration error for MCP server %q: API execution fields are not allowed on an MCP server definition", apiName)
		}
	}
	if definitionType == apiTypeAPI && apiConfig.HTTP == nil {
		if err := validateRuntimeConfig(apiName, apiConfig.Runtime); err != nil {
			return err
		}
	}
	return nil
}

func validateConfiguredHTTPAPI(apiName string, apiConfig APIConfig) error {
	httpConfig := apiConfig.HTTP
	if httpConfig == nil {
		return nil
	}
	access := configuredHTTPAccess(apiConfig)
	switch access {
	case configuredHTTPAccessBasic, configuredHTTPAccessAnonymous, configuredHTTPAccessInternal:
	default:
		return fmt.Errorf("configuration error for API %q: unsupported http.access %q", apiName, httpConfig.Access)
	}
	responseMode := configuredHTTPResponseMode(apiConfig)
	switch responseMode {
	case configuredHTTPResponseNyan, configuredHTTPResponseRaw:
	default:
		return fmt.Errorf("configuration error for API %q: unsupported http.responseMode %q", apiName, httpConfig.ResponseMode)
	}
	if access != configuredHTTPAccessInternal {
		if err := validateConfiguredHTTPPath(httpConfig.Path); err != nil {
			return fmt.Errorf("configuration error for API %q: %w", apiName, err)
		}
	}
	if responseMode == configuredHTTPResponseRaw && strings.TrimSpace(apiConfig.Script) == "" {
		return fmt.Errorf("configuration error for API %q: raw HTTP responses require script", apiName)
	}
	if httpConfig.RateLimit != nil {
		if httpConfig.RateLimit.Requests < 1 || httpConfig.RateLimit.Requests > 10000 {
			return fmt.Errorf("configuration error for API %q: http.rateLimit.requests must be between 1 and 10000", apiName)
		}
		window, err := time.ParseDuration(httpConfig.RateLimit.Window)
		if err != nil || window < time.Second || window > 24*time.Hour {
			return fmt.Errorf("configuration error for API %q: http.rateLimit.window must be between 1s and 24h", apiName)
		}
	}
	seenRemoteIPs := make(map[string]struct{})
	for _, allowedRemoteIP := range httpConfig.AllowedRemoteIPs {
		parsedIP := net.ParseIP(allowedRemoteIP)
		if parsedIP == nil {
			return fmt.Errorf("configuration error for API %q: invalid http.allowedRemoteIPs value %q", apiName, allowedRemoteIP)
		}
		canonicalIP := parsedIP.String()
		if _, exists := seenRemoteIPs[canonicalIP]; exists {
			return fmt.Errorf("configuration error for API %q: duplicate http.allowedRemoteIPs value %q", apiName, allowedRemoteIP)
		}
		seenRemoteIPs[canonicalIP] = struct{}{}
	}
	if err := validateAllowedOrigins("API "+strconv.Quote(apiName)+" http", httpConfig.AllowedOrigins); err != nil {
		return err
	}
	seenMethods := make(map[string]struct{})
	for _, method := range httpConfig.Methods {
		if !isHTTPToken(method) {
			return fmt.Errorf("configuration error for API %q: invalid HTTP method %q", apiName, method)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("configuration error for API %q: duplicate HTTP method %q", apiName, method)
		}
		seenMethods[method] = struct{}{}
	}
	if err := validateRuntimeConfig(apiName, apiConfig.Runtime); err != nil {
		return err
	}
	return nil
}

func validateMCPServerConfig(apiName string, apiConfig APIConfig, definitions map[string]APIConfig) error {
	if _, err := canonicalAPIEndpointPath(apiName); err != nil {
		return fmt.Errorf("configuration error for MCP server %q: %w", apiName, err)
	}
	if apiConfig.Transport != "streamable_http" && apiConfig.Transport != "stdio" {
		if apiConfig.Transport == "" {
			return fmt.Errorf("configuration error for MCP server %q: transport is required", apiName)
		}
		return fmt.Errorf("configuration error for MCP server %q: unsupported transport %q", apiName, apiConfig.Transport)
	}
	if err := validateRateLimitConfig("MCP server "+strconv.Quote(apiName), apiConfig.RateLimit); err != nil {
		return err
	}
	if apiConfig.Transport == "streamable_http" && len(apiConfig.AllowedOrigins) == 0 {
		return fmt.Errorf("configuration error for MCP server %q: allowedOrigins is required", apiName)
	}
	if err := validateAllowedOrigins("MCP server "+strconv.Quote(apiName), apiConfig.AllowedOrigins); err != nil {
		return err
	}
	if apiConfig.MaxConcurrent < 0 || apiConfig.MaxConcurrent > 256 {
		return fmt.Errorf("configuration error for MCP server %q: maxConcurrent must be between 1 and 256 when specified", apiName)
	}
	protocolVersions := apiConfig.ProtocolVersions
	if len(protocolVersions) == 0 {
		protocolVersions = []string{mcpProtocolVersion20251125, mcpProtocolVersion20250618}
	}
	seenProtocolVersions := make(map[string]struct{}, len(apiConfig.ProtocolVersions))
	for _, version := range protocolVersions {
		if version == "" {
			return fmt.Errorf("configuration error for MCP server %q: protocolVersions cannot contain an empty value", apiName)
		}
		if !isImplementedMCPProtocolVersion(version) {
			return fmt.Errorf("configuration error for MCP server %q: unsupported protocolVersions entry %q", apiName, version)
		}
		if _, exists := seenProtocolVersions[version]; exists {
			return fmt.Errorf("configuration error for MCP server %q: duplicate protocolVersions entry %q", apiName, version)
		}
		seenProtocolVersions[version] = struct{}{}
	}
	if preferredMCPProtocolVersion(protocolVersions) == "" {
		return fmt.Errorf("configuration error for MCP server %q: protocolVersions contains no implemented version", apiName)
	}
	oauthEnabled := mcpOAuthConfigured(apiConfig.OAuth)
	if oauthEnabled {
		if apiConfig.Transport != "streamable_http" {
			return fmt.Errorf("configuration error for MCP server %q: oauth requires streamable_http", apiName)
		}
		if err := validateMCPOAuthConfig(apiName, apiConfig, definitions); err != nil {
			return err
		}
	}
	if len(apiConfig.Tools) == 0 {
		return fmt.Errorf("configuration error for MCP server %q: tools must contain at least one API name", apiName)
	}
	seenTools := make(map[string]struct{})
	for toolIndex, tool := range apiConfig.Tools {
		toolName := strings.TrimSpace(tool.API)
		if !isValidMCPToolName(toolName) {
			return fmt.Errorf("configuration error for MCP server %q: tools[%d] API name %q is invalid", apiName, toolIndex, toolName)
		}
		if _, exists := seenTools[toolName]; exists {
			return fmt.Errorf("configuration error for MCP server %q: duplicate tool API %q", apiName, toolName)
		}
		seenTools[toolName] = struct{}{}
		target, exists := definitions[toolName]
		if !exists || getAPIType(target) != apiTypeAPI || strings.TrimSpace(target.Script) == "" {
			return fmt.Errorf("configuration error for MCP server %q: tool references invalid backing API %q", apiName, toolName)
		}
		info, err := os.Stat(target.Script)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("configuration error for MCP server %q: tool %q script must be a regular file", apiName, toolName)
		}
		schema, err := resolveAPISchema(target)
		if err != nil {
			return fmt.Errorf("configuration error for MCP server %q: tool %q schema cannot be resolved: %w", apiName, toolName, err)
		}
		if _, err := compileJSONSchema(normalizedMCPInputSchema(schema.Input)); err != nil {
			return fmt.Errorf("configuration error for MCP server %q: tool %q input schema is invalid: %w", apiName, toolName, err)
		}
		if oauthEnabled && len(mcpRequiredScopes(target.SecuritySchemes)) == 0 && len(target.Scopes) == 0 {
			return fmt.Errorf("configuration error for MCP server %q: OAuth tool %q must define scopes", apiName, toolName)
		}
	}
	return nil
}

func canonicalAPIEndpointPath(apiName string) (string, error) {
	if apiName == "" || apiName != strings.TrimSpace(apiName) || strings.HasPrefix(apiName, "/") ||
		strings.HasSuffix(apiName, "/") || strings.Contains(apiName, "//") || strings.ContainsAny(apiName, "\\?#\r\n\t") {
		return "", fmt.Errorf("invalid API name %q for endpoint", apiName)
	}
	for _, part := range strings.Split(apiName, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid API name %q for endpoint", apiName)
		}
	}
	endpointPath := "/" + apiName
	if (&url.URL{Path: endpointPath}).EscapedPath() != endpointPath {
		return "", fmt.Errorf("API name %q is not a canonical URL path", apiName)
	}
	switch endpointPath {
	case "/", "/favicon.ico", "/nyan", "/nyan-rpc":
		return "", fmt.Errorf("endpoint path %s is reserved", endpointPath)
	}
	return endpointPath, nil
}

func mcpOAuthConfigured(oauth MCPOAuthConfig) bool {
	return oauth.AuthorizationServerMetadata != "" || oauth.ProtectedResourceMetadata != "" || oauth.Authorize != "" ||
		oauth.Token != "" || oauth.Register != "" || oauth.AdminUser != "" || oauth.VerifyAccess != ""
}

func validateMCPOAuthConfig(mcpName string, mcp APIConfig, definitions map[string]APIConfig) error {
	if len(mcp.RedirectURIAllowedPrefixes) == 0 {
		return fmt.Errorf("configuration error for MCP server %q: redirectURIAllowedPrefixes is required when oauth is configured", mcpName)
	}
	for _, prefix := range mcp.RedirectURIAllowedPrefixes {
		parsed, err := url.Parse(prefix)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.Path == "" || !strings.HasSuffix(parsed.Path, "/") || parsed.EscapedPath() != parsed.Path {
			return fmt.Errorf("configuration error for MCP server %q: invalid redirect URI prefix %q", mcpName, prefix)
		}
	}
	references := []struct {
		label    string
		name     string
		metadata bool
	}{
		{"authorizationServerMetadata", mcp.OAuth.AuthorizationServerMetadata, true},
		{"protectedResourceMetadata", mcp.OAuth.ProtectedResourceMetadata, true},
		{"authorize", mcp.OAuth.Authorize, false},
		{"token", mcp.OAuth.Token, false},
		{"register", mcp.OAuth.Register, false},
		{"verifyAccess", mcp.OAuth.VerifyAccess, false},
	}
	if mcp.OAuth.AdminUser != "" {
		references = append(references, struct {
			label, name string
			metadata    bool
		}{"adminUser", mcp.OAuth.AdminUser, false})
	}
	seen := map[string]string{}
	for _, reference := range references {
		if reference.name == "" {
			return fmt.Errorf("configuration error for MCP server %q: oauth.%s API name is required", mcpName, reference.label)
		}
		if _, err := canonicalAPIEndpointPath(reference.name); err != nil {
			return fmt.Errorf("configuration error for MCP server %q: oauth.%s: %w", mcpName, reference.label, err)
		}
		if previous, exists := seen[reference.name]; exists {
			return fmt.Errorf("configuration error for MCP server %q: oauth.%s and oauth.%s reference the same API %q", mcpName, reference.label, previous, reference.name)
		}
		seen[reference.name] = reference.label
		definition, exists := definitions[reference.name]
		if !exists || getAPIType(definition) != apiTypeAPI {
			return fmt.Errorf("configuration error for MCP server %q: oauth.%s references invalid API %q", mcpName, reference.label, reference.name)
		}
		if !reference.metadata {
			info, err := os.Stat(definition.Script)
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("configuration error for MCP server %q: oauth.%s API %q must have a regular JavaScript file", mcpName, reference.label, reference.name)
			}
		}
	}
	verify := definitions[mcp.OAuth.VerifyAccess]
	if len(verify.Scopes) == 0 {
		return fmt.Errorf("configuration error for MCP server %q: oauth.verifyAccess API %q must define scopes", mcpName, mcp.OAuth.VerifyAccess)
	}
	serverScopes := map[string]struct{}{}
	for _, scope := range verify.Scopes {
		if !isValidOAuthScopeToken(scope) {
			return fmt.Errorf("configuration error for MCP server %q: invalid OAuth scope %q", mcpName, scope)
		}
		if _, duplicate := serverScopes[scope]; duplicate {
			return fmt.Errorf("configuration error for MCP server %q: duplicate OAuth scope %q", mcpName, scope)
		}
		serverScopes[scope] = struct{}{}
	}
	for _, tool := range mcp.Tools {
		target := definitions[tool.API]
		scopes := target.Scopes
		if len(target.SecuritySchemes) > 0 {
			scopes = mcpRequiredScopes(target.SecuritySchemes)
		}
		for _, scope := range scopes {
			if _, exists := serverScopes[scope]; !exists {
				return fmt.Errorf("configuration error for MCP server %q: tool %q requires unknown OAuth scope %q", mcpName, tool.API, scope)
			}
		}
	}
	return nil
}

func validateAllowedOrigins(owner string, allowedOrigins []string) error {
	seen := make(map[string]struct{}, len(allowedOrigins))
	for _, allowedOrigin := range allowedOrigins {
		canonical, err := canonicalHTTPOrigin(allowedOrigin)
		if err != nil || canonical != allowedOrigin {
			return fmt.Errorf("configuration error for %s: invalid allowed origin %q", owner, allowedOrigin)
		}
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("configuration error for %s: duplicate allowed origin %q", owner, allowedOrigin)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func validateRuntimeConfig(apiName string, runtimeConfig APIRuntimeConfig) error {
	seen := make(map[string]struct{})
	hasSQL := false
	for _, capability := range runtimeConfig.Capabilities {
		switch capability {
		case "sql", "crypto", "password":
		default:
			return fmt.Errorf("configuration error for API %q: unsupported runtime capability %q", apiName, capability)
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("configuration error for API %q: duplicate runtime capability %q", apiName, capability)
		}
		seen[capability] = struct{}{}
		if capability == "sql" {
			hasSQL = true
		}
	}
	if hasSQL && len(runtimeConfig.SQLFiles) == 0 {
		return fmt.Errorf("configuration error for API %q: runtime.sqlFiles is required for the sql capability", apiName)
	}
	if !hasSQL && len(runtimeConfig.SQLFiles) > 0 {
		return fmt.Errorf("configuration error for API %q: runtime.sqlFiles requires the sql capability", apiName)
	}
	seenSQLFiles := make(map[string]struct{})
	for _, sqlFile := range runtimeConfig.SQLFiles {
		if strings.TrimSpace(sqlFile) == "" {
			return fmt.Errorf("configuration error for API %q: runtime.sqlFiles cannot contain an empty path", apiName)
		}
		canonicalPath, err := filepath.Abs(sqlFile)
		if err != nil {
			return fmt.Errorf("configuration error for API %q: resolve runtime.sqlFiles path %q: %w", apiName, sqlFile, err)
		}
		canonicalPath = filepath.Clean(canonicalPath)
		if _, exists := seenSQLFiles[canonicalPath]; exists {
			return fmt.Errorf("configuration error for API %q: duplicate runtime.sqlFiles path %q", apiName, sqlFile)
		}
		seenSQLFiles[canonicalPath] = struct{}{}
	}
	return nil
}

func validateRateLimitConfig(owner string, rateLimit *HTTPRateLimitConfig) error {
	if rateLimit == nil {
		return nil
	}
	if rateLimit.Requests < 1 || rateLimit.Requests > 10000 {
		return fmt.Errorf("configuration error for %s: rateLimit.requests must be between 1 and 10000", owner)
	}
	window, err := time.ParseDuration(rateLimit.Window)
	if err != nil || window < time.Second || window > 24*time.Hour {
		return fmt.Errorf("configuration error for %s: rateLimit.window must be between 1s and 24h", owner)
	}
	return nil
}

func configuredHTTPAccess(apiConfig APIConfig) string {
	if apiConfig.HTTP == nil || apiConfig.HTTP.Access == "" {
		return configuredHTTPAccessBasic
	}
	return apiConfig.HTTP.Access
}

func configuredHTTPResponseMode(apiConfig APIConfig) string {
	if apiConfig.HTTP == nil || apiConfig.HTTP.ResponseMode == "" {
		return configuredHTTPResponseNyan
	}
	return apiConfig.HTTP.ResponseMode
}

func validateConfiguredHTTPPath(routePath string) error {
	if routePath == "" || !strings.HasPrefix(routePath, "/") {
		return fmt.Errorf("HTTP path must be an absolute path")
	}
	if strings.ContainsAny(routePath, "?#\\") || path.Clean(routePath) != routePath || routePath == "/" {
		return fmt.Errorf("HTTP path %q is not canonical", routePath)
	}
	return nil
}

func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

// RFC 6749 scope-token: %x21 / %x23-5B / %x5D-7E.
// Quote, backslash, whitespace, control characters, and non-ASCII bytes are rejected.
func isValidOAuthScopeToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == 0x21 || (character >= 0x23 && character <= 0x5b) || (character >= 0x5d && character <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func isValidMCPToolName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isLoopbackHostname(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "localhost" {
		return true
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func sortedAPIConfigNames(definitions map[string]APIConfig) []string {
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type apiGraphLoader struct {
	definitions map[string]APIConfig
	sources     map[string]string
	fileStates  map[string]APIFileState
}

type apiIncludeFrame struct {
	Path     string
	Identity string
}

func expandAPIConfigGraph(rootPath string, rootData []byte) (map[string]APIConfig, map[string]string, map[string]APIFileState, error) {
	canonicalRoot, err := canonicalExistingAPIFilePath(rootPath)
	if err != nil {
		return nil, nil, nil, err
	}
	loader := &apiGraphLoader{
		definitions: make(map[string]APIConfig),
		sources:     make(map[string]string),
		fileStates:  make(map[string]APIFileState),
	}
	if err := loader.loadFile(rootPath, canonicalRoot, rootData, "", nil); err != nil {
		return loader.definitions, loader.sources, loader.fileStates, err
	}
	return loader.definitions, loader.sources, loader.fileStates, nil
}

func (loader *apiGraphLoader) loadFile(filePath, identity string, data []byte, mountPrefix string, stack []apiIncludeFrame) error {
	if cycleStart := includeFrameIndex(stack, identity); cycleStart >= 0 {
		return includeCycleError(stack, filePath)
	}
	stack = append(stack, apiIncludeFrame{Path: filePath, Identity: identity})
	loader.fileStates[identity] = APIFileState{Path: identity, Exists: true, Hash: sha256.Sum256(data)}
	rawDefinitions, err := decodeRawAPIDefinitions(data)
	if err != nil {
		return fmt.Errorf("API file %s: %w", filePath, err)
	}
	definitionTypes, mounts, err := inspectDefinitionTypes(rawDefinitions, filePath)
	if err != nil {
		return err
	}
	if err := validateMountNamespaceConflicts(rawDefinitions, definitionTypes, mounts, filePath); err != nil {
		return err
	}
	for _, name := range sortedRawDefinitionNames(rawDefinitions) {
		rawDefinition := rawDefinitions[name]
		if definitionTypes[name] != apiTypeInclude {
			fullName := joinAPIName(mountPrefix, name)
			apiConfig, err := decodeAPIConfigDefinition(fullName, rawDefinition, filepath.Dir(filePath))
			if err != nil {
				return err
			}
			if err := addExpandedAPIDefinition(loader.definitions, loader.sources, fullName, apiConfig, filePath); err != nil {
				return err
			}
			continue
		}

		include, err := decodeIncludeDefinition(name, rawDefinition)
		if err != nil {
			return fmt.Errorf("API file %s: %w", filePath, err)
		}
		resolvedPath, err := resolveIncludePath(filePath, include.Path)
		if err != nil {
			return fmt.Errorf("include %q in %s: %w", name, filePath, err)
		}
		canonicalPath, state, includeData, err := inspectAPIFile(resolvedPath)
		loader.fileStates[canonicalPath] = state
		if err != nil {
			return fmt.Errorf("include %q in %s: %w", name, filePath, err)
		}
		if cycleStart := includeFrameIndex(stack, canonicalPath); cycleStart >= 0 {
			return includeCycleError(stack, resolvedPath)
		}
		if err := loader.loadFile(resolvedPath, canonicalPath, includeData, joinAPIName(mountPrefix, name), stack); err != nil {
			return err
		}
	}
	return nil
}

func inspectDefinitionTypes(rawDefinitions map[string]json.RawMessage, filePath string) (map[string]string, map[string]struct{}, error) {
	definitionTypes := make(map[string]string, len(rawDefinitions))
	mounts := make(map[string]struct{})
	for _, name := range sortedRawDefinitionNames(rawDefinitions) {
		definitionType, err := rawAPIDefinitionType(rawDefinitions[name])
		if err != nil {
			return nil, nil, fmt.Errorf("API file %s: definition %q: %w", filePath, name, err)
		}
		definitionTypes[name] = definitionType
		if definitionType == apiTypeInclude {
			if err := validateMountName(name); err != nil {
				return nil, nil, fmt.Errorf("API file %s: %w", filePath, err)
			}
			mounts[name] = struct{}{}
		}
	}
	return definitionTypes, mounts, nil
}

func validateMountNamespaceConflicts(rawDefinitions map[string]json.RawMessage, definitionTypes map[string]string, mounts map[string]struct{}, filePath string) error {
	for _, name := range sortedRawDefinitionNames(rawDefinitions) {
		if definitionTypes[name] == apiTypeInclude {
			continue
		}
		for _, mountName := range sortedStringSet(mounts) {
			if name == mountName || strings.HasPrefix(name, mountName+"/") {
				return fmt.Errorf("API file %s: API name %q conflicts with mount namespace %q", filePath, name, mountName)
			}
		}
	}
	return nil
}

func sortedStringSet(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func sortedRawDefinitionNames(rawDefinitions map[string]json.RawMessage) []string {
	names := make([]string, 0, len(rawDefinitions))
	for name := range rawDefinitions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func joinAPIName(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func includeFrameIndex(stack []apiIncludeFrame, identity string) int {
	for index, frame := range stack {
		if frame.Identity == identity {
			return index
		}
	}
	return -1
}

func includeCycleError(stack []apiIncludeFrame, repeatedPath string) error {
	cycle := make([]string, 0, len(stack)+1)
	for _, frame := range stack {
		cycle = append(cycle, frame.Path)
	}
	cycle = append(cycle, repeatedPath)
	return fmt.Errorf("include cycle detected:\n%s", strings.Join(cycle, "\n-> "))
}

func addExpandedAPIDefinition(definitions map[string]APIConfig, sources map[string]string, fullName string, apiConfig APIConfig, sourcePath string) error {
	if previousSource, exists := sources[fullName]; exists {
		return fmt.Errorf("duplicate expanded API name %q from %s and %s", fullName, previousSource, sourcePath)
	}
	definitions[fullName] = apiConfig
	sources[fullName] = sourcePath
	return nil
}

func validateMountName(name string) error {
	if name == "" || name != strings.TrimSpace(name) || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("invalid include mount name %q", name)
	}
	return nil
}

func decodeIncludeDefinition(mountName string, rawDefinition json.RawMessage) (includeDefinition, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawDefinition, &fields); err != nil {
		return includeDefinition{}, fmt.Errorf("include %q: %w", mountName, err)
	}
	for field := range fields {
		if field != "type" && field != "path" {
			return includeDefinition{}, fmt.Errorf("include %q: unsupported field %q; only type and path are allowed", mountName, field)
		}
	}
	var include includeDefinition
	if err := json.Unmarshal(rawDefinition, &include); err != nil {
		return includeDefinition{}, fmt.Errorf("include %q: %w", mountName, err)
	}
	if strings.TrimSpace(include.Type) != apiTypeInclude {
		return includeDefinition{}, fmt.Errorf("include %q: type must be %q", mountName, apiTypeInclude)
	}
	if strings.TrimSpace(include.Path) == "" {
		return includeDefinition{}, fmt.Errorf("include %q: path is empty", mountName)
	}
	return include, nil
}

func inspectAPIFile(path string) (string, APIFileState, []byte, error) {
	normalizedPath, err := normalizeAPIFilePath(path)
	if err != nil {
		state := APIFileState{Path: path, Error: "invalid_path"}
		return path, state, nil, err
	}
	info, err := os.Stat(normalizedPath)
	if err != nil {
		state := APIFileState{Path: normalizedPath}
		if os.IsNotExist(err) {
			state.Error = "not_found"
			return normalizedPath, state, nil, fmt.Errorf("file not found: %s", normalizedPath)
		}
		state.Error = "stat_error"
		return normalizedPath, state, nil, fmt.Errorf("file cannot be accessed: %s: %w", normalizedPath, err)
	}
	if !info.Mode().IsRegular() {
		state := APIFileState{Path: normalizedPath, Exists: true, Error: "not_regular"}
		return normalizedPath, state, nil, fmt.Errorf("path is not a regular file: %s", normalizedPath)
	}
	evaluatedPath, err := filepath.EvalSymlinks(normalizedPath)
	if err != nil {
		state := APIFileState{Path: normalizedPath, Exists: true, Error: "symlink_error"}
		return normalizedPath, state, nil, fmt.Errorf("resolve symlinks for %s: %w", normalizedPath, err)
	}
	identity, err := normalizeAPIFilePath(evaluatedPath)
	if err != nil {
		state := APIFileState{Path: normalizedPath, Exists: true, Error: "invalid_path"}
		return normalizedPath, state, nil, err
	}
	data, err := os.ReadFile(normalizedPath)
	if err != nil {
		state := APIFileState{Path: identity, Exists: true, Error: "read_error"}
		return identity, state, nil, fmt.Errorf("file cannot be read: %s: %w", normalizedPath, err)
	}
	state := APIFileState{Path: identity, Exists: true, Hash: sha256.Sum256(data)}
	return identity, state, data, nil
}

func canonicalExistingAPIFilePath(path string) (string, error) {
	normalizedPath, err := normalizeAPIFilePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(normalizedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file not found: %s", normalizedPath)
		}
		return "", fmt.Errorf("file cannot be accessed: %s: %w", normalizedPath, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path is not a regular file: %s", normalizedPath)
	}
	evaluatedPath, err := filepath.EvalSymlinks(normalizedPath)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks for %s: %w", normalizedPath, err)
	}
	return normalizeAPIFilePath(evaluatedPath)
}

func resolveIncludePath(parentAPIPath, includePath string) (string, error) {
	resolvedPath := includePath
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(filepath.Dir(parentAPIPath), resolvedPath)
	}
	return normalizeAPIFilePath(resolvedPath)
}

func validateNoDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, "$"); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected token after top-level value: %v", token)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %s is not a string", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, path+"["+strconv.Quote(key)+"]"); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("object at %s is not closed", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := consumeJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("array at %s is not closed", path)
		}
	default:
		return fmt.Errorf("unexpected delimiter %q at %s", delimiter, path)
	}
	return nil
}

func cloneAPIConfig(apiConfig APIConfig) APIConfig {
	cloned := apiConfig
	cloned.SQL = append([]string(nil), apiConfig.SQL...)
	if apiConfig.RateLimit != nil {
		rateLimit := *apiConfig.RateLimit
		cloned.RateLimit = &rateLimit
	}
	cloned.ProtocolVersions = append([]string(nil), apiConfig.ProtocolVersions...)
	cloned.AllowedOrigins = append([]string(nil), apiConfig.AllowedOrigins...)
	cloned.RedirectURIAllowedPrefixes = append([]string(nil), apiConfig.RedirectURIAllowedPrefixes...)
	cloned.Scopes = append([]string(nil), apiConfig.Scopes...)
	cloned.SecuritySchemes = make([]MCPSecurityScheme, len(apiConfig.SecuritySchemes))
	for index, scheme := range apiConfig.SecuritySchemes {
		cloned.SecuritySchemes[index] = scheme
		cloned.SecuritySchemes[index].Scopes = append([]string(nil), scheme.Scopes...)
	}
	cloned.Annotations.ReadOnlyHint = cloneBoolPointer(apiConfig.Annotations.ReadOnlyHint)
	cloned.Annotations.DestructiveHint = cloneBoolPointer(apiConfig.Annotations.DestructiveHint)
	cloned.Annotations.OpenWorldHint = cloneBoolPointer(apiConfig.Annotations.OpenWorldHint)
	cloned.Runtime.Capabilities = append([]string(nil), apiConfig.Runtime.Capabilities...)
	cloned.Runtime.SQLFiles = append([]string(nil), apiConfig.Runtime.SQLFiles...)
	if apiConfig.Runtime.Settings != nil {
		cloned.Runtime.Settings = cloneJSONCompatibleValue(apiConfig.Runtime.Settings).(map[string]interface{})
	}
	if apiConfig.HTTP != nil {
		httpConfig := *apiConfig.HTTP
		httpConfig.Methods = append([]string(nil), apiConfig.HTTP.Methods...)
		httpConfig.AllowedRemoteIPs = append([]string(nil), apiConfig.HTTP.AllowedRemoteIPs...)
		httpConfig.AllowedOrigins = append([]string(nil), apiConfig.HTTP.AllowedOrigins...)
		if apiConfig.HTTP.RateLimit != nil {
			rateLimit := *apiConfig.HTTP.RateLimit
			httpConfig.RateLimit = &rateLimit
		}
		cloned.HTTP = &httpConfig
	}
	cloned.Tools = make([]MCPToolConfig, len(apiConfig.Tools))
	for toolIndex, tool := range apiConfig.Tools {
		clonedTool := tool
		clonedTool.Annotations.ReadOnlyHint = cloneBoolPointer(tool.Annotations.ReadOnlyHint)
		clonedTool.Annotations.DestructiveHint = cloneBoolPointer(tool.Annotations.DestructiveHint)
		clonedTool.Annotations.OpenWorldHint = cloneBoolPointer(tool.Annotations.OpenWorldHint)
		clonedTool.SecuritySchemes = make([]MCPSecurityScheme, len(tool.SecuritySchemes))
		for schemeIndex, scheme := range tool.SecuritySchemes {
			clonedScheme := scheme
			clonedScheme.Scopes = append([]string(nil), scheme.Scopes...)
			clonedTool.SecuritySchemes[schemeIndex] = clonedScheme
		}
		cloned.Tools[toolIndex] = clonedTool
	}
	return cloned
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneJSONCompatibleValue(value interface{}) interface{} {
	switch value := value.(type) {
	case map[string]interface{}:
		cloned := make(map[string]interface{}, len(value))
		for key, item := range value {
			cloned[key] = cloneJSONCompatibleValue(item)
		}
		return cloned
	case []interface{}:
		cloned := make([]interface{}, len(value))
		for index, item := range value {
			cloned[index] = cloneJSONCompatibleValue(item)
		}
		return cloned
	case []string:
		cloned := make([]interface{}, len(value))
		for index, item := range value {
			cloned[index] = item
		}
		return cloned
	default:
		return value
	}
}

func newAPIConfigSnapshot(files map[string]APIConfig, sourcePath string, sourceHash [sha256.Size]byte) *APIConfigSnapshot {
	sources := make(map[string]string)
	for name := range files {
		if sourcePath != "" {
			sources[name] = sourcePath
		}
	}

	fileStates := make(map[string]APIFileState)
	if sourcePath != "" {
		fileStates[sourcePath] = APIFileState{
			Path:   sourcePath,
			Exists: true,
			Hash:   sourceHash,
		}
	}

	return newAPIConfigSnapshotFromParts(files, sources, fileStates)
}

func newAPIConfigSnapshotFromParts(files map[string]APIConfig, sources map[string]string, fileStates map[string]APIFileState) *APIConfigSnapshot {
	return newLoadedAPIConfigSnapshot(files, sources, fileStates, nil, nil)
}

func newLoadedAPIConfigSnapshot(files map[string]APIConfig, sources map[string]string, fileStates map[string]APIFileState, schedules map[string]scheduleJobConfig, wsClients map[string]wsClientConfig) *APIConfigSnapshot {
	definitions := make(map[string]APIConfig, len(files))
	apis := make(map[string]APIDetails)
	for name, apiConfig := range files {
		cloned := cloneAPIConfig(apiConfig)
		definitions[name] = cloned
		if getAPIType(cloned) == apiTypeAPI && cloned.HTTP == nil {
			apis[name] = APIDetails{Description: cloned.Description}
		}
	}
	clonedSources := make(map[string]string, len(sources))
	for name, sourcePath := range sources {
		clonedSources[name] = sourcePath
	}
	clonedFileStates := make(map[string]APIFileState, len(fileStates))
	for path, state := range fileStates {
		clonedFileStates[path] = state
	}
	clonedSchedules := make(map[string]scheduleJobConfig, len(schedules))
	for name, schedule := range schedules {
		clonedSchedules[name] = cloneScheduleJobConfig(schedule)
	}
	clonedWSClients := make(map[string]wsClientConfig, len(wsClients))
	for name, wsClient := range wsClients {
		clonedWSClients[name] = wsClient
	}
	return &APIConfigSnapshot{
		Definitions: definitions,
		APIs:        apis,
		Sources:     clonedSources,
		Files:       clonedFileStates,
		Schedules:   clonedSchedules,
		WSClients:   clonedWSClients,
	}
}

func cloneScheduleJobConfig(config scheduleJobConfig) scheduleJobConfig {
	cloned := config
	cloned.runtime.Capabilities = append([]string(nil), config.runtime.Capabilities...)
	cloned.runtime.SQLFiles = append([]string(nil), config.runtime.SQLFiles...)
	if config.runtime.Settings != nil {
		cloned.runtime.Settings = cloneJSONCompatibleValue(config.runtime.Settings).(map[string]interface{})
	}
	cloned.schedule.minutes = cloneCronField(config.schedule.minutes)
	cloned.schedule.hours = cloneCronField(config.schedule.hours)
	cloned.schedule.days = cloneCronField(config.schedule.days)
	cloned.schedule.months = cloneCronField(config.schedule.months)
	cloned.schedule.weekdays = cloneCronField(config.schedule.weekdays)
	return cloned
}

func cloneCronField(field cronField) cronField {
	cloned := make(cronField, len(field))
	for value, included := range field {
		cloned[value] = included
	}
	return cloned
}

func currentAPISnapshot() *APIConfigSnapshot {
	if snapshot := apiSnapshot.Load(); snapshot != nil {
		return snapshot
	}
	return &APIConfigSnapshot{
		Definitions: map[string]APIConfig{},
		APIs:        map[string]APIDetails{},
		Sources:     map[string]string{},
		Files:       map[string]APIFileState{},
		Schedules:   map[string]scheduleJobConfig{},
		WSClients:   map[string]wsClientConfig{},
	}
}

func setAPISnapshot(snapshot *APIConfigSnapshot) {
	if snapshot == nil {
		snapshot = newAPIConfigSnapshot(nil, "", [sha256.Size]byte{})
	}
	apiSnapshot.Store(snapshot)
}

// currentSQLFiles and setSQLFiles remain as compatibility helpers while the
// rest of the codebase migrates to snapshots.
func currentSQLFiles() map[string]APIConfig {
	return currentAPISnapshot().Definitions
}

func setSQLFiles(files map[string]APIConfig) {
	setAPISnapshot(newAPIConfigSnapshot(files, "", [sha256.Size]byte{}))
}

func cloneAPIFileStates(states map[string]APIFileState) map[string]APIFileState {
	cloned := make(map[string]APIFileState, len(states))
	for identity, state := range states {
		cloned[identity] = state
	}
	return cloned
}

func observeAPIFileStates(files map[string]APIFileState) (map[string]APIFileState, error) {
	observed := make(map[string]APIFileState, len(files))
	for identity, expected := range files {
		path := expected.Path
		if path == "" {
			path = identity
		}
		_, state, _, _ := inspectAPIFile(path)
		observed[identity] = state
	}
	return observed, nil
}

func mergeAPIFileStates(stateSets ...map[string]APIFileState) map[string]APIFileState {
	merged := make(map[string]APIFileState)
	for _, states := range stateSets {
		for identity, state := range states {
			merged[identity] = state
		}
	}
	return merged
}

func apiFileStatesFingerprint(states map[string]APIFileState) [sha256.Size]byte {
	identities := make([]string, 0, len(states))
	for identity := range states {
		identities = append(identities, identity)
	}
	sort.Strings(identities)

	hasher := sha256.New()
	for _, identity := range identities {
		state := states[identity]
		_, _ = io.WriteString(hasher, identity)
		_, _ = hasher.Write([]byte{0})
		_, _ = io.WriteString(hasher, state.Path)
		_, _ = hasher.Write([]byte{0})
		if state.Exists {
			_, _ = hasher.Write([]byte{1})
		} else {
			_, _ = hasher.Write([]byte{0})
		}
		_, _ = hasher.Write(state.Hash[:])
		_, _ = io.WriteString(hasher, state.Error)
		_, _ = hasher.Write([]byte{0})
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hasher.Sum(nil))
	return fingerprint
}

func verifyAPIFileStates(expected map[string]APIFileState) error {
	observed, err := observeAPIFileStates(expected)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(observed, expected) {
		return fmt.Errorf("API files changed while the configuration was being loaded")
	}
	return nil
}

func sameAPIConfigSnapshot(left, right *APIConfigSnapshot) bool {
	return reflect.DeepEqual(left.Definitions, right.Definitions) &&
		reflect.DeepEqual(left.APIs, right.APIs) &&
		reflect.DeepEqual(left.Sources, right.Sources) &&
		reflect.DeepEqual(left.Files, right.Files) &&
		reflect.DeepEqual(left.Schedules, right.Schedules) &&
		reflect.DeepEqual(left.WSClients, right.WSClients)
}

func loadAndPublishAPIConfig(apiFilePath string) (*apiConfigLoadResult, bool, error) {
	loadResult, _, reloaded, err := loadAndPublishAPIConfigAttempt(apiFilePath)
	return loadResult, reloaded, err
}

func loadAndPublishAPIConfigAttempt(apiFilePath string) (*apiConfigLoadResult, map[string]APIFileState, bool, error) {
	loadResult, discoveredFiles, err := loadAPIConfigFileAttempt(apiFilePath)
	if err != nil {
		return nil, discoveredFiles, false, err
	}
	if err := validateConfiguredServerTransportSecurity(loadResult.Snapshot, config); err != nil {
		return nil, discoveredFiles, false, err
	}
	if err := verifyAPIFileStates(loadResult.Snapshot.Files); err != nil {
		return nil, discoveredFiles, false, err
	}
	if sameAPIConfigSnapshot(currentAPISnapshot(), loadResult.Snapshot) {
		return loadResult, discoveredFiles, false, nil
	}

	setAPISnapshot(loadResult.Snapshot)
	if backgroundRuntimes != nil {
		backgroundRuntimes.reconcile(loadResult.Snapshot.Schedules, loadResult.Snapshot.WSClients)
	}
	return loadResult, discoveredFiles, true, nil
}

func validateConfiguredServerTransportSecurity(snapshot *APIConfigSnapshot, serverConfig Config) error {
	return nil
}

func reloadAPIConfigGraphIfChanged(apiFilePath string, lastObserved map[string]APIFileState) (map[string]APIFileState, bool, error) {
	observed, err := observeAPIFileStates(lastObserved)
	if err != nil {
		return cloneAPIFileStates(lastObserved), false, err
	}
	if reflect.DeepEqual(observed, lastObserved) {
		return observed, false, nil
	}

	loadResult, discoveredFiles, reloaded, err := loadAndPublishAPIConfigAttempt(apiFilePath)
	if err != nil {
		watched := mergeAPIFileStates(currentAPISnapshot().Files, discoveredFiles)
		observedWatched, observeErr := observeAPIFileStates(watched)
		if observeErr != nil {
			return cloneAPIFileStates(lastObserved), false, observeErr
		}
		return observedWatched, false, err
	}
	return cloneAPIFileStates(loadResult.Snapshot.Files), reloaded, nil
}

func reloadSQLFilesIfChanged(apiFilePath, _ string, lastObservedHash [sha256.Size]byte) ([sha256.Size]byte, bool, error) {
	normalizedPath, err := normalizeAPIFilePath(apiFilePath)
	if err != nil {
		return lastObservedHash, false, err
	}
	data, err := os.ReadFile(normalizedPath)
	if err != nil {
		return lastObservedHash, false, fmt.Errorf("read api file %s: %w", normalizedPath, err)
	}
	observedHash := sha256.Sum256(data)
	if observedHash == lastObservedHash {
		return lastObservedHash, false, nil
	}

	_, reloaded, err := loadAndPublishAPIConfig(normalizedPath)
	return observedHash, reloaded, err
}

func watchAPIFile(apiFilePath string, interval time.Duration, initialFiles map[string]APIFileState) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastObservedFiles := cloneAPIFileStates(initialFiles)
	lastReloadError := ""
	for range ticker.C {
		observedFiles, reloaded, err := reloadAPIConfigGraphIfChanged(apiFilePath, lastObservedFiles)
		lastObservedFiles = observedFiles
		if err != nil {
			errorKey := fmt.Sprintf("%x:%s", apiFileStatesFingerprint(observedFiles), err.Error())
			if errorKey != lastReloadError {
				log.Printf("API hot reload failed: %v; current API configuration remains active", err)
			}
			lastReloadError = errorKey
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
	return runOutCheckScriptWithSnapshot(currentAPISnapshot(), apiConfig, params, statusCode, contentType, body)
}

func runOutCheckScriptWithSnapshot(snapshot *APIConfigSnapshot, apiConfig APIConfig, params map[string]interface{}, statusCode int, contentType string, body []byte) (bool, int, string, error) {
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

	success, checkStatusCode, _, jsonStr, err := runCheckScriptWithSnapshot(snapshot, outCheckPath, checkParams, nil)
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
		log.Printf("Received JSON request: keys=%d", len(data))
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
	handlePublicRequestWithSnapshot(currentAPISnapshot(), w, r, apiKey, requestedPath, apiConfig)
}

func handlePublicRequestWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request, apiKey string, requestedPath string, apiConfig APIConfig) {
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
		success, statusCode, errorObj, jsonStr, err := runCheckScriptWithSnapshot(snapshot, checkScriptPath, params, nil)
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
	if handled, outStatusCode, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, contentType, fileContent); handled {
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
	runtime     APIRuntimeConfig
}

type backgroundRuntimeManager struct {
	mu        sync.Mutex
	schedules map[string]*scheduleRuntime
	wsClients map[string]*wsClientRuntime
}

type scheduleRuntime struct {
	mu      sync.Mutex
	desired *scheduleJobConfig
	wake    chan struct{}
	done    chan struct{}
	stopped bool
}

type wsClientRuntime struct {
	mu         sync.Mutex
	desired    *wsClientConfig
	wake       chan struct{}
	done       chan struct{}
	stopped    bool
	conn       *websocket.Conn
	dialCancel context.CancelFunc
}

func newBackgroundRuntimeManager() *backgroundRuntimeManager {
	return &backgroundRuntimeManager{
		schedules: make(map[string]*scheduleRuntime),
		wsClients: make(map[string]*wsClientRuntime),
	}
}

func (manager *backgroundRuntimeManager) reconcile(schedules map[string]scheduleJobConfig, wsClients map[string]wsClientConfig) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for name, runtime := range manager.schedules {
		if _, exists := schedules[name]; exists {
			continue
		}
		if _, changed := runtime.update(nil); changed {
			log.Printf("Stopping schedule job %s", name)
		}
	}
	for name, cfg := range schedules {
		if runtime, exists := manager.schedules[name]; exists {
			accepted, changed := runtime.update(&cfg)
			if accepted {
				if changed {
					log.Printf("Updated schedule job %s with cron %q", name, cfg.trigger.Value)
				}
				continue
			}
		}
		runtime := newScheduleRuntime(cfg)
		manager.schedules[name] = runtime
		log.Printf("Starting schedule job %s with cron %q", name, cfg.trigger.Value)
		go manager.runSchedule(name, runtime)
	}

	for name, runtime := range manager.wsClients {
		if _, exists := wsClients[name]; exists {
			continue
		}
		if _, changed, _ := runtime.update(nil); changed {
			log.Printf("Stopping WebSocket client %s", name)
		}
	}
	for name, cfg := range wsClients {
		if runtime, exists := manager.wsClients[name]; exists {
			accepted, changed, reconnect := runtime.update(&cfg)
			if accepted {
				if changed {
					log.Printf("Updated WebSocket client %s reconnect=%t", name, reconnect)
				}
				continue
			}
		}
		runtime := newWSClientRuntime(cfg)
		manager.wsClients[name] = runtime
		log.Printf("Starting WebSocket client %s -> %s", name, cfg.connectURL)
		go manager.runWSClient(name, runtime)
	}
}

func (manager *backgroundRuntimeManager) runSchedule(name string, runtime *scheduleRuntime) {
	runtime.run()
	manager.mu.Lock()
	if manager.schedules[name] == runtime {
		delete(manager.schedules, name)
	}
	manager.mu.Unlock()
}

func (manager *backgroundRuntimeManager) runWSClient(name string, runtime *wsClientRuntime) {
	runtime.run()
	manager.mu.Lock()
	if manager.wsClients[name] == runtime {
		delete(manager.wsClients, name)
	}
	manager.mu.Unlock()
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

func buildScheduleJobConfigs(files map[string]APIConfig, execDir string) (map[string]scheduleJobConfig, error) {
	configs := make(map[string]scheduleJobConfig)
	var firstErr error
	for name, apiConfig := range files {
		if getAPIType(apiConfig) != apiTypeSchedule {
			continue
		}

		scriptPath := strings.TrimSpace(apiConfig.Script)
		triggerType := strings.TrimSpace(apiConfig.Trigger.Type)
		triggerValue := strings.TrimSpace(apiConfig.Trigger.Value)

		if scriptPath == "" {
			err := fmt.Errorf("schedule %s: script is missing", name)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if triggerType != "cron" {
			err := fmt.Errorf("schedule %s: unsupported trigger type %q", name, triggerType)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		schedule, err := parseCronSchedule(triggerValue)
		if err != nil {
			err = fmt.Errorf("schedule %s: invalid cron trigger %q: %w", name, triggerValue, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(apiConfig.Runtime.Capabilities) > 0 || len(apiConfig.Runtime.SQLFiles) > 0 || len(apiConfig.Runtime.Settings) > 0 {
			if err := validateRuntimeConfig(name, apiConfig.Runtime); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}

		scriptAbs := scriptPath
		if !filepath.IsAbs(scriptPath) {
			scriptAbs = filepath.Join(execDir, scriptPath)
		}

		configs[name] = scheduleJobConfig{
			name:        name,
			scriptPath:  scriptAbs,
			trigger:     apiConfig.Trigger,
			description: apiConfig.Description,
			schedule:    schedule,
			runtime:     apiConfig.Runtime,
		}
	}

	return configs, firstErr
}

func newScheduleRuntime(cfg scheduleJobConfig) *scheduleRuntime {
	copyOfConfig := cfg
	return &scheduleRuntime{
		desired: &copyOfConfig,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
}

func sameScheduleJobConfig(a, b scheduleJobConfig) bool {
	return a.name == b.name &&
		a.scriptPath == b.scriptPath &&
		a.trigger == b.trigger &&
		reflect.DeepEqual(a.runtime, b.runtime)
}

func signalRuntime(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (runtime *scheduleRuntime) update(cfg *scheduleJobConfig) (bool, bool) {
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		return false, false
	}
	if cfg == nil {
		if runtime.desired == nil {
			runtime.mu.Unlock()
			return true, false
		}
		runtime.desired = nil
		runtime.mu.Unlock()
		signalRuntime(runtime.wake)
		return true, true
	}
	if runtime.desired != nil && sameScheduleJobConfig(*runtime.desired, *cfg) {
		runtime.mu.Unlock()
		return true, false
	}
	copyOfConfig := *cfg
	runtime.desired = &copyOfConfig
	runtime.mu.Unlock()
	signalRuntime(runtime.wake)
	return true, true
}

func (runtime *scheduleRuntime) currentConfigOrStop() (scheduleJobConfig, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.desired == nil {
		runtime.stopped = true
		return scheduleJobConfig{}, false
	}
	return *runtime.desired, true
}

func (runtime *scheduleRuntime) currentConfig() (scheduleJobConfig, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.desired == nil {
		return scheduleJobConfig{}, false
	}
	return *runtime.desired, true
}

func (runtime *scheduleRuntime) run() {
	defer close(runtime.done)
	for {
		cfg, active := runtime.currentConfigOrStop()
		if !active {
			return
		}
		next := cfg.schedule.next(time.Now())
		if next.IsZero() {
			log.Printf("Schedule job %s has no next run time", cfg.name)
			<-runtime.wake
			continue
		}

		log.Printf("Schedule job %s next run at %s", cfg.name, next.Format(time.RFC3339))
		timer := time.NewTimer(time.Until(next))
		select {
		case <-runtime.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		case <-timer.C:
		}

		latest, active := runtime.currentConfig()
		if !active || !sameScheduleJobConfig(cfg, latest) {
			continue
		}

		params := map[string]interface{}{
			"nyan_job_name":              latest.name,
			"nyan_schedule_trigger_type": latest.trigger.Type,
			"nyan_schedule_trigger":      latest.trigger.Value,
			"nyan_schedule_time":         next.Format(time.RFC3339),
		}
		var result string
		var err error
		if len(latest.runtime.Capabilities) > 0 || len(latest.runtime.SQLFiles) > 0 || len(latest.runtime.Settings) > 0 {
			result, err = runScriptWithRuntimeWithSnapshot(currentAPISnapshot(), []string{latest.scriptPath}, params, latest.runtime, true)
		} else {
			result, err = runScript([]string{latest.scriptPath}, params)
		}
		if err != nil {
			log.Printf("Schedule job %s failed: %v", latest.name, err)
			continue
		}
		log.Printf("Schedule job %s completed: %s", latest.name, result)
	}
}

func buildWSClientConfigs(files map[string]APIConfig, execDir string) (map[string]wsClientConfig, error) {
	configs := make(map[string]wsClientConfig)
	var firstErr error
	for name, apiConfig := range files {
		if getAPIType(apiConfig) != apiTypeWSClient {
			continue
		}

		scriptPath := strings.TrimSpace(apiConfig.Script)
		connectURLRaw := strings.TrimSpace(apiConfig.ConnectURL)

		if scriptPath == "" {
			err := fmt.Errorf("ws_client %s: script is missing", name)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if connectURLRaw == "" {
			err := fmt.Errorf("ws_client %s: connectURL is missing", name)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		connectURL, err := resolveConnectURL(connectURLRaw)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ws_client %s: %w", name, err)
			}
			continue
		}

		scriptAbs := scriptPath
		if !filepath.IsAbs(scriptPath) {
			scriptAbs = filepath.Join(execDir, scriptPath)
		}

		configs[name] = wsClientConfig{
			name:        name,
			scriptPath:  scriptAbs,
			connectURL:  connectURL,
			description: apiConfig.Description,
		}
	}

	return configs, firstErr
}

func newWSClientRuntime(cfg wsClientConfig) *wsClientRuntime {
	copyOfConfig := cfg
	return &wsClientRuntime{
		desired: &copyOfConfig,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
}

func sameWSClientConfig(a, b wsClientConfig) bool {
	return a == b
}

func (runtime *wsClientRuntime) update(cfg *wsClientConfig) (bool, bool, bool) {
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		return false, false, false
	}
	if cfg == nil {
		if runtime.desired == nil {
			runtime.mu.Unlock()
			return true, false, false
		}
		runtime.desired = nil
		conn := runtime.conn
		cancel := runtime.dialCancel
		runtime.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		signalRuntime(runtime.wake)
		return true, true, false
	}
	if runtime.desired != nil && sameWSClientConfig(*runtime.desired, *cfg) {
		runtime.mu.Unlock()
		return true, false, false
	}
	reconnect := runtime.desired == nil || runtime.desired.connectURL != cfg.connectURL
	copyOfConfig := *cfg
	runtime.desired = &copyOfConfig
	conn := runtime.conn
	cancel := runtime.dialCancel
	runtime.mu.Unlock()
	if reconnect {
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		signalRuntime(runtime.wake)
	}
	return true, true, reconnect
}

func (runtime *wsClientRuntime) currentConfigOrStop() (wsClientConfig, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.desired == nil {
		runtime.stopped = true
		return wsClientConfig{}, false
	}
	return *runtime.desired, true
}

func (runtime *wsClientRuntime) currentConfig() (wsClientConfig, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.desired == nil {
		return wsClientConfig{}, false
	}
	return *runtime.desired, true
}

func (runtime *wsClientRuntime) beginDial(cfg wsClientConfig) (context.Context, context.CancelFunc, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stopped || runtime.desired == nil || runtime.desired.connectURL != cfg.connectURL {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime.dialCancel = cancel
	return ctx, cancel, true
}

func (runtime *wsClientRuntime) finishDial(cancel context.CancelFunc) {
	runtime.mu.Lock()
	runtime.dialCancel = nil
	runtime.mu.Unlock()
	cancel()
}

func (runtime *wsClientRuntime) acceptConnection(conn *websocket.Conn, connectURL string) bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stopped || runtime.desired == nil || runtime.desired.connectURL != connectURL {
		return false
	}
	runtime.conn = conn
	return true
}

func (runtime *wsClientRuntime) clearConnection(conn *websocket.Conn) {
	runtime.mu.Lock()
	if runtime.conn == conn {
		runtime.conn = nil
	}
	runtime.mu.Unlock()
}

// 常時接続を維持し、設定変更や削除に応じて接続を更新する。
func (runtime *wsClientRuntime) run() {
	defer close(runtime.done)
	backoff := time.Second
	for {
		cfg, active := runtime.currentConfigOrStop()
		if !active {
			return
		}

		err := runtime.connectAndListen(cfg)
		latest, active := runtime.currentConfigOrStop()
		if !active {
			return
		}
		if latest.connectURL != cfg.connectURL {
			select {
			case <-runtime.wake:
			default:
			}
			backoff = time.Second
			continue
		}
		if err != nil {
			log.Printf("WebSocket client %s disconnected: %v", cfg.name, err)
		}

		timer := time.NewTimer(backoff)
		select {
		case <-runtime.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			backoff = time.Second
		case <-timer.C:
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}
}

func (runtime *wsClientRuntime) connectAndListen(cfg wsClientConfig) error {
	ctx, cancel, ok := runtime.beginDial(cfg)
	if !ok {
		return nil
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, cfg.connectURL, nil)
	runtime.finishDial(cancel)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	if !runtime.acceptConnection(conn, cfg.connectURL) {
		_ = conn.Close()
		return nil
	}
	defer runtime.clearConnection(conn)
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

		latest, active := runtime.currentConfig()
		if !active || latest.connectURL != cfg.connectURL {
			return nil
		}

		allParams := map[string]interface{}{
			"api":             latest.name,
			"ws_client":       latest.name,
			"ws_message_type": websocketMessageTypeLabel(msgType),
			"ws_message_text": string(data),
			"ws_connect_url":  latest.connectURL,
			"ws_description":  latest.description,
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

		result, err := runScript([]string{latest.scriptPath}, allParams)
		if err != nil {
			log.Printf("ws_client %s script error: %v", latest.name, err)
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
	handleRequestWithSnapshot(currentAPISnapshot(), w, r)
}

func handleRequestWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request) {
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
	apiConfig, exists := snapshot.Definitions[apiKey]
	if !exists {
		sendJSONError(w, "SQL files not found", http.StatusNotFound)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		sendJSONError(w, fmt.Sprintf("API %s is not an HTTP/WebSocket endpoint", apiKey), http.StatusBadRequest)
		return
	}
	if apiConfig.HTTP != nil {
		if dispatched, _ := r.Context().Value(configuredAPIDispatchContextKey{}).(bool); !dispatched {
			sendJSONError(w, "API not found", http.StatusNotFound)
			return
		}
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
		success, statusCode, errorObj, jsonStr, err := runCheckScriptWithSnapshot(snapshot, checkScriptPath, params, acceptedKeys)
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
			performPush(snapshot, apiConfig, params)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			performPush(snapshot, apiConfig, params)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(jsonStr))
			return
		}
	}

	if apiConfig.Script != "" {
		scriptResult, err := runScriptWithSnapshot(snapshot, []string{apiConfig.Script}, params)
		if err != nil {
			log.Printf("Script execution error: %v", err)
			sendJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := []byte(scriptResult)
		if handled, outStatusCode, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, "application/json", body); handled {
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
		performPush(snapshot, apiConfig, params)
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
	if handled, outStatusCode, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, "application/json", body); handled {
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
	performPush(snapshot, apiConfig, params)
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

	estimatedJSONBytes := 2
	for rows.Next() {
		if len(results) >= maxSQLJSONRows {
			return nil, fmt.Errorf("SQL result exceeds the maximum row count of %d", maxSQLJSONRows)
		}
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
				if len(v) > maxSQLJSONBytes-estimatedJSONBytes {
					return nil, fmt.Errorf("SQL result exceeds the maximum JSON size of %d bytes", maxSQLJSONBytes)
				}
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
			case string:
				if len(v) > maxSQLJSONBytes-estimatedJSONBytes {
					return nil, fmt.Errorf("SQL result exceeds the maximum JSON size of %d bytes", maxSQLJSONBytes)
				}
				entry[col] = v
			default:
				entry[col] = v
			}
		}
		rowJSON, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		estimatedJSONBytes += len(rowJSON)
		if len(results) > 0 {
			estimatedJSONBytes++
		}
		if estimatedJSONBytes > maxSQLJSONBytes {
			return nil, fmt.Errorf("SQL result exceeds the maximum JSON size of %d bytes", maxSQLJSONBytes)
		}
		results = append(results, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxSQLJSONBytes {
		return nil, fmt.Errorf("SQL result exceeds the maximum JSON size of %d bytes", maxSQLJSONBytes)
	}
	return encoded, nil
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
	handleNyanWithSnapshot(currentAPISnapshot(), w, r)
}

func handleNyanWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request) {
	response := NyanResponse{
		Name:    config.Name,
		Profile: config.Profile,
		Version: config.Version,
		Apis:    snapshot.APIs,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleNyanOrDetail(w http.ResponseWriter, r *http.Request) {
	snapshot := currentAPISnapshot()
	subPath := strings.TrimPrefix(r.URL.Path, "/nyan")
	if subPath == "" || subPath == "/" {
		handleNyanWithSnapshot(snapshot, w, r)
	} else {
		handleNyanDetailWithSnapshot(snapshot, w, r)
	}
}

func handleNyanDetail(w http.ResponseWriter, r *http.Request) {
	handleNyanDetailWithSnapshot(currentAPISnapshot(), w, r)
}

func handleNyanDetailWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request) {
	type detailSchemaSource struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	}
	type detailResponse struct {
		API                string                 `json:"api"`
		Description        string                 `json:"description"`
		NyanAcceptedParams map[string]interface{} `json:"nyanAcceptedParams,omitempty"`
		InputSchema        map[string]interface{} `json:"inputSchema"`
		OutputSchema       map[string]interface{} `json:"outputSchema"`
		SchemaSource       detailSchemaSource     `json:"schemaSource"`
	}
	apiName := strings.TrimPrefix(r.URL.Path, "/nyan/")
	if apiName == "" {
		sendJSONError(w, "API name is required", http.StatusBadRequest)
		return
	}
	apiConfig, exists := snapshot.Definitions[apiName]
	if !exists {
		sendJSONError(w, "API not found", http.StatusNotFound)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		sendJSONError(w, "API not found", http.StatusNotFound)
		return
	}
	if apiConfig.HTTP != nil {
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
	if apiConfig.Script != "" {
		acceptedParamsFromScript, err = parseScriptAcceptedParams(apiConfig.Script)
		if err != nil {
			log.Printf("Failed to parse script constants: %v", err)
		} else {
			for k, v := range acceptedParamsFromScript {
				paramsMap[k] = v
			}
		}
	}
	apiSchema, err := resolveAPISchema(apiConfig)
	if err != nil {
		log.Printf("Failed to resolve API schemas for %s: %v", apiName, err)
		sendJSONError(w, err, http.StatusInternalServerError)
		return
	}
	var visibleAcceptedParams map[string]interface{}
	if apiSchema.InputSource != schemaSourceParamCheck && len(paramsMap) > 0 {
		visibleAcceptedParams = paramsMap
	}
	resp := detailResponse{
		API:                apiName,
		Description:        apiConfig.Description,
		NyanAcceptedParams: visibleAcceptedParams,
		InputSchema:        apiSchema.Input,
		OutputSchema:       apiSchema.Output,
		SchemaSource: detailSchemaSource{
			Input:  normalizeSchemaSource(apiSchema.InputSource),
			Output: normalizeSchemaSource(apiSchema.OutputSource),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
	}
}

func normalizeSchemaSource(source string) string {
	switch source {
	case schemaSourceParamCheck, schemaSourceOutCheck, schemaSourceSQL, schemaSourceScriptLegacy:
		return source
	default:
		return schemaSourceUnknown
	}
}

type sqlInputParameterInference struct {
	shape      string
	valueType  string
	examples   []interface{}
	required   bool
	conflicted bool
}

type sqlSchemaBlockKind int

const (
	sqlSchemaBlockBegin sqlSchemaBlockKind = iota
	sqlSchemaBlockIf
)

func generateSQLInputSchema(filePaths []string) (map[string]interface{}, error) {
	sources := make([]string, 0, len(filePaths))
	for _, filePath := range filePaths {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read SQL file %s for input schema: %w", filePath, err)
		}
		sources = append(sources, string(data))
	}
	return generateSQLInputSchemaFromSources(sources), nil
}

func generateSQLInputSchemaFromSources(sources []string) map[string]interface{} {
	parameters := make(map[string]*sqlInputParameterInference)
	for _, source := range sources {
		collectSQLInputParameterInferences(source, parameters)
	}

	properties := make(map[string]interface{}, len(parameters))
	required := make([]string, 0, len(parameters))
	names := make([]string, 0, len(parameters))
	for name := range parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		inference := parameters[name]
		properties[name] = sqlInputParameterSchema(inference)
		if inference.required {
			required = append(required, name)
		}
	}

	schema := map[string]interface{}{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": true,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func collectSQLInputParameterInferences(source string, parameters map[string]*sqlInputParameterInference) {
	blocks := make([]sqlSchemaBlockKind, 0)
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'' || source[index] == '"' || source[index] == '`':
			index = scanSQLSchemaQuotedValue(source, index)
			continue
		case index+1 < len(source) && source[index] == '-' && source[index+1] == '-':
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
			continue
		case index+1 < len(source) && source[index] == '/' && source[index+1] == '*':
			commentEnd := strings.Index(source[index+2:], "*/")
			if commentEnd < 0 {
				return
			}
			commentEnd += index + 2
			comment := strings.TrimSpace(source[index+2 : commentEnd])
			upperComment := strings.ToUpper(comment)
			if condition, ok := sqlSchemaIFCondition(comment); ok {
				for _, match := range reSQLSchemaConditionParam.FindAllStringSubmatch(condition, -1) {
					registerSQLInputParameter(parameters, match[1], "", "", nil, false)
				}
				blocks = append(blocks, sqlSchemaBlockIf)
			} else {
				switch {
				case upperComment == "BEGIN":
					blocks = append(blocks, sqlSchemaBlockBegin)
				case upperComment == "END":
					if len(blocks) > 0 {
						blocks = blocks[:len(blocks)-1]
					}
				case isSQLSchemaParameterName(comment):
					rawDefault, ok := sqlSchemaPlaceholderDefault(source, commentEnd+2)
					if ok {
						shape, valueType, example := inferSQLSchemaDefault(rawDefault, isSQLSchemaINParameter(source, index))
						registerSQLInputParameter(parameters, comment, shape, valueType, example, !containsSQLSchemaIFBlock(blocks))
					}
				}
			}
			index = commentEnd + 2
			continue
		default:
			index++
		}
	}
}

func sqlSchemaIFCondition(comment string) (string, bool) {
	if len(comment) <= 2 || !strings.EqualFold(comment[:2], "IF") || !isSQLSchemaWhitespace(comment[2]) {
		return "", false
	}
	return strings.TrimSpace(comment[2:]), true
}

func registerSQLInputParameter(parameters map[string]*sqlInputParameterInference, name, shape, valueType string, example interface{}, required bool) {
	inference, exists := parameters[name]
	if !exists {
		inference = &sqlInputParameterInference{}
		parameters[name] = inference
	}
	if required {
		inference.required = true
	}
	if inference.conflicted || shape == "" {
		return
	}
	if inference.shape == "" {
		inference.shape = shape
		inference.valueType = valueType
	} else if inference.shape != shape || (inference.valueType != "" && valueType != "" && inference.valueType != valueType) {
		inference.shape = ""
		inference.valueType = ""
		inference.examples = nil
		inference.conflicted = true
		return
	} else if inference.valueType == "" {
		inference.valueType = valueType
	}
	if example != nil && !containsInterfaceValue(inference.examples, example) {
		inference.examples = append(inference.examples, example)
	}
}

func sqlInputParameterSchema(inference *sqlInputParameterInference) map[string]interface{} {
	if inference == nil || inference.conflicted || inference.shape == "" {
		return map[string]interface{}{}
	}
	schema := make(map[string]interface{})
	if inference.shape == "array" {
		schema["type"] = "array"
		items := make(map[string]interface{})
		if inference.valueType != "" {
			items["type"] = inference.valueType
		}
		schema["items"] = items
	} else if inference.valueType != "" {
		schema["type"] = inference.valueType
	}
	if len(inference.examples) > 0 {
		schema["examples"] = append([]interface{}(nil), inference.examples...)
	}
	return schema
}

func containsInterfaceValue(values []interface{}, candidate interface{}) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, candidate) {
			return true
		}
	}
	return false
}

func containsSQLSchemaIFBlock(blocks []sqlSchemaBlockKind) bool {
	for _, block := range blocks {
		if block == sqlSchemaBlockIf {
			return true
		}
	}
	return false
}

func isSQLSchemaParameterName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9') || (index > 0 && (char == '.' || char == '-')) {
			continue
		}
		return false
	}
	return true
}

func sqlSchemaPlaceholderDefault(source string, offset int) (string, bool) {
	index := offset
	for index < len(source) && isSQLSchemaWhitespace(source[index]) {
		index++
	}
	if index >= len(source) {
		return "", false
	}
	start := index
	switch source[index] {
	case '\'', '"':
		index = scanSQLSchemaQuotedValue(source, index)
	case '{':
		index = scanBalancedSQLValue(source, index, '{', '}')
	case '[':
		index = scanBalancedSQLValue(source, index, '[', ']')
	default:
		for index < len(source) && !strings.ContainsRune(" \t\r\n,;)", rune(source[index])) {
			index++
		}
	}
	if index <= start {
		return "", false
	}
	return source[start:index], true
}

func scanSQLSchemaQuotedValue(source string, start int) int {
	quote := source[start]
	for index := start + 1; index < len(source); index++ {
		if source[index] == '\\' && index+1 < len(source) {
			index++
			continue
		}
		if source[index] != quote {
			continue
		}
		if index+1 < len(source) && source[index+1] == quote {
			index++
			continue
		}
		return index + 1
	}
	return len(source)
}

func isSQLSchemaWhitespace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

func isSQLSchemaINParameter(source string, commentStart int) bool {
	index := commentStart - 1
	for index >= 0 && isSQLSchemaWhitespace(source[index]) {
		index--
	}
	if index < 0 || source[index] != '(' {
		return false
	}
	index--
	for index >= 0 && isSQLSchemaWhitespace(source[index]) {
		index--
	}
	wordEnd := index + 1
	for index >= 0 && ((source[index] >= 'a' && source[index] <= 'z') || (source[index] >= 'A' && source[index] <= 'Z')) {
		index--
	}
	return strings.EqualFold(source[index+1:wordEnd], "IN")
}

func inferSQLSchemaDefault(rawDefault string, array bool) (string, string, interface{}) {
	rawDefault = strings.TrimSpace(rawDefault)
	valueType, example := inferSQLSchemaScalarDefault(rawDefault)
	if array {
		if example == nil {
			return "array", valueType, nil
		}
		return "array", valueType, []interface{}{example}
	}
	if valueType == "" {
		return "", "", nil
	}
	return "scalar", valueType, example
}

func inferSQLSchemaScalarDefault(rawDefault string) (string, interface{}) {
	if len(rawDefault) >= 2 && (rawDefault[0] == '\'' || rawDefault[0] == '"') && rawDefault[len(rawDefault)-1] == rawDefault[0] {
		quote := string(rawDefault[0])
		value := rawDefault[1 : len(rawDefault)-1]
		value = strings.ReplaceAll(value, quote+quote, quote)
		return "string", value
	}
	if strings.EqualFold(rawDefault, "true") {
		return "boolean", true
	}
	if strings.EqualFold(rawDefault, "false") {
		return "boolean", false
	}
	if integer, err := strconv.ParseInt(rawDefault, 10, 64); err == nil {
		return "integer", integer
	}
	if number, err := strconv.ParseFloat(rawDefault, 64); err == nil && !math.IsInf(number, 0) && !math.IsNaN(number) {
		return "number", number
	}
	return "", nil
}

type sqlTopLevelToken struct {
	value string
	start int
	end   int
}

func generateSQLOutputSchema(filePaths []string) (map[string]interface{}, error) {
	if len(filePaths) == 0 {
		return map[string]interface{}{}, nil
	}
	filePath := filePaths[len(filePaths)-1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read SQL file %s for output schema: %w", filePath, err)
	}
	return generateSQLOutputSchemaFromSource(string(data)), nil
}

func generateSQLOutputSchemaFromSources(sources []string) map[string]interface{} {
	if len(sources) == 0 {
		return map[string]interface{}{}
	}
	return generateSQLOutputSchemaFromSource(sources[len(sources)-1])
}

func generateSQLOutputSchemaFromSource(source string) map[string]interface{} {
	if !isSelectQuery(source) && !isReturningQuery(source) {
		return sqlMutationOutputSchema()
	}

	columns, safe := extractSQLResultColumnNames(source)
	return sqlResultSetOutputSchema(columns, safe)
}

func resolveAPISchema(apiConfig APIConfig) (APISchema, error) {
	resolved := unknownAPISchema()

	paramCheckPath := strings.TrimSpace(getParamCheckScriptPath(apiConfig))
	if paramCheckPath != "" {
		input, found, err := readOptionalStaticJavaScriptObjectConstant(paramCheckPath, "nyanInputSchema")
		if err != nil {
			return APISchema{}, fmt.Errorf("input schema from paramCheck: %w", err)
		}
		if found {
			resolved.Input = input
			resolved.InputSource = schemaSourceParamCheck
		}
	}

	outCheckPath := strings.TrimSpace(apiConfig.OutCheck)
	if outCheckPath != "" {
		output, found, err := readOptionalStaticJavaScriptObjectConstant(outCheckPath, "nyanOutputSchema")
		if err != nil {
			return APISchema{}, fmt.Errorf("output schema from outCheck: %w", err)
		}
		if found {
			resolved.Output = output
			resolved.OutputSource = schemaSourceOutCheck
		}
	}

	if len(apiConfig.SQL) > 0 {
		if resolved.InputSource == schemaSourceUnknown {
			input, err := generateSQLInputSchema(apiConfig.SQL)
			if err == nil {
				resolved.Input = input
				resolved.InputSource = schemaSourceSQL
			}
		}
		if resolved.OutputSource == schemaSourceUnknown {
			output, err := generateSQLOutputSchema(apiConfig.SQL)
			if err == nil {
				resolved.Output = output
				resolved.OutputSource = schemaSourceSQL
			}
		}
	}

	if apiConfig.Script != "" && resolved.InputSource == schemaSourceUnknown {
		acceptedParams, acceptedFound, err := readStaticLegacyAcceptedParams(apiConfig.Script)
		if err == nil {
			if acceptedFound {
				resolved.Input = legacyInputSchema(acceptedParams)
				resolved.InputSource = schemaSourceScriptLegacy
			}
		}
	}

	return resolved, nil
}

func readStaticLegacyAcceptedParams(filePath string) (map[string]interface{}, bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, err
	}
	acceptedValue, acceptedFound, err := extractStaticJavaScriptConstant(filePath, data, "nyanAcceptedParams")
	if err != nil {
		return nil, false, err
	}

	acceptedParams := map[string]interface{}{}
	if acceptedFound {
		var ok bool
		acceptedParams, ok = acceptedValue.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("nyanAcceptedParams must be a static object literal, got %T", acceptedValue)
		}
	}
	return acceptedParams, acceptedFound, nil
}

func readOptionalStaticJavaScriptObjectConstant(filePath, constantName string) (map[string]interface{}, bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, nil
	}
	return extractStaticJavaScriptObjectConstant(filePath, data, constantName)
}

func unknownAPISchema() APISchema {
	return APISchema{
		Input:        map[string]interface{}{},
		Output:       map[string]interface{}{},
		InputSource:  schemaSourceUnknown,
		OutputSource: schemaSourceUnknown,
	}
}

func legacyInputSchema(params map[string]interface{}) map[string]interface{} {
	properties := make(map[string]interface{}, len(params))
	for name, value := range params {
		properties[name] = legacyValueSchema(value)
	}
	return map[string]interface{}{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": true,
	}
}

func legacyValueSchema(value interface{}) map[string]interface{} {
	schema := make(map[string]interface{})
	switch value := value.(type) {
	case string:
		schema["type"] = "string"
	case bool:
		schema["type"] = "boolean"
	case float64:
		if math.IsInf(value, 0) || math.IsNaN(value) {
			return schema
		}
		if math.Trunc(value) == value {
			schema["type"] = "integer"
		} else {
			schema["type"] = "number"
		}
	case float32:
		number := float64(value)
		if math.IsInf(number, 0) || math.IsNaN(number) {
			return schema
		}
		if math.Trunc(number) == number {
			schema["type"] = "integer"
		} else {
			schema["type"] = "number"
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		schema["type"] = "integer"
	case map[string]interface{}:
		properties := make(map[string]interface{}, len(value))
		for name, item := range value {
			properties[name] = legacyValueSchema(item)
		}
		schema["type"] = "object"
		schema["properties"] = properties
		schema["additionalProperties"] = true
	case []interface{}:
		schema["type"] = "array"
		schema["items"] = legacyArrayItemsSchema(value)
	case nil:
		return schema
	default:
		return schema
	}
	schema["examples"] = []interface{}{cloneJSONCompatibleValue(value)}
	return schema
}

func legacyArrayItemsSchema(values []interface{}) map[string]interface{} {
	if len(values) == 0 {
		return map[string]interface{}{}
	}
	first := legacyValueSchema(values[0])
	delete(first, "examples")
	for _, value := range values[1:] {
		candidate := legacyValueSchema(value)
		delete(candidate, "examples")
		if !reflect.DeepEqual(first, candidate) {
			return map[string]interface{}{}
		}
	}
	return first
}

func sqlResponseOutputSchema(resultSchema map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"success": map[string]interface{}{"const": true},
			"status":  map[string]interface{}{"const": int64(http.StatusOK)},
			"result":  resultSchema,
		},
		"required":             []string{"success", "status", "result"},
		"additionalProperties": false,
	}
}

func sqlMutationOutputSchema() map[string]interface{} {
	return sqlResponseOutputSchema(map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
	})
}

func sqlResultSetOutputSchema(columns []string, safe bool) map[string]interface{} {
	items := map[string]interface{}{
		"type": "object",
	}
	if safe {
		properties := make(map[string]interface{}, len(columns))
		for _, column := range columns {
			properties[column] = map[string]interface{}{}
		}
		items["properties"] = properties
		items["required"] = append([]string(nil), columns...)
		items["additionalProperties"] = false
	} else {
		items["additionalProperties"] = true
	}
	return sqlResponseOutputSchema(map[string]interface{}{
		"type":  "array",
		"items": items,
	})
}

func extractSQLResultColumnNames(source string) ([]string, bool) {
	tokens := scanSQLTopLevelTokens(source)
	clauseIndex := -1
	clauseName := ""
	for index, token := range tokens {
		if token.value == "RETURNING" {
			clauseIndex = index
			clauseName = token.value
		}
	}
	if clauseIndex < 0 {
		for index, token := range tokens {
			if token.value == "SELECT" {
				clauseIndex = index
				clauseName = token.value
				break
			}
		}
	}
	if clauseIndex < 0 {
		return nil, false
	}

	start := tokens[clauseIndex].end
	end := len(source)
	if clauseName == "SELECT" {
		for _, token := range tokens[clauseIndex+1:] {
			if token.value == "FROM" || token.value == "INTO" {
				end = token.start
				break
			}
		}
	}
	if semicolon := findSQLTopLevelSemicolon(source, start, end); semicolon >= 0 {
		end = semicolon
	}
	if start >= end {
		return nil, false
	}

	columnList := source[start:end]
	if containsSQLConditionalDirective(columnList) {
		return nil, false
	}
	if clauseName == "SELECT" {
		columnList = trimSQLSelectModifier(columnList)
	}
	expressions := splitSQLTopLevelExpressions(columnList)
	if len(expressions) == 0 {
		return nil, false
	}

	columns := make([]string, 0, len(expressions))
	seen := make(map[string]struct{}, len(expressions))
	for _, expression := range expressions {
		column, ok := extractSQLResultColumnName(expression)
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[column]; duplicate {
			return nil, false
		}
		seen[column] = struct{}{}
		columns = append(columns, column)
	}
	return columns, true
}

func scanSQLTopLevelTokens(source string) []sqlTopLevelToken {
	tokens := make([]sqlTopLevelToken, 0)
	depth := 0
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'' || source[index] == '"' || source[index] == '`':
			index = scanSQLSchemaQuotedValue(source, index)
		case source[index] == '[':
			index = scanSQLBracketIdentifier(source, index)
		case index+1 < len(source) && source[index] == '-' && source[index+1] == '-':
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
		case index+1 < len(source) && source[index] == '/' && source[index+1] == '*':
			commentEnd := strings.Index(source[index+2:], "*/")
			if commentEnd < 0 {
				return tokens
			}
			index += commentEnd + 4
		case source[index] == '(':
			depth++
			index++
		case source[index] == ')':
			if depth > 0 {
				depth--
			}
			index++
		case isSQLIdentifierStart(source[index]):
			start := index
			index++
			for index < len(source) && isSQLIdentifierPart(source[index]) {
				index++
			}
			if depth == 0 {
				tokens = append(tokens, sqlTopLevelToken{
					value: strings.ToUpper(source[start:index]),
					start: start,
					end:   index,
				})
			}
		default:
			index++
		}
	}
	return tokens
}

func findSQLTopLevelSemicolon(source string, start, end int) int {
	depth := 0
	for index := start; index < end; {
		switch {
		case source[index] == '\'' || source[index] == '"' || source[index] == '`':
			index = scanSQLSchemaQuotedValue(source, index)
		case source[index] == '[':
			index = scanSQLBracketIdentifier(source, index)
		case index+1 < end && source[index] == '-' && source[index+1] == '-':
			index += 2
			for index < end && source[index] != '\n' {
				index++
			}
		case index+1 < end && source[index] == '/' && source[index+1] == '*':
			commentEnd := strings.Index(source[index+2:end], "*/")
			if commentEnd < 0 {
				return -1
			}
			index += commentEnd + 4
		case source[index] == '(':
			depth++
			index++
		case source[index] == ')':
			if depth > 0 {
				depth--
			}
			index++
		case source[index] == ';' && depth == 0:
			return index
		default:
			index++
		}
	}
	return -1
}

func containsSQLConditionalDirective(source string) bool {
	for index := 0; index+1 < len(source); {
		if source[index] == '\'' || source[index] == '"' || source[index] == '`' {
			index = scanSQLSchemaQuotedValue(source, index)
			continue
		}
		if source[index] != '/' || source[index+1] != '*' {
			index++
			continue
		}
		commentEnd := strings.Index(source[index+2:], "*/")
		if commentEnd < 0 {
			return true
		}
		commentEnd += index + 2
		comment := strings.TrimSpace(source[index+2 : commentEnd])
		if _, ok := sqlSchemaIFCondition(comment); ok || strings.EqualFold(comment, "BEGIN") || strings.EqualFold(comment, "END") {
			return true
		}
		index = commentEnd + 2
	}
	return false
}

func trimSQLSelectModifier(columnList string) string {
	trimmed := strings.TrimSpace(columnList)
	for _, modifier := range []string{"DISTINCT", "ALL"} {
		if len(trimmed) > len(modifier) && strings.EqualFold(trimmed[:len(modifier)], modifier) && isSQLSchemaWhitespace(trimmed[len(modifier)]) {
			return strings.TrimSpace(trimmed[len(modifier):])
		}
	}
	return trimmed
}

func splitSQLTopLevelExpressions(source string) []string {
	result := make([]string, 0)
	start := 0
	depth := 0
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'' || source[index] == '"' || source[index] == '`':
			index = scanSQLSchemaQuotedValue(source, index)
		case source[index] == '[':
			index = scanSQLBracketIdentifier(source, index)
		case index+1 < len(source) && source[index] == '-' && source[index+1] == '-':
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
		case index+1 < len(source) && source[index] == '/' && source[index+1] == '*':
			commentEnd := strings.Index(source[index+2:], "*/")
			if commentEnd < 0 {
				return nil
			}
			index += commentEnd + 4
		case source[index] == '(':
			depth++
			index++
		case source[index] == ')':
			if depth == 0 {
				return nil
			}
			depth--
			index++
		case source[index] == ',' && depth == 0:
			if expression := strings.TrimSpace(source[start:index]); expression != "" {
				result = append(result, expression)
			} else {
				return nil
			}
			index++
			start = index
		default:
			index++
		}
	}
	if depth != 0 {
		return nil
	}
	if expression := strings.TrimSpace(source[start:]); expression != "" {
		result = append(result, expression)
	} else {
		return nil
	}
	return result
}

func extractSQLResultColumnName(expression string) (string, bool) {
	tokens := scanSQLTopLevelTokens(expression)
	for index := len(tokens) - 1; index >= 0; index-- {
		if tokens[index].value != "AS" {
			continue
		}
		alias, ok := parseSQLStandaloneIdentifier(expression[tokens[index].end:])
		if !ok {
			return "", false
		}
		if strings.TrimSpace(expression[:tokens[index].start]) == "" {
			return "", false
		}
		return alias, true
	}
	return parseSQLQualifiedIdentifier(expression)
}

func parseSQLStandaloneIdentifier(source string) (string, bool) {
	trimmed := strings.TrimSpace(stripSQLComments(source))
	identifier, next, ok := scanSQLIdentifierSegment(trimmed, 0)
	if !ok || strings.TrimSpace(trimmed[next:]) != "" {
		return "", false
	}
	return identifier, true
}

func parseSQLQualifiedIdentifier(source string) (string, bool) {
	trimmed := strings.TrimSpace(stripSQLComments(source))
	index := 0
	last := ""
	for {
		for index < len(trimmed) && isSQLSchemaWhitespace(trimmed[index]) {
			index++
		}
		identifier, next, ok := scanSQLIdentifierSegment(trimmed, index)
		if !ok {
			return "", false
		}
		last = identifier
		index = next
		for index < len(trimmed) && isSQLSchemaWhitespace(trimmed[index]) {
			index++
		}
		if index == len(trimmed) {
			return last, true
		}
		if trimmed[index] != '.' {
			return "", false
		}
		index++
	}
}

func scanSQLIdentifierSegment(source string, start int) (string, int, bool) {
	if start >= len(source) {
		return "", start, false
	}
	switch source[start] {
	case '"', '`':
		quote := source[start]
		var value strings.Builder
		for index := start + 1; index < len(source); index++ {
			if source[index] != quote {
				value.WriteByte(source[index])
				continue
			}
			if index+1 < len(source) && source[index+1] == quote {
				value.WriteByte(quote)
				index++
				continue
			}
			if value.Len() == 0 {
				return "", start, false
			}
			return value.String(), index + 1, true
		}
	case '[':
		var value strings.Builder
		for index := start + 1; index < len(source); index++ {
			if source[index] != ']' {
				value.WriteByte(source[index])
				continue
			}
			if index+1 < len(source) && source[index+1] == ']' {
				value.WriteByte(']')
				index++
				continue
			}
			if value.Len() == 0 {
				return "", start, false
			}
			return value.String(), index + 1, true
		}
	default:
		if !isSQLIdentifierStart(source[start]) {
			return "", start, false
		}
		index := start + 1
		for index < len(source) && isSQLIdentifierPart(source[index]) {
			index++
		}
		return source[start:index], index, true
	}
	return "", start, false
}

func scanSQLBracketIdentifier(source string, start int) int {
	for index := start + 1; index < len(source); index++ {
		if source[index] != ']' {
			continue
		}
		if index+1 < len(source) && source[index+1] == ']' {
			index++
			continue
		}
		return index + 1
	}
	return len(source)
}

func stripSQLComments(source string) string {
	var result strings.Builder
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'' || source[index] == '"' || source[index] == '`':
			end := scanSQLSchemaQuotedValue(source, index)
			result.WriteString(source[index:end])
			index = end
		case source[index] == '[':
			end := scanSQLBracketIdentifier(source, index)
			result.WriteString(source[index:end])
			index = end
		case index+1 < len(source) && source[index] == '-' && source[index+1] == '-':
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
			result.WriteByte(' ')
		case index+1 < len(source) && source[index] == '/' && source[index+1] == '*':
			commentEnd := strings.Index(source[index+2:], "*/")
			if commentEnd < 0 {
				return result.String()
			}
			index += commentEnd + 4
			result.WriteByte(' ')
		default:
			result.WriteByte(source[index])
			index++
		}
	}
	return result.String()
}

func isSQLIdentifierStart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_'
}

func isSQLIdentifierPart(char byte) bool {
	return isSQLIdentifierStart(char) || (char >= '0' && char <= '9') || char == '$'
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

type nyanSQLExecer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func nyanRunSQLHandler(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	return nyanRunSQLHandlerWithExecer(vm, call, db, nil)
}

func nyanRunSQLHandlerWithExecer(vm *goja.Runtime, call goja.FunctionCall, execer nyanSQLExecer, allowedSQLFiles map[string]struct{}) goja.Value {
	// 第一引数: SQLファイルのパス
	if len(call.Arguments) < 1 {
		panic(vm.ToValue("nyanRunSQL requires at least the SQL file path as argument"))
	}
	sqlFilePath := call.Argument(0).String()
	if allowedSQLFiles != nil {
		canonicalPath, err := filepath.Abs(sqlFilePath)
		if err != nil {
			panic(vm.ToValue("SQL file path could not be resolved"))
		}
		canonicalPath = filepath.Clean(canonicalPath)
		if _, allowed := allowedSQLFiles[canonicalPath]; !allowed {
			panic(vm.ToValue("SQL file is not allowed for this runtime"))
		}
		sqlFilePath = canonicalPath
	}

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
	return runCheckScriptWithSnapshot(currentAPISnapshot(), apiCheckScriptPath, params, acceptedParamsKeys)
}

func runCheckScriptWithSnapshot(snapshot *APIConfigSnapshot, apiCheckScriptPath string, params map[string]interface{}, acceptedParamsKeys []string) (bool, int, interface{}, string, error) {
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
	registerNyanFuncs(vm, snapshot, params, acceptedParamsKeys)

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
// この関数の先頭で DB トランザクションを開始し、nyanRunSQL のclosureだけに渡します。
// スクリプト内で複数の nyanRunSQL 呼び出しがあった場合、すべて同一トランザクション下で実行されます。
// スクリプトの実行が成功すればコミット、エラーがあればロールバックします。
func runScript(scriptPaths []string, params map[string]interface{}) (string, error) {
	return runScriptWithSnapshot(currentAPISnapshot(), scriptPaths, params)
}

func runScriptWithSnapshot(snapshot *APIConfigSnapshot, scriptPaths []string, params map[string]interface{}) (string, error) {
	return runScriptWithRuntimeWithSnapshot(snapshot, scriptPaths, params, APIRuntimeConfig{}, false)
}

func runScriptWithRuntimeWithSnapshot(snapshot *APIConfigSnapshot, scriptPaths []string, params map[string]interface{}, runtimeConfig APIRuntimeConfig, restricted bool) (string, error) {
	if restricted && runtimeHasCapability(runtimeConfig, "password") {
		select {
		case restrictedPasswordExecutions <- struct{}{}:
			defer func() { <-restrictedPasswordExecutions }()
		default:
			return "", errRestrictedRuntimeBusy
		}
	}
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
	registerNyanFuncs(vm, snapshot, params, nil)
	var allowedSQLFiles map[string]struct{}
	if restricted {
		allowedSQLFiles = make(map[string]struct{}, len(runtimeConfig.SQLFiles))
		for _, sqlFile := range runtimeConfig.SQLFiles {
			canonicalPath, pathErr := filepath.Abs(sqlFile)
			if pathErr != nil {
				return "", fmt.Errorf("resolve allowed SQL file path: %w", pathErr)
			}
			allowedSQLFiles[filepath.Clean(canonicalPath)] = struct{}{}
		}
	}
	vm.Set("nyanRunSQL", func(call goja.FunctionCall) goja.Value {
		return nyanRunSQLHandlerWithExecer(vm, call, tx, allowedSQLFiles)
	})
	if runtimeConfig.Settings == nil {
		vm.Set("nyanRuntimeSettings", map[string]interface{}{})
	} else {
		vm.Set("nyanRuntimeSettings", cloneJSONCompatibleValue(runtimeConfig.Settings))
	}
	if restricted {
		restrictNyanRuntimeCapabilities(vm, runtimeConfig.Capabilities)
	}

	var stopExecutionWatchdog func()
	if restricted {
		timer := time.NewTimer(maxRestrictedScriptRuntime)
		finished := make(chan struct{})
		watcherDone := make(chan struct{})
		go func() {
			defer close(watcherDone)
			select {
			case <-timer.C:
				vm.Interrupt("restricted JavaScript execution timed out")
			case <-finished:
			}
		}()
		stopExecutionWatchdog = func() {
			close(finished)
			timer.Stop()
			<-watcherDone
			vm.ClearInterrupt()
		}
	}

	// スクリプト実行
	value, err := vm.RunString(combinedScript.String())
	if stopExecutionWatchdog != nil {
		stopExecutionWatchdog()
	}
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
	exported := value.Export()
	if text, ok := exported.(string); ok {
		return text, nil
	}
	encoded, err := json.Marshal(exported)
	if err != nil {
		return "", fmt.Errorf("encode script result: %w", err)
	}
	return string(encoded), nil
}

func runtimeHasCapability(runtimeConfig APIRuntimeConfig, target string) bool {
	for _, capability := range runtimeConfig.Capabilities {
		if capability == target {
			return true
		}
	}
	return false
}

func restrictNyanRuntimeCapabilities(vm *goja.Runtime, capabilities []string) {
	allowed := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		allowed[capability] = struct{}{}
	}
	if _, ok := allowed["sql"]; !ok {
		vm.Set("nyanRunSQL", goja.Undefined())
	}
	if _, ok := allowed["crypto"]; !ok {
		vm.Set("nyanCrypto", goja.Undefined())
		vm.Set("nyanRandomBase64URL", goja.Undefined())
		vm.Set("nyanSHA256Base64URL", goja.Undefined())
		vm.Set("sha256", goja.Undefined())
		vm.Set("nyanBase64Encode", goja.Undefined())
		vm.Set("nyanBase64Decode", goja.Undefined())
	}
	vm.Set("sha1", goja.Undefined())
	if _, ok := allowed["password"]; !ok {
		vm.Set("nyanPassword", goja.Undefined())
		vm.Set("nyanArgon2idHash", goja.Undefined())
		vm.Set("nyanArgon2idVerify", goja.Undefined())
	}
	for _, functionName := range []string{
		"nyanGetAPI",
		"nyanJsonAPI",
		"nyanCallAPI",
		"nyanHostExec",
		"nyanGetFile",
		"nyanCallMe",
		"nyanSaveFile",
	} {
		vm.Set(functionName, goja.Undefined())
	}
	vm.Set("console", map[string]interface{}{
		"log": func(call goja.FunctionCall) goja.Value {
			log.Printf("[JS:restricted] message suppressed (%d argument(s))", len(call.Arguments))
			return goja.Undefined()
		},
	})
}

// callNyanAPIFromVM は、JavaScript VM から api.json の API を check/script/sql 含めて実行します。
func callNyanAPIFromVM(apiName string, allParams map[string]interface{}) (string, error) {
	return callNyanAPIFromVMWithSnapshot(currentAPISnapshot(), apiName, allParams)
}

func callNyanAPIFromVMWithSnapshot(snapshot *APIConfigSnapshot, apiName string, allParams map[string]interface{}) (string, error) {
	if strings.TrimSpace(apiName) == "" {
		return "", fmt.Errorf("api name is required")
	}

	apiConfig, exists := snapshot.Definitions[apiName]
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
		success, statusCode, errorObj, jsonStr, err := runCheckScriptWithSnapshot(snapshot, checkScriptPath, params, acceptedKeys)
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
			performPush(snapshot, apiConfig, params)
			return jsonStr, nil
		}
		if apiConfig.Script != "" {
			result, err := runScriptWithSnapshot(snapshot, []string{apiConfig.Script}, params)
			if err != nil {
				return "", fmt.Errorf("failed to run API %s: %v", apiName, err)
			}
			if handled, _, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, "application/json", []byte(result)); handled {
				if err != nil {
					return "", fmt.Errorf("outCheck script error: %v", err)
				}
				return outJSON, nil
			}
			performPush(snapshot, apiConfig, params)
			return result, nil
		}
		if len(apiConfig.SQL) == 0 && apiConfig.Script == "" {
			performPush(snapshot, apiConfig, params)
			return jsonStr, nil
		}
	}

	if apiConfig.Script != "" {
		result, err := runScriptWithSnapshot(snapshot, []string{apiConfig.Script}, params)
		if err != nil {
			return "", fmt.Errorf("failed to run API %s: %v", apiName, err)
		}
		if handled, _, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, "application/json", []byte(result)); handled {
			if err != nil {
				return "", fmt.Errorf("outCheck script error: %v", err)
			}
			return outJSON, nil
		}
		performPush(snapshot, apiConfig, params)
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
	if handled, _, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, params, http.StatusOK, "application/json", b); handled {
		if err != nil {
			return "", fmt.Errorf("outCheck script error: %v", err)
		}
		return outJSON, nil
	}
	performPush(snapshot, apiConfig, params)
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
	return executeAPIConfigWithSnapshot(currentAPISnapshot(), apiConfig)
}

func executeAPIConfigWithSnapshot(snapshot *APIConfigSnapshot, apiConfig APIConfig) ([]byte, error) {
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
		result, err := runScriptWithSnapshot(snapshot, []string{apiConfig.Script}, make(map[string]interface{}))
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

func parseStaticJavaScriptValue(filename, source string) (interface{}, error) {
	program, err := parser.ParseFile(nil, filename, "("+source+");", 0)
	if err != nil {
		return nil, fmt.Errorf("parse static JavaScript value: %w", err)
	}
	if len(program.Body) != 1 {
		return nil, fmt.Errorf("parse static JavaScript value: expected one expression")
	}
	statement, ok := program.Body[0].(*ast.ExpressionStatement)
	if !ok {
		return nil, fmt.Errorf("parse static JavaScript value: expected an expression, got %T", program.Body[0])
	}
	return convertStaticJavaScriptValue(statement.Expression, "$")
}

func convertStaticJavaScriptValue(expression ast.Expression, path string) (interface{}, error) {
	switch value := expression.(type) {
	case *ast.ObjectLiteral:
		result := make(map[string]interface{}, len(value.Value))
		for _, rawProperty := range value.Value {
			property, ok := rawProperty.(*ast.PropertyKeyed)
			if !ok {
				return nil, fmt.Errorf("static JavaScript value at %s: %s are not supported", path, staticJavaScriptPropertyDescription(rawProperty))
			}
			if property.Computed {
				return nil, fmt.Errorf("static JavaScript value at %s: computed property names are not supported", path)
			}
			if property.Kind != ast.PropertyKindValue {
				return nil, fmt.Errorf("static JavaScript value at %s: property kind %q is not supported", path, property.Kind)
			}
			keyLiteral, ok := property.Key.(*ast.StringLiteral)
			if !ok {
				return nil, fmt.Errorf("static JavaScript value at %s: property names must be strings, got %T", path, property.Key)
			}
			key := keyLiteral.Value.String()
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("static JavaScript value at %s: duplicate property %q", path, key)
			}
			converted, err := convertStaticJavaScriptValue(property.Value, staticJavaScriptChildPath(path, key))
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case *ast.ArrayLiteral:
		result := make([]interface{}, len(value.Value))
		for index, item := range value.Value {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			if item == nil {
				return nil, fmt.Errorf("static JavaScript value at %s: array holes are not supported", itemPath)
			}
			converted, err := convertStaticJavaScriptValue(item, itemPath)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case *ast.StringLiteral:
		return value.Value.String(), nil
	case *ast.NumberLiteral:
		return staticJavaScriptNumber(value.Value, path)
	case *ast.BooleanLiteral:
		return value.Value, nil
	case *ast.NullLiteral:
		return nil, nil
	case *ast.UnaryExpression:
		if value.Postfix || (value.Operator != token.MINUS && value.Operator != token.PLUS) {
			return nil, fmt.Errorf("static JavaScript value at %s: unary operator %q is not supported", path, value.Operator)
		}
		numberLiteral, ok := value.Operand.(*ast.NumberLiteral)
		if !ok {
			return nil, fmt.Errorf("static JavaScript value at %s: unary %q requires a numeric literal", path, value.Operator)
		}
		number, err := staticJavaScriptNumber(numberLiteral.Value, path)
		if err != nil {
			return nil, err
		}
		if value.Operator == token.PLUS {
			return number, nil
		}
		switch number := number.(type) {
		case int64:
			return -number, nil
		case float64:
			return -number, nil
		default:
			return nil, fmt.Errorf("static JavaScript value at %s: unsupported numeric value %T", path, number)
		}
	default:
		return nil, fmt.Errorf("static JavaScript value at %s: %s are not supported", path, staticJavaScriptExpressionDescription(expression))
	}
}

func staticJavaScriptNumber(value interface{}, path string) (interface{}, error) {
	switch number := value.(type) {
	case int64:
		return number, nil
	case float64:
		if math.IsInf(number, 0) || math.IsNaN(number) {
			return nil, fmt.Errorf("static JavaScript value at %s: non-finite numbers are not JSON-compatible", path)
		}
		return number, nil
	default:
		return nil, fmt.Errorf("static JavaScript value at %s: numeric value %T is not JSON-compatible", path, value)
	}
}

func staticJavaScriptChildPath(parent, key string) string {
	if key != "" && !strings.ContainsAny(key, ".[]") {
		return parent + "." + key
	}
	return fmt.Sprintf("%s[%q]", parent, key)
}

func staticJavaScriptPropertyDescription(property ast.Property) string {
	switch property.(type) {
	case *ast.SpreadElement:
		return "spread properties"
	case *ast.PropertyShort:
		return "shorthand properties"
	default:
		return fmt.Sprintf("properties of type %T", property)
	}
}

func staticJavaScriptExpressionDescription(expression ast.Expression) string {
	switch expression.(type) {
	case *ast.CallExpression:
		return "function calls"
	case *ast.Identifier:
		return "identifier references"
	case *ast.SpreadElement:
		return "spread elements"
	case *ast.ConditionalExpression:
		return "conditional expressions"
	case *ast.TemplateLiteral:
		return "template literals"
	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		return "function values"
	case *ast.BinaryExpression:
		return "computed expressions"
	default:
		return fmt.Sprintf("expressions of type %T", expression)
	}
}

func readStaticJavaScriptObjectConstant(filePath, constantName string) (map[string]interface{}, bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("read JavaScript file %s: %w", filePath, err)
	}
	return extractStaticJavaScriptObjectConstant(filePath, data, constantName)
}

func extractStaticJavaScriptObjectConstant(filename string, source []byte, constantName string) (map[string]interface{}, bool, error) {
	converted, found, err := extractStaticJavaScriptConstant(filename, source, constantName)
	if err != nil || !found {
		return nil, found, err
	}
	object, ok := converted.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("JavaScript file %s: %s must be a static object literal, got %T", filename, constantName, converted)
	}
	return object, true, nil
}

func extractStaticJavaScriptConstant(filename string, source []byte, constantName string) (interface{}, bool, error) {
	if strings.TrimSpace(constantName) == "" {
		return nil, false, fmt.Errorf("JavaScript constant name is empty")
	}
	program, err := parser.ParseFile(nil, filename, source, 0)
	if err != nil {
		return nil, false, fmt.Errorf("parse JavaScript file %s: %w", filename, err)
	}

	var initializer ast.Expression
	for _, statement := range program.Body {
		switch declaration := statement.(type) {
		case *ast.LexicalDeclaration:
			for _, binding := range declaration.List {
				if !staticJavaScriptBindingHasName(binding, constantName) {
					continue
				}
				if declaration.Token != token.CONST {
					return nil, false, fmt.Errorf("JavaScript file %s: %s must be declared with const", filename, constantName)
				}
				if initializer != nil {
					return nil, false, fmt.Errorf("JavaScript file %s: duplicate declaration of %s", filename, constantName)
				}
				if binding.Initializer == nil {
					return nil, false, fmt.Errorf("JavaScript file %s: %s has no initializer", filename, constantName)
				}
				initializer = binding.Initializer
			}
		case *ast.VariableStatement:
			for _, binding := range declaration.List {
				if staticJavaScriptBindingHasName(binding, constantName) {
					return nil, false, fmt.Errorf("JavaScript file %s: %s must be declared with const", filename, constantName)
				}
			}
		}
	}

	if initializer == nil {
		return nil, false, nil
	}
	converted, err := convertStaticJavaScriptValue(initializer, constantName)
	if err != nil {
		return nil, false, fmt.Errorf("JavaScript file %s: %w", filename, err)
	}
	return converted, true, nil
}

func staticJavaScriptBindingHasName(binding *ast.Binding, constantName string) bool {
	if binding == nil {
		return false
	}
	identifier, ok := binding.Target.(*ast.Identifier)
	return ok && identifier.Name.String() == constantName
}

// parseScriptAcceptedParams は、指定されたスクリプトファイルから従来形式の入力パラメータ例をパースします。
func parseScriptAcceptedParams(scriptPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read script file %s: %v", scriptPath, err)
	}
	content := string(data)

	var acceptedParams map[string]interface{} = map[string]interface{}{}

	// const nyanAcceptedParams = {...};
	reAcceptedParams := regexp.MustCompile(`(?s)const\s+nyanAcceptedParams\s*=\s*({[\s\S]*?})\s*;`)
	if match := reAcceptedParams.FindStringSubmatch(content); len(match) >= 2 {
		jsonStr := match[1]
		if err := json.Unmarshal([]byte(jsonStr), &acceptedParams); err != nil {
			return nil, fmt.Errorf("failed to parse nyanAcceptedParams: %v", err)
		}
	}
	return acceptedParams, nil
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
	handleJSONRPCWithSnapshot(currentAPISnapshot(), w, r)
}

func handleJSONRPCWithSnapshot(snapshot *APIConfigSnapshot, w http.ResponseWriter, r *http.Request) {
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

	apiConfig, exists := snapshot.Definitions[apiKey]
	fmt.Print(apiConfig)
	if !exists {
		respondJSONRPCError(w, rpcReq.ID, -32601, "SQL files not found", nil)
		return
	}
	if getAPIType(apiConfig) != apiTypeAPI {
		respondJSONRPCError(w, rpcReq.ID, -32601, "Method not found", nil)
		return
	}
	if apiConfig.HTTP != nil {
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
		success, statusCode, errorObj, jsonStr, err := runCheckScriptWithSnapshot(snapshot, checkScriptPath, allParams, acceptedKeys)
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
		scriptResult, err := runScriptWithSnapshot(snapshot, []string{apiConfig.Script}, allParams)
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
	if handled, outStatusCode, outJSON, err := runOutCheckScriptWithSnapshot(snapshot, apiConfig, allParams, statusCode, "application/json", finalBody); handled {
		if err != nil {
			respondJSONRPCError(w, rpcReq.ID, -32603, "outCheck script error", err.Error())
			return
		}
		respondJSONRPCResultJSON(w, rpcReq.ID, outStatusCode, outJSON)
		return
	}

	// 6) Push処理（必要な場合）
	performPush(snapshot, apiConfig, allParams)

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

func performPush(snapshot *APIConfigSnapshot, apiConfig APIConfig, allParams map[string]interface{}) {
	if apiConfig.Push != "" {
		pushConfig, exists := snapshot.Definitions[apiConfig.Push]
		if exists {
			var pushResult []byte
			var err error
			if pushConfig.Script != "" {
				s, err := runScriptWithSnapshot(snapshot, []string{pushConfig.Script}, allParams)
				if err != nil {
					log.Printf("Push script error: %v", err)
				} else {
					pushResult = []byte(s)
				}
			} else {
				pushResult, err = executeAPIConfigWithSnapshot(snapshot, pushConfig)
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

func registerNyanFuncs(vm *goja.Runtime, snapshot *APIConfigSnapshot, params map[string]interface{}, acceptedParamsKeys []string) {
	vm.Set("nyanAllParams", params)
	vm.Set("nyanAcceptedParamsKeys", acceptedParamsKeys)
	if requestContext, ok := params["nyan_request"]; ok {
		vm.Set("nyanRequest", requestContext)
	} else {
		vm.Set("nyanRequest", map[string]interface{}{})
	}
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

		result, err := callNyanAPIFromVMWithSnapshot(snapshot, apiName, params)
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
	registerNyanCryptographicFunctions(vm)
}

func registerNyanCryptographicFunctions(vm *goja.Runtime) {
	vm.Set("nyanCrypto", map[string]interface{}{
		"randomBase64URL": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 1 {
				panic(vm.ToValue("nyanCrypto.randomBase64URL(bytes) requires exactly 1 argument"))
			}
			size := int(call.Argument(0).ToInteger())
			value, err := secureRandomBase64URL(size)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(value)
		},
		"sha256Base64URL": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 1 {
				panic(vm.ToValue("nyanCrypto.sha256Base64URL(text) requires exactly 1 argument"))
			}
			return vm.ToValue(sha256Base64URL(call.Argument(0).String()))
		},
		"sha256Hex": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 1 {
				panic(vm.ToValue("nyanCrypto.sha256Hex(text) requires exactly 1 argument"))
			}
			return vm.ToValue(sha256Hash(call.Argument(0).String()))
		},
		"timingSafeEqual": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 2 {
				panic(vm.ToValue("nyanCrypto.timingSafeEqual(a, b) requires exactly 2 arguments"))
			}
			return vm.ToValue(timingSafeStringEqual(call.Argument(0).String(), call.Argument(1).String()))
		},
	})
	vm.Set("nyanPassword", map[string]interface{}{
		"hash": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 1 {
				panic(vm.ToValue("nyanPassword.hash(password) requires exactly 1 argument"))
			}
			encoded, err := hashPasswordArgon2ID(call.Argument(0).String())
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(encoded)
		},
		"verify": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) != 2 {
				panic(vm.ToValue("nyanPassword.verify(password, hash) requires exactly 2 arguments"))
			}
			valid, err := verifyPasswordArgon2ID(call.Argument(0).String(), call.Argument(1).String())
			if err != nil {
				return vm.ToValue(false)
			}
			return vm.ToValue(valid)
		},
	})
	vm.Set("nyanRandomBase64URL", func(call goja.FunctionCall) goja.Value {
		value, err := secureRandomBase64URL(int(call.Argument(0).ToInteger()))
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(value)
	})
	vm.Set("nyanSHA256Base64URL", func(call goja.FunctionCall) goja.Value { return vm.ToValue(sha256Base64URL(call.Argument(0).String())) })
	vm.Set("nyanArgon2idHash", func(call goja.FunctionCall) goja.Value {
		value, err := hashPasswordArgon2ID(call.Argument(0).String())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(value)
	})
	vm.Set("nyanArgon2idVerify", func(call goja.FunctionCall) goja.Value {
		valid, _ := verifyPasswordArgon2ID(call.Argument(0).String(), call.Argument(1).String())
		return vm.ToValue(valid)
	})
}

const (
	argon2TimeCost    = uint32(3)
	argon2MemoryKiB   = uint32(64 * 1024)
	argon2Parallelism = uint8(2)
	argon2SaltLength  = 16
	argon2KeyLength   = uint32(32)
)

func secureRandomBase64URL(size int) (string, error) {
	if size < 16 || size > 128 {
		return "", fmt.Errorf("random byte size must be between 16 and 128")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", fmt.Errorf("generate secure random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func sha256Base64URL(input string) string {
	digest := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func timingSafeStringEqual(left, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1 && len(left) == len(right)
}

func hashPasswordArgon2ID(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	if len(password) > 4096 {
		return "", fmt.Errorf("password is too long")
	}
	salt := make([]byte, argon2SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argon2TimeCost, argon2MemoryKiB, argon2Parallelism, argon2KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2MemoryKiB,
		argon2TimeCost,
		argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func verifyPasswordArgon2ID(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid Argon2id hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, fmt.Errorf("unsupported Argon2id version")
	}
	var memory, timeCost uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
		return false, fmt.Errorf("invalid Argon2id parameters")
	}
	if memory < argon2MemoryKiB || memory > 256*1024 || timeCost < argon2TimeCost || timeCost > 10 || parallelism < 1 || parallelism > 16 {
		return false, fmt.Errorf("unsafe Argon2id parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argon2SaltLength || len(salt) > 64 {
		return false, fmt.Errorf("invalid Argon2id salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false, fmt.Errorf("invalid Argon2id hash")
	}
	actual := argon2.IDKey([]byte(password), salt, timeCost, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func sha1Hash(input string) string {
	hash := sha1.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}
