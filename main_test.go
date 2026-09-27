package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/gorilla/websocket"
)

func captureServiceLogs(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	writer, flags, prefix, previousLevel := log.Writer(), log.Flags(), log.Prefix(), serviceLogLevel.Level()
	var output bytes.Buffer
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	serviceLogLevel.Set(level)
	t.Cleanup(func() {
		log.SetOutput(writer)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
		serviceLogLevel.Set(previousLevel)
	})
	return &output
}

func TestServiceLoggingLevelsAndErrorPrivacy(t *testing.T) {
	output := captureServiceLogs(t, slog.LevelInfo)
	secretError := errors.New("password=private-error\nforged log line")
	serviceLog(slog.LevelDebug, "hidden_debug_event")
	logServiceError(slog.LevelError, "execution_failed", secretError, "api", "example\napi")
	if strings.Contains(output.String(), "private-error") || strings.Contains(output.String(), "hidden_debug_event") {
		t.Fatalf("info log contains debug data: %s", output.String())
	}
	if bytes.Count(output.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("log injection produced extra lines: %s", output.String())
	}
	record := decodeTestJSONObject(t, output.Bytes())
	if record["msg"] != "execution_failed" || record["level"] != "ERROR" || record["error_type"] == nil || record["api"] != "example\napi" {
		t.Fatalf("missing diagnostic metadata: %#v", record)
	}
	output.Reset()
	serviceLogLevel.Set(slog.LevelDebug)
	logServiceError(slog.LevelError, "execution_failed", secretError)
	record = decodeTestJSONObject(t, output.Bytes())
	if record["error_detail"] != secretError.Error() {
		t.Fatalf("debug log missing error detail: %#v", record)
	}
	output.Reset()
	serviceLogLevel.Set(slog.LevelError)
	serviceLog(slog.LevelInfo, "hidden_info")
	serviceLog(slog.LevelWarn, "hidden_warning")
	if output.Len() != 0 {
		t.Fatalf("error level emitted lower levels: %s", output.String())
	}
}

func TestSetupLoggerRejectsInvalidLevelWithoutChangingOutput(t *testing.T) {
	output := captureServiceLogs(t, slog.LevelInfo)
	previous := config.Log
	t.Cleanup(func() { config.Log = previous })
	config.Log = LogConfig{Level: "verbose"}
	if err := setupLogger(t.TempDir()); err == nil {
		t.Fatal("invalid log.Level was accepted")
	}
	if log.Writer() != output || serviceLogLevel.Level() != slog.LevelInfo {
		t.Fatal("invalid configuration partially changed the logger")
	}
}

func TestRuntimeLoggingDoesNotDumpPayloads(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	output := captureServiceLogs(t, slog.LevelDebug)
	// Catch direct stdout writes as well as writes through the logger.
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = stdoutFile
	t.Cleanup(func() { os.Stdout = oldStdout; stdoutFile.Close() })
	sqlFile := filepath.Join(t.TempDir(), "query.sql")
	writeTestFile(t, sqlFile, "SELECT 'private-sql-source' AS value;")
	check := writeTestScript(t, `const secret = "private-check-source"; ({success:true,status:200})`)
	push := writeTestScript(t, `({value:"private-push-result"})`)
	script := writeTestScript(t, fmt.Sprintf(`nyanRunSQL(%q, {}); ({ok:true})`, sqlFile))
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"query": {SQL: []string{sqlFile}, ParamCheck: check, Push: "push"},
		"push":  {Script: push, Runtime: APIRuntimeConfig{Settings: map[string]interface{}{"secret": "private-config-value"}}},
		"js":    {Script: script},
	}, "", [32]byte{})
	oldHub := hub
	hub = NewHub()
	t.Cleanup(func() { hub = oldHub })
	for _, api := range []string{"query", "js"} {
		response := httptest.NewRecorder()
		handleRequestWithSnapshot(snapshot, response, httptest.NewRequest("GET", "/"+api, nil))
		if response.Code != 200 {
			t.Fatalf("%s failed: %s", api, response.Body.String())
		}
	}
	rpc := httptest.NewRecorder()
	handleJSONRPCWithSnapshot(snapshot, rpc, httptest.NewRequest("POST", "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"push"}`)))
	if rpc.Code != 200 || !strings.Contains(rpc.Body.String(), "private-push-result") {
		t.Fatalf("JSON-RPC execution changed: %s", rpc.Body.String())
	}
	for _, secret := range []string{"private-sql-source", "private-check-source", "private-push-result", "private-config-value"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("automatic log exposed %s: %s", secret, output.String())
		}
	}
	stdout, err := os.ReadFile(stdoutFile.Name())
	if err != nil || len(stdout) != 0 {
		t.Fatalf("runtime wrote directly to stdout: %q (error=%v)", stdout, err)
	}
	if !strings.Contains(output.String(), "push_broadcast") {
		t.Fatalf("missing push metadata: %s", output.String())
	}
}

func TestScriptConsoleLoggingRequiresDebug(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	output := captureServiceLogs(t, slog.LevelInfo)
	script := writeTestScript(t, `console.log("private-console-message\nsecond line"); ({ok:true})`)
	if _, err := runScript([]string{script}, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("info log exposed console: %s", output.String())
	}
	serviceLogLevel.Set(slog.LevelDebug)
	if _, err := runScript([]string{script}, nil); err != nil {
		t.Fatal(err)
	}
	record := decodeTestJSONObject(t, output.Bytes())
	if record["message"] != "private-console-message\nsecond line" {
		t.Fatalf("debug console changed message: %#v", record)
	}
	output.Reset()
	if _, err := runScriptWithRuntimeWithSnapshot(currentAPISnapshot(), []string{script}, nil, APIRuntimeConfig{}, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private-console-message") {
		t.Fatalf("restricted runtime exposed console: %s", output.String())
	}
	if len(boundedLogText(strings.Repeat("x", 10000))) > 4200 {
		t.Fatal("debug text was not bounded")
	}
}

func TestWebSocketLoggingPrivacyAndNormalClose(t *testing.T) {
	output := captureServiceLogs(t, slog.LevelInfo)
	endpoint := "wss://user:private-password@example.com/private-path?token=private-token#private-fragment"
	serviceLog(slog.LevelInfo, "ws_client_starting", "origin", logURLOrigin(endpoint))
	record := decodeTestJSONObject(t, output.Bytes())
	if record["origin"] != "wss://example.com" {
		t.Fatalf("URL was not sanitized: %#v", record)
	}
	output.Reset()
	logWebSocketDisconnect("ws_client_disconnected", "example", fmt.Errorf("read: %w", &websocket.CloseError{Code: 1000, Text: "private-close-text"}))
	if output.Len() != 0 {
		t.Fatalf("normal close logged as a warning: %s", output.String())
	}
	logWebSocketDisconnect("ws_client_disconnected", "example", &websocket.CloseError{Code: 1006, Text: "private-close-text"})
	record = decodeTestJSONObject(t, output.Bytes())
	if record["level"] != "WARN" || record["close_code"] != float64(1006) || strings.Contains(output.String(), "private-close-text") {
		t.Fatalf("unexpected disconnect log: %#v", record)
	}
}

func TestMCPStdioProcessLogging(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "tool.js"), `console.log("stdio-console-marker"); ({ok:true})`)
	writeTestFile(t, filepath.Join(dir, "api.json"), `{"tool":{"script":"tool.js"},"mcp":{"type":"mcp","transport":"stdio","tools":["tool"]}}`)
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n" +
		"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"tool\",\"arguments\":{}}}\n"
	for _, tc := range []struct {
		name, level string
		file        bool
	}{
		{name: "default_stderr"},
		{name: "debug_stderr", level: "debug"},
		{name: "rotating_file", file: true},
		{name: "debug_rotating_file", level: "debug", file: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logFile := filepath.Join(dir, tc.name+".log")
			cfg, err := json.Marshal(Config{DatabaseType: "sqlite", DBName: filepath.Join(dir, tc.name+".db"), Log: LogConfig{EnableLogging: tc.file, Filename: logFile, Level: tc.level}})
			if err != nil {
				t.Fatal(err)
			}
			configFile := filepath.Join(dir, tc.name+".json")
			writeTestFile(t, configFile, string(cfg))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPStdioLoggingHelper$", "--", "--config", configFile, "--api", filepath.Join(dir, "api.json"), "--mcp-server", "mcp")
			cmd.Env = append(os.Environ(), "NYANQL_TEST_STDIO_LOGGING_CHILD=1")
			cmd.Stdin = strings.NewReader(input)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("stdio process failed: %v; stderr=%s", err, stderr.String())
			}
			lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("stdout contains non-protocol data: %s", stdout.String())
			}
			for _, line := range lines {
				record := decodeTestJSONObject(t, []byte(line))
				if record["jsonrpc"] != "2.0" || record["error"] != nil {
					t.Fatalf("invalid protocol response: %s", line)
				}
			}
			logs := stderr.Bytes()
			if tc.file {
				if len(logs) != 0 {
					t.Fatalf("file logging also wrote stderr: %s", logs)
				}
				logs, err = os.ReadFile(logFile)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Contains(logs, []byte("mcp_stdio_starting")) {
				t.Fatalf("missing startup diagnostics: %s", logs)
			}
			for _, line := range bytes.Split(bytes.TrimSpace(logs), []byte("\n")) {
				decodeTestJSONObject(t, line)
			}
			if bytes.Contains(logs, []byte("stdio-console-marker")) != (tc.level == "debug") {
				t.Fatalf("unexpected console logging: %s", logs)
			}
		})
	}
}

func TestMCPStdioLoggingHelper(t *testing.T) {
	if os.Getenv("NYANQL_TEST_STDIO_LOGGING_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0) // Do not let the test runner write PASS to protocol stdout.
		}
	}
	os.Exit(2)
}

func TestGetParamCheckScriptPath(t *testing.T) {
	tests := []struct {
		name     string
		config   APIConfig
		wantPath string
	}{
		{
			name:     "uses check as alias",
			config:   APIConfig{Check: "./javascript/check.js"},
			wantPath: "./javascript/check.js",
		},
		{
			name:     "uses paramCheck",
			config:   APIConfig{ParamCheck: "./javascript/param_check.js"},
			wantPath: "./javascript/param_check.js",
		},
		{
			name:     "paramCheck takes precedence",
			config:   APIConfig{Check: "./javascript/check.js", ParamCheck: "./javascript/param_check.js"},
			wantPath: "./javascript/param_check.js",
		},
		{
			name:     "empty when no check configured",
			config:   APIConfig{},
			wantPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getParamCheckScriptPath(tt.config); got != tt.wantPath {
				t.Fatalf("getParamCheckScriptPath() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestAPIConfigUnmarshalCheckAlias(t *testing.T) {
	var config APIConfig
	if err := json.Unmarshal([]byte(`{"check":"./javascript/check.js"}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if config.ParamCheck != "./javascript/check.js" {
		t.Fatalf("ParamCheck = %q, want %q", config.ParamCheck, "./javascript/check.js")
	}
	if config.Check != "" {
		t.Fatalf("Check = %q, want empty deprecated alias field", config.Check)
	}
}

func TestAPIConfigUnmarshalParamCheckPrecedence(t *testing.T) {
	var config APIConfig
	data := []byte(`{"check":"./javascript/check.js","paramCheck":"./javascript/param_check.js"}`)
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if config.ParamCheck != "./javascript/param_check.js" {
		t.Fatalf("ParamCheck = %q, want %q", config.ParamCheck, "./javascript/param_check.js")
	}
}

func TestAPIConfigUnmarshalOutCheck(t *testing.T) {
	var config APIConfig
	if err := json.Unmarshal([]byte(`{"outCheck":"./javascript/out_check.js"}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if config.OutCheck != "./javascript/out_check.js" {
		t.Fatalf("OutCheck = %q, want %q", config.OutCheck, "./javascript/out_check.js")
	}
}

func TestAPIConfigUnmarshalLowercaseParamCheck(t *testing.T) {
	var config APIConfig
	if err := json.Unmarshal([]byte(`{"paramcheck":"./javascript/param_check.js"}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if config.ParamCheck != "./javascript/param_check.js" {
		t.Fatalf("ParamCheck = %q, want %q", config.ParamCheck, "./javascript/param_check.js")
	}
}

func TestAPIConfigUnmarshalLowercaseOutCheck(t *testing.T) {
	var config APIConfig
	if err := json.Unmarshal([]byte(`{"outcheck":"./javascript/out_check.js"}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if config.OutCheck != "./javascript/out_check.js" {
		t.Fatalf("OutCheck = %q, want %q", config.OutCheck, "./javascript/out_check.js")
	}
}

func TestResolveServiceFilePathsDefaultsToExecDir(t *testing.T) {
	execDir := t.TempDir()
	writeTestFile(t, filepath.Join(execDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(execDir, "config.json"), "{}")

	paths, err := resolveServiceFilePaths(execDir, nil)
	if err != nil {
		t.Fatalf("resolveServiceFilePaths() error = %v", err)
	}
	if paths.API.Path != filepath.Join(execDir, "api.json") {
		t.Fatalf("API path = %q, want %q", paths.API.Path, filepath.Join(execDir, "api.json"))
	}
	if paths.API.Source != "default" {
		t.Fatalf("API source = %q, want default", paths.API.Source)
	}
	if paths.Config.Path != filepath.Join(execDir, "config.json") {
		t.Fatalf("Config path = %q, want %q", paths.Config.Path, filepath.Join(execDir, "config.json"))
	}
	if paths.Config.Source != "default" {
		t.Fatalf("Config source = %q, want default", paths.Config.Source)
	}
}

func TestResolveServiceFilePathsCLIOverridesEnvironment(t *testing.T) {
	execDir := t.TempDir()
	envDir := t.TempDir()
	cliDir := t.TempDir()
	writeTestFile(t, filepath.Join(execDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(execDir, "config.json"), "{}")
	writeTestFile(t, filepath.Join(envDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(envDir, "config.json"), "{}")
	writeTestFile(t, filepath.Join(cliDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(cliDir, "config.json"), "{}")
	t.Setenv("NYAN_API_PATH", filepath.Join(envDir, "api.json"))
	t.Setenv("NYAN_CONFIG_PATH", filepath.Join(envDir, "config.json"))

	paths, err := resolveServiceFilePaths(execDir, []string{
		"--api", filepath.Join(cliDir, "api.json"),
		"--config", filepath.Join(cliDir, "config.json"),
	})
	if err != nil {
		t.Fatalf("resolveServiceFilePaths() error = %v", err)
	}
	if paths.API.Path != filepath.Join(cliDir, "api.json") {
		t.Fatalf("API path = %q, want CLI path", paths.API.Path)
	}
	if paths.API.Source != "--api" {
		t.Fatalf("API source = %q, want --api", paths.API.Source)
	}
	if paths.Config.Path != filepath.Join(cliDir, "config.json") {
		t.Fatalf("Config path = %q, want CLI path", paths.Config.Path)
	}
	if paths.Config.Source != "--config" {
		t.Fatalf("Config source = %q, want --config", paths.Config.Source)
	}
}

func TestResolveServiceFilePathsUsesEnvironmentBeforeDefault(t *testing.T) {
	execDir := t.TempDir()
	envDir := t.TempDir()
	writeTestFile(t, filepath.Join(execDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(execDir, "config.json"), "{}")
	writeTestFile(t, filepath.Join(envDir, "api.json"), "{}")
	writeTestFile(t, filepath.Join(envDir, "config.json"), "{}")
	t.Setenv("NYAN_API_PATH", filepath.Join(envDir, "api.json"))
	t.Setenv("NYAN_CONFIG_PATH", filepath.Join(envDir, "config.json"))

	paths, err := resolveServiceFilePaths(execDir, nil)
	if err != nil {
		t.Fatalf("resolveServiceFilePaths() error = %v", err)
	}
	if paths.API.Path != filepath.Join(envDir, "api.json") {
		t.Fatalf("API path = %q, want env path", paths.API.Path)
	}
	if paths.API.Source != "NYAN_API_PATH" {
		t.Fatalf("API source = %q, want NYAN_API_PATH", paths.API.Source)
	}
	if paths.Config.Path != filepath.Join(envDir, "config.json") {
		t.Fatalf("Config path = %q, want env path", paths.Config.Path)
	}
	if paths.Config.Source != "NYAN_CONFIG_PATH" {
		t.Fatalf("Config source = %q, want NYAN_CONFIG_PATH", paths.Config.Source)
	}
}

func TestResolveServiceFilePathsResolvesRelativeCLIPaths(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	execDir := t.TempDir()
	writeTestFile(t, filepath.Join(cwd, "api.json"), "{}")
	writeTestFile(t, filepath.Join(cwd, "config.json"), "{}")

	paths, err := resolveServiceFilePaths(execDir, []string{"--api", "./api.json", "--config", "./config.json"})
	if err != nil {
		t.Fatalf("resolveServiceFilePaths() error = %v", err)
	}
	if paths.API.Path != filepath.Join(cwd, "api.json") {
		t.Fatalf("API path = %q, want %q", paths.API.Path, filepath.Join(cwd, "api.json"))
	}
	if paths.Config.Path != filepath.Join(cwd, "config.json") {
		t.Fatalf("Config path = %q, want %q", paths.Config.Path, filepath.Join(cwd, "config.json"))
	}
}

func TestResolveServiceFilePathsReportsMissingFileWithSource(t *testing.T) {
	execDir := t.TempDir()
	configPath := filepath.Join(execDir, "config.json")
	writeTestFile(t, configPath, "{}")

	_, err := resolveServiceFilePaths(execDir, []string{"--api", "./missing-api.json", "--config", configPath})
	if err == nil {
		t.Fatal("resolveServiceFilePaths() error = nil, want missing file error")
	}
	if !strings.Contains(err.Error(), "api file not found:") || !strings.Contains(err.Error(), "(source: --api)") {
		t.Fatalf("error = %q, want missing api file with --api source", err.Error())
	}
}

func TestLoadSQLFilesResolvesAPIPathsFromAPIFileDirectory(t *testing.T) {
	apiDir := t.TempDir()
	apiPath := filepath.Join(apiDir, "api.json")
	writeTestFile(t, apiPath, `{
		"list": {
			"sql": ["./sql/list.sql"],
			"path": "./public"
		},
		"scripted": {
			"script": "./javascript/script.js",
			"paramCheck": "./javascript/param_check.js",
			"outCheck": "./javascript/out_check.js"
		}
	}`)
	setTestSQLFiles(t, nil)

	files, _, err := readSQLFiles(apiPath, t.TempDir())
	if err != nil {
		t.Fatalf("readSQLFiles() error = %v", err)
	}
	setSQLFiles(files)

	apiConfig := currentSQLFiles()["list"]
	scriptConfig := currentSQLFiles()["scripted"]
	if apiConfig.SQL[0] != filepath.Join(apiDir, "sql/list.sql") {
		t.Fatalf("SQL path = %q, want api-relative path", apiConfig.SQL[0])
	}
	if scriptConfig.Script != filepath.Join(apiDir, "javascript/script.js") {
		t.Fatalf("Script path = %q, want api-relative path", scriptConfig.Script)
	}
	if scriptConfig.ParamCheck != filepath.Join(apiDir, "javascript/param_check.js") {
		t.Fatalf("ParamCheck path = %q, want api-relative path", scriptConfig.ParamCheck)
	}
	if scriptConfig.OutCheck != filepath.Join(apiDir, "javascript/out_check.js") {
		t.Fatalf("OutCheck path = %q, want api-relative path", scriptConfig.OutCheck)
	}
	if apiConfig.Path != filepath.Join(apiDir, "public") {
		t.Fatalf("Public path = %q, want api-relative path", apiConfig.Path)
	}
}

func TestDecodeSQLFilesRejectsDuplicateKeysAtEveryObjectLevel(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantPath string
	}{
		{
			name:     "top level",
			data:     `{"api":{},"api":{}}`,
			wantPath: `$`,
		},
		{
			name:     "API definition",
			data:     `{"api":{"description":"first","description":"second"}}`,
			wantPath: `$["api"]`,
		},
		{
			name:     "nested trigger",
			data:     `{"job":{"type":"schedule","script":"job.js","trigger":{"type":"cron","type":"other","value":"* * * * *"}}}`,
			wantPath: `$["job"]["trigger"]`,
		},
		{
			name:     "object in array",
			data:     `{"api":{"unknown":[{"value":1,"value":2}]}}`,
			wantPath: `$["api"]["unknown"][0]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeSQLFiles([]byte(tt.data), t.TempDir())
			if err == nil {
				t.Fatal("decodeSQLFiles() error = nil, want duplicate-key error")
			}
			if !strings.Contains(err.Error(), "duplicate key") || !strings.Contains(err.Error(), tt.wantPath) {
				t.Fatalf("decodeSQLFiles() error = %q, want duplicate key at %s", err, tt.wantPath)
			}
		})
	}
}

func TestDecodeSQLFilesAllowsSameKeyInDifferentObjects(t *testing.T) {
	files, err := decodeSQLFiles([]byte(`{
		"first":{"description":"one"},
		"second":{"description":"two"}
	}`), t.TempDir())
	if err != nil {
		t.Fatalf("decodeSQLFiles() error = %v", err)
	}
	if files["first"].Description != "one" || files["second"].Description != "two" {
		t.Fatalf("decoded files = %#v", files)
	}
}

func TestDecodeSQLFilesRequiresObjectDefinitions(t *testing.T) {
	for _, data := range []string{
		`{"api":null}`,
		`{"api":"invalid"}`,
		`{"api":[]}`,
	} {
		_, err := decodeSQLFiles([]byte(data), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), `definition "api" must be an object`) {
			t.Fatalf("decodeSQLFiles(%s) error = %v, want object-definition error", data, err)
		}
	}
}

func TestLoadAPIConfigFileValidatesAllDefinitionsBeforePublishing(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "API with script and SQL",
			data: `{"api":{"script":"api.js","sql":["api.sql"]}}`,
			want: "if script is set, sql cannot be specified",
		},
		{
			name: "schedule without script",
			data: `{"job":{"type":"schedule","trigger":{"type":"cron","value":"* * * * *"}}}`,
			want: "script is missing",
		},
		{
			name: "schedule with invalid cron",
			data: `{"job":{"type":"schedule","script":"job.js","trigger":{"type":"cron","value":"invalid"}}}`,
			want: "invalid cron trigger",
		},
		{
			name: "ws_client without connectURL",
			data: `{"client":{"type":"ws_client","script":"client.js"}}`,
			want: "connectURL is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiPath := filepath.Join(t.TempDir(), "api.json")
			writeTestFile(t, apiPath, tt.data)
			result, err := loadAPIConfigFile(apiPath)
			if err == nil {
				t.Fatalf("loadAPIConfigFile() result = %#v, want validation error", result)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadAPIConfigFile() error = %q, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadAPIConfigFileKeepsUnknownTypeCompatibility(t *testing.T) {
	apiPath := filepath.Join(t.TempDir(), "api.json")
	writeTestFile(t, apiPath, `{"custom":{"type":"future_type","description":"kept"}}`)

	result, err := loadAPIConfigFile(apiPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	if got := result.Snapshot.Definitions["custom"]; got.Type != "future_type" || got.Description != "kept" {
		t.Fatalf("custom definition = %#v", got)
	}
}

func TestLoadAPIConfigFileBuildsValidatedBackgroundConfigs(t *testing.T) {
	apiDir := t.TempDir()
	apiPath := filepath.Join(apiDir, "api.json")
	writeTestFile(t, apiPath, `{
		"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 10 * * *"}},
		"client":{"type":"ws_client","script":"./client.js","connectURL":"ws://localhost:8080/events"}
	}`)

	result, err := loadAPIConfigFile(apiPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	if got := result.Schedules["job"].scriptPath; got != filepath.Join(apiDir, "job.js") {
		t.Fatalf("schedule script path = %q, want API-relative path", got)
	}
	if got := result.WSClients["client"].scriptPath; got != filepath.Join(apiDir, "client.js") {
		t.Fatalf("ws_client script path = %q, want API-relative path", got)
	}
}

func TestLoadAPIConfigFileExpandsOneLevelInclude(t *testing.T) {
	rootDir := t.TempDir()
	childDir := filepath.Join(rootDir, "sub")
	rootPath := filepath.Join(rootDir, "api.json")
	childPath := filepath.Join(childDir, "api.json")
	writeTestFile(t, rootPath, `{
		"health":{"sql":["./sql/health.sql"],"description":"root"},
		"sub":{"type":"include","path":"./sub/api.json"}
	}`)
	writeTestFile(t, childPath, `{
		"getItem":{"sql":["./sql/get_item.sql"],"paramCheck":"./check.js","outCheck":"./out.js","description":"child"},
		"assets":{"type":"public","path":"./public"},
		"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 10 * * *"}},
		"client":{"type":"ws_client","script":"./client.js","connectURL":"ws://localhost:8080/events"}
	}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	definitions := result.Snapshot.Definitions
	if _, exists := definitions["sub"]; exists {
		t.Fatal("include definition was published as an executable API")
	}
	if got := definitions["health"].SQL[0]; got != filepath.Join(rootDir, "sql/health.sql") {
		t.Fatalf("root SQL path = %q, want root-relative path", got)
	}
	if got := definitions["sub/getItem"].SQL[0]; got != filepath.Join(childDir, "sql/get_item.sql") {
		t.Fatalf("included SQL path = %q, want child-relative path", got)
	}
	if got := definitions["sub/getItem"].ParamCheck; got != filepath.Join(childDir, "check.js") {
		t.Fatalf("included paramCheck path = %q, want child-relative path", got)
	}
	if got := definitions["sub/getItem"].OutCheck; got != filepath.Join(childDir, "out.js") {
		t.Fatalf("included outCheck path = %q, want child-relative path", got)
	}
	if got := definitions["sub/assets"].Path; got != filepath.Join(childDir, "public") {
		t.Fatalf("included public path = %q, want child-relative path", got)
	}
	if got := result.Schedules["sub/job"].scriptPath; got != filepath.Join(childDir, "job.js") {
		t.Fatalf("included schedule path = %q, want child-relative path", got)
	}
	if got := result.WSClients["sub/client"].scriptPath; got != filepath.Join(childDir, "client.js") {
		t.Fatalf("included ws_client path = %q, want child-relative path", got)
	}
	if got := result.Snapshot.Sources["health"]; got != rootPath {
		t.Fatalf("root source = %q, want %q", got, rootPath)
	}
	if got := result.Snapshot.Sources["sub/getItem"]; got != childPath {
		t.Fatalf("included source = %q, want %q", got, childPath)
	}
	if len(result.Snapshot.Files) != 2 {
		t.Fatalf("snapshot file count = %d, want 2", len(result.Snapshot.Files))
	}
	for _, path := range []string{rootPath, childPath} {
		identity, err := canonicalExistingAPIFilePath(path)
		if err != nil {
			t.Fatal(err)
		}
		state, exists := result.Snapshot.Files[path]
		if !exists || !state.Exists || state.Path != path || state.Identity != identity {
			t.Fatalf("file state for %s = %#v, exists=%t", identity, state, exists)
		}
	}
}

func TestOneLevelIncludedAPICallForms(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	childPath := filepath.Join(rootDir, "sub", "api.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"./sub/api.json"}}`)
	writeTestFile(t, childPath, `{"getItem":{"script":"./get_item.js","description":"included"}}`)
	writeTestFile(t, filepath.Join(rootDir, "sub", "get_item.js"), `JSON.stringify({api:nyanAllParams.api})`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}

	tests := []struct {
		name    string
		request *http.Request
	}{
		{name: "URL path", request: httptest.NewRequest(http.MethodGet, "/sub/getItem", nil)},
		{name: "query parameter", request: httptest.NewRequest(http.MethodGet, "/?api=sub/getItem", nil)},
		{name: "POST JSON", request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"api":"sub/getItem"}`))},
	}
	tests[2].request.Header.Set("Content-Type", "application/json")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handleRequestWithSnapshot(result.Snapshot, recorder, tt.request)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"api":"sub/getItem"`) {
				t.Fatalf("response = status %d body %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	rpcRecorder := httptest.NewRecorder()
	rpcRequest := httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","method":"sub/getItem","params":{},"id":1}`))
	handleJSONRPCWithSnapshot(result.Snapshot, rpcRecorder, rpcRequest)
	if rpcRecorder.Code != http.StatusOK || !strings.Contains(rpcRecorder.Body.String(), `"api":"sub/getItem"`) {
		t.Fatalf("JSON-RPC response = status %d body %s", rpcRecorder.Code, rpcRecorder.Body.String())
	}

	detailRecorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(result.Snapshot, detailRecorder, httptest.NewRequest(http.MethodGet, "/nyan/sub/getItem", nil))
	if detailRecorder.Code != http.StatusOK || !strings.Contains(detailRecorder.Body.String(), `"api":"sub/getItem"`) {
		t.Fatalf("detail response = status %d body %s", detailRecorder.Code, detailRecorder.Body.String())
	}

	listRecorder := httptest.NewRecorder()
	handleNyanWithSnapshot(result.Snapshot, listRecorder, httptest.NewRequest(http.MethodGet, "/nyan/", nil))
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), `"sub/getItem"`) {
		t.Fatalf("API list response = status %d body %s", listRecorder.Code, listRecorder.Body.String())
	}
}

func TestOneLevelIncludedPublicAPIUsesFullMountPath(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	childPath := filepath.Join(rootDir, "sub", "api.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"./sub/api.json"}}`)
	writeTestFile(t, childPath, `{"assets":{"type":"public","path":"./public"}}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	apiKey, requestedPath, _, ok := findPublicAPIForPathInSnapshot(result.Snapshot, "/sub/assets/app.js")
	if !ok || apiKey != "sub/assets" || requestedPath != "app.js" {
		t.Fatalf("public match = key %q path %q ok=%t", apiKey, requestedPath, ok)
	}
}

func TestOneLevelIncludeDefinitionValidation(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "missing path", data: `{"sub":{"type":"include"}}`, want: "path is empty"},
		{name: "empty path", data: `{"sub":{"type":"include","path":"  "}}`, want: "path is empty"},
		{name: "non-string path", data: `{"sub":{"type":"include","path":1}}`, want: "cannot unmarshal number"},
		{name: "SQL mixed in", data: `{"sub":{"type":"include","path":"child.json","sql":["query.sql"]}}`, want: `unsupported field "sql"`},
		{name: "description mixed in", data: `{"sub":{"type":"include","path":"child.json","description":"ambiguous"}}`, want: `unsupported field "description"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootPath := filepath.Join(t.TempDir(), "api.json")
			writeTestFile(t, rootPath, tt.data)
			_, err := loadAPIConfigFile(rootPath)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadAPIConfigFile() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestOneLevelIncludeRejectsInvalidMountNames(t *testing.T) {
	for _, mountName := range []string{"", ".", "..", "sub/admin", " sub", "sub "} {
		t.Run(fmt.Sprintf("mount_%q", mountName), func(t *testing.T) {
			rootDir := t.TempDir()
			rootPath := filepath.Join(rootDir, "api.json")
			writeTestFile(t, filepath.Join(rootDir, "child.json"), `{}`)
			writeTestFile(t, rootPath, fmt.Sprintf(`{%q:{"type":"include","path":"child.json"}}`, mountName))
			_, err := loadAPIConfigFile(rootPath)
			if err == nil || !strings.Contains(err.Error(), "invalid include mount name") {
				t.Fatalf("loadAPIConfigFile() error = %v, want invalid mount error", err)
			}
		})
	}
}

func TestOneLevelIncludeFileValidation(t *testing.T) {
	tests := []struct {
		name       string
		childSetup func(t *testing.T, path string)
		want       string
	}{
		{name: "missing file", want: "file not found"},
		{
			name: "directory",
			childSetup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "not a regular file",
		},
		{
			name: "invalid JSON",
			childSetup: func(t *testing.T, path string) {
				writeTestFile(t, path, `{"broken":`)
			},
			want: "decode api JSON",
		},
		{
			name: "non-object JSON",
			childSetup: func(t *testing.T, path string) {
				writeTestFile(t, path, `[]`)
			},
			want: "top-level value must be an object",
		},
		{
			name: "duplicate child key",
			childSetup: func(t *testing.T, path string) {
				writeTestFile(t, path, `{"item":{"description":"first"},"item":{"description":"second"}}`)
			},
			want: "duplicate key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootDir := t.TempDir()
			rootPath := filepath.Join(rootDir, "api.json")
			childPath := filepath.Join(rootDir, "child.json")
			writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
			if tt.childSetup != nil {
				tt.childSetup(t, childPath)
			}
			_, err := loadAPIConfigFile(rootPath)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadAPIConfigFile() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestIncludeRejectsMountNamespaceCollision(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	writeTestFile(t, rootPath, `{
		"sub/item":{"description":"direct"},
		"sub":{"type":"include","path":"child.json"}
	}`)
	writeTestFile(t, filepath.Join(rootDir, "child.json"), `{"item":{"description":"included"}}`)

	_, err := loadAPIConfigFile(rootPath)
	if err == nil || !strings.Contains(err.Error(), `API name "sub/item" conflicts with mount namespace "sub"`) {
		t.Fatalf("loadAPIConfigFile() error = %v, want mount namespace collision", err)
	}
}

func TestOneLevelIncludeAllowsSameFileAtDifferentMounts(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	childPath := filepath.Join(rootDir, "child.json")
	writeTestFile(t, rootPath, `{
		"first":{"type":"include","path":"child.json"},
		"second":{"type":"include","path":"./child.json"}
	}`)
	writeTestFile(t, childPath, `{"item":{"description":"shared"}}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	for _, name := range []string{"first/item", "second/item"} {
		if result.Snapshot.Definitions[name].Description != "shared" {
			t.Fatalf("definition %q was not expanded", name)
		}
	}
	if len(result.Snapshot.Files) != 2 {
		t.Fatalf("physical file count = %d, want root and deduplicated child", len(result.Snapshot.Files))
	}
}

func TestLoadAPIConfigFileExpandsMultiLevelInclude(t *testing.T) {
	rootDir := t.TempDir()
	subDir := filepath.Join(rootDir, "sub")
	adminDir := filepath.Join(subDir, "admin")
	rootPath := filepath.Join(rootDir, "api.json")
	subPath := filepath.Join(subDir, "api.json")
	adminPath := filepath.Join(adminDir, "api.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"./sub/api.json"}}`)
	writeTestFile(t, subPath, `{
		"getItem":{"sql":["./sql/get_item.sql"]},
		"admin":{"type":"include","path":"./admin/api.json"}
	}`)
	writeTestFile(t, adminPath, `{
		"getUser":{"script":"./get_user.js","description":"nested"},
		"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 10 * * *"}}
	}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	if got := result.Snapshot.Definitions["sub/getItem"].SQL[0]; got != filepath.Join(subDir, "sql/get_item.sql") {
		t.Fatalf("second-level SQL path = %q, want sub-file-relative path", got)
	}
	if got := result.Snapshot.Definitions["sub/admin/getUser"].Script; got != filepath.Join(adminDir, "get_user.js") {
		t.Fatalf("third-level script path = %q, want admin-file-relative path", got)
	}
	if got := result.Snapshot.Sources["sub/admin/getUser"]; got != adminPath {
		t.Fatalf("nested source = %q, want %q", got, adminPath)
	}
	if got := result.Schedules["sub/admin/job"].scriptPath; got != filepath.Join(adminDir, "job.js") {
		t.Fatalf("nested schedule path = %q, want admin-file-relative path", got)
	}
	if len(result.Snapshot.Files) != 3 {
		t.Fatalf("physical file count = %d, want 3", len(result.Snapshot.Files))
	}
}

func TestNyanListsIncludedAPIsAsFlatCompleteNames(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	subPath := filepath.Join(rootDir, "sub", "api.json")
	adminPath := filepath.Join(rootDir, "sub", "admin", "api.json")
	writeTestFile(t, rootPath, `{
		"health":{"description":"root"},
		"legacy/path":{"description":"legacy"},
		"sub":{"type":"include","path":"./sub/api.json"}
	}`)
	writeTestFile(t, subPath, `{
		"getItem":{"description":"item"},
		"assets":{"type":"public","path":"./public"},
		"admin":{"type":"include","path":"./admin/api.json"}
	}`)
	writeTestFile(t, adminPath, `{
		"getUser":{"description":"user"},
		"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 10 * * *"}}
	}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	handleNyanWithSnapshot(result.Snapshot, recorder, httptest.NewRequest(http.MethodGet, "/nyan/", nil))

	var response NyanResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := map[string]APIDetails{
		"health":            {Description: "root"},
		"legacy/path":       {Description: "legacy"},
		"sub/getItem":       {Description: "item"},
		"sub/admin/getUser": {Description: "user"},
	}
	if !reflect.DeepEqual(response.Apis, want) {
		t.Fatalf("apis = %#v, want %#v", response.Apis, want)
	}
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &rawResponse); err != nil {
		t.Fatal(err)
	}
	if _, exists := rawResponse["apiTree"]; exists {
		t.Fatalf("response unexpectedly contains apiTree: %s", recorder.Body.String())
	}
}

func TestMultiLevelIncludedAPIPathCalls(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	subPath := filepath.Join(rootDir, "sub", "api.json")
	adminPath := filepath.Join(rootDir, "sub", "admin", "api.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"./sub/api.json"}}`)
	writeTestFile(t, subPath, `{"admin":{"type":"include","path":"./admin/api.json"}}`)
	writeTestFile(t, adminPath, `{"getUser":{"script":"./get_user.js"}}`)
	writeTestFile(t, filepath.Join(rootDir, "sub", "admin", "get_user.js"), `JSON.stringify({api:nyanAllParams.api})`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/sub/admin/getUser", nil),
		httptest.NewRequest(http.MethodGet, "/?api=sub/admin/getUser", nil),
	} {
		recorder := httptest.NewRecorder()
		handleRequestWithSnapshot(result.Snapshot, recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"api":"sub/admin/getUser"`) {
			t.Fatalf("response = status %d body %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestIncludeCycleDetection(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "api.json")
		writeTestFile(t, rootPath, `{"self":{"type":"include","path":"./api.json"}}`)
		_, err := loadAPIConfigFile(rootPath)
		if err == nil || !strings.Contains(err.Error(), "include cycle detected:") || strings.Count(err.Error(), rootPath) != 2 {
			t.Fatalf("loadAPIConfigFile() error = %v, want direct cycle path", err)
		}
	})

	t.Run("indirect", func(t *testing.T) {
		rootDir := t.TempDir()
		rootPath := filepath.Join(rootDir, "api.json")
		subPath := filepath.Join(rootDir, "sub", "api.json")
		adminPath := filepath.Join(rootDir, "sub", "admin", "api.json")
		writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"./sub/api.json"}}`)
		writeTestFile(t, subPath, `{"admin":{"type":"include","path":"./admin/api.json"}}`)
		writeTestFile(t, adminPath, `{"root":{"type":"include","path":"../../api.json"}}`)

		_, err := loadAPIConfigFile(rootPath)
		if err == nil || !strings.Contains(err.Error(), "include cycle detected:") {
			t.Fatalf("loadAPIConfigFile() error = %v, want indirect cycle", err)
		}
		for _, path := range []string{rootPath, subPath, adminPath} {
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("cycle error = %q, want path %s", err, path)
			}
		}
		if strings.Count(err.Error(), rootPath) != 2 {
			t.Fatalf("cycle error = %q, want repeated root path", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		rootDir := t.TempDir()
		rootPath := filepath.Join(rootDir, "api.json")
		aliasPath := filepath.Join(rootDir, "alias.json")
		writeTestFile(t, rootPath, `{"alias":{"type":"include","path":"./alias.json"}}`)
		if err := os.Symlink(rootPath, aliasPath); err != nil {
			t.Skipf("symlink is unavailable: %v", err)
		}
		_, err := loadAPIConfigFile(rootPath)
		if err == nil || !strings.Contains(err.Error(), "include cycle detected:") || !strings.Contains(err.Error(), aliasPath) {
			t.Fatalf("loadAPIConfigFile() error = %v, want symlink cycle", err)
		}
	})
}

func TestNestedMountNamespaceCollision(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	childPath := filepath.Join(rootDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{
		"admin/getUser":{"description":"direct"},
		"admin":{"type":"include","path":"admin.json"}
	}`)
	writeTestFile(t, filepath.Join(rootDir, "admin.json"), `{}`)

	_, err := loadAPIConfigFile(rootPath)
	if err == nil || !strings.Contains(err.Error(), `API name "admin/getUser" conflicts with mount namespace "admin"`) {
		t.Fatalf("loadAPIConfigFile() error = %v, want nested namespace collision", err)
	}
}

func TestMountNamespaceDoesNotBlockOtherSlashNames(t *testing.T) {
	rootDir := t.TempDir()
	rootPath := filepath.Join(rootDir, "api.json")
	writeTestFile(t, rootPath, `{
		"legacy/path":{"description":"legacy"},
		"submarine/item":{"description":"separate prefix"},
		"sub":{"type":"include","path":"child.json"}
	}`)
	writeTestFile(t, filepath.Join(rootDir, "child.json"), `{"item":{"description":"included"}}`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	for _, name := range []string{"legacy/path", "submarine/item", "sub/item"} {
		if _, exists := result.Snapshot.Definitions[name]; !exists {
			t.Fatalf("definition %q is missing", name)
		}
	}
}

func TestParseAPIHotReloadInterval(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", value: "", want: time.Second},
		{name: "duration", value: "250ms", want: 250 * time.Millisecond},
		{name: "invalid", value: "later", wantErr: true},
		{name: "zero", value: "0s", wantErr: true},
		{name: "negative", value: "-1s", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAPIHotReloadInterval(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseAPIHotReloadInterval(%q) error = nil, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAPIHotReloadInterval(%q) error = %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseAPIHotReloadInterval(%q) = %s, want %s", tt.value, got, tt.want)
			}
		})
	}
}

func TestConfigAPIHotReloadDefaultsAndOverrides(t *testing.T) {
	tests := []struct {
		name string
		data string
		want APIHotReloadConfig
	}{
		{
			name: "omitted",
			data: `{}`,
			want: APIHotReloadConfig{Enabled: true, Interval: "1s"},
		},
		{
			name: "explicitly disabled",
			data: `{"APIHotReload":{"Enabled":false}}`,
			want: APIHotReloadConfig{Enabled: false, Interval: "1s"},
		},
		{
			name: "custom interval",
			data: `{"APIHotReload":{"Enabled":true,"Interval":"2s"}}`,
			want: APIHotReloadConfig{Enabled: true, Interval: "2s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Config
			applyConfigDefaults(&got)
			if err := json.Unmarshal([]byte(tt.data), &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if got.APIHotReload != tt.want {
				t.Fatalf("APIHotReload = %#v, want %#v", got.APIHotReload, tt.want)
			}
		})
	}
}

func TestReloadSQLFilesIfChangedAppliesHTTPChanges(t *testing.T) {
	apiDir := t.TempDir()
	apiPath := filepath.Join(apiDir, "api.json")
	writeTestFile(t, apiPath, `{"old":{"description":"old"}}`)

	initialFiles, initialHash, err := readSQLFiles(apiPath, apiDir)
	if err != nil {
		t.Fatalf("readSQLFiles() error = %v", err)
	}
	setTestSQLFiles(t, initialFiles)
	writeTestFile(t, apiPath, `{"new":{"description":"new"}}`)

	observedHash, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, initialHash)
	if err != nil {
		t.Fatalf("reloadSQLFilesIfChanged() error = %v", err)
	}
	if !reloaded {
		t.Fatal("reloadSQLFilesIfChanged() reloaded = false, want true")
	}
	if observedHash == initialHash {
		t.Fatal("observed hash was not updated")
	}
	files := currentSQLFiles()
	if _, exists := files["old"]; exists {
		t.Fatal("old API remains after reload")
	}
	if files["new"].Description != "new" {
		t.Fatalf("new API = %#v, want updated definition", files["new"])
	}
}

func TestReloadSQLFilesIfChangedKeepsCurrentDefinitionOnInvalidJSON(t *testing.T) {
	apiDir := t.TempDir()
	apiPath := filepath.Join(apiDir, "api.json")
	writeTestFile(t, apiPath, `{"current":{"description":"active"}}`)

	initialFiles, initialHash, err := readSQLFiles(apiPath, apiDir)
	if err != nil {
		t.Fatalf("readSQLFiles() error = %v", err)
	}
	setTestSQLFiles(t, initialFiles)
	writeTestFile(t, apiPath, `{"broken":`)

	observedHash, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, initialHash)
	if err == nil {
		t.Fatal("reloadSQLFilesIfChanged() error = nil, want JSON error")
	}
	if reloaded {
		t.Fatal("reloadSQLFilesIfChanged() reloaded = true, want false")
	}
	if observedHash == initialHash {
		t.Fatal("invalid content was not recorded as observed")
	}
	if currentSQLFiles()["current"].Description != "active" {
		t.Fatal("current API definition changed after invalid JSON")
	}

	secondHash, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, observedHash)
	if err != nil {
		t.Fatalf("unchanged invalid content was parsed again: %v", err)
	}
	if reloaded || secondHash != observedHash {
		t.Fatal("unchanged invalid content should be skipped")
	}
}

func TestReloadSQLFilesIfChangedRejectsDuplicateKeys(t *testing.T) {
	apiDir := t.TempDir()
	apiPath := filepath.Join(apiDir, "api.json")
	writeTestFile(t, apiPath, `{"current":{"description":"active"}}`)

	initialFiles, initialHash, err := readSQLFiles(apiPath, apiDir)
	if err != nil {
		t.Fatalf("readSQLFiles() error = %v", err)
	}
	setTestSQLFiles(t, initialFiles)
	writeTestFile(t, apiPath, `{"replacement":{"description":"first"},"replacement":{"description":"second"}}`)

	observedHash, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, initialHash)
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("reloadSQLFilesIfChanged() error = %v, want duplicate-key error", err)
	}
	if reloaded {
		t.Fatal("reloadSQLFilesIfChanged() reloaded = true, want false")
	}
	if currentSQLFiles()["current"].Description != "active" {
		t.Fatal("current API definition changed after duplicate-key error")
	}

	secondHash, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, observedHash)
	if err != nil || reloaded || secondHash != observedHash {
		t.Fatalf("unchanged duplicate content should be skipped: hash=%x reloaded=%t err=%v", secondHash, reloaded, err)
	}
}

func TestReloadSQLFilesIfChangedAppliesBackgroundChanges(t *testing.T) {
	tests := []struct {
		name    string
		initial string
		changed string
	}{
		{
			name:    "schedule",
			initial: `{"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 10 * * *"}},"api":{"description":"old"}}`,
			changed: `{"job":{"type":"schedule","script":"./job.js","trigger":{"type":"cron","value":"0 11 * * *"}},"api":{"description":"new"}}`,
		},
		{
			name:    "ws_client",
			initial: `{"client":{"type":"ws_client","script":"./client.js","connectURL":"ws://localhost:8080/old"},"api":{"description":"old"}}`,
			changed: `{"client":{"type":"ws_client","script":"./client.js","connectURL":"ws://localhost:8080/new"},"api":{"description":"new"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiDir := t.TempDir()
			apiPath := filepath.Join(apiDir, "api.json")
			writeTestFile(t, apiPath, tt.initial)
			initialFiles, initialHash, err := readSQLFiles(apiPath, apiDir)
			if err != nil {
				t.Fatalf("readSQLFiles() error = %v", err)
			}
			setTestSQLFiles(t, initialFiles)
			writeTestFile(t, apiPath, tt.changed)

			_, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, initialHash)
			if err != nil {
				t.Fatalf("reloadSQLFilesIfChanged() error = %v", err)
			}
			if !reloaded {
				t.Fatal("reloadSQLFilesIfChanged() reloaded = false, want true")
			}
			if currentSQLFiles()["api"].Description != "new" {
				t.Fatal("HTTP API change was not applied with background change")
			}
		})
	}
}

func TestReloadSQLFilesIfChangedRejectsInvalidBackgroundConfig(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
	}{
		{
			name:      "schedule without script",
			candidate: `{"job":{"type":"schedule","trigger":{"type":"cron","value":"0 10 * * *"}}}`,
		},
		{
			name:      "ws_client without connectURL",
			candidate: `{"client":{"type":"ws_client","script":"./client.js"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiDir := t.TempDir()
			apiPath := filepath.Join(apiDir, "api.json")
			writeTestFile(t, apiPath, `{"current":{"description":"active"}}`)
			initialFiles, initialHash, err := readSQLFiles(apiPath, apiDir)
			if err != nil {
				t.Fatalf("readSQLFiles() error = %v", err)
			}
			setTestSQLFiles(t, initialFiles)
			writeTestFile(t, apiPath, tt.candidate)

			_, reloaded, err := reloadSQLFilesIfChanged(apiPath, apiDir, initialHash)
			if err == nil {
				t.Fatal("reloadSQLFilesIfChanged() error = nil, want validation error")
			}
			if reloaded {
				t.Fatal("reloadSQLFilesIfChanged() reloaded = true, want false")
			}
			if currentSQLFiles()["current"].Description != "active" {
				t.Fatal("current API definition changed after invalid background config")
			}
		})
	}
}

func TestReloadAPIConfigGraphDetectsNestedIncludeChanges(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	grandchildPath := filepath.Join(apiDir, "grandchild.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"local":{"description":"old child"},"admin":{"type":"include","path":"grandchild.json"}}`)
	writeTestFile(t, grandchildPath, `{"user":{"description":"old grandchild"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, childPath, `{"local":{"description":"new child"},"admin":{"type":"include","path":"grandchild.json"}}`)
	writeTestFile(t, grandchildPath, `{"user":{"description":"new grandchild"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil {
		t.Fatalf("reloadAPIConfigGraphIfChanged() error = %v", err)
	}
	if !reloaded {
		t.Fatal("reloadAPIConfigGraphIfChanged() reloaded = false, want true")
	}
	if len(observed) != 3 {
		t.Fatalf("observed file count = %d, want 3", len(observed))
	}
	if got := currentSQLFiles()["sub/local"].Description; got != "new child" {
		t.Fatalf("sub/local description = %q, want new child", got)
	}
	if got := currentSQLFiles()["sub/admin/user"].Description; got != "new grandchild" {
		t.Fatalf("sub/admin/user description = %q, want new grandchild", got)
	}
}

func TestReloadAPIConfigGraphUpdatesWatchedFilesAfterIncludeAddAndRemove(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"health":{"description":"ok"}}`)
	writeTestFile(t, childPath, `{"item":{"description":"included"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, rootPath, `{"health":{"description":"ok"},"sub":{"type":"include","path":"child.json"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("add include reload: reloaded=%t err=%v", reloaded, err)
	}
	if len(observed) != 2 {
		t.Fatalf("file count after add = %d, want 2", len(observed))
	}
	if _, exists := currentSQLFiles()["sub/item"]; !exists {
		t.Fatal("included API was not published")
	}

	writeTestFile(t, rootPath, `{"health":{"description":"ok"}}`)
	observed, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("remove include reload: reloaded=%t err=%v", reloaded, err)
	}
	if len(observed) != 1 {
		t.Fatalf("file count after remove = %d, want 1", len(observed))
	}
	if _, exists := currentSQLFiles()["sub/item"]; exists {
		t.Fatal("removed included API remains published")
	}
}

func TestReloadAPIConfigGraphUpdatesWatchedFilesFromNestedInclude(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	grandchildPath := filepath.Join(apiDir, "grandchild.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"local":{"description":"local"}}`)
	writeTestFile(t, grandchildPath, `{"user":{"description":"nested"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, childPath, `{"local":{"description":"local"},"admin":{"type":"include","path":"grandchild.json"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("nested include add reload: reloaded=%t err=%v", reloaded, err)
	}
	if len(observed) != 3 {
		t.Fatalf("file count after nested add = %d, want 3", len(observed))
	}
	if _, exists := currentSQLFiles()["sub/admin/user"]; !exists {
		t.Fatal("nested included API was not published")
	}

	writeTestFile(t, childPath, `{"local":{"description":"local"}}`)
	observed, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("nested include remove reload: reloaded=%t err=%v", reloaded, err)
	}
	if len(observed) != 2 {
		t.Fatalf("file count after nested remove = %d, want 2", len(observed))
	}
	if _, exists := currentSQLFiles()["sub/admin/user"]; exists {
		t.Fatal("removed nested API remains published")
	}
}

func TestReloadAPIConfigGraphPublishesChangedSourceWithSameDefinitions(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	firstPath := filepath.Join(apiDir, "first.json")
	secondPath := filepath.Join(apiDir, "second.json")
	definition := `{"item":{"description":"same"}}`
	writeTestFile(t, firstPath, definition)
	writeTestFile(t, secondPath, definition)
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"first.json"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"second.json"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil {
		t.Fatalf("reloadAPIConfigGraphIfChanged() error = %v", err)
	}
	if !reloaded {
		t.Fatal("source-only change was not published")
	}
	if got := currentAPISnapshot().Sources["sub/item"]; got != secondPath {
		t.Fatalf("source = %q, want %q", got, secondPath)
	}
	if _, exists := observed[secondPath]; !exists {
		t.Fatal("new include file is not in the watched set")
	}
}

func TestVerifyAPIFileStatesRejectsChangesAfterLoad(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"item":{"description":"old"}}`)

	loaded := loadTestAPIConfig(t, rootPath)
	writeTestFile(t, childPath, `{"item":{"description":"new"}}`)
	if err := verifyAPIFileStates(loaded.Snapshot.Files); err == nil {
		t.Fatal("verifyAPIFileStates() error = nil, want concurrent-change error")
	}
}

func TestReloadAPIConfigGraphWatchesMissingCandidateIncludeUntilCreated(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"health":{"description":"active"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, rootPath, `{"health":{"description":"candidate"},"sub":{"type":"include","path":"child.json"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err == nil || !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("missing include error = %v, want file-not-found error", err)
	}
	if reloaded {
		t.Fatal("invalid candidate was published")
	}
	if got := currentSQLFiles()["health"].Description; got != "active" {
		t.Fatalf("active snapshot changed to %q", got)
	}
	missingState, exists := observed[childPath]
	if !exists || missingState.Exists || missingState.Error != "not_found" {
		t.Fatalf("missing include state = %#v, exists=%t", missingState, exists)
	}

	unchanged, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || reloaded {
		t.Fatalf("unchanged failed candidate was retried: reloaded=%t err=%v", reloaded, err)
	}
	if !reflect.DeepEqual(unchanged, observed) {
		t.Fatal("unchanged failed candidate altered the watched state")
	}

	writeTestFile(t, childPath, `{"item":{"description":"created"}}`)
	observed, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("created include reload: reloaded=%t err=%v", reloaded, err)
	}
	if got := currentSQLFiles()["sub/item"].Description; got != "created" {
		t.Fatalf("created include description = %q", got)
	}
	if len(observed) != 2 {
		t.Fatalf("successful watched file count = %d, want 2", len(observed))
	}
}

func TestReloadAPIConfigGraphWatchesMissingNestedCandidateInclude(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	grandchildPath := filepath.Join(apiDir, "grandchild.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"local":{"description":"active"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, childPath, `{"local":{"description":"candidate"},"admin":{"type":"include","path":"grandchild.json"}}`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err == nil || reloaded {
		t.Fatalf("missing nested include: reloaded=%t err=%v", reloaded, err)
	}
	if _, exists := observed[grandchildPath]; !exists {
		t.Fatal("missing nested include was not retained in watched files")
	}
	if got := currentSQLFiles()["sub/local"].Description; got != "active" {
		t.Fatalf("active nested definition changed to %q", got)
	}

	writeTestFile(t, grandchildPath, `{"user":{"description":"created"}}`)
	observed, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("created nested include reload: reloaded=%t err=%v", reloaded, err)
	}
	if len(observed) != 3 {
		t.Fatalf("successful watched file count = %d, want 3", len(observed))
	}
	if _, exists := currentSQLFiles()["sub/admin/user"]; !exists {
		t.Fatal("created nested API was not published")
	}
}

func TestReloadAPIConfigGraphWatchesInvalidCandidateIncludeUntilCorrected(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"health":{"description":"active"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"broken":`)

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err == nil || reloaded {
		t.Fatalf("invalid include reload: reloaded=%t err=%v", reloaded, err)
	}
	invalidState, exists := observed[childPath]
	if !exists || !invalidState.Exists || invalidState.Hash == ([sha256.Size]byte{}) {
		t.Fatalf("invalid include state = %#v, exists=%t", invalidState, exists)
	}
	if _, exists := currentSQLFiles()["health"]; !exists {
		t.Fatal("active snapshot was replaced after invalid include JSON")
	}

	writeTestFile(t, childPath, `{"item":{"description":"corrected"}}`)
	_, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("corrected include reload: reloaded=%t err=%v", reloaded, err)
	}
	if got := currentSQLFiles()["sub/item"].Description; got != "corrected" {
		t.Fatalf("corrected description = %q", got)
	}
}

func TestReloadAPIConfigGraphKeepsDeletedActiveIncludeWatched(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"item":{"description":"active"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	if err := os.Remove(childPath); err != nil {
		t.Fatal(err)
	}

	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err == nil || reloaded {
		t.Fatalf("deleted include reload: reloaded=%t err=%v", reloaded, err)
	}
	if _, exists := currentSQLFiles()["sub/item"]; !exists {
		t.Fatal("active API was removed after include deletion")
	}
	missingState, exists := observed[childPath]
	if !exists || missingState.Exists || missingState.Error != "not_found" {
		t.Fatalf("deleted include state = %#v, exists=%t", missingState, exists)
	}

	writeTestFile(t, childPath, `{"item":{"description":"restored"}}`)
	_, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("restored include reload: reloaded=%t err=%v", reloaded, err)
	}
	if got := currentSQLFiles()["sub/item"].Description; got != "restored" {
		t.Fatalf("restored description = %q", got)
	}
}

func TestAPIFileStatesFingerprintIsDeterministicAndStateSensitive(t *testing.T) {
	first := map[string]APIFileState{
		"/b.json": {Path: "/b.json", Exists: false, Error: "not_found"},
		"/a.json": {Path: "/a.json", Exists: true, Hash: [sha256.Size]byte{1}},
	}
	second := map[string]APIFileState{
		"/a.json": {Path: "/a.json", Exists: true, Hash: [sha256.Size]byte{1}},
		"/b.json": {Path: "/b.json", Exists: false, Error: "not_found"},
	}
	if apiFileStatesFingerprint(first) != apiFileStatesFingerprint(second) {
		t.Fatal("fingerprint depends on map iteration order")
	}
	changed := cloneAPIFileStates(second)
	changed["/b.json"] = APIFileState{Path: "/b.json", Exists: true, Hash: [sha256.Size]byte{2}}
	if apiFileStatesFingerprint(first) == apiFileStatesFingerprint(changed) {
		t.Fatal("fingerprint did not change with file state")
	}
	retargeted := cloneAPIFileStates(first)
	state := retargeted["/a.json"]
	state.Identity = "/new-target.json"
	retargeted["/a.json"] = state
	if apiFileStatesFingerprint(first) == apiFileStatesFingerprint(retargeted) {
		t.Fatal("fingerprint did not change with symlink target")
	}
}

func TestIncludedScheduleHotReloadUpdatesAndStopsWithMount(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"job":{"type":"schedule","script":"job-v1.js","trigger":{"type":"cron","value":"0 0 1 1 *"}}}`)

	initial := loadTestAPIConfig(t, rootPath)
	oldSnapshot := currentAPISnapshot()
	oldBackgroundRuntimes := backgroundRuntimes
	manager := newBackgroundRuntimeManager()
	setAPISnapshot(initial.Snapshot)
	backgroundRuntimes = manager
	manager.reconcile(initial.Snapshot.Schedules, initial.Snapshot.WSClients)
	t.Cleanup(func() {
		manager.reconcile(nil, nil)
		backgroundRuntimes = oldBackgroundRuntimes
		setAPISnapshot(oldSnapshot)
	})

	manager.mu.Lock()
	runtime := manager.schedules["sub/job"]
	manager.mu.Unlock()
	if runtime == nil {
		t.Fatal("included schedule was not started with its full name")
	}

	writeTestFile(t, childPath, `{"job":{"type":"schedule","script":"job-v2.js","trigger":{"type":"cron","value":"0 0 2 1 *"}}}`)
	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("schedule update reload: reloaded=%t err=%v", reloaded, err)
	}
	manager.mu.Lock()
	updatedRuntime := manager.schedules["sub/job"]
	manager.mu.Unlock()
	if updatedRuntime != runtime {
		t.Fatal("included schedule update created a second runtime")
	}
	updated, active := runtime.currentConfig()
	if !active || updated.scriptPath != filepath.Join(apiDir, "job-v2.js") || updated.trigger.Value != "0 0 2 1 *" {
		t.Fatalf("updated schedule = %#v, active=%t", updated, active)
	}
	if got := currentAPISnapshot().Schedules["sub/job"].scriptPath; got != updated.scriptPath {
		t.Fatalf("snapshot schedule path = %q, want %q", got, updated.scriptPath)
	}

	writeTestFile(t, rootPath, `{}`)
	observed, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("schedule mount removal reload: reloaded=%t err=%v", reloaded, err)
	}
	waitForSignal(t, runtime.done, "included schedule stop")
	if _, exists := currentAPISnapshot().Schedules["sub/job"]; exists {
		t.Fatal("removed included schedule remains in snapshot")
	}
	if len(observed) != 1 {
		t.Fatalf("watched file count after mount removal = %d, want 1", len(observed))
	}
}

func TestIncludedWSClientHotReloadReconnectsAndStopsWithMount(t *testing.T) {
	firstURL, firstConnected, firstDisconnected := newWebSocketRuntimeTestServer(t)
	secondURL, secondConnected, secondDisconnected := newWebSocketRuntimeTestServer(t)
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, fmt.Sprintf(`{"client":{"type":"ws_client","script":"client-v1.js","connectURL":%q}}`, firstURL))

	initial := loadTestAPIConfig(t, rootPath)
	oldSnapshot := currentAPISnapshot()
	oldBackgroundRuntimes := backgroundRuntimes
	manager := newBackgroundRuntimeManager()
	setAPISnapshot(initial.Snapshot)
	backgroundRuntimes = manager
	manager.reconcile(initial.Snapshot.Schedules, initial.Snapshot.WSClients)
	t.Cleanup(func() {
		manager.reconcile(nil, nil)
		backgroundRuntimes = oldBackgroundRuntimes
		setAPISnapshot(oldSnapshot)
	})
	waitForSignal(t, firstConnected, "included WebSocket connection")

	manager.mu.Lock()
	runtime := manager.wsClients["sub/client"]
	manager.mu.Unlock()
	if runtime == nil {
		t.Fatal("included ws_client was not started with its full name")
	}

	writeTestFile(t, childPath, fmt.Sprintf(`{"client":{"type":"ws_client","script":"client-v2.js","connectURL":%q}}`, secondURL))
	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("ws_client update reload: reloaded=%t err=%v", reloaded, err)
	}
	waitForSignal(t, firstDisconnected, "old included WebSocket disconnection")
	waitForSignal(t, secondConnected, "updated included WebSocket connection")
	updated, active := runtime.currentConfig()
	if !active || updated.connectURL != secondURL || updated.scriptPath != filepath.Join(apiDir, "client-v2.js") {
		t.Fatalf("updated ws_client = %#v, active=%t", updated, active)
	}
	if got := currentAPISnapshot().WSClients["sub/client"].connectURL; got != secondURL {
		t.Fatalf("snapshot ws_client URL = %q, want %q", got, secondURL)
	}

	writeTestFile(t, rootPath, `{}`)
	_, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("ws_client mount removal reload: reloaded=%t err=%v", reloaded, err)
	}
	waitForSignal(t, secondDisconnected, "included WebSocket mount removal")
	waitForSignal(t, runtime.done, "included ws_client stop")
	if _, exists := currentAPISnapshot().WSClients["sub/client"]; exists {
		t.Fatal("removed included ws_client remains in snapshot")
	}
}

func TestIncludedPublicAPIHotReloadUsesNewCompletePath(t *testing.T) {
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"assets":{"type":"public","path":"public-v1"}}`)

	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	writeTestFile(t, childPath, `{"static":{"type":"public","path":"public-v2"}}`)

	_, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("public update reload: reloaded=%t err=%v", reloaded, err)
	}
	snapshot := currentAPISnapshot()
	if _, _, _, ok := findPublicAPIForPathInSnapshot(snapshot, "/sub/assets/app.js"); ok {
		t.Fatal("removed included public path still matches")
	}
	apiName, requestedPath, config, ok := findPublicAPIForPathInSnapshot(snapshot, "/sub/static/app.js")
	if !ok || apiName != "sub/static" || requestedPath != "app.js" {
		t.Fatalf("new public match = name %q path %q ok=%t", apiName, requestedPath, ok)
	}
	if config.Path != filepath.Join(apiDir, "public-v2") {
		t.Fatalf("new public filesystem path = %q", config.Path)
	}
	if _, exists := snapshot.APIs["sub/static"]; exists {
		t.Fatal("public definition was included in HTTP API list")
	}
}

func TestBackgroundRuntimeManagerUpdatesAndStopsSchedule(t *testing.T) {
	manager := newBackgroundRuntimeManager()
	firstSchedule, err := parseCronSchedule("0 0 1 1 *")
	if err != nil {
		t.Fatal(err)
	}
	first := scheduleJobConfig{
		name:       "job",
		scriptPath: "/tmp/job-v1.js",
		trigger:    TriggerConfig{Type: "cron", Value: "0 0 1 1 *"},
		schedule:   firstSchedule,
	}
	manager.reconcile(map[string]scheduleJobConfig{"job": first}, nil)

	manager.mu.Lock()
	runtime := manager.schedules["job"]
	manager.mu.Unlock()
	if runtime == nil {
		t.Fatal("schedule runtime was not started")
	}

	secondSchedule, err := parseCronSchedule("0 0 2 1 *")
	if err != nil {
		t.Fatal(err)
	}
	second := scheduleJobConfig{
		name:       "job",
		scriptPath: "/tmp/job-v2.js",
		trigger:    TriggerConfig{Type: "cron", Value: "0 0 2 1 *"},
		schedule:   secondSchedule,
	}
	manager.reconcile(map[string]scheduleJobConfig{"job": second}, nil)

	manager.mu.Lock()
	updatedRuntime := manager.schedules["job"]
	manager.mu.Unlock()
	if updatedRuntime != runtime {
		t.Fatal("schedule update created a second runtime")
	}
	got, active := runtime.currentConfig()
	if !active || got.scriptPath != second.scriptPath || got.trigger != second.trigger {
		t.Fatalf("schedule runtime config = %#v, want %#v", got, second)
	}

	manager.reconcile(nil, nil)
	waitForSignal(t, runtime.done, "schedule runtime stop")
	waitForCondition(t, "schedule runtime cleanup", func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		_, exists := manager.schedules["job"]
		return !exists
	})
}

func TestBackgroundRuntimeManagerUpdatesWebSocketClient(t *testing.T) {
	firstURL, firstConnected, firstDisconnected := newWebSocketRuntimeTestServer(t)
	secondURL, secondConnected, secondDisconnected := newWebSocketRuntimeTestServer(t)
	manager := newBackgroundRuntimeManager()
	first := wsClientConfig{
		name:        "client",
		scriptPath:  "/tmp/client-v1.js",
		connectURL:  firstURL,
		description: "first",
	}
	manager.reconcile(nil, map[string]wsClientConfig{"client": first})
	waitForSignal(t, firstConnected, "first WebSocket connection")

	manager.mu.Lock()
	runtime := manager.wsClients["client"]
	manager.mu.Unlock()
	if runtime == nil {
		t.Fatal("ws_client runtime was not started")
	}

	softUpdate := first
	softUpdate.scriptPath = "/tmp/client-v2.js"
	softUpdate.description = "second"
	manager.reconcile(nil, map[string]wsClientConfig{"client": softUpdate})
	select {
	case <-firstDisconnected:
		t.Fatal("script/description update unexpectedly closed the WebSocket connection")
	case <-time.After(100 * time.Millisecond):
	}

	manager.mu.Lock()
	updatedRuntime := manager.wsClients["client"]
	manager.mu.Unlock()
	if updatedRuntime != runtime {
		t.Fatal("ws_client update created a second runtime")
	}
	got, active := runtime.currentConfig()
	if !active || got.scriptPath != softUpdate.scriptPath || got.description != softUpdate.description {
		t.Fatalf("ws_client runtime config = %#v, want %#v", got, softUpdate)
	}

	reconnectUpdate := softUpdate
	reconnectUpdate.connectURL = secondURL
	manager.reconcile(nil, map[string]wsClientConfig{"client": reconnectUpdate})
	waitForSignal(t, firstDisconnected, "old WebSocket disconnection")
	waitForSignal(t, secondConnected, "new WebSocket connection")

	manager.reconcile(nil, nil)
	waitForSignal(t, secondDisconnected, "new WebSocket disconnection")
	waitForSignal(t, runtime.done, "ws_client runtime stop")
	waitForCondition(t, "ws_client runtime cleanup", func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		_, exists := manager.wsClients["client"]
		return !exists
	})
}

func TestSQLFilesConcurrentReadAndReplace(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{"api": {Description: "initial"}})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				files := currentSQLFiles()
				_ = files["api"].Description
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		setSQLFiles(map[string]APIConfig{"api": {Description: fmt.Sprintf("updated-%d", i)}})
	}
	wg.Wait()
}

func TestNewAPIConfigSnapshotClonesAndIndexesDefinitions(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "api.json")
	sourceHash := [32]byte{1, 2, 3}
	files := map[string]APIConfig{
		"api": {
			SQL:         []string{"/sql/original.sql"},
			Description: "original",
		},
		"job": {
			Type:        apiTypeSchedule,
			Description: "scheduled",
		},
	}

	snapshot := newAPIConfigSnapshot(files, sourcePath, sourceHash)
	originalAPI := files["api"]
	originalAPI.SQL[0] = "/sql/mutated.sql"
	files["api"] = APIConfig{Description: "replaced"}
	originalJob := files["job"]
	originalJob.Description = "changed"
	files["job"] = originalJob

	if got := snapshot.Definitions["api"].Description; got != "original" {
		t.Fatalf("snapshot API description = %q, want original", got)
	}
	if got := snapshot.Definitions["api"].SQL[0]; got != "/sql/original.sql" {
		t.Fatalf("snapshot SQL path = %q, want original path", got)
	}
	if _, exists := snapshot.APIs["job"]; exists {
		t.Fatal("schedule definition was included in HTTP API index")
	}
	if got := snapshot.Sources["api"]; got != sourcePath {
		t.Fatalf("snapshot source = %q, want %q", got, sourcePath)
	}
	if got := snapshot.Files[sourcePath]; got.Path != sourcePath || !got.Exists || got.Hash != sourceHash {
		t.Fatalf("snapshot file state = %#v, want root file state", got)
	}
}

func TestPublishedAPISnapshotRemainsStableAfterReplacement(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{"old": {Description: "old generation"}})
	captured := currentAPISnapshot()

	setSQLFiles(map[string]APIConfig{"new": {Description: "new generation"}})

	if _, exists := captured.Definitions["old"]; !exists {
		t.Fatal("captured snapshot lost its original definition")
	}
	if _, exists := captured.Definitions["new"]; exists {
		t.Fatal("captured snapshot observed a later definition")
	}
	if _, exists := currentAPISnapshot().Definitions["new"]; !exists {
		t.Fatal("current snapshot was not replaced")
	}
}

func TestRunScriptKeepsSnapshotForNyanCallMe(t *testing.T) {
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	testDB.SetMaxOpenConns(2)

	oldTarget := writeTestScript(t, `JSON.stringify({"generation":"old"})`)
	newTarget := writeTestScript(t, `JSON.stringify({"generation":"new"})`)
	caller := writeTestScript(t, `JSON.stringify(nyanCallMe({api:"target"}))`)
	captured := newAPIConfigSnapshot(map[string]APIConfig{
		"target": {Script: oldTarget},
	}, "", [32]byte{})
	setTestSQLFiles(t, map[string]APIConfig{
		"target": {Script: newTarget},
	})

	result, err := runScriptWithSnapshot(captured, []string{caller}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("runScriptWithSnapshot() error = %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Fatalf("runScriptWithSnapshot() result = %q: %v", result, err)
	}
	if got := decoded["generation"]; got != "old" {
		t.Fatalf("nested API generation = %v, want old", got)
	}
}

func TestIncludedCompleteAPINameIsPreservedForNyanCallMeAndPush(t *testing.T) {
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	testDB.SetMaxOpenConns(2)
	apiDir := t.TempDir()
	rootPath := filepath.Join(apiDir, "api.json")
	childPath := filepath.Join(apiDir, "child.json")
	targetScript := filepath.Join(apiDir, "target.js")
	callerScript := filepath.Join(apiDir, "caller.js")
	writeTestFile(t, targetScript, `JSON.stringify({called:nyanAllParams.api})`)
	writeTestFile(t, callerScript, `JSON.stringify(nyanCallMe({api:"sub/target"}))`)
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child.json"}}`)
	writeTestFile(t, childPath, `{"target":{"script":"target.js"},"emitter":{"script":"target.js","push":"sub/target"}}`)

	loaded := loadTestAPIConfig(t, rootPath)
	if got := loaded.Snapshot.Definitions["sub/emitter"].Push; got != "sub/target" {
		t.Fatalf("included push target = %q, want complete API name", got)
	}
	result, err := runScriptWithSnapshot(loaded.Snapshot, []string{callerScript}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("runScriptWithSnapshot() error = %v", err)
	}
	if result != `{"called":"sub/target"}` {
		t.Fatalf("nyanCallMe result = %q", result)
	}
}

func TestFindPublicAPIForPath(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{
		"public":        {Type: apiTypePublic, Path: "./public"},
		"public/assets": {Type: apiTypePublic, Path: "./assets"},
		"api":           {SQL: []string{"./sql/list.sql"}},
	})

	apiKey, requestedPath, _, ok := findPublicAPIForPath("/public/assets/app.js")
	if !ok {
		t.Fatal("findPublicAPIForPath() ok = false, want true")
	}
	if apiKey != "public/assets" {
		t.Fatalf("apiKey = %q, want %q", apiKey, "public/assets")
	}
	if requestedPath != "app.js" {
		t.Fatalf("requestedPath = %q, want %q", requestedPath, "app.js")
	}
}

func TestUnifiedHandlerServesPublicFileWithoutBasicAuth(t *testing.T) {
	resetJavascriptInclude(t)
	publicDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(publicDir, "test.txt"), []byte("hello public"), 0o644); err != nil {
		t.Fatal(err)
	}
	setTestSQLFiles(t, map[string]APIConfig{
		"assets": {Type: apiTypePublic, Path: publicDir},
	})

	req := httptest.NewRequest(http.MethodGet, "/assets/test.txt", nil)
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "hello public" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "hello public")
	}
}

func TestFileHelpersAndPublicBinaryWithoutHTTPSettings(t *testing.T) {
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.json")
	writeTestFile(t, apiPath, `{"assets":{"type":"public","path":"./files"}}`)
	loaded := loadTestAPIConfig(t, apiPath)
	setTestAPISnapshot(t, loaded.Snapshot)
	binary := []byte{0, 255, 128, 1, 13, 10, 0, 254}
	vm := goja.New()
	registerNyanFuncs(vm, loaded.Snapshot, map[string]interface{}{"data": base64.StdEncoding.EncodeToString(binary)}, nil)
	value, err := vm.RunString(`
nyanSaveFile(nyanAllParams.data, "./files/download.bin");
nyanSaveFile(nyanBase64Encode("file helpers work"), "./files/note.txt");
nyanGetFile("./files/note.txt");`)
	if err != nil || value.String() != "file helpers work" {
		t.Fatalf("file helpers failed: value=%v err=%v", value, err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "files", "download.bin"))
	if err != nil || !bytes.Equal(saved, binary) {
		t.Fatalf("saved binary=%v err=%v", saved, err)
	}
	rec := httptest.NewRecorder()
	unifiedHandler(rec, httptest.NewRequest(http.MethodGet, "/assets/download.bin", nil))
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), binary) {
		t.Fatalf("public binary response: status=%d body=%v", rec.Code, rec.Body.Bytes())
	}
}

func TestPublicEndpointCheckOnlyWithoutParamCheck(t *testing.T) {
	resetJavascriptInclude(t)
	publicDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(publicDir, "test.txt"), []byte("file content"), 0o644); err != nil {
		t.Fatal(err)
	}
	setTestSQLFiles(t, map[string]APIConfig{
		"assets": {Type: apiTypePublic, Path: publicDir},
	})

	req := httptest.NewRequest(http.MethodGet, "/assets/test.txt?nyan_mode=checkOnly", nil)
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response %q: %v", rec.Body.String(), err)
	}
	if response["success"] != true {
		t.Fatalf("success = %v, want true", response["success"])
	}
}

func TestPublicParamCheckUsesSuccess(t *testing.T) {
	for _, test := range []struct {
		name, check                 string
		status                      int
		outStatus                   int
		checkOnly, legacy, wantFile bool
	}{
		{name: "unset", status: 200, wantFile: true},
		{name: "success_200", check: `({success:true,status:200});`, status: 200, wantFile: true},
		{name: "success_201", check: `({success:true,status:201});`, status: 200, wantFile: true},
		{name: "success_503", check: `({success:true,status:503});`, status: 200, wantFile: true},
		{name: "success_without_status", check: `({success:true});`, status: 200, wantFile: true},
		{name: "legacy_check", check: `({success:true,status:201});`, status: 200, legacy: true, wantFile: true},
		{name: "output_sets_status", check: `({success:true,status:503});`, status: 201, outStatus: 201, wantFile: true},
		{name: "denied", check: `({success:false,status:403,result:"denied"});`, status: 403},
		{name: "denied_with_200", check: `({success:false,status:200,result:"denied"});`, status: 200},
		{name: "exception", check: `throw new Error("input failed");`, status: 500},
		{name: "check_only", check: `({success:true,status:201,result:"checked"});`, status: 201, checkOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "test.txt"), "original file")
			marker := filepath.Join(t.TempDir(), "out")
			outStatus := test.outStatus
			if outStatus == 0 {
				outStatus = 200
			}
			definition := APIConfig{Type: apiTypePublic, Path: dir, OutCheck: writeTestScript(t, fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"),%q); ({success:true,status:%d});`, marker, outStatus))}
			if test.check != "" {
				definition.ParamCheck = writeTestScript(t, test.check)
				if test.legacy {
					definition.Check, definition.ParamCheck = definition.ParamCheck, ""
				}
			}
			setTestSQLFiles(t, map[string]APIConfig{"assets": definition})
			path := "/assets/test.txt"
			if test.checkOnly {
				path += "?nyan_mode=checkOnly"
			}
			w := httptest.NewRecorder()
			unifiedHandler(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != test.status || (w.Body.String() == "original file") != test.wantFile {
				t.Fatalf("HTTP %d body=%s, want status=%d file=%t", w.Code, w.Body.String(), test.status, test.wantFile)
			}
			data, err := os.ReadFile(marker)
			if test.wantFile {
				if err != nil || string(data) != "ran" {
					t.Fatalf("outCheck did not run: %q %v", data, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("outCheck ran after input check stopped request: %q %v", data, err)
			}
		})
	}
}

func TestPublicEndpointOutCheckBlocksFile(t *testing.T) {
	resetJavascriptInclude(t)
	publicDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(publicDir, "test.txt"), []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	outCheckScript := writeTestScript(t, `
({ success: false, status: 409, result: { message: "blocked", body: nyanAllParams.nyan_output_body } });
`)
	setTestSQLFiles(t, map[string]APIConfig{
		"assets": {Type: apiTypePublic, Path: publicDir, OutCheck: outCheckScript},
	})

	req := httptest.NewRequest(http.MethodGet, "/assets/test.txt", nil)
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if rec.Body.String() == "unexpected" {
		t.Fatal("outCheck failure returned original file content")
	}
}

func TestPublicEndpointOutCheckSuccessUsesStatus(t *testing.T) {
	for _, status := range []int{201, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			resetJavascriptInclude(t)
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "test.txt"), "original file")
			setTestSQLFiles(t, map[string]APIConfig{
				"assets": {Type: apiTypePublic, Path: dir, OutCheck: writeTestScript(t, fmt.Sprintf(`({success:true,status:%d,result:"must not replace file"});`, status))},
			})
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				r := httptest.NewRequest(method, "/assets/test.txt", nil)
				w := httptest.NewRecorder()
				unifiedHandler(w, r)
				wantBody := "original file"
				if method == http.MethodHead {
					wantBody = ""
				}
				if w.Code != status || w.Body.String() != wantBody {
					t.Fatalf("successful outCheck replaced file: %s HTTP %d %s", method, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestRunOutCheckScriptAllowsOutput(t *testing.T) {
	resetJavascriptInclude(t)
	scriptPath := writeTestScript(t, `
if (nyanAllParams.nyan_output.body === "main ok" && nyanAllParams.nyan_output_body === "main ok") {
  ({ success: true, status: 200, result: {} });
} else {
  ({ success: false, status: 409, result: { body: nyanAllParams.nyan_output_body } });
}
`)

	handled, statusCode, jsonStr, err := runOutCheckScript(APIConfig{OutCheck: scriptPath}, map[string]interface{}{}, 201, "application/json", []byte("main ok"))
	if err != nil {
		t.Fatalf("runOutCheckScript() error = %v", err)
	}
	if handled {
		t.Fatalf("handled = true, want false; status=%d body=%q", statusCode, jsonStr)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d, want outCheck status 200", statusCode)
	}
}

func TestRunOutCheckScriptBlocksOutput(t *testing.T) {
	resetJavascriptInclude(t)
	scriptPath := writeTestScript(t, `
({ success: false, status: 409, result: { message: "output mismatch", body: nyanAllParams.nyan_output_body } });
`)

	handled, statusCode, jsonStr, err := runOutCheckScript(APIConfig{OutCheck: scriptPath}, map[string]interface{}{}, 200, "application/json", []byte("unexpected"))
	if err != nil {
		t.Fatalf("runOutCheckScript() error = %v", err)
	}
	if !handled {
		t.Fatal("handled = false, want true")
	}
	if statusCode != 409 {
		t.Fatalf("statusCode = %d, want 409", statusCode)
	}
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &response); err != nil {
		t.Fatalf("failed to unmarshal outCheck response %q: %v", jsonStr, err)
	}
	if response["success"] != false {
		t.Fatalf("success = %v, want false", response["success"])
	}
}

func TestCollectRequestParamsKeepsJSONObjectAsSingleValue(t *testing.T) {
	req := httptest.NewRequest("GET", "/addhogejson?doc={%22id%22:36,%20%22name%22:%22%E3%82%B5%E3%83%96%E3%83%AD%E3%83%BC%22}", nil)

	params, err := collectRequestParams(req)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]interface{}{"id": float64(36), "name": "サブロー"}
	if !reflect.DeepEqual(params["doc"], want) {
		t.Fatalf("doc = %#v", params["doc"])
	}
}

func TestCollectRequestParamsStillSplitsCommaSeparatedValues(t *testing.T) {
	req := httptest.NewRequest("GET", "/ids?ids=1,2,3", nil)

	params, err := collectRequestParams(req)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := params["ids"].([]string)
	if !ok {
		t.Fatalf("ids type = %T", params["ids"])
	}
	if strings.Join(got, ",") != "1,2,3" {
		t.Fatalf("ids = %#v", got)
	}
}

func TestCollectRequestParamsBodyOverridesQuery(t *testing.T) {
	for _, test := range []struct {
		name, contentType, query, body, want string
	}{
		{"json_merge", "application/json", "api=target&value=query&queryOnly=1", `{"value":"body","bodyOnly":2}`, `{"api":"target","value":"body","queryOnly":"1","bodyOnly":2}`},
		{"json_empty", "application/json", "api=target&nyan_mode=checkOnly", "", `{"api":"target","nyan_mode":"checkOnly"}`},
		{"json_null_body", "application/json", "api=target", "null", `{"api":"target"}`},
		{"json_explicit_values", "application/json", "a=query&b=query&c=query&d=query&e=query", `{"a":null,"b":false,"c":0,"d":"","e":[]}`, `{"a":null,"b":false,"c":0,"d":"","e":[]}`},
		{"json_preserves_types", "application/json", "tag=a&tag=b&ids=1,2&doc=%7B%22x%22%3A1%7D", `{"value":"a,b"}`, `{"tag":["a","b"],"ids":["1","2"],"doc":{"x":1},"value":"a,b"}`},
		{"form_merge", "application/x-www-form-urlencoded", "api=target&value=query&queryOnly=1&nyan_mode=checkOnly", "value=body&bodyOnly=2&nyan_mode=checkOnly", `{"api":"target","value":"body","queryOnly":"1","bodyOnly":"2","nyan_mode":"checkOnly"}`},
		{"form_single_over_multiple", "application/x-www-form-urlencoded", "tag=a&tag=b", "tag=c", `{"tag":"c"}`},
		{"form_multiple_over_single", "application/x-www-form-urlencoded", "tag=a", "tag=b&tag=c", `{"tag":["b","c"]}`},
		{"form_conversions", "application/x-www-form-urlencoded", "ids=query&doc=query", "ids=1,2&doc=%7B%22x%22%3A1%7D&empty=", `{"ids":["1","2"],"doc":{"x":1},"empty":""}`},
		{"form_empty_override", "application/x-www-form-urlencoded", "nyan_mode=checkOnly", "nyan_mode=", `{"nyan_mode":""}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/?"+test.query+"&nyan_request=forged", strings.NewReader(test.body))
			r.Header.Set("Content-Type", test.contentType)
			params, err := collectRequestParams(r)
			if err != nil {
				t.Fatal(err)
			}
			request, ok := params["nyan_request"].(map[string]interface{})
			if !ok || request["body"] != test.body || request["path"] != "/" {
				t.Fatalf("actual request context lost: %#v", params["nyan_request"])
			}
			if !reflect.DeepEqual(request["query"], urlValuesToInterfaceMap(r.URL.Query())) {
				t.Fatalf("query source changed: %#v", request["query"])
			}
			if test.contentType == "application/json" {
				var want interface{}
				if test.body != "" {
					if err := json.Unmarshal([]byte(test.body), &want); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(request["json"], want) {
					t.Fatalf("JSON source changed: %#v", request["json"])
				}
			} else {
				values, err := url.ParseQuery(test.body)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(request["form"], urlValuesToInterfaceMap(values)) {
					t.Fatalf("form source changed: %#v", request["form"])
				}
			}
			delete(params, "nyan_request")
			got, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decodeTestJSONObject(t, got), decodeTestJSONObject(t, []byte(test.want))) {
				t.Fatalf("params=%s, want %s", got, test.want)
			}
		})
	}
}

func TestHTTPMergedParamsControlCheckOnly(t *testing.T) {
	for _, route := range []string{"/target?", "/?api=target&"} {
		for _, test := range []struct {
			name, contentType, body string
			checkOnly               bool
		}{
			{"json_query_mode", "application/json", `{"value":"body"}`, true},
			{"json_duplicate_mode", "application/json", `{"value":"body","nyan_mode":"checkOnly"}`, true},
			{"json_body_mode_overrides", "application/json", `{"value":"body","nyan_mode":""}`, false},
			{"form_query_mode", "application/x-www-form-urlencoded", "value=body", true},
			{"form_duplicate_mode", "application/x-www-form-urlencoded", "value=body&nyan_mode=checkOnly", true},
			{"form_body_mode_overrides", "application/x-www-form-urlencoded", "value=body&nyan_mode=", false},
		} {
			t.Run(route+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				dir := t.TempDir()
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"), %q);`, filepath.Join(dir, stage))
				}
				setTestSQLFiles(t, map[string]APIConfig{
					"target": {
						ParamCheck: writeTestScript(t, mark("param")+`
if (nyanAllParams.api !== "target" || nyanAllParams.tenant !== "abc" || nyanAllParams.value !== "body") throw new Error("wrong merged params");
if (nyanRequest.query.value !== "query" || nyanRequest.query.nyan_mode !== "checkOnly") throw new Error("query context changed");
if ((nyanRequest.json || nyanRequest.form).value !== "body") throw new Error("body context changed");
({success:true,status:200,result:{checked:true}});`),
						Script:   writeTestScript(t, mark("body")+`({success:true,status:200,result:{executed:true}});`),
						OutCheck: writeTestScript(t, mark("out")+`({success:true,status:200});`),
						Push:     "events",
					},
					"events": {Script: writeTestScript(t, mark("push")+`({status:200});`)},
				})
				r := httptest.NewRequest(http.MethodPost, route+"tenant=abc&value=query&nyan_mode=checkOnly", strings.NewReader(test.body))
				r.Header.Set("Content-Type", test.contentType)
				w := httptest.NewRecorder()
				handleRequest(w, r)
				if w.Code != 200 {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
				}
				result := decodeTestJSONObject(t, w.Body.Bytes())["result"]
				key := "executed"
				if test.checkOnly {
					key = "checked"
				}
				if !reflect.DeepEqual(result, map[string]interface{}{key: true}) {
					t.Fatalf("unexpected result: %#v", result)
				}
				for _, stage := range []string{"param", "body", "out", "push"} {
					data, err := os.ReadFile(filepath.Join(dir, stage))
					if stage == "param" || !test.checkOnly {
						if err != nil || string(data) != "ran" {
							t.Fatalf("%s did not run: %q %v", stage, data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("%s ran during checkOnly: %q %v", stage, data, err)
					}
				}
			})
		}
	}
}

func TestAPISelectionUsesPathAndRPCMethod(t *testing.T) {
	for _, test := range []struct {
		name, path, contentType, body, api string
		status                             int
		rpc, checkOnly                     bool
	}{
		{name: "query", path: "/sub/alpha?api=beta", api: "sub/alpha", status: 200},
		{name: "duplicate_query", path: "/sub/alpha?api=beta&api=beta", api: "sub/alpha", status: 200},
		{name: "json", path: "/sub/alpha?api=beta", contentType: "application/json", body: `{"api":"beta"}`, api: "sub/alpha", status: 200},
		{name: "json_null", path: "/sub/alpha", contentType: "application/json", body: `{"api":null}`, api: "sub/alpha", status: 200},
		{name: "json_array", path: "/sub/alpha", contentType: "application/json", body: `{"api":["beta"]}`, api: "sub/alpha", status: 200},
		{name: "json_empty", path: "/sub/alpha", contentType: "application/json", body: `{"api":""}`, api: "sub/alpha", status: 200},
		{name: "form", path: "/sub/alpha", contentType: "application/x-www-form-urlencoded", body: "api=beta", api: "sub/alpha", status: 200},
		{name: "missing_path", path: "/missing?api=beta", status: 404},
		{name: "root_query", path: "/?api=beta", api: "beta", status: 200},
		{name: "root_body", path: "/?api=sub/alpha", contentType: "application/json", body: `{"api":"beta"}`, api: "beta", status: 200},
		{name: "root_missing", path: "/", status: 400},
		{name: "check_only", path: "/sub/alpha?api=beta&nyan_mode=checkOnly", api: "sub/alpha", status: 200, checkOnly: true},
		{name: "denied", path: "/sub/alpha?api=beta&deny=yes", api: "sub/alpha", status: 403},
		{name: "rpc", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"sub/alpha","params":{"api":"beta"}}`, api: "sub/alpha", status: 200},
		{name: "rpc_null", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"sub/alpha","params":{"api":null}}`, api: "sub/alpha", status: 200},
		{name: "rpc_array", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"sub/alpha","params":{"api":["beta"]}}`, api: "sub/alpha", status: 200},
		{name: "rpc_missing_method", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"missing","params":{"api":"beta"}}`, status: 404},
		{name: "rpc_empty_method", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"","params":{"api":"beta"}}`, status: 404},
		{name: "rpc_check_only", rpc: true, body: `{"jsonrpc":"2.0","id":1,"method":"sub/alpha","params":{"api":"beta","nyan_mode":"checkOnly"}}`, api: "sub/alpha", status: 200, checkOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			dir := t.TempDir()
			files := make(map[string]APIConfig)
			for _, api := range []string{"sub/alpha", "beta"} {
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"),%q);`, filepath.Join(dir, api, stage))
				}
				guard := fmt.Sprintf(`if(nyanAllParams.api!==%q) throw new Error("wrong effective API name");`, api)
				files[api] = APIConfig{
					ParamCheck: writeTestScript(t, guard+mark("param")+`({success:!nyanAllParams.deny,status:nyanAllParams.deny?403:200,result:{api:nyanAllParams.api,request:nyanRequest}});`),
					Script:     writeTestScript(t, guard+mark("body")+`({success:true,status:200,result:{api:nyanAllParams.api,request:nyanRequest}});`),
					OutCheck:   writeTestScript(t, guard+mark("out")+`({success:true,status:200});`),
					Push:       api + "/events",
				}
				files[api+"/events"] = APIConfig{Script: writeTestScript(t, mark("push")+`({status:200});`)}
			}
			setTestSQLFiles(t, files)
			path, contentType := test.path, test.contentType
			if test.rpc {
				path, contentType = "/nyan-rpc", "application/json"
			}
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", contentType)
			r.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
			w := httptest.NewRecorder()
			if test.rpc {
				handleJSONRPC(w, r)
			} else {
				unifiedHandler(w, r)
			}
			if w.Code != test.status {
				t.Fatalf("HTTP %d, want %d: %s", w.Code, test.status, w.Body.String())
			}
			if test.api != "" {
				response := decodeTestJSONObject(t, w.Body.Bytes())
				if test.rpc {
					response = response["result"].(map[string]interface{})
				}
				result := response["result"].(map[string]interface{})
				if result["api"] != test.api {
					t.Fatalf("selected API=%v, want %s", result["api"], test.api)
				}
				request := result["request"].(map[string]interface{})
				if request["path"] != path && request["path"] != strings.Split(path, "?")[0] {
					t.Fatalf("request path changed: %#v", request)
				}
				if contentType == "application/json" && !reflect.DeepEqual(request["json"], decodeTestJSONObject(t, []byte(test.body))) {
					t.Fatalf("original JSON changed: %#v", request["json"])
				}
				query, _ := json.Marshal(urlValuesToInterfaceMap(r.URL.Query()))
				if !reflect.DeepEqual(request["query"], decodeTestJSONObject(t, query)) {
					t.Fatalf("original query changed: %#v", request["query"])
				}
				if contentType == "application/x-www-form-urlencoded" && !reflect.DeepEqual(request["form"], map[string]interface{}{"api": "beta"}) {
					t.Fatalf("original form changed: %#v", request["form"])
				}
			}
			for _, api := range []string{"sub/alpha", "beta"} {
				for _, stage := range []string{"param", "body", "out", "push"} {
					data, err := os.ReadFile(filepath.Join(dir, api, stage))
					want := api == test.api && (stage == "param" || (!test.checkOnly && test.status == 200))
					if want {
						if err != nil || string(data) != "ran" {
							t.Fatalf("%s/%s did not run: %q %v", api, stage, data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("unexpected %s/%s execution: %q %v", api, stage, data, err)
					}
				}
			}
		})
	}
}

func TestPrepareQueryWithParamsScansJSONDocumentCommentDefaults(t *testing.T) {
	query, args := prepareQueryWithParams(
		`INSERT INTO hoge2 VALUES /*doc*/{"id":9, "name":"たまこ"};`,
		map[string]interface{}{"doc": map[string]interface{}{"id": float64(36), "name": "サブロー"}},
	)

	if query != `INSERT INTO hoge2 VALUES ?;` {
		t.Fatalf("query = %q", query)
	}
	if len(args) != 1 || args[0] != `{"id":36,"name":"サブロー"}` {
		t.Fatalf("args = %#v", args)
	}
}

func TestProcessWhereBlockDropsBeginBlockWhenNestedIFFalse(t *testing.T) {
	query := `SELECT
  id AS id,
  name AS name
FROM hoge2
/*BEGIN*/
WHERE
  /*IF id != null*/ id = /*id*/3 /*END*/
/*END*/
;`

	got := processWhereBlock(query, map[string]interface{}{})

	if strings.Contains(got, "WHERE") {
		t.Fatalf("query should not contain WHERE when id is absent:\n%s", got)
	}
	if !strings.Contains(got, "FROM hoge2") || !strings.Contains(got, ";") {
		t.Fatalf("query lost expected base SQL:\n%s", got)
	}
}

func TestProcessWhereBlockKeepsBeginBlockWhenNestedIFTrue(t *testing.T) {
	query := `SELECT
  id AS id,
  name AS name
FROM hoge2
/*BEGIN*/
WHERE
  /*IF id != null*/ id = /*id*/3 /*END*/
/*END*/
;`

	got := processWhereBlock(query, map[string]interface{}{"id": "3"})

	if !strings.Contains(got, "WHERE") || !strings.Contains(got, "id = /*id*/3") {
		t.Fatalf("query should keep WHERE when id is present:\n%s", got)
	}
}

func TestBasicAuthAllowsOnlyConfiguredCredentials(t *testing.T) {
	cfg := Config{BasicAuth: BasicAuthConfig{Username: "nyan", Password: "secret"}}
	called := false
	handler := basicAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}, cfg)

	tests := []struct {
		name       string
		username   string
		password   string
		setAuth    bool
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "wrong password", username: "nyan", password: "wrong", setAuth: true, wantStatus: http.StatusUnauthorized},
		{name: "accepted", username: "nyan", password: "secret", setAuth: true, wantStatus: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setAuth {
				req.SetBasicAuth(tt.username, tt.password)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if called != (tt.wantStatus == http.StatusNoContent) {
				t.Fatalf("next handler called = %t", called)
			}
			if tt.wantStatus == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("WWW-Authenticate header is missing")
			}
		})
	}
}

func TestRowsToJSONConvertsBlobsAndNulls(t *testing.T) {
	testDB := setTestSQLiteDB(t)
	rows, err := testDB.Query(`SELECT CAST('{"ok":true}' AS BLOB) AS document, CAST('plain' AS BLOB) AS text_value, NULL AS empty_value`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	data, err := RowsToJSON(rows)
	if err != nil {
		t.Fatalf("RowsToJSON() error = %v", err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", data, err)
	}
	if len(result) != 1 {
		t.Fatalf("row count = %d, want 1", len(result))
	}
	document, ok := result[0]["document"].(map[string]interface{})
	if !ok || document["ok"] != true {
		t.Fatalf("document = %#v, want parsed JSON object", result[0]["document"])
	}
	if result[0]["text_value"] != "plain" {
		t.Fatalf("text_value = %#v, want plain", result[0]["text_value"])
	}
	if result[0]["empty_value"] != nil {
		t.Fatalf("empty_value = %#v, want nil", result[0]["empty_value"])
	}
}

func TestHandleRequestExecutesSQLAPI(t *testing.T) {
	setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	sqlPath := filepath.Join(t.TempDir(), "lookup.sql")
	writeTestFile(t, sqlPath, `SELECT /*id*/0 AS id, CAST('{"source":"http"}' AS BLOB) AS metadata`)
	setTestSQLFiles(t, map[string]APIConfig{
		"lookup": {SQL: []string{sqlPath}, Description: "lookup"},
	})

	req := httptest.NewRequest(http.MethodGet, "/lookup?id=42", nil)
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var response struct {
		Success bool                     `json:"success"`
		Status  int                      `json:"status"`
		Result  []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response %q: %v", rec.Body.String(), err)
	}
	if !response.Success || response.Status != http.StatusOK || len(response.Result) != 1 {
		t.Fatalf("response = %#v", response)
	}
	if fmt.Sprint(response.Result[0]["id"]) != "42" {
		t.Fatalf("id = %#v, want 42", response.Result[0]["id"])
	}
	metadata, ok := response.Result[0]["metadata"].(map[string]interface{})
	if !ok || metadata["source"] != "http" {
		t.Fatalf("metadata = %#v", response.Result[0]["metadata"])
	}
}

func TestHandleJSONRPCExecutesSQLAPI(t *testing.T) {
	setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	sqlPath := filepath.Join(t.TempDir(), "lookup.sql")
	writeTestFile(t, sqlPath, `SELECT /*id*/0 AS id`)
	setTestSQLFiles(t, map[string]APIConfig{
		"lookup": {SQL: []string{sqlPath}},
	})

	req := httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","method":"lookup","params":{"id":42},"id":7}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleJSONRPC(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response %q: %v", rec.Body.String(), err)
	}
	if response["jsonrpc"] != "2.0" || fmt.Sprint(response["id"]) != "7" {
		t.Fatalf("JSON-RPC envelope = %#v", response)
	}
	result, ok := response["result"].(map[string]interface{})
	if !ok || result["success"] != true {
		t.Fatalf("result = %#v", response["result"])
	}
	rows, ok := result["result"].([]interface{})
	if !ok || len(rows) != 1 {
		t.Fatalf("SQL rows = %#v", result["result"])
	}
}

func TestHandleJSONRPCRejectsInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":`))
	rec := httptest.NewRecorder()
	handleJSONRPC(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	var response JSONRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32700 {
		t.Fatalf("error = %#v, want parse error", response.Error)
	}
}

func TestRunScriptUsesParamsAndCommits(t *testing.T) {
	setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	scriptPath := writeTestScript(t, `JSON.stringify({success: true, value: nyanAllParams.value});`)

	result, err := runScript([]string{scriptPath}, map[string]interface{}{"value": "hello"})
	if err != nil {
		t.Fatalf("runScript() error = %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Fatalf("runScript() result = %q: %v", result, err)
	}
	if decoded["success"] != true || decoded["value"] != "hello" {
		t.Fatalf("runScript() result = %#v", decoded)
	}
}

func TestCallNyanAPIFromVMExecutesSQL(t *testing.T) {
	setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	sqlPath := filepath.Join(t.TempDir(), "lookup.sql")
	writeTestFile(t, sqlPath, `SELECT /*name*/'unknown' AS name`)
	setTestSQLFiles(t, map[string]APIConfig{
		"lookup": {SQL: []string{sqlPath}},
	})

	result, err := callNyanAPIFromVM("lookup", map[string]interface{}{"name": "mike"})
	if err != nil {
		t.Fatalf("callNyanAPIFromVM() error = %v", err)
	}
	var response struct {
		Success bool                     `json:"success"`
		Result  []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal([]byte(result), &response); err != nil {
		t.Fatalf("failed to decode %q: %v", result, err)
	}
	if !response.Success || len(response.Result) != 1 || response.Result[0]["name"] != "mike" {
		t.Fatalf("response = %#v", response)
	}
}

func TestHubBroadcastsToRequestedChannel(t *testing.T) {
	oldHub := hub
	hub = NewHub()
	t.Cleanup(func() { hub = oldHub })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleWebSocketWithSnapshot(&APIConfigSnapshot{}, w, r)
	}))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sub/updates"
	headers := http.Header{"Origin": []string{"https://example.invalid"}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	waitForCondition(t, "WebSocket client registration", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.clients["sub/updates"]) == 1
	})
	hub.mu.Lock()
	_, shortened := hub.clients["updates"]
	hub.mu.Unlock()
	if shortened {
		t.Fatal("mounted WebSocket channel was shortened to its last segment")
	}
	hub.Broadcast("sub/updates", []byte("hello"))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("WebSocket read failed: %v", err)
	}
	if messageType != websocket.TextMessage || string(message) != "hello" {
		t.Fatalf("message type=%d body=%q", messageType, message)
	}
}

func TestHTTPClientHelpers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			user, pass, ok := r.BasicAuth()
			if !ok || user != "nyan" || pass != "secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("get-ok"))
		case http.MethodPost:
			if r.Header.Get("X-Nyan-Test") != "yes" {
				http.Error(w, "missing header", http.StatusBadRequest)
				return
			}
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["value"] != "post" {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("post-ok"))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)

	getResult, err := getAPI(server.URL, "nyan", "secret")
	if err != nil || getResult != "get-ok" {
		t.Fatalf("getAPI() result=%q error=%v", getResult, err)
	}
	postResult, err := jsonAPI(server.URL, []byte(`{"value":"post"}`), "", "", map[string]string{"X-Nyan-Test": "yes"})
	if err != nil || postResult != "post-ok" {
		t.Fatalf("jsonAPI() result=%q error=%v", postResult, err)
	}
}

func TestQueryClassification(t *testing.T) {
	tests := []struct {
		query         string
		wantSelect    bool
		wantReturning bool
	}{
		{query: "SELECT 1", wantSelect: true},
		{query: "  with values_cte as (select 1) select * from values_cte", wantSelect: true},
		{query: "UPDATE items SET name = 'x'", wantSelect: false},
		{query: "WITH updated AS (UPDATE items SET name = 'x' RETURNING id) SELECT id FROM updated", wantReturning: true},
		{query: "INSERT INTO items(name) VALUES ('x') RETURNING id", wantReturning: true},
	}
	for _, tt := range tests {
		if got := isSelectQuery(tt.query); got != tt.wantSelect {
			t.Errorf("isSelectQuery(%q) = %t, want %t", tt.query, got, tt.wantSelect)
		}
		if got := isReturningQuery(tt.query); got != tt.wantReturning {
			t.Errorf("isReturningQuery(%q) = %t, want %t", tt.query, got, tt.wantReturning)
		}
	}
}

func TestMetadataParsers(t *testing.T) {
	sqlPath := filepath.Join(t.TempDir(), "metadata.sql")
	writeTestFile(t, sqlPath, `SELECT /*count*/'10' AS count, /*ratio*/"1.5" AS ratio, /*name*/'nyan' AS name`)
	params, err := parseSQLParams([]string{sqlPath})
	if err != nil {
		t.Fatal(err)
	}
	if params["count"] != 10 || params["ratio"] != 1.5 || params["name"] != "nyan" {
		t.Fatalf("params = %#v", params)
	}

	scriptPath := writeTestScript(t, `
const nyanAcceptedParams = {"name":"default"};
`)
	accepted, err := parseScriptAcceptedParams(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if accepted["name"] != "default" {
		t.Fatalf("accepted=%#v", accepted)
	}
}

func TestParseStaticJavaScriptValueConvertsJSONCompatibleLiterals(t *testing.T) {
	source := `{
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    id: {type: "integer", minimum: -10},
    ratio: {type: "number", examples: [1.5, +2]},
    enabled: {type: "boolean", default: false},
    note: {default: null},
    names: {type: "array", items: {type: "string"}}
  },
  required: ["id"],
  additionalProperties: false
}`

	got, err := parseStaticJavaScriptValue("schema.js", source)
	if err != nil {
		t.Fatalf("parseStaticJavaScriptValue() error = %v", err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var normalizedGot interface{}
	if err := json.Unmarshal(encoded, &normalizedGot); err != nil {
		t.Fatal(err)
	}
	var want interface{}
	if err := json.Unmarshal([]byte(`{
      "$schema":"https://json-schema.org/draft/2020-12/schema",
      "type":"object",
      "properties":{
        "id":{"type":"integer","minimum":-10},
        "ratio":{"type":"number","examples":[1.5,2]},
        "enabled":{"type":"boolean","default":false},
        "note":{"default":null},
        "names":{"type":"array","items":{"type":"string"}}
      },
      "required":["id"],
      "additionalProperties":false
    }`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizedGot, want) {
		t.Fatalf("static value = %#v, want %#v", normalizedGot, want)
	}
}

func TestParseStaticJavaScriptValueRejectsDynamicAndNonJSONValues(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "function call", source: `{value: createSchema()}`, want: `$.value: function calls are not supported`},
		{name: "identifier reference", source: `{type: schemaType}`, want: `$.type: identifier references are not supported`},
		{name: "object spread", source: `{...commonSchema}`, want: `spread properties are not supported`},
		{name: "array spread", source: `[...values]`, want: `$[0]: spread elements are not supported`},
		{name: "conditional", source: `condition ? {} : []`, want: `conditional expressions are not supported`},
		{name: "computed property", source: `{[key]: 1}`, want: `computed property names are not supported`},
		{name: "shorthand property", source: `{id}`, want: `shorthand properties are not supported`},
		{name: "getter", source: `{get id() { return 1; }}`, want: `property kind "get" is not supported`},
		{name: "template literal", source: "`object`", want: `template literals are not supported`},
		{name: "array hole", source: `[1,,2]`, want: `$[1]: array holes are not supported`},
		{name: "bigint", source: `1n`, want: `numeric value *big.Int is not JSON-compatible`},
		{name: "infinity", source: `1e400`, want: `non-finite numbers are not JSON-compatible`},
		{name: "duplicate property", source: `{id: 1, id: 2}`, want: `duplicate property "id"`},
		{name: "numeric property", source: `{1: "value"}`, want: `property names must be strings`},
		{name: "unsupported unary", source: `!true`, want: `unary operator "!" is not supported`},
		{name: "unary identifier", source: `-value`, want: `unary "-" requires a numeric literal`},
		{name: "computed expression", source: `1 + 2`, want: `computed expressions are not supported`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStaticJavaScriptValue("schema.js", tt.source)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseStaticJavaScriptValue() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseStaticJavaScriptValueReportsParserErrors(t *testing.T) {
	_, err := parseStaticJavaScriptValue("broken-schema.js", `{type: }`)
	if err == nil {
		t.Fatal("parseStaticJavaScriptValue() error = nil, want parser error")
	}
	if !strings.Contains(err.Error(), "broken-schema.js") {
		t.Fatalf("parseStaticJavaScriptValue() error = %v, want filename", err)
	}
}

func TestExtractStaticJavaScriptObjectConstantReadsTopLevelConst(t *testing.T) {
	source := []byte(`
const helper = "unchanged";
const nyanInputSchema = {
  type: "object",
  properties: {
    id: {type: "integer", minimum: -1}
  },
  required: ["id"],
  additionalProperties: false
};

function checkInput() {
  return nyanAllParams.id !== undefined;
}
`)

	got, found, err := extractStaticJavaScriptObjectConstant("param-check.js", source, "nyanInputSchema")
	if err != nil {
		t.Fatalf("extractStaticJavaScriptObjectConstant() error = %v", err)
	}
	if !found {
		t.Fatal("extractStaticJavaScriptObjectConstant() found = false, want true")
	}
	if got["type"] != "object" || got["additionalProperties"] != false {
		t.Fatalf("schema = %#v", got)
	}
	if _, exists := got["$schema"]; exists {
		t.Fatal("$schema was added to a schema that omitted it")
	}
	properties, ok := got["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("properties = %#v", got["properties"])
	}
	id, ok := properties["id"].(map[string]interface{})
	if !ok || id["type"] != "integer" || id["minimum"] != int64(-1) {
		t.Fatalf("id schema = %#v", properties["id"])
	}
}

func TestReadStaticJavaScriptObjectConstantPreservesSchemaKeyword(t *testing.T) {
	path := writeTestScript(t, `
const ignored = null, nyanOutputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    success: {const: true}
  }
};
`)

	got, found, err := readStaticJavaScriptObjectConstant(path, "nyanOutputSchema")
	if err != nil {
		t.Fatalf("readStaticJavaScriptObjectConstant() error = %v", err)
	}
	if !found {
		t.Fatal("readStaticJavaScriptObjectConstant() found = false, want true")
	}
	if got["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %#v", got["$schema"])
	}
}

func TestExtractStaticJavaScriptObjectConstantReturnsNotFound(t *testing.T) {
	source := []byte(`
const nyanInputSchemaExample = {type: "object"};
function makeCheck() {
  const nyanInputSchema = {type: "array"};
  return nyanInputSchema;
}
`)

	got, found, err := extractStaticJavaScriptObjectConstant("without-schema.js", source, "nyanInputSchema")
	if err != nil {
		t.Fatalf("extractStaticJavaScriptObjectConstant() error = %v", err)
	}
	if found || got != nil {
		t.Fatalf("schema = %#v, found=%t; want nil, false", got, found)
	}
}

func TestExtractStaticJavaScriptObjectConstantRejectsInvalidDeclarations(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "let declaration", source: `let nyanInputSchema = {};`, want: `must be declared with const`},
		{name: "var declaration", source: `var nyanInputSchema = {};`, want: `must be declared with const`},
		{name: "array value", source: `const nyanInputSchema = [];`, want: `must be a static object literal`},
		{name: "null value", source: `const nyanInputSchema = null;`, want: `must be a static object literal`},
		{name: "function call", source: `const nyanInputSchema = createSchema();`, want: `function calls are not supported`},
		{name: "identifier reference", source: `const schema = {}; const nyanInputSchema = schema;`, want: `identifier references are not supported`},
		{name: "spread", source: `const nyanInputSchema = {...commonSchema};`, want: `spread properties are not supported`},
		{name: "duplicate", source: `const nyanInputSchema = {}; const nyanInputSchema = {};`, want: `nyanInputSchema`},
		{name: "syntax error", source: `const nyanInputSchema = {type: };`, want: `invalid-schema.js`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := extractStaticJavaScriptObjectConstant("invalid-schema.js", []byte(tt.source), "nyanInputSchema")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("extractStaticJavaScriptObjectConstant() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestExtractStaticJavaScriptObjectConstantValidatesArgumentsAndReadErrors(t *testing.T) {
	if _, _, err := extractStaticJavaScriptObjectConstant("schema.js", []byte(`const value = {};`), " "); err == nil {
		t.Fatal("empty constant name error = nil")
	}
	missingPath := filepath.Join(t.TempDir(), "missing.js")
	if _, _, err := readStaticJavaScriptObjectConstant(missingPath, "nyanInputSchema"); err == nil || !strings.Contains(err.Error(), missingPath) {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestGenerateSQLInputSchemaFromSourcesInfersTypesAndRequired(t *testing.T) {
	schema := generateSQLInputSchemaFromSources([]string{`
SELECT *
FROM items
/*BEGIN*/
WHERE tenant_id = /*tenant_id*/1
  AND id = /*id*/42
  AND price >= /*price*/1.5
  AND name = /*name*/'cat'
  AND enabled = /*enabled*/true
  AND status IN (/*statuses*/'active')
  /*IF category != null*/
  AND category = /*category*/'book'
  /*END*/
	  /*IF	include_deleted != null*/
  AND deleted = false
  /*END*/
/*END*/
`})

	want := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"tenant_id":       map[string]interface{}{"type": "integer", "examples": []interface{}{int64(1)}},
			"id":              map[string]interface{}{"type": "integer", "examples": []interface{}{int64(42)}},
			"price":           map[string]interface{}{"type": "number", "examples": []interface{}{1.5}},
			"name":            map[string]interface{}{"type": "string", "examples": []interface{}{"cat"}},
			"enabled":         map[string]interface{}{"type": "boolean", "examples": []interface{}{true}},
			"statuses":        map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "examples": []interface{}{[]interface{}{"active"}}},
			"category":        map[string]interface{}{"type": "string", "examples": []interface{}{"book"}},
			"include_deleted": map[string]interface{}{},
		},
		"required":             []string{"enabled", "id", "name", "price", "statuses", "tenant_id"},
		"additionalProperties": true,
	}
	if !reflect.DeepEqual(schema, want) {
		t.Fatalf("generateSQLInputSchemaFromSources() = %#v, want %#v", schema, want)
	}
	for name, property := range schema["properties"].(map[string]interface{}) {
		if _, exists := property.(map[string]interface{})["default"]; exists {
			t.Fatalf("property %q unexpectedly contains default: %#v", name, property)
		}
	}
}

func TestGenerateSQLInputSchemaFromSourcesMergesFilesAndFallsBackOnConflicts(t *testing.T) {
	schema := generateSQLInputSchemaFromSources([]string{
		`SELECT * FROM items WHERE id = /*id*/1 AND value = /*conflict*/1`,
		`SELECT * FROM items /*IF id != null*/ WHERE id = /*id*/1 /*END*/ AND value = /*conflict*/'one' /*IF optional != null*/ AND flag = /*optional*/false /*END*/`,
	})

	properties := schema["properties"].(map[string]interface{})
	if got := properties["id"]; !reflect.DeepEqual(got, map[string]interface{}{"type": "integer", "examples": []interface{}{int64(1)}}) {
		t.Fatalf("id schema = %#v", got)
	}
	if got := properties["conflict"]; !reflect.DeepEqual(got, map[string]interface{}{}) {
		t.Fatalf("conflicting schema = %#v, want empty schema", got)
	}
	if got := properties["optional"]; !reflect.DeepEqual(got, map[string]interface{}{"type": "boolean", "examples": []interface{}{false}}) {
		t.Fatalf("optional schema = %#v", got)
	}
	if got := schema["required"]; !reflect.DeepEqual(got, []string{"conflict", "id"}) {
		t.Fatalf("required = %#v", got)
	}
}

func TestGenerateSQLInputSchemaFromSourcesIgnoresQuotedAndLineCommentMarkers(t *testing.T) {
	schema := generateSQLInputSchemaFromSources([]string{`
SELECT '/*quoted*/1', "/*identifier*/2", ` + "`/*backtick*/3`" + `
-- WHERE ignored = /*line_comment*/4
WHERE real = /*real*/5
`})

	properties := schema["properties"].(map[string]interface{})
	if len(properties) != 1 {
		t.Fatalf("properties = %#v, want only real", properties)
	}
	if _, exists := properties["real"]; !exists {
		t.Fatalf("properties = %#v, want real", properties)
	}
}

func TestGenerateSQLInputSchemaReadsFilesAndReportsErrors(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.sql")
	second := filepath.Join(dir, "second.sql")
	writeTestFile(t, first, `SELECT /*first*/1`)
	writeTestFile(t, second, `SELECT /*second*/'two'`)

	schema, err := generateSQLInputSchema([]string{first, second})
	if err != nil {
		t.Fatalf("generateSQLInputSchema() error = %v", err)
	}
	properties := schema["properties"].(map[string]interface{})
	if len(properties) != 2 {
		t.Fatalf("properties = %#v", properties)
	}

	missing := filepath.Join(dir, "missing.sql")
	if _, err := generateSQLInputSchema([]string{missing}); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestGenerateSQLInputSchemaFromSourcesWithoutParameters(t *testing.T) {
	schema := generateSQLInputSchemaFromSources([]string{`SELECT 1`})
	want := map[string]interface{}{
		"type":                 "object",
		"properties":           map[string]interface{}{},
		"additionalProperties": true,
	}
	if !reflect.DeepEqual(schema, want) {
		t.Fatalf("schema = %#v, want %#v", schema, want)
	}
}

func TestGenerateSQLOutputSchemaFromSourceExtractsSelectColumns(t *testing.T) {
	schema := generateSQLOutputSchemaFromSource(`
WITH source AS (
  SELECT id, name FROM items
)
SELECT DISTINCT
  source.id,
  source.name AS display_name,
  COUNT(*) AS "totalCount",
  'fixed' AS [label]
FROM source
GROUP BY source.id, source.name
`)

	want := sqlResponseOutputSchema(map[string]interface{}{
		"type": "array",
		"items": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":           map[string]interface{}{},
				"display_name": map[string]interface{}{},
				"totalCount":   map[string]interface{}{},
				"label":        map[string]interface{}{},
			},
			"required":             []string{"id", "display_name", "totalCount", "label"},
			"additionalProperties": false,
		},
	})
	if !reflect.DeepEqual(schema, want) {
		t.Fatalf("generateSQLOutputSchemaFromSource() = %#v, want %#v", schema, want)
	}
}

func TestGenerateSQLOutputSchemaFromSourceExtractsReturningColumns(t *testing.T) {
	schema := generateSQLOutputSchemaFromSource(`
UPDATE items
SET name = /*name*/'cat'
WHERE id = /*id*/1
RETURNING id, updated_at AS "updatedAt"
`)

	result := schema["properties"].(map[string]interface{})["result"].(map[string]interface{})
	items := result["items"].(map[string]interface{})
	wantProperties := map[string]interface{}{
		"id":        map[string]interface{}{},
		"updatedAt": map[string]interface{}{},
	}
	if !reflect.DeepEqual(items["properties"], wantProperties) {
		t.Fatalf("RETURNING properties = %#v, want %#v", items["properties"], wantProperties)
	}
	if !reflect.DeepEqual(items["required"], []string{"id", "updatedAt"}) || items["additionalProperties"] != false {
		t.Fatalf("RETURNING items = %#v", items)
	}
}

func TestGenerateSQLOutputSchemaFromSourceMatchesMutationResponse(t *testing.T) {
	schema := generateSQLOutputSchemaFromSource(`DELETE FROM items WHERE id = /*id*/1`)
	want := sqlResponseOutputSchema(map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
	})
	if !reflect.DeepEqual(schema, want) {
		t.Fatalf("mutation schema = %#v, want %#v", schema, want)
	}
}

func TestGenerateSQLOutputSchemaFromSourceFallsBackForUnsafeColumns(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{name: "wildcard", sql: `SELECT * FROM items`},
		{name: "qualified wildcard", sql: `SELECT items.* FROM items`},
		{name: "expression without alias", sql: `SELECT COUNT(*) FROM items`},
		{name: "implicit alias", sql: `SELECT id item_id FROM items`},
		{name: "duplicate name", sql: `SELECT first.id, second.id FROM first JOIN second ON true`},
		{name: "conditional column", sql: `SELECT id /*IF include_name != null*/, name /*END*/ FROM items`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := generateSQLOutputSchemaFromSource(tt.sql)
			result := schema["properties"].(map[string]interface{})["result"].(map[string]interface{})
			items := result["items"].(map[string]interface{})
			if items["additionalProperties"] != true {
				t.Fatalf("items = %#v, want unrestricted properties", items)
			}
			if _, exists := items["properties"]; exists {
				t.Fatalf("items = %#v, properties must be omitted", items)
			}
			if _, exists := items["required"]; exists {
				t.Fatalf("items = %#v, required must be omitted", items)
			}
		})
	}
}

func TestGenerateSQLOutputSchemaUsesLastSQL(t *testing.T) {
	schema := generateSQLOutputSchemaFromSources([]string{
		`SELECT old_id FROM old_items`,
		`SELECT new_id, new_name AS name FROM new_items`,
	})
	result := schema["properties"].(map[string]interface{})["result"].(map[string]interface{})
	items := result["items"].(map[string]interface{})
	if got := items["required"]; !reflect.DeepEqual(got, []string{"new_id", "name"}) {
		t.Fatalf("last SQL required = %#v", got)
	}
}

func TestGenerateSQLOutputSchemaReadsOnlyLastFileAndReportsErrors(t *testing.T) {
	dir := t.TempDir()
	missingEarlier := filepath.Join(dir, "unused-missing.sql")
	last := filepath.Join(dir, "last.sql")
	writeTestFile(t, last, `SELECT id AS item_id FROM items`)

	schema, err := generateSQLOutputSchema([]string{missingEarlier, last})
	if err != nil {
		t.Fatalf("generateSQLOutputSchema() error = %v", err)
	}
	result := schema["properties"].(map[string]interface{})["result"].(map[string]interface{})
	items := result["items"].(map[string]interface{})
	if got := items["required"]; !reflect.DeepEqual(got, []string{"item_id"}) {
		t.Fatalf("required = %#v", got)
	}

	missingLast := filepath.Join(dir, "missing-last.sql")
	if _, err := generateSQLOutputSchema([]string{last, missingLast}); err == nil || !strings.Contains(err.Error(), missingLast) {
		t.Fatalf("missing last file error = %v", err)
	}
}

func TestGenerateSQLOutputSchemaWithoutSQLReturnsUnknownSchema(t *testing.T) {
	if got := generateSQLOutputSchemaFromSources(nil); !reflect.DeepEqual(got, map[string]interface{}{}) {
		t.Fatalf("empty sources schema = %#v", got)
	}
	got, err := generateSQLOutputSchema(nil)
	if err != nil || !reflect.DeepEqual(got, map[string]interface{}{}) {
		t.Fatalf("empty files schema = %#v, error = %v", got, err)
	}
}

func TestResolveAPISchemaAppliesPriorityAndSources(t *testing.T) {
	dir := t.TempDir()
	paramCheck := filepath.Join(dir, "param-check.js")
	outCheckWithoutSchema := filepath.Join(dir, "out-check.js")
	sqlPath := filepath.Join(dir, "query.sql")
	legacyScript := filepath.Join(dir, "legacy.js")
	writeTestFile(t, paramCheck, `
const nyanInputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {explicit_id: {type: "integer"}},
  required: ["explicit_id"]
};
`)
	writeTestFile(t, outCheckWithoutSchema, `({success: true, status: 200});`)
	writeTestFile(t, sqlPath, `SELECT id AS id, name AS name FROM items WHERE id = /*sql_id*/1`)
	writeTestFile(t, legacyScript, `
const nyanAcceptedParams = {legacy_id:1,price:1.5,enabled:true,tags:["a","b"],nested:{name:"cat"}};
`)

	explicit, err := resolveAPISchema(APIConfig{
		ParamCheck: paramCheck,
		OutCheck:   outCheckWithoutSchema,
		SQL:        []string{sqlPath},
	})
	if err != nil {
		t.Fatalf("resolveAPISchema(explicit) error = %v", err)
	}
	if explicit.InputSource != schemaSourceParamCheck || explicit.OutputSource != schemaSourceSQL {
		t.Fatalf("explicit sources = input:%q output:%q", explicit.InputSource, explicit.OutputSource)
	}
	if explicit.Input["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("explicit input schema = %#v", explicit.Input)
	}
	if _, exists := explicit.Input["sql_id"]; exists {
		t.Fatalf("SQL input unexpectedly replaced explicit schema: %#v", explicit.Input)
	}
	result := explicit.Output["properties"].(map[string]interface{})["result"].(map[string]interface{})
	items := result["items"].(map[string]interface{})
	if !reflect.DeepEqual(items["required"], []string{"id", "name"}) {
		t.Fatalf("SQL output required = %#v", items["required"])
	}

	legacy, err := resolveAPISchema(APIConfig{Script: legacyScript})
	if err != nil {
		t.Fatalf("resolveAPISchema(legacy) error = %v", err)
	}
	if legacy.InputSource != schemaSourceScriptLegacy || legacy.OutputSource != schemaSourceUnknown {
		t.Fatalf("legacy sources = input:%q output:%q", legacy.InputSource, legacy.OutputSource)
	}
	legacyProperties := legacy.Input["properties"].(map[string]interface{})
	if legacyProperties["legacy_id"].(map[string]interface{})["type"] != "integer" || legacyProperties["price"].(map[string]interface{})["type"] != "number" {
		t.Fatalf("legacy input properties = %#v", legacyProperties)
	}
	if legacyProperties["nested"].(map[string]interface{})["type"] != "object" {
		t.Fatalf("nested legacy input = %#v", legacyProperties["nested"])
	}
	if _, exists := legacy.Input["required"]; exists {
		t.Fatalf("legacy input must not infer required: %#v", legacy.Input)
	}

	unknown, err := resolveAPISchema(APIConfig{})
	if err != nil {
		t.Fatalf("resolveAPISchema(unknown) error = %v", err)
	}
	if unknown.InputSource != schemaSourceUnknown || unknown.OutputSource != schemaSourceUnknown || len(unknown.Input) != 0 || len(unknown.Output) != 0 {
		t.Fatalf("unknown schema = %#v", unknown)
	}
}

func TestLegacyValueSchemaFallsBackSafelyForMixedArrays(t *testing.T) {
	schema := legacyInputSchema(map[string]interface{}{
		"nested":  map[string]interface{}{"name": "cat"},
		"mixed":   []interface{}{float64(1), "two"},
		"empty":   []interface{}{},
		"unknown": nil,
	})
	properties := schema["properties"].(map[string]interface{})
	nested := properties["nested"].(map[string]interface{})
	if nested["type"] != "object" {
		t.Fatalf("nested schema = %#v", nested)
	}
	mixed := properties["mixed"].(map[string]interface{})
	if mixed["type"] != "array" || !reflect.DeepEqual(mixed["items"], map[string]interface{}{}) {
		t.Fatalf("mixed schema = %#v", mixed)
	}
	empty := properties["empty"].(map[string]interface{})
	if empty["type"] != "array" || !reflect.DeepEqual(empty["items"], map[string]interface{}{}) {
		t.Fatalf("empty schema = %#v", empty)
	}
	if got := properties["unknown"]; !reflect.DeepEqual(got, map[string]interface{}{}) {
		t.Fatalf("unknown value schema = %#v", got)
	}
}

func TestHandleNyanDetailResolvesSchemasForMountedAPIs(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "api.json")
	includedPath := filepath.Join(dir, "sub", "api.json")
	writeTestFile(t, rootPath, `{
  "unknown": {"description":"unknown"},
  "sub": {"type":"include","path":"./sub/api.json"}
}`)
	writeTestFile(t, includedPath, `{
  "item": {
    "paramCheck":"./check.js",
    "sql":["./query.sql"],
    "description":"included"
  }
}`)
	writeTestFile(t, filepath.Join(dir, "sub", "check.js"), `const nyanInputSchema = {type:"object", properties:{id:{type:"integer"}}};`)
	writeTestFile(t, filepath.Join(dir, "sub", "query.sql"), `SELECT id AS id FROM items WHERE id = /*id*/1`)

	result, err := loadAPIConfigFile(rootPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	if len(result.Snapshot.Files) != 2 {
		t.Fatalf("watched files = %#v, want only root and included api.json", result.Snapshot.Files)
	}
	recorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(result.Snapshot, recorder, httptest.NewRequest(http.MethodGet, "/nyan/sub/item", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("included detail status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var detail map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail["api"] != "sub/item" {
		t.Fatalf("included detail API = %#v", detail["api"])
	}
	source := detail["schemaSource"].(map[string]interface{})
	if source["input"] != schemaSourceParamCheck || source["output"] != schemaSourceSQL {
		t.Fatalf("included detail schemaSource = %#v", source)
	}
}

func TestHandleNyanDetailReloadsSchemaOnEveryRequest(t *testing.T) {
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.json")
	checkPath := filepath.Join(dir, "check.js")
	writeTestFile(t, checkPath, `const nyanInputSchema = {type:"object", properties:{id:{type:"integer"}}};`)
	writeTestFile(t, apiPath, `{"item":{"paramCheck":"./check.js","description":"live schema"}}`)
	snapshot := loadTestAPIConfig(t, apiPath).Snapshot

	first := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(snapshot, first, httptest.NewRequest(http.MethodGet, "/nyan/item", nil))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"id"`) {
		t.Fatalf("first detail = status %d body %s", first.Code, first.Body.String())
	}

	writeTestFile(t, checkPath, `const nyanInputSchema = {type:"object", properties:{name:{type:"string"}}};`)
	second := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(snapshot, second, httptest.NewRequest(http.MethodGet, "/nyan/item", nil))
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"name"`) || strings.Contains(second.Body.String(), `"id"`) {
		t.Fatalf("second detail = status %d body %s", second.Code, second.Body.String())
	}
}

func TestInvalidExplicitSchemaDoesNotBlockAPIConfigReload(t *testing.T) {
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.json")
	checkPath := filepath.Join(dir, "check.js")
	writeTestFile(t, checkPath, `const nyanInputSchema = createSchema();`)
	writeTestFile(t, apiPath, `{"item":{"paramCheck":"./check.js","description":"dynamic schema"}}`)
	setTestAPISnapshot(t, newAPIConfigSnapshot(nil, "", [sha256.Size]byte{}))

	_, reloaded, err := loadAndPublishAPIConfig(apiPath)
	if err != nil || !reloaded {
		t.Fatalf("config reload reloaded=%t error=%v", reloaded, err)
	}
	if got := currentAPISnapshot().Definitions["item"].Description; got != "dynamic schema" {
		t.Fatalf("published description = %q", got)
	}
	recorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(currentAPISnapshot(), recorder, httptest.NewRequest(http.MethodGet, "/nyan/item", nil))
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "function calls are not supported") {
		t.Fatalf("detail = status %d body %s", recorder.Code, recorder.Body.String())
	}
}

func TestCronScheduleNext(t *testing.T) {
	schedule, err := parseCronSchedule("*/15 9-10 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, time.July, 20, 8, 59, 30, 0, time.UTC)
	want := time.Date(2026, time.July, 20, 9, 0, 0, 0, time.UTC)
	if got := schedule.next(after); !got.Equal(want) {
		t.Fatalf("next() = %s, want %s", got, want)
	}
}

func TestHandleNyanListsOnlyHTTPAPIs(t *testing.T) {
	oldConfig := config
	config = Config{Name: "NyanQL", Profile: "test", Version: "v-test"}
	t.Cleanup(func() { config = oldConfig })
	setTestSQLFiles(t, map[string]APIConfig{
		"http-api": {Description: "visible"},
		"job":      {Type: apiTypeSchedule, Description: "hidden"},
		"client":   {Type: apiTypeWSClient, Description: "hidden"},
	})

	rec := httptest.NewRecorder()
	handleNyan(rec, httptest.NewRequest(http.MethodGet, "/nyan/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	var response NyanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Name != "NyanQL" || len(response.Apis) != 1 || response.Apis["http-api"].Description != "visible" {
		t.Fatalf("response = %#v", response)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Fatalf("list response fields = %#v, want only name, profile, version, apis", raw)
	}
	for _, unexpected := range []string{"inputSchema", "outputSchema", "schemaSource"} {
		if _, exists := raw[unexpected]; exists {
			t.Fatalf("list response unexpectedly contains %q: %#v", unexpected, raw)
		}
	}
}

func TestHandleNyanReturnsEmptyAPIsObject(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{})
	recorder := httptest.NewRecorder()
	handleNyan(recorder, httptest.NewRequest(http.MethodGet, "/nyan/", nil))

	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	apis, exists := response["apis"].(map[string]interface{})
	if !exists || len(apis) != 0 {
		t.Fatalf("apis = %#v, want existing empty object", response["apis"])
	}
}

func TestHandleNyanDetailPublishesExplicitSchemas(t *testing.T) {
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.json")
	writeTestFile(t, filepath.Join(dir, "param-check.js"), `
const nyanInputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {id: {type: "integer"}},
  required: ["id"],
  additionalProperties: false
};
`)
	writeTestFile(t, filepath.Join(dir, "out-check.js"), `
const nyanOutputSchema = {
  type: "object",
  properties: {success: {const: true}},
  required: ["success"]
};
`)
	writeTestFile(t, filepath.Join(dir, "query.sql"), `SELECT /*id*/1 AS id`)
	writeTestFile(t, apiPath, `{
  "item": {
    "paramCheck":"./param-check.js",
    "outCheck":"./out-check.js",
    "sql":["./query.sql"],
    "description":"explicit schemas"
  }
}`)
	snapshot := loadTestAPIConfig(t, apiPath).Snapshot

	recorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(snapshot, recorder, httptest.NewRequest(http.MethodGet, "/nyan/item", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	source := response["schemaSource"].(map[string]interface{})
	if source["input"] != schemaSourceParamCheck || source["output"] != schemaSourceOutCheck {
		t.Fatalf("schemaSource = %#v", source)
	}
	input := response["inputSchema"].(map[string]interface{})
	if input["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("inputSchema = %#v", input)
	}
	output := response["outputSchema"].(map[string]interface{})
	if _, exists := output["$schema"]; exists {
		t.Fatalf("$schema was added to outputSchema: %#v", output)
	}
	if _, exists := response["nyanAcceptedParams"]; exists {
		t.Fatalf("nyanAcceptedParams must be omitted for an explicit input schema: %#v", response)
	}
}

func TestHandleNyanDetailPublishesLegacyAndUnknownSchemas(t *testing.T) {
	legacyScript := writeTestScript(t, `
const nyanAcceptedParams = {"id":1,"name":"cat"};
JSON.stringify({success:true});
`)
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"legacy":  {Script: legacyScript, Description: "legacy"},
		"unknown": {Description: "unknown"},
	}, "", [sha256.Size]byte{})

	legacyRecorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(snapshot, legacyRecorder, httptest.NewRequest(http.MethodGet, "/nyan/legacy", nil))
	if legacyRecorder.Code != http.StatusOK {
		t.Fatalf("legacy status = %d; body=%s", legacyRecorder.Code, legacyRecorder.Body.String())
	}
	var legacy map[string]interface{}
	if err := json.Unmarshal(legacyRecorder.Body.Bytes(), &legacy); err != nil {
		t.Fatal(err)
	}
	legacySource := legacy["schemaSource"].(map[string]interface{})
	if legacySource["input"] != schemaSourceScriptLegacy || legacySource["output"] != schemaSourceUnknown {
		t.Fatalf("legacy schemaSource = %#v", legacySource)
	}
	if legacy["nyanAcceptedParams"].(map[string]interface{})["name"] != "cat" {
		t.Fatalf("nyanAcceptedParams = %#v", legacy["nyanAcceptedParams"])
	}
	if _, exists := legacy["nyanOutputColumns"]; exists {
		t.Fatalf("nyanOutputColumns must be removed: %#v", legacy)
	}

	unknownRecorder := httptest.NewRecorder()
	handleNyanDetailWithSnapshot(snapshot, unknownRecorder, httptest.NewRequest(http.MethodGet, "/nyan/unknown", nil))
	if unknownRecorder.Code != http.StatusOK {
		t.Fatalf("unknown status = %d; body=%s", unknownRecorder.Code, unknownRecorder.Body.String())
	}
	var unknown map[string]interface{}
	if err := json.Unmarshal(unknownRecorder.Body.Bytes(), &unknown); err != nil {
		t.Fatal(err)
	}
	unknownSource := unknown["schemaSource"].(map[string]interface{})
	if unknownSource["input"] != schemaSourceUnknown || unknownSource["output"] != schemaSourceUnknown {
		t.Fatalf("unknown schemaSource = %#v", unknownSource)
	}
	if len(unknown["inputSchema"].(map[string]interface{})) != 0 || len(unknown["outputSchema"].(map[string]interface{})) != 0 {
		t.Fatalf("unknown schemas = input:%#v output:%#v", unknown["inputSchema"], unknown["outputSchema"])
	}
}

func TestCheckAliasSchemaDoesNotEnableRuntimeValidation(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.json")
	writeTestFile(t, filepath.Join(dir, "check.js"), `
const nyanInputSchema = {
  type: "object",
  properties: {id: {type: "integer"}},
  required: ["id"],
  additionalProperties: false
};
({success: true, status: 200, error: null});
`)
	writeTestFile(t, filepath.Join(dir, "main.js"), `
JSON.stringify({success: true, status: 200, result: {id: nyanAllParams.id}});
`)
	writeTestFile(t, apiPath, `{
  "item": {
    "check":"./check.js",
    "script":"./main.js",
    "description":"check alias"
  }
	}`)
	snapshot := loadTestAPIConfig(t, apiPath).Snapshot
	resolved, err := resolveAPISchema(snapshot.Definitions["item"])
	if err != nil {
		t.Fatalf("resolveAPISchema() error = %v", err)
	}
	if got := resolved.InputSource; got != schemaSourceParamCheck {
		t.Fatalf("check alias input source = %q", got)
	}

	recorder := httptest.NewRecorder()
	handleRequestWithSnapshot(snapshot, recorder, httptest.NewRequest(http.MethodGet, "/?api=item&id=not-an-integer", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	result := response["result"].(map[string]interface{})
	if result["id"] != "not-an-integer" {
		t.Fatalf("schema unexpectedly validated or converted input: %#v", response)
	}
}

func TestSaveBase64ToFileAndHashes(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "nested", "message.txt")
	if err := saveBase64ToFile(destination, "aGVsbG8="); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Fatalf("content = %q, want hello", content)
	}
	if err := saveBase64ToFile(destination, "not-base64"); err == nil {
		t.Fatal("saveBase64ToFile() error = nil, want invalid base64 error")
	}
	if got := sha256Hash("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256Hash(abc) = %q", got)
	}
	if got := sha1Hash("abc"); got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("sha1Hash(abc) = %q", got)
	}
}

func TestConnectDBRejectsUnsupportedDatabase(t *testing.T) {
	if _, err := connectDB(Config{DatabaseType: "unsupported"}); err == nil {
		t.Fatal("connectDB() error = nil, want unsupported database error")
	}
}

func TestRunScriptCommitsAndRollsBackNyanRunSQL(t *testing.T) {
	testDB := setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	if _, err := testDB.Exec(`CREATE TABLE items (name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	sqlPath := filepath.Join(t.TempDir(), "insert.sql")
	writeTestFile(t, sqlPath, `INSERT INTO items(name) VALUES (/*name*/'default')`)
	encodedPath, err := json.Marshal(sqlPath)
	if err != nil {
		t.Fatal(err)
	}

	commitScript := writeTestScript(t, fmt.Sprintf(`
nyanRunSQL(%s, {name: "committed"});
JSON.stringify({success: true});
`, encodedPath))
	if _, err := runScript([]string{commitScript}, nil); err != nil {
		t.Fatalf("committing script failed: %v", err)
	}

	rollbackScript := writeTestScript(t, fmt.Sprintf(`
nyanRunSQL(%s, {name: "rolled-back"});
throw new Error("stop");
`, encodedPath))
	if _, err := runScript([]string{rollbackScript}, nil); err == nil {
		t.Fatal("failing script error = nil")
	}

	rows, err := testDB.Query(`SELECT name FROM items ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"committed"}) {
		t.Fatalf("stored names = %#v, want only committed row", names)
	}
}

func TestHandleNyanDetailCombinesSQLAndScriptMetadata(t *testing.T) {
	sqlPath := filepath.Join(t.TempDir(), "detail.sql")
	writeTestFile(t, sqlPath, `SELECT /*id*/'1' AS id`)
	scriptPath := writeTestScript(t, `
const nyanAcceptedParams = {"name":"default"};
`)
	setTestSQLFiles(t, map[string]APIConfig{
		"detail": {
			SQL:         []string{sqlPath},
			Script:      scriptPath,
			Description: "detail API",
		},
	})

	rec := httptest.NewRecorder()
	handleNyanOrDetail(rec, httptest.NewRequest(http.MethodGet, "/nyan/detail", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	var response struct {
		API                string                 `json:"api"`
		Description        string                 `json:"description"`
		NyanAcceptedParams map[string]interface{} `json:"nyanAcceptedParams"`
		InputSchema        map[string]interface{} `json:"inputSchema"`
		OutputSchema       map[string]interface{} `json:"outputSchema"`
		SchemaSource       struct {
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"schemaSource"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.API != "detail" || response.Description != "detail API" {
		t.Fatalf("response = %#v", response)
	}
	if fmt.Sprint(response.NyanAcceptedParams["id"]) != "1" || response.NyanAcceptedParams["name"] != "default" {
		t.Fatalf("accepted params = %#v", response.NyanAcceptedParams)
	}
	if response.SchemaSource.Input != schemaSourceSQL || response.SchemaSource.Output != schemaSourceSQL {
		t.Fatalf("schema source = %#v", response.SchemaSource)
	}
	if response.InputSchema["type"] != "object" || response.OutputSchema["type"] != "object" {
		t.Fatalf("schemas = input:%#v output:%#v", response.InputSchema, response.OutputSchema)
	}
}

func TestExecCommandReportsSuccessAndFailure(t *testing.T) {
	result, err := execCommand("echo nyan")
	if err != nil {
		t.Fatalf("execCommand(success) error = %v", err)
	}
	if !result.Success || strings.TrimSpace(result.Stdout) != "nyan" || result.ExitCode != 0 {
		t.Fatalf("success result = %#v", result)
	}

	result, err = execCommand("exit 7")
	if err != nil {
		t.Fatalf("execCommand(nonzero exit) error = %v", err)
	}
	if result.Success || result.ExitCode != 7 {
		t.Fatalf("failure result = %#v", result)
	}
}

func hostExecTestCommand(exitCode int) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("echo processing& echo problem 1>&2& exit /b %d", exitCode)
	}
	return fmt.Sprintf("echo processing; echo problem >&2; exit %d", exitCode)
}

func TestNyanHostExecReturnsCommandResults(t *testing.T) {
	for _, exitCode := range []int{0, 1, 7} {
		t.Run(fmt.Sprintf("exit_%d", exitCode), func(t *testing.T) {
			vm := goja.New()
			registerNyanFuncs(vm, nil, nil, nil)
			value, err := vm.RunString(fmt.Sprintf(`nyanHostExec(%q);`, hostExecTestCommand(exitCode)))
			if err != nil {
				t.Fatalf("command result became an exception: %v", err)
			}
			result, ok := value.Export().(map[string]interface{})
			if !ok {
				t.Fatalf("result is not an object: %#v", value.Export())
			}
			if len(result) != 4 || result["success"] != (exitCode == 0) || result["exit_code"] != float64(exitCode) ||
				strings.TrimSpace(result["stdout"].(string)) != "processing" || strings.TrimSpace(result["stderr"].(string)) != "problem" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
	t.Run("command_not_found", func(t *testing.T) {
		vm := goja.New()
		registerNyanFuncs(vm, nil, nil, nil)
		value, err := vm.RunString(`const result = nyanHostExec("nyanql_missing_command_643acf5e");
result.success === false && result.exit_code !== 0 && result.stderr.length > 0;`)
		if err != nil || !value.ToBoolean() {
			t.Fatalf("missing command result=%v err=%v", value, err)
		}
	})
}

func TestNyanHostExecInvocationErrorsRemainExceptions(t *testing.T) {
	t.Run("missing_argument", func(t *testing.T) {
		vm := goja.New()
		registerNyanFuncs(vm, nil, nil, nil)
		if _, err := vm.RunString(`nyanHostExec();`); err == nil || !strings.Contains(err.Error(), "No command provided") {
			t.Fatalf("missing argument error=%v", err)
		}
	})
	t.Run("shell_unavailable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows may find cmd in system directories independently of PATH")
		}
		t.Setenv("PATH", t.TempDir())
		result, err := execCommand("echo test")
		if err == nil || result.Success || result.ExitCode != -1 {
			t.Fatalf("shell launch failure: result=%#v err=%v", result, err)
		}
		vm := goja.New()
		registerNyanFuncs(vm, nil, nil, nil)
		if _, err := vm.RunString(`nyanHostExec("echo test");`); err == nil || !strings.Contains(err.Error(), "failed to exec") {
			t.Fatalf("shell launch failure was not an exception: %v", err)
		}
	})
}

func TestNyanHostExecAPIResultControlsPush(t *testing.T) {
	for _, route := range []string{"http", "nyanCallMe"} {
		for _, test := range []struct {
			name          string
			exitCode      int
			handleFailure bool
		}{
			{"success", 0, false},
			{"failure", 7, false},
			{"handled_failure", 7, true},
		} {
			t.Run(route+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				oldHub := hub
				hub = NewHub()
				t.Cleanup(func() { hub = oldHub })
				dir := t.TempDir()
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"), %q);`, filepath.Join(dir, stage))
				}
				body := fmt.Sprintf(`const result = nyanHostExec(%q);`, hostExecTestCommand(test.exitCode)) + mark("after")
				if test.handleFailure {
					body += `({success:true,handled_exit:result.exit_code});`
				} else {
					body += `JSON.stringify(result);`
				}
				setTestSQLFiles(t, map[string]APIConfig{
					"origin": {Script: writeTestScript(t, body), OutCheck: writeTestScript(t, mark("out")+`({success:true,status:200});`), Push: "events"},
					"events": {Script: writeTestScript(t, mark("push")+`({success:true});`)},
				})
				var response map[string]interface{}
				if route == "http" {
					w := httptest.NewRecorder()
					handleRequest(w, httptest.NewRequest(http.MethodGet, "/origin", nil))
					if w.Code != http.StatusOK {
						t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
					}
					response = decodeTestJSONObject(t, w.Body.Bytes())
				} else {
					vm := goja.New()
					registerNyanFuncs(vm, currentAPISnapshot(), nil, nil)
					v, err := vm.RunString(`JSON.stringify(nyanCallMe({api:"origin"}));`)
					if err != nil {
						t.Fatal(err)
					}
					response = decodeTestJSONObject(t, []byte(v.String()))
				}
				wantSuccess := test.exitCode == 0 || test.handleFailure
				if response["success"] != wantSuccess {
					t.Fatalf("response=%#v", response)
				}
				codeKey := "exit_code"
				if test.handleFailure {
					codeKey = "handled_exit"
				}
				if response[codeKey] != float64(test.exitCode) {
					t.Fatalf("exit code lost: %#v", response)
				}
				for stage, want := range map[string]bool{"after": true, "out": true, "push": wantSuccess} {
					_, err := os.Stat(filepath.Join(dir, stage))
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					if (err == nil) != want {
						t.Fatalf("stage %s executed=%t want %t", stage, err == nil, want)
					}
				}
			})
		}
	}
}

func TestAdjustPathsResolvesRelativeValues(t *testing.T) {
	baseDir := t.TempDir()
	cfg := Config{
		CertPath:          "cert.pem",
		KeyPath:           "key.pem",
		DatabaseType:      "sqlite",
		DBName:            "data.db",
		JavascriptInclude: []string{"common.js", filepath.Join(baseDir, "absolute.js")},
	}
	adjustPaths(baseDir, &cfg)
	if cfg.CertPath != filepath.Join(baseDir, "cert.pem") || cfg.KeyPath != filepath.Join(baseDir, "key.pem") {
		t.Fatalf("certificate paths = %q, %q", cfg.CertPath, cfg.KeyPath)
	}
	if cfg.DBName != filepath.Join(baseDir, "data.db") {
		t.Fatalf("DBName = %q", cfg.DBName)
	}
	wantIncludes := []string{filepath.Join(baseDir, "common.js"), filepath.Join(baseDir, "absolute.js")}
	if !reflect.DeepEqual(cfg.JavascriptInclude, wantIncludes) {
		t.Fatalf("JavascriptInclude = %#v", cfg.JavascriptInclude)
	}
}

func TestWebSocketMessageTypeLabels(t *testing.T) {
	tests := map[int]string{
		websocket.TextMessage:   "text",
		websocket.BinaryMessage: "binary",
		websocket.CloseMessage:  "close",
		websocket.PingMessage:   "ping",
		websocket.PongMessage:   "pong",
		999:                     "unknown(999)",
	}
	for messageType, want := range tests {
		if got := websocketMessageTypeLabel(messageType); got != want {
			t.Errorf("websocketMessageTypeLabel(%d) = %q, want %q", messageType, got, want)
		}
	}
}

func TestNewAPIConfigSnapshotDeepClonesConfiguredExtensions(t *testing.T) {
	readOnly := true
	destructive := false
	openWorld := false
	original := APIConfig{
		Type:             apiTypeMCP,
		RateLimit:        &HTTPRateLimitConfig{Requests: 50, Window: "1m"},
		MaxConcurrent:    4,
		Runtime:          APIRuntimeConfig{Capabilities: []string{"crypto"}, SQLFiles: []string{"/sql/original.sql"}, Settings: map[string]interface{}{"nested": map[string]interface{}{"value": "original"}, "items": []interface{}{"first"}}},
		ProtocolVersions: []string{mcpProtocolVersion20251125},
		Tools: []MCPToolConfig{{
			Name: "tool",
			API:  "target",
			SecuritySchemes: []MCPSecurityScheme{{
				Type:   "oauth2",
				Scopes: []string{"read"},
			}},
			Annotations: MCPToolAnnotations{ReadOnlyHint: &readOnly, DestructiveHint: &destructive, OpenWorldHint: &openWorld},
		}},
	}
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{"server": original}, "", [sha256.Size]byte{})

	original.Runtime.Capabilities[0] = "sql"
	original.Runtime.SQLFiles[0] = "/sql/mutated.sql"
	original.Runtime.Settings["nested"].(map[string]interface{})["value"] = "mutated"
	original.Runtime.Settings["items"].([]interface{})[0] = "mutated"
	original.ProtocolVersions[0] = "mutated"
	original.RateLimit.Requests = 999
	original.RateLimit.Window = "24h"
	original.Tools[0].SecuritySchemes[0].Scopes[0] = "write"
	*original.Tools[0].Annotations.ReadOnlyHint = false
	*original.Tools[0].Annotations.DestructiveHint = true
	*original.Tools[0].Annotations.OpenWorldHint = true

	got := snapshot.Definitions["server"]
	if !reflect.DeepEqual(got.Runtime.Capabilities, []string{"crypto"}) || !reflect.DeepEqual(got.Runtime.SQLFiles, []string{"/sql/original.sql"}) || got.Runtime.Settings["nested"].(map[string]interface{})["value"] != "original" || got.Runtime.Settings["items"].([]interface{})[0] != "first" {
		t.Fatalf("snapshot runtime = %#v", got.Runtime)
	}
	if !reflect.DeepEqual(got.ProtocolVersions, []string{mcpProtocolVersion20251125}) || got.Tools[0].SecuritySchemes[0].Scopes[0] != "read" {
		t.Fatalf("snapshot MCP slices = versions:%#v tools:%#v", got.ProtocolVersions, got.Tools)
	}
	if got.RateLimit == original.RateLimit || got.RateLimit.Requests != 50 || got.RateLimit.Window != "1m" || got.MaxConcurrent != 4 {
		t.Fatalf("snapshot MCP limits = rate:%#v maxConcurrent:%d", got.RateLimit, got.MaxConcurrent)
	}
	annotations := got.Tools[0].Annotations
	if annotations.ReadOnlyHint == nil || !*annotations.ReadOnlyHint || annotations.DestructiveHint == nil || *annotations.DestructiveHint || annotations.OpenWorldHint == nil || *annotations.OpenWorldHint {
		t.Fatalf("snapshot annotations = %#v", annotations)
	}
}

func TestLoadAPIConfigRejectsHTTPSettings(t *testing.T) {
	for _, httpSettings := range []string{`{}`, `null`, `{"path":"/hello","methods":["GET"],"access":"basic","responseMode":"raw"}`} {
		t.Run(httpSettings, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "script.js"), `({ok:true});`)
			apiPath := filepath.Join(dir, "api.json")
			writeTestFile(t, apiPath, fmt.Sprintf(`{"endpoint":{"type":"api","script":"script.js","http":%s}}`, httpSettings))
			if _, err := loadAPIConfigFile(apiPath); err == nil || !strings.Contains(err.Error(), `unsupported field "http"`) {
				t.Fatalf("http setting was not rejected: %v", err)
			}
		})
	}
}

func TestHTTPRunsOutputCheck(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	setTestSQLFiles(t, map[string]APIConfig{
		"endpoint": {
			ParamCheck: writeTestScript(t, `nyanAllParams.checked = true; ({success:true,status:200});`),
			Script:     writeTestScript(t, `({checked:nyanAllParams.checked});`),
			OutCheck: writeTestScript(t, `
if (JSON.parse(nyanAllParams.nyan_output.body).checked !== true) throw new Error("paramCheck was skipped");
({success:false,status:409,error:"output rejected"});`),
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
	req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
	unifiedHandler(rec, req)
	if rec.Code != http.StatusConflict || decodeTestJSONObject(t, rec.Body.Bytes())["error"] != "output rejected" {
		t.Fatalf("HTTP skipped checks: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRestrictedRuntimeSQLAllowlistAndNoTransactionGlobal(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	allowedSQL := filepath.Join(dir, "allowed.sql")
	deniedSQL := filepath.Join(dir, "denied.sql")
	writeTestFile(t, allowedSQL, `SELECT 'allowed' AS value`)
	writeTestFile(t, deniedSQL, `SELECT 'denied' AS value`)
	encodedAllowed, err := json.Marshal(allowedSQL)
	if err != nil {
		t.Fatal(err)
	}
	encodedDenied, err := json.Marshal(deniedSQL)
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig := APIRuntimeConfig{Capabilities: []string{"sql"}, SQLFiles: []string{allowedSQL}}

	allowedScript := writeTestScript(t, fmt.Sprintf(`
const rows = nyanRunSQL(%s, {});
JSON.stringify({transactionType:typeof nyanTx, value:rows[0].value});
`, encodedAllowed))
	result, err := runScriptWithRuntimeWithSnapshot(newAPIConfigSnapshot(nil, "", [sha256.Size]byte{}), []string{allowedScript}, map[string]interface{}{}, runtimeConfig, true)
	if err != nil {
		t.Fatalf("allowed restricted SQL error = %v", err)
	}
	allowedResult := decodeTestJSONObject(t, []byte(result))
	if allowedResult["transactionType"] != "undefined" || allowedResult["value"] != "allowed" {
		t.Fatalf("allowed restricted SQL result = %#v", allowedResult)
	}

	deniedScript := writeTestScript(t, fmt.Sprintf(`nyanRunSQL(%s, {});`, encodedDenied))
	if _, err := runScriptWithRuntimeWithSnapshot(newAPIConfigSnapshot(nil, "", [sha256.Size]byte{}), []string{deniedScript}, map[string]interface{}{}, runtimeConfig, true); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("non-allowlisted restricted SQL error = %v", err)
	}
}

func TestGenericCryptographicPrimitives(t *testing.T) {
	first, err := secureRandomBase64URL(32)
	if err != nil {
		t.Fatalf("secureRandomBase64URL() error = %v", err)
	}
	second, err := secureRandomBase64URL(32)
	if err != nil {
		t.Fatalf("secureRandomBase64URL() second error = %v", err)
	}
	if first == second || strings.Contains(first, "=") {
		t.Fatalf("random values are not unique raw base64url values: first=%q second=%q", first, second)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("random value decode = %d bytes, error=%v, value=%q", len(decoded), err, first)
	}
	for _, size := range []int{-1, 0, 1025} {
		if _, err := secureRandomBase64URL(size); err == nil {
			t.Fatalf("secureRandomBase64URL(%d) error = nil", size)
		}
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := sha256Base64URL(verifier); got != challenge {
		t.Fatalf("sha256Base64URL(PKCE verifier) = %q, want %q", got, challenge)
	}
	if !timingSafeStringEqual("same", "same") || timingSafeStringEqual("same", "different") || timingSafeStringEqual("a", "a\x00") {
		t.Fatal("timingSafeStringEqual() returned an unexpected result")
	}

	encoded, err := hashPasswordArgon2ID("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPasswordArgon2ID() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=") {
		t.Fatalf("password hash = %q, want Argon2id PHC string", encoded)
	}
	valid, err := verifyPasswordArgon2ID("correct horse battery staple", encoded)
	if err != nil || !valid {
		t.Fatalf("verifyPasswordArgon2ID(correct) = %t, error=%v", valid, err)
	}
	valid, err = verifyPasswordArgon2ID("wrong", encoded)
	if err != nil || valid {
		t.Fatalf("verifyPasswordArgon2ID(wrong) = %t, error=%v", valid, err)
	}
	if valid, err := verifyPasswordArgon2ID("password", "not-a-phc-string"); err == nil || valid {
		t.Fatalf("verifyPasswordArgon2ID(malformed) = %t, error=%v", valid, err)
	}
}

func TestRandomBase64URLJavaScriptArguments(t *testing.T) {
	for _, function := range []string{"nyanRandomBase64URL", "nyanCrypto.randomBase64URL"} {
		t.Run(function, func(t *testing.T) {
			for _, size := range []int{1, 15, 16, 32, 128, 129, 256, 1024} {
				t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
					vm := goja.New()
					registerNyanCryptographicFunctions(vm)
					value, err := vm.RunString(fmt.Sprintf("%s(%d)", function, size))
					if err != nil {
						t.Fatal(err)
					}
					encoded, ok := value.Export().(string)
					if !ok {
						t.Fatalf("result is not a string: %#v", value.Export())
					}
					decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
					if err != nil || len(decoded) != size || len(encoded) != base64.RawURLEncoding.EncodedLen(size) || strings.ContainsAny(encoded, "=+/\r\n") {
						t.Fatalf("unexpected Base64URL: %q, decoded size=%d, error=%v", encoded, len(decoded), err)
					}
				})
			}
			for _, argument := range []string{"0", "-1", "1025", "undefined", "null"} {
				t.Run("invalid="+argument, func(t *testing.T) {
					vm := goja.New()
					registerNyanCryptographicFunctions(vm)
					value, err := vm.RunString(fmt.Sprintf(`
try { %s(%s); false; }
catch (error) { String(error).includes("between 1 and 1024"); }
`, function, argument))
					if err != nil || !value.ToBoolean() {
						t.Fatalf("expected catchable range exception, value=%v, error=%v", value, err)
					}
				})
			}
		})
	}
	t.Run("default", func(t *testing.T) {
		vm := goja.New()
		registerNyanCryptographicFunctions(vm)
		value, err := vm.RunString("nyanRandomBase64URL()")
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value.String())
		if err != nil || len(decoded) != 32 || len(value.String()) != 43 {
			t.Fatalf("default result=%q, decoded size=%d, error=%v", value.String(), len(decoded), err)
		}
	})
	for _, arguments := range []string{"", "32, 64"} {
		t.Run("crypto_argument_count="+arguments, func(t *testing.T) {
			vm := goja.New()
			registerNyanCryptographicFunctions(vm)
			_, err := vm.RunString("nyanCrypto.randomBase64URL(" + arguments + ")")
			if err == nil || !strings.Contains(err.Error(), "requires exactly 1 argument") {
				t.Fatalf("expected argument count exception, error=%v", err)
			}
		})
	}
}

func TestMCPInitialize(t *testing.T) {
	oldConfig := config
	config.Name = "NyanQL Test"
	config.Version = "v-test"
	t.Cleanup(func() { config = oldConfig })
	serverConfig := APIConfig{
		Type:             apiTypeMCP,
		Path:             "/mcp",
		ProtocolVersions: []string{mcpProtocolVersion20251125},
		Resource:         "http://localhost/mcp",
		Instructions:     "Test instructions",
	}
	rec := performTestMCPRequest(t, newAPIConfigSnapshot(nil, "", [sha256.Size]byte{}), serverConfig, `{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("MCP-Protocol-Version") != mcpProtocolVersion20251125 || rec.Header().Get("MCP-Session-Id") != "" {
		t.Fatalf("MCP headers = %#v", rec.Header())
	}
	response := decodeTestJSONObject(t, rec.Body.Bytes())
	if response["jsonrpc"] != "2.0" || response["id"] != float64(7) {
		t.Fatalf("JSON-RPC response = %#v", response)
	}
	result := response["result"].(map[string]interface{})
	if result["protocolVersion"] != mcpProtocolVersion20251125 || result["instructions"] != "Test instructions" {
		t.Fatalf("initialize result = %#v", result)
	}
	serverInfo := result["serverInfo"].(map[string]interface{})
	if serverInfo["name"] != "NyanQL Test" || serverInfo["version"] != "v-test" {
		t.Fatalf("serverInfo = %#v", serverInfo)
	}
	toolsCapability := result["capabilities"].(map[string]interface{})["tools"].(map[string]interface{})
	if toolsCapability["listChanged"] != false {
		t.Fatalf("tools capability = %#v", toolsCapability)
	}
}

func TestMCPProtocolVersionNegotiation(t *testing.T) {
	serverConfig := APIConfig{
		Type: apiTypeMCP,
		Path: "/mcp",
		ProtocolVersions: []string{
			mcpProtocolVersion20251125,
			mcpProtocolVersion20250618,
		},
		Resource: "http://localhost/mcp",
	}
	snapshot := newAPIConfigSnapshot(nil, "", [sha256.Size]byte{})

	initialize := performTestMCPRequestWithProtocol(
		t,
		snapshot,
		serverConfig,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"chatgpt","version":"1"}}}`,
		"",
		mcpProtocolVersion20250618,
	)
	if initialize.Code != http.StatusOK {
		t.Fatalf("2025-06-18 initialize status = %d; body=%s", initialize.Code, initialize.Body.String())
	}
	if got := initialize.Header().Get("MCP-Protocol-Version"); got != mcpProtocolVersion20250618 {
		t.Fatalf("2025-06-18 initialize response header = %q", got)
	}
	initializeResult := decodeTestJSONObject(t, initialize.Body.Bytes())["result"].(map[string]interface{})
	if got := initializeResult["protocolVersion"]; got != mcpProtocolVersion20250618 {
		t.Fatalf("2025-06-18 initialize result protocolVersion = %#v", got)
	}

	toolsList := performTestMCPRequestWithProtocol(
		t,
		snapshot,
		serverConfig,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		"",
		mcpProtocolVersion20250618,
	)
	if toolsList.Code != http.StatusOK {
		t.Fatalf("2025-06-18 tools/list status = %d; body=%s", toolsList.Code, toolsList.Body.String())
	}
	if got := toolsList.Header().Get("MCP-Protocol-Version"); got != mcpProtocolVersion20250618 {
		t.Fatalf("2025-06-18 tools/list response header = %q", got)
	}

	unsupportedInitialize := performTestMCPRequestWithProtocol(
		t,
		snapshot,
		serverConfig,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"future-client","version":"1"}}}`,
		"",
		"2099-01-01",
	)
	if unsupportedInitialize.Code != http.StatusOK {
		t.Fatalf("unsupported initialize status = %d; body=%s", unsupportedInitialize.Code, unsupportedInitialize.Body.String())
	}
	unsupportedResult := decodeTestJSONObject(t, unsupportedInitialize.Body.Bytes())["result"].(map[string]interface{})
	if got := unsupportedResult["protocolVersion"]; got != mcpProtocolVersion20251125 {
		t.Fatalf("unsupported initialize negotiated protocolVersion = %#v", got)
	}

	unsupportedSubsequent := performTestMCPRequestWithProtocol(
		t,
		snapshot,
		serverConfig,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`,
		"",
		"2099-01-01",
	)
	if unsupportedSubsequent.Code != http.StatusBadRequest {
		t.Fatalf("unsupported subsequent protocol status = %d; body=%s", unsupportedSubsequent.Code, unsupportedSubsequent.Body.String())
	}

	missingSubsequent := performTestMCPRequestWithProtocol(
		t,
		snapshot,
		serverConfig,
		`{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}`,
		"",
		"",
	)
	if missingSubsequent.Code != http.StatusBadRequest {
		t.Fatalf("missing subsequent protocol status = %d; body=%s", missingSubsequent.Code, missingSubsequent.Body.String())
	}
}

func TestMCPConcurrencyLimiter(t *testing.T) {
	mcpConcurrencyLimiters.Lock()
	oldLimiters := mcpConcurrencyLimiters.Limiters
	mcpConcurrencyLimiters.Limiters = make(map[string]chan struct{})
	mcpConcurrencyLimiters.Unlock()
	t.Cleanup(func() {
		mcpConcurrencyLimiters.Lock()
		mcpConcurrencyLimiters.Limiters = oldLimiters
		mcpConcurrencyLimiters.Unlock()
	})

	releaseFirst, acquired := acquireMCPExecutionSlot("server", 1)
	if !acquired {
		t.Fatal("first MCP execution slot was not acquired")
	}
	if release, acquired := acquireMCPExecutionSlot("server", 1); acquired {
		release()
		t.Fatal("MCP execution exceeded maxConcurrent")
	}
	releaseOther, acquired := acquireMCPExecutionSlot("other-server", 1)
	if !acquired {
		t.Fatal("different MCP server incorrectly shared concurrency slots")
	}
	releaseOther()
	releaseFirst()
	releaseAgain, acquired := acquireMCPExecutionSlot("server", 1)
	if !acquired {
		t.Fatal("released MCP execution slot was not reusable")
	}
	releaseAgain()
}

func TestMCPToolsListUsesAllowlistSchemasAndMetadata(t *testing.T) {
	t.Skip("旧MCP Tool object形式は廃止済み")
	dir := t.TempDir()
	paramCheck := filepath.Join(dir, "param_check.js")
	outCheck := filepath.Join(dir, "out_check.js")
	writeTestFile(t, paramCheck, `
const nyanInputSchema = {
  type: "object",
  properties: {id: {type: "integer"}},
  required: ["id"],
  additionalProperties: false
};
({success:true,status:200,error:null});
`)
	writeTestFile(t, outCheck, `
const nyanOutputSchema = {
  type: "object",
  properties: {success: {type: "boolean"}},
  required: ["success"]
};
({success:true,status:200,error:null});
`)
	readOnly := true
	destructive := false
	openWorld := false
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"listed": {ParamCheck: paramCheck, OutCheck: outCheck, Description: "Fallback description"},
		"hidden": {Description: "Must not be exposed"},
	}, "", [sha256.Size]byte{})
	serverConfig := APIConfig{Tools: []MCPToolConfig{{
		Name:  "get_stamp",
		API:   "listed",
		Title: "Get stamp",
		SecuritySchemes: []MCPSecurityScheme{{
			Type:   "oauth2",
			Scopes: []string{"stamps:read"},
		}},
		Annotations: MCPToolAnnotations{ReadOnlyHint: &readOnly, DestructiveHint: &destructive, OpenWorldHint: &openWorld},
	}}}
	rec := performTestMCPRequest(t, snapshot, serverConfig, `{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	response := decodeTestJSONObject(t, rec.Body.Bytes())
	result := response["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("tools = %#v, want one allowlisted tool", tools)
	}
	tool := tools[0].(map[string]interface{})
	if tool["name"] != "get_stamp" || tool["title"] != "Get stamp" || tool["description"] != "Fallback description" {
		t.Fatalf("tool identity = %#v", tool)
	}
	input := tool["inputSchema"].(map[string]interface{})
	if !reflect.DeepEqual(input["required"], []interface{}{"id"}) || input["additionalProperties"] != false {
		t.Fatalf("input schema = %#v", input)
	}
	if _, ok := tool["outputSchema"].(map[string]interface{}); !ok {
		t.Fatalf("output schema = %#v", tool["outputSchema"])
	}
	annotations := tool["annotations"].(map[string]interface{})
	if annotations["readOnlyHint"] != true || annotations["destructiveHint"] != false || annotations["openWorldHint"] != false {
		t.Fatalf("annotations = %#v", annotations)
	}
	security := tool["securitySchemes"].([]interface{})
	if len(security) != 1 || security[0].(map[string]interface{})["type"] != "oauth2" {
		t.Fatalf("securitySchemes = %#v", security)
	}
	metaSecurity := tool["_meta"].(map[string]interface{})["securitySchemes"].([]interface{})
	if !reflect.DeepEqual(security, metaSecurity) {
		t.Fatalf("top-level and _meta securitySchemes differ: %#v / %#v", security, metaSecurity)
	}
}

func TestNyan8CompatibleMCPConfigurationAndRouting(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "tool.js"), `JSON.stringify({success:true,status:200,result:{value:nyanAllParams.value}});`)
	writeTestFile(t, filepath.Join(dir, "input.js"), `const nyanInputSchema={type:"object",properties:{value:{type:"string"}},required:["value"],additionalProperties:false}; ({success:true,status:200});`)
	writeTestFile(t, filepath.Join(dir, "oauth.js"), `JSON.stringify({status:200,headers:{"Content-Type":"application/json"},body:{ok:true}});`)
	apiPath := filepath.Join(dir, "api.json")
	writeTestFile(t, apiPath, `{
  "shared_tool":{"type":"api","script":"tool.js","paramCheck":"input.js","title":"Shared Tool","description":"共通Tool","securitySchemes":[{"type":"oauth2","scopes":["example:read"]}],"annotations":{"readOnlyHint":true}},
  ".well-known/oauth-authorization-server":{"type":"api"},
  ".well-known/oauth-protected-resource/http_mcp":{"type":"api"},
  "oauth/authorize":{"type":"api","script":"oauth.js"},
  "oauth/token":{"type":"api","script":"oauth.js"},
  "oauth/register":{"type":"api","script":"oauth.js"},
  "oauth/verify_access":{"type":"api","script":"oauth.js","scopes":["example:read"]},
  "http_mcp":{"type":"mcp","transport":"streamable_http","allowedOrigins":["https://chatgpt.com"],"redirectURIAllowedPrefixes":["https://chatgpt.com/connector/oauth/"],"oauth":{"authorizationServerMetadata":".well-known/oauth-authorization-server","protectedResourceMetadata":".well-known/oauth-protected-resource/http_mcp","authorize":"oauth/authorize","token":"oauth/token","register":"oauth/register","verifyAccess":"oauth/verify_access"},"tools":["shared_tool"]},
  "local_mcp":{"type":"mcp","transport":"stdio","tools":["shared_tool"]}
}`)
	loaded, err := loadAPIConfigFile(apiPath)
	if err != nil {
		t.Fatalf("load new MCP format: %v", err)
	}
	if got := loaded.Snapshot.Definitions["http_mcp"]; got.Transport != "streamable_http" || got.Tools[0].API != "shared_tool" || len(got.ProtocolVersions) != 2 {
		t.Fatalf("HTTP MCP = %#v", got)
	}
	if _, got, err := selectMCPStdioServer(loaded.Snapshot, "local_mcp"); err != nil || got.Transport != "stdio" {
		t.Fatalf("select stdio MCP: %#v, %v", got, err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://service.example/http_mcp", nil)
	if name, _, ok := findMCPServerForRequestInSnapshot(loaded.Snapshot, req); !ok || name != "http_mcp" {
		t.Fatalf("canonical route = %q, %t", name, ok)
	}
	queryReq := httptest.NewRequest(http.MethodPost, "https://service.example/?api=http_mcp", nil)
	if name, _, ok := findMCPServerForRequestInSnapshot(loaded.Snapshot, queryReq); !ok || name != "http_mcp" {
		t.Fatalf("query route = %q, %t", name, ok)
	}
	stdioReq := httptest.NewRequest(http.MethodPost, "https://service.example/local_mcp", nil)
	if _, _, ok := findMCPServerForRequestInSnapshot(loaded.Snapshot, stdioReq); ok {
		t.Fatal("stdio MCP was exposed over HTTP")
	}

	tool, err := buildMCPToolDefinition(loaded.Snapshot, loaded.Snapshot.Definitions["http_mcp"].Tools[0])
	if err != nil {
		t.Fatal(err)
	}
	if tool["name"] != "shared_tool" || tool["title"] != "Shared Tool" || tool["description"] != "共通Tool" {
		t.Fatalf("dynamic Tool = %#v", tool)
	}
}

func TestNyan8CompatibleMCPRejectsLegacyAndInvalidTransportFormats(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "tool.js"), `JSON.stringify({success:true,status:200,result:{}});`)
	for name, data := range map[string]string{
		"legacy path":       `{"tool":{"type":"api","script":"tool.js"},"m":{"type":"mcp","path":"/m","transport":"stdio","tools":["tool"]}}`,
		"legacy transports": `{"tool":{"type":"api","script":"tool.js"},"m":{"type":"mcp","transports":["stdio"],"tools":["tool"]}}`,
		"missing transport": `{"tool":{"type":"api","script":"tool.js"},"m":{"type":"mcp","tools":["tool"]}}`,
		"tool object":       `{"tool":{"type":"api","script":"tool.js"},"m":{"type":"mcp","transport":"stdio","tools":[{"name":"tool","api":"tool"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
			writeTestFile(t, path, data)
			if _, err := loadAPIConfigFile(path); err == nil {
				t.Fatalf("legacy/invalid format was accepted: %s", data)
			}
		})
	}
}

func TestNyan8CompatibleMCPStdioLifecycleAndPrincipal(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "tool.js")
	writeTestFile(t, script, `JSON.stringify({success:true,status:200,result:{value:nyanAllParams.value,transport:nyanAllParams.mcp_principal.transport,spoofed:nyanAllParams.mcp_principal.username}});`)
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{"tool": {Type: apiTypeAPI, Script: script, Title: "Tool"}}, "", [sha256.Size]byte{})
	server := APIConfig{Type: apiTypeMCP, Transport: "stdio", ProtocolVersions: []string{mcpProtocolVersion20251125, mcpProtocolVersion20250618}, Tools: []MCPToolConfig{{Name: "tool", API: "tool"}}}
	input := strings.NewReader("" +
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tool","arguments":{"value":"ok","mcp_principal":{"username":"attacker"}}}}` + "\n")
	var output bytes.Buffer
	if err := serveMCPStdio(input, &output, snapshot, "local_mcp", server); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("stdio responses = %d; %s", len(lines), output.String())
	}
	last := decodeTestJSONObject(t, []byte(lines[2]))
	structured := last["result"].(map[string]interface{})["structuredContent"].(map[string]interface{})["result"].(map[string]interface{})
	if structured["transport"] != "stdio" || structured["spoofed"] != "local-process" {
		t.Fatalf("stdio principal = %#v", structured)
	}
}

func TestNyan8CompatibleMCPDynamicOAuthMetadata(t *testing.T) {
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"auth_meta": {Type: apiTypeAPI}, "resource_meta": {Type: apiTypeAPI}, "authorize": {Type: apiTypeAPI}, "token": {Type: apiTypeAPI}, "register": {Type: apiTypeAPI},
		"verify": {Type: apiTypeAPI, Scopes: []string{"example:read"}},
	}, "", [sha256.Size]byte{})
	server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", AllowedOrigins: []string{"https://chatgpt.com"}, OAuth: MCPOAuthConfig{AuthorizationServerMetadata: "auth_meta", ProtectedResourceMetadata: "resource_meta", Authorize: "authorize", Token: "token", Register: "register", VerifyAccess: "verify"}}
	req := httptest.NewRequest(http.MethodGet, "https://service.example/auth_meta", nil)
	rec := httptest.NewRecorder()
	handleMCPOAuthHTTPRequest(snapshot, rec, req, "mcp_server", server, "auth_meta", "authorizationServerMetadata")
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeTestJSONObject(t, rec.Body.Bytes())
	if body["issuer"] != "https://service.example" || body["authorization_endpoint"] != "https://service.example/authorize" || body["token_endpoint"] != "https://service.example/token" {
		t.Fatalf("dynamic metadata = %#v", body)
	}
}

func TestMCPHTTPToolCallWithoutHTTPMode(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "tool.js"), `({value:nyanAllParams.value});`)
	apiPath := filepath.Join(dir, "api.json")
	writeTestFile(t, apiPath, `{
  "tool":{"type":"api","script":"tool.js"},
  "mcp":{"type":"mcp","transport":"streamable_http","allowedOrigins":["https://client.example"],"tools":["tool"]}
}`)
	loaded := loadTestAPIConfig(t, apiPath)
	setTestAPISnapshot(t, loaded.Snapshot)
	req := httptest.NewRequest(http.MethodPost, "https://service.example/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool","arguments":{"value":"ok"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion20251125)
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	response := decodeTestJSONObject(t, rec.Body.Bytes())
	if rec.Code != http.StatusOK || response["error"] != nil {
		t.Fatalf("MCP tool call status=%d body=%s", rec.Code, rec.Body.String())
	}
	result := response["result"].(map[string]interface{})
	if result["isError"] == true || result["structuredContent"].(map[string]interface{})["value"] != "ok" {
		t.Fatalf("MCP tool result=%#v", result)
	}
}

func TestMCPCheckOnlyAcrossTransports(t *testing.T) {
	for _, transport := range []string{"streamable_http", "stdio"} {
		for _, test := range []struct {
			name, arguments, check         string
			wantError, wantCheck, wantBody bool
		}{
			{name: "check_only", arguments: `{"id":1,"nyan_mode":"checkOnly"}`, wantCheck: true},
			{name: "normal", arguments: `{"id":1}`, wantCheck: true, wantBody: true},
			{name: "rejected", arguments: `{"id":1,"nyan_mode":"checkOnly"}`, check: `({success:false,status:403,error:"denied"});`, wantCheck: true, wantError: true},
			{name: "exception", arguments: `{"id":1,"nyan_mode":"checkOnly"}`, check: `throw new Error("check failed");`, wantCheck: true, wantError: true},
			{name: "invalid_type", arguments: `{"id":"1","nyan_mode":"checkOnly"}`, wantError: true},
			{name: "missing_required", arguments: `{"nyan_mode":"checkOnly"}`, wantError: true},
			{name: "unknown_property", arguments: `{"id":1,"extra":true,"nyan_mode":"checkOnly"}`, wantError: true},
			{name: "unknown_mode", arguments: `{"id":1,"nyan_mode":"checkOnyl"}`, wantError: true},
			{name: "null_mode", arguments: `{"id":1,"nyan_mode":null}`, wantError: true},
			{name: "array_mode", arguments: `{"id":1,"nyan_mode":["checkOnly"]}`, wantError: true},
			{name: "empty_mode", arguments: `{"id":1,"nyan_mode":""}`, wantError: true},
		} {
			t.Run(transport+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				oldHub := hub
				hub = NewHub()
				t.Cleanup(func() { hub = oldHub })
				dir := t.TempDir()
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"), %q);`, filepath.Join(dir, stage))
				}
				const allow = `({success:true,status:200,result:{checked:true}});`
				check := test.check
				if check == "" {
					check = allow
				}
				input := writeTestScript(t, `const nyanInputSchema={type:"object",properties:{id:{type:"integer"}},required:["id"],additionalProperties:false};`+mark("param")+check)
				snapshot := newAPIConfigSnapshot(map[string]APIConfig{
					"tool":   {ParamCheck: input, Script: writeTestScript(t, mark("body")+`({success:true,status:200,result:{executed:true}});`), OutCheck: writeTestScript(t, mark("out")+allow), Push: "events"},
					"events": {ParamCheck: writeTestScript(t, mark("push_param")+allow), Script: writeTestScript(t, mark("push_body")+allow), OutCheck: writeTestScript(t, mark("push_out")+allow)},
				}, "", [sha256.Size]byte{})
				server := APIConfig{Type: apiTypeMCP, Transport: transport, ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{API: "tool"}}}
				call := func(message string) map[string]interface{} {
					t.Helper()
					if transport == "stdio" {
						state := mcpStdioReady
						response, reply := handleMCPStdioMessage(snapshot, "test_mcp", server, &state, []byte(message))
						if !reply {
							t.Fatal("stdio did not reply")
						}
						return response
					}
					rec := performTestMCPRequest(t, snapshot, server, message, "")
					if rec.Code != http.StatusOK {
						t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
					}
					return decodeTestJSONObject(t, rec.Body.Bytes())
				}
				listed := call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
				encoded, err := json.Marshal(listed)
				if err != nil {
					t.Fatal(err)
				}
				listed = decodeTestJSONObject(t, encoded)
				published := listed["result"].(map[string]interface{})["tools"].([]interface{})[0].(map[string]interface{})["inputSchema"].(map[string]interface{})
				arguments := decodeTestJSONObject(t, []byte(test.arguments))
				// Client-visible schema and execution must agree on the control
				// parameter without weakening required/type/additionalProperties.
				wantSchemaError := !test.wantCheck
				if err := validateJSONSchemaValue(published, arguments); (err != nil) != wantSchemaError {
					t.Fatalf("published schema validation=%v, want error=%v", err, wantSchemaError)
				}
				response := call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tool","arguments":` + test.arguments + `}}`)
				if response["error"] != nil {
					t.Fatalf("protocol error: %#v", response)
				}
				result := response["result"].(map[string]interface{})
				if (result["isError"] == true) != test.wantError {
					t.Fatalf("result=%#v, want error=%v", result, test.wantError)
				}
				if !test.wantError {
					want := `{"success":true,"status":200,"result":{"checked":true}}`
					if test.wantBody {
						want = `{"success":true,"status":200,"result":{"executed":true}}`
					}
					if !reflect.DeepEqual(result["structuredContent"], decodeTestJSONObject(t, []byte(want))) {
						t.Fatalf("wrong result: %#v", result)
					}
				}
				for _, stage := range []string{"param", "body", "out", "push_param", "push_body", "push_out"} {
					_, err := os.Stat(filepath.Join(dir, stage))
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					want := test.wantBody || stage == "param" && test.wantCheck
					if (err == nil) != want {
						t.Errorf("%s executed=%v, want %v", stage, err == nil, want)
					}
				}
			})
		}
	}
}

func TestMCPCheckOnlyStillAuthenticates(t *testing.T) {
	for _, test := range []struct {
		name, token string
		status      int
	}{
		{name: "missing_token", status: http.StatusUnauthorized},
		{name: "invalid_token", token: "Bearer invalid", status: http.StatusUnauthorized},
		{name: "insufficient_scope", token: "Bearer forbidden", status: http.StatusForbidden},
		{name: "authenticated", token: "Bearer good", status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			marker := filepath.Join(t.TempDir(), "checked")
			verify := writeTestScript(t, `
if (nyanAllParams.nyan_mode !== undefined) throw new Error("checkOnly reached authentication");
({authenticated:nyanAllParams.authorization === "Bearer good", forbidden:nyanAllParams.authorization === "Bearer forbidden", principal:{user_id:"verified"}});`)
			input := writeTestScript(t, fmt.Sprintf(`
const nyanInputSchema={type:"object",properties:{id:{type:"integer"}},required:["id"],additionalProperties:false};
if (nyanAllParams.mcp_principal.user_id !== "verified") throw new Error("missing verified principal");
nyanSaveFile(nyanBase64Encode("checked"), %q);
({success:true,status:200,result:{checked:true}});`, marker))
			snapshot := newAPIConfigSnapshot(map[string]APIConfig{
				"verify": {Script: verify, Scopes: []string{"tool:read"}},
				"tool":   {ParamCheck: input, Script: writeTestScript(t, `throw new Error("body must not run");`), Scopes: []string{"tool:read"}},
			}, "", [sha256.Size]byte{})
			server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", Tools: []MCPToolConfig{{API: "tool"}}, OAuth: MCPOAuthConfig{VerifyAccess: "verify"}}
			rec := performTestMCPRequest(t, snapshot, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool","arguments":{"id":1,"nyan_mode":"checkOnly"}}}`, test.token)
			if rec.Code != test.status {
				t.Fatalf("status=%d, want %d: %s", rec.Code, test.status, rec.Body.String())
			}
			result := decodeTestJSONObject(t, rec.Body.Bytes())["result"].(map[string]interface{})
			if (result["isError"] == true) != (test.status != http.StatusOK) {
				t.Fatalf("result=%#v", result)
			}
			_, err := os.Stat(marker)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if (err == nil) != (test.status == http.StatusOK) {
				t.Fatalf("paramCheck execution did not follow authentication: %v", err)
			}
		})
	}
}

func TestMCPOutputValidationUsesOutCheck(t *testing.T) {
	for _, transport := range []string{"streamable_http", "stdio"} {
		for _, test := range []struct {
			name, check string
			wantError   bool
		}{
			{name: "allowed_despite_schema_mismatch", check: `({success:true,status:200});`},
			{name: "rejected_by_javascript", check: `({success:false,status:409,error:"output denied by JavaScript"});`, wantError: true},
			{name: "javascript_exception", check: `throw new Error("output check failed");`, wantError: true},
		} {
			t.Run(transport+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				marker := filepath.Join(t.TempDir(), "out-checked")
				const originalBody = `{"actual":"kept"}`
				input := writeTestScript(t, `
const nyanInputSchema = {type:"object",properties:{id:{type:"integer"}},required:["id"]};
nyanAllParams.checked = true;
({success:true,status:200});`)
				script := writeTestScript(t, fmt.Sprintf(`
if (!nyanAllParams.checked) throw new Error("paramCheck was skipped");
%q;`, originalBody))
				output := writeTestScript(t, fmt.Sprintf(`
const nyanOutputSchema = {type:"object",properties:{expected:{type:"integer"}},required:["expected"],additionalProperties:false};
if (nyanAllParams.nyan_output.body !== %q) throw new Error("wrong original output");
nyanSaveFile(nyanBase64Encode("checked"), %q);
`, originalBody, marker)+test.check)
				snapshot := newAPIConfigSnapshot(map[string]APIConfig{
					"tool": {Type: apiTypeAPI, Script: script, ParamCheck: input, OutCheck: output},
				}, "", [sha256.Size]byte{})
				server := APIConfig{Type: apiTypeMCP, Transport: transport, ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{Name: "tool", API: "tool"}}}
				call := func(message string) map[string]interface{} {
					t.Helper()
					if transport == "stdio" {
						state := mcpStdioReady
						response, reply := handleMCPStdioMessage(snapshot, "test_mcp", server, &state, []byte(message))
						if !reply {
							t.Fatal("stdio did not reply")
						}
						return response
					}
					rec := performTestMCPRequest(t, snapshot, server, message, "")
					if rec.Code != http.StatusOK {
						t.Fatalf("HTTP status=%d body=%s", rec.Code, rec.Body.String())
					}
					return decodeTestJSONObject(t, rec.Body.Bytes())
				}
				// Publishing the schema must remain available even though the API
				// output is accepted or rejected by JavaScript, not by this schema.
				listed := call(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
				encoded, err := json.Marshal(listed)
				if err != nil || !bytes.Contains(encoded, []byte(`"outputSchema"`)) || !bytes.Contains(encoded, []byte(`"expected"`)) {
					t.Fatalf("output schema was not published: %s err=%v", encoded, err)
				}
				response := call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tool","arguments":{"id":1}}}`)
				if response["error"] != nil {
					t.Fatalf("MCP protocol error: %#v", response)
				}
				result := response["result"].(map[string]interface{})
				if (result["isError"] == true) != test.wantError {
					t.Fatalf("MCP result=%#v, want error=%v", result, test.wantError)
				}
				data, err := os.ReadFile(marker)
				if err != nil || string(data) != "checked" {
					t.Fatalf("outCheck did not run: marker=%q err=%v", data, err)
				}
				encoded, err = json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				if test.name == "allowed_despite_schema_mismatch" {
					if !reflect.DeepEqual(result["structuredContent"], decodeTestJSONObject(t, []byte(originalBody))) {
						t.Fatalf("original output was replaced: %#v", result)
					}
				} else if test.name == "rejected_by_javascript" {
					if !bytes.Contains(encoded, []byte("output denied by JavaScript")) {
						t.Fatalf("JavaScript rejection was replaced: %s", encoded)
					}
				}
			})
		}
	}
}

func newOAuthChecksFixture(t *testing.T) (map[string]APIConfig, APIConfig, func(string) string, func() string) {
	t.Helper()
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	if _, err := testDB.Exec(`CREATE TABLE oauth_stages (stage TEXT);`); err != nil {
		t.Fatal(err)
	}
	markerSQL := filepath.Join(t.TempDir(), "mark.sql")
	writeTestFile(t, markerSQL, `INSERT INTO oauth_stages (stage) VALUES (/*stage*/'unknown');`)
	mark := func(stage string) string { return fmt.Sprintf(`nyanRunSQL(%q, {stage:%q});`, markerSQL, stage) }
	stages := func() string {
		t.Helper()
		rows, err := testDB.Query(`SELECT stage FROM oauth_stages ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var values []string
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(values, ",")
	}
	const allow = `({success:true,status:200,result:{checked:true}});`
	const restrictions = `
if (typeof nyanHostExec !== "undefined" || typeof nyanCallMe !== "undefined" || typeof nyanGetAPI !== "undefined" || typeof nyanSaveFile !== "undefined" || typeof nyanCrypto !== "undefined") throw new Error("unrestricted OAuth VM");
if (nyanRuntimeSettings.issuer !== "https://service.example") throw new Error("missing runtime settings");
`
	definition := APIConfig{
		ParamCheck: writeTestScript(t, restrictions+mark("input")+allow),
		Script:     writeTestScript(t, restrictions+mark("body")+`({status:302,contentType:"text/plain",headers:{Location:"https://client.example/done","Set-Cookie":["one=1; HttpOnly","two=2; HttpOnly"]},body:"original"});`),
		OutCheck:   writeTestScript(t, restrictions+mark("output")+allow),
		Runtime:    APIRuntimeConfig{Capabilities: []string{"sql"}, SQLFiles: []string{markerSQL}},
	}
	definitions := map[string]APIConfig{}
	for _, name := range []string{"authorize", "token", "register", "admin", "auth_meta", "resource_meta", "verify"} {
		definitions[name] = definition
	}
	for _, name := range []string{"auth_meta", "resource_meta"} {
		metadata := definition
		metadata.Script = writeTestScript(t, `throw new Error("metadata must be generated by Go");`)
		definitions[name] = metadata
	}
	verify := definition
	verify.Script = writeTestScript(t, restrictions+mark("verify")+`({authenticated:nyanAllParams.authorization === "Bearer good",principal:{user_id:"verified"}});`)
	verify.Scopes = []string{"tool:read"}
	definitions["verify"] = verify
	definitions["tool"] = APIConfig{
		ParamCheck: writeTestScript(t, mark("tool_input")+allow),
		Script:     writeTestScript(t, mark("tool_body")+`({success:true,status:200,result:{executed:true}});`),
		Scopes:     []string{"tool:read"},
	}
	server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{API: "tool"}}, OAuth: MCPOAuthConfig{
		AuthorizationServerMetadata: "auth_meta", ProtectedResourceMetadata: "resource_meta", Authorize: "authorize", Token: "token", Register: "register", AdminUser: "admin", VerifyAccess: "verify",
	}}
	return definitions, server, mark, stages
}

func TestOAuthChecksHTTPRoutes(t *testing.T) {
	for _, role := range []string{"oauthAuthorize", "oauthToken", "oauthRegister", "oauthAdminUser", "authorizationServerMetadata", "protectedResourceMetadata"} {
		for _, test := range []string{"allowed", "output_non_200_success", "input_denied", "output_denied", "input_exception", "output_exception", "invalid_input", "invalid_output", "missing_file", "check_only", "check_only_denied", "check_only_missing", "check_alias"} {
			t.Run(role+"/"+test, func(t *testing.T) {
				definitions, server, mark, stages := newOAuthChecksFixture(t)
				apiName := mcpOAuthAPIForRole(server, role)
				definition := definitions[apiName]
				wantStatus, wantStages := http.StatusOK, "input,body,output"
				if isMCPOAuthMetadataRole(role) {
					wantStatus, wantStages = http.StatusOK, "input,output"
				}
				const denied = `({success:false,status:403,result:{reason:"denied"}});`
				switch test {
				case "output_non_200_success":
					definition.OutCheck = writeTestScript(t, mark("output")+`({success:true,status:503,result:{checked:true}});`)
					wantStatus = http.StatusServiceUnavailable
				case "input_denied", "check_only_denied":
					definition.ParamCheck = writeTestScript(t, mark("input")+denied)
					wantStatus, wantStages = http.StatusForbidden, "input"
				case "output_denied":
					definition.OutCheck = writeTestScript(t, mark("output")+denied)
					wantStatus = http.StatusForbidden
				case "input_exception", "invalid_input", "missing_file":
					check := `throw new Error("private-check-detail");`
					if test == "invalid_input" {
						check = `({success:"true",status:200});`
					}
					definition.ParamCheck = writeTestScript(t, check)
					if test == "missing_file" {
						definition.ParamCheck += ".missing"
					}
					wantStatus, wantStages = http.StatusInternalServerError, ""
				case "output_exception", "invalid_output":
					check := `throw new Error("private-check-detail");`
					if test == "invalid_output" {
						check = `({success:true});`
					}
					definition.OutCheck = writeTestScript(t, check)
					wantStatus, wantStages = http.StatusInternalServerError, strings.TrimSuffix(wantStages, ",output")
				case "check_only":
					wantStatus, wantStages = http.StatusOK, "input"
				case "check_only_missing":
					definition.ParamCheck = ""
					wantStatus, wantStages = http.StatusInternalServerError, ""
				case "check_alias":
					definition.Check, definition.ParamCheck = definition.ParamCheck, ""
				}
				definitions[apiName] = definition
				snapshot := newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{})
				method, contentType, body := http.MethodPost, "application/x-www-form-urlencoded", "value=1"
				if role == "oauthRegister" || role == "oauthAdminUser" {
					contentType, body = "application/json", `{"value":1}`
				}
				if role == "oauthAuthorize" || isMCPOAuthMetadataRole(role) {
					method, body = http.MethodGet, ""
				}
				target := "https://service.example/" + apiName
				if strings.HasPrefix(test, "check_only") {
					target += "?nyan_mode=checkOnly"
				}
				req := httptest.NewRequest(method, target, strings.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				req.RemoteAddr = "127.0.0.1:1234"
				req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
				rec := httptest.NewRecorder()
				handleMCPOAuthHTTPRequest(snapshot, rec, req, t.Name(), server, apiName, role)
				if rec.Code != wantStatus || stages() != wantStages {
					t.Fatalf("status=%d want=%d stages=%q want=%q body=%s", rec.Code, wantStatus, stages(), wantStages, rec.Body.String())
				}
				if test != "allowed" && test != "check_alias" && test != "output_non_200_success" {
					if rec.Header().Get("Location") != "" || len(rec.Header().Values("Set-Cookie")) != 0 {
						t.Fatalf("script headers escaped: %v", rec.Header())
					}
				} else if !isMCPOAuthMetadataRole(role) {
					if rec.Body.String() != "original" || len(rec.Header().Values("Set-Cookie")) != 2 {
						t.Fatalf("original response lost: %s %v", rec.Body.String(), rec.Header())
					}
				} else {
					value := decodeTestJSONObject(t, rec.Body.Bytes())
					if value["issuer"] == nil && value["resource"] == nil {
						t.Fatalf("missing metadata: %v", value)
					}
				}
				if wantStatus == http.StatusForbidden {
					if !reflect.DeepEqual(decodeTestJSONObject(t, rec.Body.Bytes())["result"], map[string]interface{}{"reason": "denied"}) {
						t.Fatalf("check result lost: %s", rec.Body.String())
					}
				}
				if test == "check_only" && !strings.Contains(rec.Body.String(), `"checked":true`) {
					t.Fatalf("check result lost: %s", rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "private-check-detail") {
					t.Fatal("check exception leaked")
				}
			})
		}
	}
}

func TestOAuthVerifyChecksBeforeMCPTool(t *testing.T) {
	for _, mode := range []string{"normal", "checkOnly"} {
		for _, test := range []string{"allowed", "input_denied", "output_denied", "input_exception", "output_exception", "invalid_check", "non_200_output", "invalid_token"} {
			t.Run(mode+"/"+test, func(t *testing.T) {
				definitions, server, mark, stages := newOAuthChecksFixture(t)
				definition := definitions["verify"]
				const noMode = `if (nyanAllParams.nyan_mode !== undefined) throw new Error("authentication was put in checkOnly mode");`
				definition.ParamCheck = writeTestScript(t, noMode+mark("input")+`({success:true,status:200});`)
				definition.OutCheck = writeTestScript(t, noMode+mark("output")+`
const decision=JSON.parse(nyanAllParams.nyan_output.body);
if (decision.principal.user_id !== "verified") throw new Error("whole decision missing");
nyanAllParams.nyan_output.body = '{"authenticated":false}';
({success:true,status:200});`)
				wantStatus, wantStages := http.StatusUnauthorized, ""
				token := "Bearer good"
				switch test {
				case "allowed", "non_200_output":
					if test == "non_200_output" {
						definition.OutCheck = writeTestScript(t, mark("output")+`({success:true,status:201});`)
					}
					wantStatus, wantStages = http.StatusOK, "input,verify,output,tool_input"
					if mode == "normal" {
						wantStages += ",tool_body"
					}
				case "input_denied":
					// Even a rejection containing a forged authentication decision
					// must be treated as a check rejection, not as verified access.
					definition.ParamCheck = writeTestScript(t, mark("input")+`({success:false,status:403,authenticated:true,allow:true,principal:{user_id:"forged"}});`)
					wantStages = "input"
				case "output_denied":
					result := `({success:false,status:403,authenticated:true,principal:{user_id:"forged"}});`
					definition.OutCheck = writeTestScript(t, mark("output")+result)
					wantStages = "input,verify,output"
				case "input_exception":
					definition.ParamCheck = writeTestScript(t, `throw new Error("private-auth-error");`)
				case "output_exception":
					definition.OutCheck = writeTestScript(t, `throw new Error("private-auth-error");`)
					wantStages = "input,verify"
				case "invalid_check":
					definition.ParamCheck = writeTestScript(t, `({authenticated:true,principal:{user_id:"forged"}});`)
				case "invalid_token":
					token, wantStages = "Bearer invalid", "input,verify,output"
				}
				definitions["verify"] = definition
				snapshot := newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{})
				arguments := `{}`
				if mode == "checkOnly" {
					arguments = `{"nyan_mode":"checkOnly"}`
				}
				message := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool","arguments":` + arguments + `}}`
				req := httptest.NewRequest(http.MethodPost, "https://service.example/mcp", nil)
				req.Header.Set("Authorization", token)
				urls, err := deriveMCPRuntimeURLs(req, "mcp", server)
				if err != nil {
					t.Fatal(err)
				}
				var request MCPJSONRPCRequest
				if err := json.Unmarshal([]byte(message), &request); err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				handleMCPToolCall(snapshot, rec, req, request, t.Name(), server, urls)
				if rec.Code != wantStatus || stages() != wantStages {
					t.Fatalf("status=%d want=%d stages=%q want=%q body=%s", rec.Code, wantStatus, stages(), wantStages, rec.Body.String())
				}
				result := decodeTestJSONObject(t, rec.Body.Bytes())["result"].(map[string]interface{})
				if (result["isError"] == true) != (wantStatus != http.StatusOK) {
					t.Fatalf("wrong Tool result: %v", result)
				}
				if wantStatus == http.StatusUnauthorized && !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
					t.Fatalf("missing challenge: %v", rec.Header())
				}
			})
		}
	}
}

func TestOAuthCheckOnlyHTTPValidation(t *testing.T) {
	for _, test := range []struct {
		name, role, method, contentType, query, body string
		status                                       int
		stages                                       string
		noAdminAuth                                  bool
	}{
		{name: "query", role: "oauthAuthorize", method: "GET", query: "?nyan_mode=checkOnly", status: 200, stages: "input"},
		{name: "form", role: "oauthToken", method: "POST", contentType: "application/x-www-form-urlencoded", body: "nyan_mode=checkOnly", status: 200, stages: "input"},
		{name: "json", role: "oauthRegister", method: "POST", contentType: "application/json", body: `{"nyan_mode":"checkOnly"}`, status: 200, stages: "input"},
		{name: "form_over_query", role: "oauthToken", method: "POST", contentType: "application/x-www-form-urlencoded", query: "?nyan_mode=checkOnly", body: "nyan_mode=", status: 200, stages: "input,body,output"},
		{name: "json_over_query", role: "oauthRegister", method: "POST", contentType: "application/json", query: "?nyan_mode=checkOnly", body: `{"nyan_mode":""}`, status: 200, stages: "input,body,output"},
		{name: "invalid_mode", role: "oauthAuthorize", method: "GET", query: "?nyan_mode=checkOnyl", status: 400},
		{name: "repeated_mode", role: "oauthAuthorize", method: "GET", query: "?nyan_mode=checkOnly&nyan_mode=checkOnly", status: 400},
		{name: "null_mode", role: "oauthRegister", method: "POST", contentType: "application/json", body: `{"nyan_mode":null}`, status: 400},
		{name: "wrong_method", role: "oauthToken", method: "GET", query: "?nyan_mode=checkOnly", status: 405},
		{name: "metadata_wrong_method", role: "authorizationServerMetadata", method: "POST", query: "?nyan_mode=checkOnly", status: 405},
		{name: "wrong_content_type", role: "oauthToken", method: "POST", contentType: "application/json", query: "?nyan_mode=checkOnly", body: `{}`, status: 415},
		{name: "invalid_json", role: "oauthRegister", method: "POST", contentType: "application/json", query: "?nyan_mode=checkOnly", body: `{`, status: 400},
		{name: "duplicate_json_key", role: "oauthRegister", method: "POST", contentType: "application/json", body: `{"nyan_mode":"checkOnly","nyan_mode":""}`, status: 400},
		{name: "invalid_form", role: "oauthToken", method: "POST", contentType: "application/x-www-form-urlencoded", query: "?nyan_mode=checkOnly", body: "value=%", status: 400},
		{name: "oversized_request", role: "oauthRegister", method: "POST", contentType: "application/json", query: "?nyan_mode=checkOnly", body: strings.Repeat("x", maxConfiguredHTTPBodyBytes+1), status: 413},
		{name: "admin_auth", role: "oauthAdminUser", method: "POST", contentType: "application/json", body: `{"nyan_mode":"checkOnly"}`, status: 401, noAdminAuth: true},
		{name: "options", role: "oauthAuthorize", method: "OPTIONS", query: "?nyan_mode=checkOnly", status: 204},
		{name: "metadata_options", role: "protectedResourceMetadata", method: "OPTIONS", query: "?nyan_mode=checkOnly", status: 204},
	} {
		t.Run(test.name, func(t *testing.T) {
			definitions, server, _, stages := newOAuthChecksFixture(t)
			apiName := mcpOAuthAPIForRole(server, test.role)
			req := httptest.NewRequest(test.method, "https://service.example/"+apiName+test.query, strings.NewReader(test.body))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Content-Type", test.contentType)
			if !test.noAdminAuth {
				req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
			}
			rec := httptest.NewRecorder()
			handleMCPOAuthHTTPRequest(newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{}), rec, req, t.Name(), server, apiName, test.role)
			if rec.Code != test.status || stages() != test.stages {
				t.Fatalf("status=%d want=%d stages=%q want=%q body=%s", rec.Code, test.status, stages(), test.stages, rec.Body.String())
			}
		})
	}
}

func TestOAuthCheckResponseBoundaries(t *testing.T) {
	for _, test := range []string{"inspection_copy", "invalid_header", "invalid_content_type", "invalid_status", "oversized_body", "oversized_input_check", "oversized_output_check", "non_200_output", "forbidden_sql_input", "forbidden_sql_output"} {
		t.Run(test, func(t *testing.T) {
			definitions, server, mark, stages := newOAuthChecksFixture(t)
			definition := definitions["authorize"]
			wantStatus, wantStages := http.StatusInternalServerError, "input,body"
			query := ""
			switch test {
			case "inspection_copy":
				definition.OutCheck = writeTestScript(t, mark("output")+`
const output=nyanAllParams.nyan_output;
if (output.status !== 302 || output.contentType !== "text/plain" || output.body !== "original" || output.bodyBase64 !== "b3JpZ2luYWw=" || output.bodyLengthBytes !== 8) throw new Error("wrong output metadata");
if (output.headers.Location !== "https://client.example/done" || output.headers["Set-Cookie"].length !== 2) throw new Error("missing response headers");
if (nyanAllParams.nyan_output_body !== output.body || nyanAllParams.nyan_output_status !== 302) throw new Error("missing output aliases");
output.headers.Location="https://changed.example/";
output.headers["Set-Cookie"][0]="changed=1";
output.body="changed";
({success:true,status:200});`)
				wantStatus, wantStages = http.StatusOK, "input,body,output"
			case "invalid_header":
				definition.Script = writeTestScript(t, mark("body")+`({status:302,headers:{Location:"https://client.example/","Set-Cookie":"secret=1",Connection:"close"},body:"original"});`)
			case "invalid_content_type":
				definition.Script = writeTestScript(t, mark("body")+`({status:302,headers:{Location:"https://client.example/","Set-Cookie":"secret=1"},contentType:"text/plain;=",body:"original"});`)
			case "invalid_status":
				definition.Script = writeTestScript(t, mark("body")+`({status:302.5,headers:{"Set-Cookie":"secret=1"},body:"original"});`)
			case "oversized_body":
				definition.Script = writeTestScript(t, mark("body")+fmt.Sprintf(`({status:200,headers:{"Set-Cookie":"secret=1"},body:"x".repeat(%d)});`, maxConfiguredHTTPResponseBytes+1))
			case "oversized_input_check", "oversized_output_check":
				path := writeTestScript(t, fmt.Sprintf(`({success:true,status:200,result:"x".repeat(%d)});`, maxConfiguredHTTPResponseBytes))
				if test == "oversized_input_check" {
					definition.ParamCheck, wantStages, query = path, "", "?nyan_mode=checkOnly"
				} else {
					definition.OutCheck = path
				}
			case "non_200_output":
				definition.OutCheck = writeTestScript(t, mark("output")+`({success:true,status:201,result:{checked:true}});`)
				wantStatus, wantStages = http.StatusCreated, "input,body,output"
			case "forbidden_sql_input", "forbidden_sql_output":
				forbidden := filepath.Join(t.TempDir(), "forbidden.sql")
				writeTestFile(t, forbidden, `INSERT INTO oauth_stages VALUES ('forbidden');`)
				path := writeTestScript(t, fmt.Sprintf(`nyanRunSQL(%q, {}); ({success:true,status:200});`, forbidden))
				if test == "forbidden_sql_input" {
					definition.ParamCheck, wantStages = path, ""
				} else {
					definition.OutCheck = path
				}
			}
			definitions["authorize"] = definition
			req := httptest.NewRequest(http.MethodGet, "https://service.example/authorize"+query, nil)
			rec := httptest.NewRecorder()
			handleMCPOAuthHTTPRequest(newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{}), rec, req, t.Name(), server, "authorize", "oauthAuthorize")
			if rec.Code != wantStatus || stages() != wantStages {
				t.Fatalf("status=%d want=%d stages=%q want=%q body=%.200s", rec.Code, wantStatus, stages(), wantStages, rec.Body.String())
			}
			if test == "inspection_copy" || test == "non_200_output" {
				if rec.Body.String() != "original" || rec.Header().Get("Location") != "https://client.example/done" || rec.Header().Values("Set-Cookie")[0] != "one=1; HttpOnly" {
					t.Fatalf("response mutated: %s %v", rec.Body.String(), rec.Header())
				}
			} else if rec.Header().Get("Location") != "" || len(rec.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("script headers escaped: %v", rec.Header())
			}
		})
	}
}

func TestOAuthMetadataChecksUseExecutionLimits(t *testing.T) {
	for _, role := range []string{"authorizationServerMetadata", "protectedResourceMetadata"} {
		for _, limit := range []string{"rate", "concurrency"} {
			t.Run(role+"/"+limit, func(t *testing.T) {
				definitions, server, _, stages := newOAuthChecksFixture(t)
				apiName := mcpOAuthAPIForRole(server, role)
				server.RateLimit = &HTTPRateLimitConfig{Requests: 1, Window: "1m"}
				wantStatus, wantStages := http.StatusTooManyRequests, "input,output"
				if limit == "concurrency" {
					server.MaxConcurrent = 1
					release, acquired := acquireMCPExecutionSlot(t.Name()+":oauth:"+role, 1)
					if !acquired {
						t.Fatal("failed to acquire test slot")
					}
					defer release()
					wantStatus, wantStages = http.StatusServiceUnavailable, ""
				}
				snapshot := newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{})
				call := func() *httptest.ResponseRecorder {
					rec := httptest.NewRecorder()
					handleMCPOAuthHTTPRequest(snapshot, rec, httptest.NewRequest(http.MethodGet, "https://service.example/"+apiName, nil), t.Name(), server, apiName, role)
					return rec
				}
				if limit == "rate" {
					if rec := call(); rec.Code != http.StatusOK {
						t.Fatalf("first request: %d %s", rec.Code, rec.Body.String())
					}
				}
				rec := call()
				if rec.Code != wantStatus || stages() != wantStages || rec.Header().Get("Retry-After") == "" {
					t.Fatalf("status=%d stages=%q headers=%v", rec.Code, stages(), rec.Header())
				}
			})
		}
	}
}

func TestMCPOAuthResponsesWithoutHTTPMode(t *testing.T) {
	for _, test := range []struct {
		name, result, contentType, body, location string
		status                                    int
	}{
		{name: "json", result: `({status:201,contentType:"application/json",headers:{"X-Script":"ok"},body:{created:true}})`, status: 201, contentType: "application/json", body: `{"created":true}`},
		{name: "html", result: `({status:200,contentType:"text/html; charset=utf-8",body:"<h1>Authorize</h1>"})`, status: 200, contentType: "text/html; charset=utf-8", body: "<h1>Authorize</h1>"},
		{name: "redirect", result: `({status:302,headers:{Location:"https://client.example/complete"},body:""})`, status: 302, location: "https://client.example/complete"},
		{name: "invalid_status", result: `({status:700,body:"must not be sent"})`, status: 500},
		{name: "hop_by_hop_header", result: `({status:200,headers:{Connection:"close"},body:"must not be sent"})`, status: 500},
		{name: "content_length", result: `({status:200,headers:{"Content-Length":"2"},body:"must not be sent"})`, status: 500},
		{name: "header_newline", result: `({status:200,headers:{"X-Test":"ok\r\nInjected: yes"},body:"must not be sent"})`, status: 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "oauth.js"), test.result+";")
			apiPath := filepath.Join(dir, "api.json")
			writeTestFile(t, apiPath, `{
  "auth_meta":{"type":"api"},
  "resource_meta":{"type":"api"},
  "authorize":{"type":"api","script":"oauth.js"},
  "token":{"type":"api","script":"oauth.js"},
  "register":{"type":"api","script":"oauth.js"},
  "verify":{"type":"api","script":"oauth.js","scopes":["example:read"]},
  "tool":{"type":"api","script":"oauth.js","scopes":["example:read"]},
  "mcp":{"type":"mcp","transport":"streamable_http","allowedOrigins":["https://client.example"],"redirectURIAllowedPrefixes":["https://client.example/"],"oauth":{"authorizationServerMetadata":"auth_meta","protectedResourceMetadata":"resource_meta","authorize":"authorize","token":"token","register":"register","verifyAccess":"verify"},"tools":["tool"]}
}`)
			loaded := loadTestAPIConfig(t, apiPath)
			setTestAPISnapshot(t, loaded.Snapshot)
			rec := httptest.NewRecorder()
			unifiedHandler(rec, httptest.NewRequest(http.MethodGet, "https://service.example/authorize", nil))
			if rec.Code != test.status {
				t.Fatalf("OAuth response status=%d, want %d; body=%s", rec.Code, test.status, rec.Body.String())
			}
			if test.status == http.StatusInternalServerError {
				if strings.Contains(rec.Body.String(), "must not be sent") {
					t.Fatal("invalid OAuth response body was sent")
				}
				return
			}
			if rec.Body.String() != test.body || rec.Header().Get("Location") != test.location {
				t.Fatalf("OAuth response body=%q headers=%v", rec.Body.String(), rec.Header())
			}
			if test.contentType != "" && rec.Header().Get("Content-Type") != test.contentType {
				t.Fatalf("OAuth Content-Type=%q", rec.Header().Get("Content-Type"))
			}
			if test.name == "json" && rec.Header().Get("X-Script") != "ok" {
				t.Fatal("JavaScript response header was lost")
			}
		})
	}
}

func TestNyan8CompatibleOAuthAPIRegistersClientInSQLite(t *testing.T) {
	t.Skip("OAuth運用資材をNyanQL本体から分離しているため一時停止")
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	migrateOAuthTestDatabase(t, testDB)

	loaded, err := loadAPIConfigFile(oauthTestAssetPath(t, "api.vps.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := loaded.Snapshot.Definitions["mcp"]
	body := `{"redirect_uris":["https://chatgpt.com/connector/oauth/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"stamps:read offline_access","client_name":"NyanQL test"}`
	req := httptest.NewRequest(http.MethodPost, "https://stamp.necomori.asia/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleMCPOAuthHTTPRequest(loaded.Snapshot, rec, req, "mcp", server, "oauth/register", "oauthRegister")
	if rec.Code != http.StatusCreated {
		t.Fatalf("registration status=%d body=%s", rec.Code, rec.Body.String())
	}
	response := decodeTestJSONObject(t, rec.Body.Bytes())
	clientID, ok := response["client_id"].(string)
	if !ok || !strings.HasPrefix(clientID, "nyan_client_") {
		t.Fatalf("registration response = %#v", response)
	}
	var storedClientID string
	if err := testDB.QueryRow(`SELECT client_id FROM oauth_clients WHERE client_id = ?`, clientID).Scan(&storedClientID); err != nil {
		t.Fatalf("SQLite OAuth client was not stored: %v", err)
	}
}

func TestMCPToolsListSupportsGeneratedSQLSchemas(t *testing.T) {
	dir := t.TempDir()
	query := filepath.Join(dir, "list.sql")
	writeTestFile(t, query, `SELECT id, stamp_date FROM stamps ORDER BY stamp_date DESC;`)
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"sql_list": {
			SQL:         []string{query},
			Description: "List stamps from SQL",
		},
	}, "", [sha256.Size]byte{})
	serverConfig := APIConfig{Tools: []MCPToolConfig{{
		Name: "list_stamps",
		API:  "sql_list",
		SecuritySchemes: []MCPSecurityScheme{{
			Type: "noauth",
		}},
	}}}

	rec := performTestMCPRequest(t, snapshot, serverConfig, `{"jsonrpc":"2.0","id":"sql-list","method":"tools/list","params":{}}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	response := decodeTestJSONObject(t, rec.Body.Bytes())
	tools := response["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("tools = %#v, want one generated SQL tool", tools)
	}
	tool := tools[0].(map[string]interface{})
	outputSchema := tool["outputSchema"].(map[string]interface{})
	required := outputSchema["required"].([]interface{})
	if !reflect.DeepEqual(required, []interface{}{"success", "status", "result"}) {
		t.Fatalf("generated SQL output required = %#v", required)
	}
	items := outputSchema["properties"].(map[string]interface{})["result"].(map[string]interface{})["items"].(map[string]interface{})
	if !reflect.DeepEqual(items["required"], []interface{}{"id", "stamp_date"}) {
		t.Fatalf("generated SQL item required = %#v", items["required"])
	}
}

func TestMCPToolCallValidatesArgumentsAndHonorsGuard(t *testing.T) {
	t.Skip("旧guard方式は独立OAuth API参照方式へ置換済み")
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	guardScript := filepath.Join(dir, "guard.js")
	paramCheck := filepath.Join(dir, "param_check.js")
	targetScript := filepath.Join(dir, "target.js")
	writeTestFile(t, guardScript, `
(function () {
  const challenge = 'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"';
  if (nyanRequest.headers.authorization !== "Bearer good-token") {
    return JSON.stringify({allow:false,status:401,headers:{"WWW-Authenticate":challenge},mcpMeta:{"mcp/www_authenticate":[challenge]}});
  }
  return JSON.stringify({allow:true,status:200,principal:{subject:"user-1"}});
})()
`)
	writeTestFile(t, paramCheck, `
const nyanInputSchema = {
  type: "object",
  properties: {id: {type: "integer"}},
  required: ["id"],
  additionalProperties: false
};
({success:true,status:200,error:null});
`)
	writeTestFile(t, targetScript, `
JSON.stringify({success:true,status:200,result:{id:nyanAllParams.id,subject:nyanAllParams.nyan_guard.subject}});
`)
	snapshot := newAPIConfigSnapshot(map[string]APIConfig{
		"guard": {
			Script:  guardScript,
			Runtime: APIRuntimeConfig{},
		},
		"target": {Script: targetScript, ParamCheck: paramCheck, Description: "target"},
	}, "", [sha256.Size]byte{})
	serverConfig := APIConfig{
		Resource: "http://localhost/mcp",
		Guard:    MCPGuardConfig{API: "guard"},
		Tools: []MCPToolConfig{{
			Name: "target",
			API:  "target",
			SecuritySchemes: []MCPSecurityScheme{{
				Type:   "oauth2",
				Scopes: []string{"target:read"},
			}},
		}},
	}

	invalid := performTestMCPRequest(t, snapshot, serverConfig, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"target","arguments":{"id":"not-an-integer"}}}`, "Bearer good-token")
	invalidResponse := decodeTestJSONObject(t, invalid.Body.Bytes())
	invalidResult := invalidResponse["result"].(map[string]interface{})
	if invalidResult["isError"] != true || !strings.Contains(invalidResult["content"].([]interface{})[0].(map[string]interface{})["text"].(string), "arguments") {
		t.Fatalf("invalid argument result = %#v", invalidResult)
	}

	denied := performTestMCPRequest(t, snapshot, serverConfig, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"target","arguments":{"id":7}}}`, "")
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("denied HTTP status = %d; body=%s", denied.Code, denied.Body.String())
	}
	if got := denied.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	deniedResult := decodeTestJSONObject(t, denied.Body.Bytes())["result"].(map[string]interface{})
	if deniedResult["isError"] != true {
		t.Fatalf("denied result = %#v", deniedResult)
	}
	meta := deniedResult["_meta"].(map[string]interface{})
	if len(meta["mcp/www_authenticate"].([]interface{})) != 1 {
		t.Fatalf("denied MCP metadata = %#v", meta)
	}

	allowed := performTestMCPRequest(t, snapshot, serverConfig, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"target","arguments":{"id":7}}}`, "Bearer good-token")
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed HTTP status = %d; body=%s", allowed.Code, allowed.Body.String())
	}
	allowedResponse := decodeTestJSONObject(t, allowed.Body.Bytes())
	if _, exists := allowedResponse["error"]; exists {
		t.Fatalf("allowed response = %#v", allowedResponse)
	}
	allowedResult := allowedResponse["result"].(map[string]interface{})
	structured := allowedResult["structuredContent"].(map[string]interface{})
	result := structured["result"].(map[string]interface{})
	if result["id"] != float64(7) || result["subject"] != "user-1" {
		t.Fatalf("structuredContent = %#v", structured)
	}
	if len(allowedResult["content"].([]interface{})) != 1 {
		t.Fatalf("content = %#v", allowedResult["content"])
	}
}

func TestOAuthSQLiteEndToEndWithRealAssets(t *testing.T) {
	t.Skip("旧MCP guard配線の統合テスト。SQLite OAuthは新API参照形式の専用テストで検証する")
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	migrateOAuthTestDatabase(t, testDB)

	oldConfig := config
	config.BasicAuth = BasicAuthConfig{Username: "admin", Password: "bootstrap-secret"}
	t.Cleanup(func() { config = oldConfig })

	targetScript := writeTestScript(t, `
JSON.stringify({
  success: true,
  status: 200,
  result: {
    echo: nyanAllParams.echo,
    api: nyanAllParams.api,
    username: nyanAllParams.nyan_guard.username,
    clientId: nyanAllParams.nyan_guard.clientId,
    hasInjectedMode: Object.prototype.hasOwnProperty.call(nyanAllParams, "nyan_mode"),
    hasInjectedRequest: Object.prototype.hasOwnProperty.call(nyanAllParams, "nyan_request")
  }
});
`)
	snapshot := newOAuthIntegrationTestSnapshot(t, targetScript)
	setTestAPISnapshot(t, snapshot)

	oversized := strings.Repeat("x", maxConfiguredHTTPBodyBytes+1)
	tooLargeRegister := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/register", "application/json", oversized, nil)
	if tooLargeRegister.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized registration status = %d, want %d; body=%s", tooLargeRegister.Code, http.StatusRequestEntityTooLarge, tooLargeRegister.Body.String())
	}
	var clientCount int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_clients`).Scan(&clientCount); err != nil {
		t.Fatal(err)
	}
	if clientCount != 0 {
		t.Fatalf("clients after oversized registration = %d, want 0", clientCount)
	}
	tooLargeMCP := performOAuthTestMCPRequest(t, oversized, "")
	if tooLargeMCP.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized MCP status = %d, want %d; body=%s", tooLargeMCP.Code, http.StatusRequestEntityTooLarge, tooLargeMCP.Body.String())
	}

	protectedMetadata := performOAuthTestHTTPRequest(t, http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", "", nil)
	if protectedMetadata.Code != http.StatusOK {
		t.Fatalf("protected resource metadata status = %d; body=%s", protectedMetadata.Code, protectedMetadata.Body.String())
	}
	protectedMetadataBody := decodeTestJSONObject(t, protectedMetadata.Body.Bytes())
	if protectedMetadataBody["resource"] != oauthIntegrationTestResource || !reflect.DeepEqual(protectedMetadataBody["authorization_servers"], []interface{}{oauthIntegrationTestIssuer}) || !reflect.DeepEqual(protectedMetadataBody["scopes_supported"], []interface{}{"stamps:read", "offline_access"}) {
		t.Fatalf("protected resource metadata = %#v", protectedMetadataBody)
	}
	authorizationMetadata := performOAuthTestHTTPRequest(t, http.MethodGet, "/.well-known/oauth-authorization-server", "", "", nil)
	if authorizationMetadata.Code != http.StatusOK {
		t.Fatalf("authorization server metadata status = %d; body=%s", authorizationMetadata.Code, authorizationMetadata.Body.String())
	}
	authorizationMetadataBody := decodeTestJSONObject(t, authorizationMetadata.Body.Bytes())
	if authorizationMetadataBody["issuer"] != oauthIntegrationTestIssuer || authorizationMetadataBody["authorization_endpoint"] != oauthIntegrationTestIssuer+"/oauth/authorize" || !reflect.DeepEqual(authorizationMetadataBody["code_challenge_methods_supported"], []interface{}{"S256"}) || !reflect.DeepEqual(authorizationMetadataBody["grant_types_supported"], []interface{}{"authorization_code", "refresh_token"}) {
		t.Fatalf("authorization server metadata = %#v", authorizationMetadataBody)
	}

	bootstrap := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/admin/users", "application/json", `{
		"username":"integration-user",
		"password":"correct horse battery staple",
		"display_name":"Integration User"
	}`, func(req *http.Request) {
		req.SetBasicAuth("admin", "bootstrap-secret")
	})
	if bootstrap.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d; body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	bootstrapBody := decodeTestJSONObject(t, bootstrap.Body.Bytes())
	if bootstrapBody["success"] != true {
		t.Fatalf("bootstrap response = %#v", bootstrapBody)
	}
	var passwordHash string
	if err := testDB.QueryRow(`SELECT password_hash FROM oauth_users WHERE username = ?`, "integration-user").Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if passwordHash == "correct horse battery staple" || !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Fatalf("stored password hash = %q", passwordHash)
	}

	const callbackURL = "https://chatgpt.com/connector/oauth/integration-callback"
	badDCR := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/register", "application/json", `{
		"client_name":"Untrusted redirect",
		"redirect_uris":["https://attacker.example/callback"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"stamps:read offline_access"
	}`, nil)
	if badDCR.Code != http.StatusBadRequest {
		t.Fatalf("untrusted DCR status = %d; body=%s", badDCR.Code, badDCR.Body.String())
	}

	const registrationBody = `{
			"client_name":"ChatGPT integration test",
			"redirect_uris":["https://chatgpt.com/connector/oauth/integration-callback"],
			"response_types":["code"],
			"token_endpoint_auth_method":"none"
		}`
	dcr := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/register", "application/json", registrationBody, nil)
	if dcr.Code != http.StatusCreated {
		t.Fatalf("DCR status = %d; body=%s", dcr.Code, dcr.Body.String())
	}
	dcrBody := decodeTestJSONObject(t, dcr.Body.Bytes())
	clientID, _ := dcrBody["client_id"].(string)
	if !strings.HasPrefix(clientID, "nyan_client_") || dcrBody["token_endpoint_auth_method"] != "none" || !reflect.DeepEqual(dcrBody["grant_types"], []interface{}{"authorization_code", "refresh_token"}) || dcrBody["scope"] != "stamps:read offline_access" {
		t.Fatalf("DCR response = %#v", dcrBody)
	}
	capacityDCR := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/register", "application/json", registrationBody, nil)
	if capacityDCR.Code != http.StatusServiceUnavailable {
		t.Fatalf("DCR capacity status = %d; body=%s", capacityDCR.Code, capacityDCR.Body.String())
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := sha256Base64URL(verifier)
	authorizationTarget := func(redirectURI, resource string) string {
		query := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"resource":              {resource},
			"scope":                 {"stamps:read offline_access"},
			"state":                 {"state-integration"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		return "/oauth/authorize?" + query.Encode()
	}

	badRedirect := performOAuthTestHTTPRequest(t, http.MethodGet, authorizationTarget("https://attacker.example/callback", oauthIntegrationTestResource), "", "", nil)
	if badRedirect.Code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect status = %d, want %d; location=%q body=%s", badRedirect.Code, http.StatusBadRequest, badRedirect.Header().Get("Location"), badRedirect.Body.String())
	}
	if badRedirect.Header().Get("Location") != "" {
		t.Fatalf("unregistered redirect was followed: %q", badRedirect.Header().Get("Location"))
	}

	badResource := performOAuthTestHTTPRequest(t, http.MethodGet, authorizationTarget(callbackURL, "https://server.example/wrong-resource"), "", "", nil)
	if badResource.Code != http.StatusFound {
		t.Fatalf("invalid resource authorization status = %d; body=%s", badResource.Code, badResource.Body.String())
	}
	badResourceLocation, err := url.Parse(badResource.Header().Get("Location"))
	if err != nil || badResourceLocation.Query().Get("error") != "invalid_target" || badResourceLocation.Query().Get("state") != "state-integration" {
		t.Fatalf("invalid resource redirect = %q, error=%v", badResource.Header().Get("Location"), err)
	}

	authorizeGET := performOAuthTestHTTPRequest(t, http.MethodGet, authorizationTarget(callbackURL, oauthIntegrationTestResource), "", "", nil)
	if authorizeGET.Code != http.StatusOK || !strings.Contains(authorizeGET.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("authorize GET status = %d headers=%#v body=%s", authorizeGET.Code, authorizeGET.Header(), authorizeGET.Body.String())
	}
	if authorizeGET.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatalf("authorize Referrer-Policy = %q, want strict-origin", authorizeGET.Header().Get("Referrer-Policy"))
	}
	wantAuthorizeCSP := "default-src 'none'; form-action 'self' https://chatgpt.com; base-uri 'none'; frame-ancestors 'none'"
	if got := authorizeGET.Header().Get("Content-Security-Policy"); got != wantAuthorizeCSP {
		t.Fatalf("authorize Content-Security-Policy = %q, want %q", got, wantAuthorizeCSP)
	}
	requestID := extractTestHTMLInputValue(t, authorizeGET.Body.String(), "request_id")
	var csrfCookie *http.Cookie
	for _, cookie := range authorizeGET.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "nyan_oauth_csrf_") {
			csrfCookie = cookie
			break
		}
	}
	expectedCSRFCookieName := "nyan_oauth_csrf_" + sha256Hash(requestID)[:32]
	if csrfCookie == nil || csrfCookie.Name != expectedCSRFCookieName || csrfCookie.Value == "" || !csrfCookie.HttpOnly || !csrfCookie.Secure {
		t.Fatalf("authorization CSRF cookie = %#v", csrfCookie)
	}

	parallelAuthorizeGET := performOAuthTestHTTPRequest(t, http.MethodGet, authorizationTarget(callbackURL, oauthIntegrationTestResource), "", "", nil)
	if parallelAuthorizeGET.Code != http.StatusOK {
		t.Fatalf("parallel authorize GET status = %d; body=%s", parallelAuthorizeGET.Code, parallelAuthorizeGET.Body.String())
	}
	parallelRequestID := extractTestHTMLInputValue(t, parallelAuthorizeGET.Body.String(), "request_id")
	var parallelCSRFCookie *http.Cookie
	for _, cookie := range parallelAuthorizeGET.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "nyan_oauth_csrf_") {
			parallelCSRFCookie = cookie
			break
		}
	}
	if parallelCSRFCookie == nil || parallelCSRFCookie.Name == csrfCookie.Name || parallelCSRFCookie.Name != "nyan_oauth_csrf_"+sha256Hash(parallelRequestID)[:32] {
		t.Fatalf("parallel authorization CSRF cookies = first:%#v second:%#v", csrfCookie, parallelCSRFCookie)
	}

	authorizeForm := url.Values{
		"request_id": {requestID},
		"decision":   {"allow"},
		"username":   {"integration-user"},
		"password":   {"correct horse battery staple"},
	}
	authorizePOST := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/authorize", "application/x-www-form-urlencoded", authorizeForm.Encode(), func(req *http.Request) {
		req.AddCookie(csrfCookie)
		req.AddCookie(parallelCSRFCookie)
	})
	if authorizePOST.Code != http.StatusSeeOther {
		t.Fatalf("authorize POST status = %d; body=%s", authorizePOST.Code, authorizePOST.Body.String())
	}
	clearedCSRFCookies := authorizePOST.Result().Cookies()
	if len(clearedCSRFCookies) != 1 {
		t.Fatalf("cleared authorization CSRF cookies = %#v", clearedCSRFCookies)
	}
	clearedCSRFCookie := clearedCSRFCookies[0]
	if clearedCSRFCookie.Name != csrfCookie.Name || clearedCSRFCookie.MaxAge >= 0 {
		t.Fatalf("cleared authorization CSRF cookie = %#v", clearedCSRFCookie)
	}
	callback, err := url.Parse(authorizePOST.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect %q: %v", authorizePOST.Header().Get("Location"), err)
	}
	code := callback.Query().Get("code")
	if callback.Scheme+"://"+callback.Host+callback.Path != callbackURL || !strings.HasPrefix(code, "nyan_ac_") || callback.Query().Get("state") != "state-integration" {
		t.Fatalf("authorize redirect = %q", callback.String())
	}

	denyForm := url.Values{
		"request_id": {parallelRequestID},
		"decision":   {"deny"},
	}
	denyPOST := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/authorize", "application/x-www-form-urlencoded", denyForm.Encode(), func(req *http.Request) {
		req.AddCookie(csrfCookie)
		req.AddCookie(parallelCSRFCookie)
	})
	if denyPOST.Code != http.StatusSeeOther {
		t.Fatalf("parallel authorize denial status = %d; body=%s", denyPOST.Code, denyPOST.Body.String())
	}
	denialCallback, err := url.Parse(denyPOST.Header().Get("Location"))
	if err != nil || denialCallback.Query().Get("error") != "access_denied" || denialCallback.Query().Get("state") != "state-integration" {
		t.Fatalf("parallel authorize denial redirect = %q, error=%v", denyPOST.Header().Get("Location"), err)
	}
	clearedParallelCSRFCookies := denyPOST.Result().Cookies()
	if len(clearedParallelCSRFCookies) != 1 {
		t.Fatalf("cleared parallel authorization CSRF cookies = %#v", clearedParallelCSRFCookies)
	}
	clearedParallelCSRFCookie := clearedParallelCSRFCookies[0]
	if clearedParallelCSRFCookie.Name != parallelCSRFCookie.Name || clearedParallelCSRFCookie.MaxAge >= 0 {
		t.Fatalf("cleared parallel authorization CSRF cookie = %#v", clearedParallelCSRFCookie)
	}

	var storedCodeHash string
	var consumedAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT code_hash, consumed_at FROM oauth_authorization_codes WHERE client_id = ?`, clientID).Scan(&storedCodeHash, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if storedCodeHash == code || storedCodeHash != sha256Hash(code) || strings.Contains(storedCodeHash, code) || consumedAt.Valid {
		t.Fatalf("stored authorization code = hash:%q plaintext:%q consumed:%#v", storedCodeHash, code, consumedAt)
	}

	tokenRequest := func(codeValue, verifierValue, redirectURI, resource string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {codeValue},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifierValue},
			"resource":      {resource},
		}
		return performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), nil)
	}

	wrongResourceToken := tokenRequest(code, verifier, callbackURL, "https://server.example/wrong-resource")
	if wrongResourceToken.Code != http.StatusBadRequest || decodeTestJSONObject(t, wrongResourceToken.Body.Bytes())["error"] != "invalid_target" {
		t.Fatalf("wrong resource token response = status:%d body:%s", wrongResourceToken.Code, wrongResourceToken.Body.String())
	}
	wrongRedirectToken := tokenRequest(code, verifier, "https://chatgpt.com/connector/oauth/another-callback", oauthIntegrationTestResource)
	if wrongRedirectToken.Code != http.StatusBadRequest || decodeTestJSONObject(t, wrongRedirectToken.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("wrong redirect token response = status:%d body:%s", wrongRedirectToken.Code, wrongRedirectToken.Body.String())
	}
	wrongVerifierToken := tokenRequest(code, strings.Repeat("A", 43), callbackURL, oauthIntegrationTestResource)
	if wrongVerifierToken.Code != http.StatusBadRequest || decodeTestJSONObject(t, wrongVerifierToken.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("wrong PKCE token response = status:%d body:%s", wrongVerifierToken.Code, wrongVerifierToken.Body.String())
	}
	if err := testDB.QueryRow(`SELECT consumed_at FROM oauth_authorization_codes WHERE code_hash = ?`, storedCodeHash).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	if consumedAt.Valid {
		t.Fatalf("authorization code consumed by a rejected token request: %#v", consumedAt)
	}

	tokenResponse := tokenRequest(code, verifier, callbackURL, oauthIntegrationTestResource)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token status = %d; body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	tokenBody := decodeTestJSONObject(t, tokenResponse.Body.Bytes())
	accessToken, _ := tokenBody["access_token"].(string)
	refreshToken, _ := tokenBody["refresh_token"].(string)
	if !strings.HasPrefix(accessToken, "nyan_at_") || !strings.HasPrefix(refreshToken, "nyan_rt_") || tokenBody["token_type"] != "Bearer" || tokenBody["scope"] != "stamps:read offline_access" {
		t.Fatalf("token response = %#v", tokenBody)
	}

	codeReuse := tokenRequest(code, verifier, callbackURL, oauthIntegrationTestResource)
	if codeReuse.Code != http.StatusBadRequest || decodeTestJSONObject(t, codeReuse.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("authorization code reuse response = status:%d body:%s", codeReuse.Code, codeReuse.Body.String())
	}

	var storedTokenHash string
	var revokedAt sql.NullInt64
	var refreshFamilyID sql.NullInt64
	if err := testDB.QueryRow(`SELECT token_hash, revoked_at, refresh_family_id FROM oauth_access_tokens WHERE client_id = ?`, clientID).Scan(&storedTokenHash, &revokedAt, &refreshFamilyID); err != nil {
		t.Fatal(err)
	}
	if storedTokenHash == accessToken || storedTokenHash != sha256Hash(accessToken) || strings.Contains(storedTokenHash, accessToken) || revokedAt.Valid || !refreshFamilyID.Valid {
		t.Fatalf("stored access token = hash:%q plaintext:%q revoked:%#v family:%#v", storedTokenHash, accessToken, revokedAt, refreshFamilyID)
	}

	var initialRefreshID int64
	var initialRefreshFamilyID int64
	var storedRefreshHash string
	var refreshParentID sql.NullInt64
	var refreshConsumedAt sql.NullInt64
	var refreshRevokedAt sql.NullInt64
	var refreshFamilyRevokedAt sql.NullInt64
	if err := testDB.QueryRow(`
		SELECT rt.id, rt.family_id, rt.token_hash, rt.parent_id, rt.consumed_at, rt.revoked_at, f.revoked_at
		FROM oauth_refresh_tokens AS rt
		JOIN oauth_refresh_token_families AS f ON f.id = rt.family_id
		WHERE rt.token_hash = ?`, sha256Hash(refreshToken)).Scan(
		&initialRefreshID,
		&initialRefreshFamilyID,
		&storedRefreshHash,
		&refreshParentID,
		&refreshConsumedAt,
		&refreshRevokedAt,
		&refreshFamilyRevokedAt,
	); err != nil {
		t.Fatal(err)
	}
	if storedRefreshHash == refreshToken || storedRefreshHash != sha256Hash(refreshToken) || strings.Contains(storedRefreshHash, refreshToken) || refreshParentID.Valid || refreshConsumedAt.Valid || refreshRevokedAt.Valid || refreshFamilyRevokedAt.Valid || refreshFamilyID.Int64 <= 0 || refreshFamilyID.Int64 != initialRefreshFamilyID {
		t.Fatalf("stored refresh token = hash:%q plaintext:%q parent:%#v consumed:%#v revoked:%#v familyRevoked:%#v family:%#v", storedRefreshHash, refreshToken, refreshParentID, refreshConsumedAt, refreshRevokedAt, refreshFamilyRevokedAt, refreshFamilyID)
	}

	mcpCallBody := `{"jsonrpc":"2.0","id":"oauth-e2e","method":"tools/call","params":{"name":"oauth_e2e","arguments":{"echo":"hello","api":"attacker","nyan_mode":"checkOnly","nyan_guard":{"username":"attacker"},"nyan_request":{"headers":{"authorization":"Bearer attacker"}}}}}`
	authorizedMCP := performOAuthTestMCPRequest(t, mcpCallBody, "Bearer "+accessToken)
	if authorizedMCP.Code != http.StatusOK {
		t.Fatalf("authorized MCP status = %d; headers=%#v body=%s", authorizedMCP.Code, authorizedMCP.Header(), authorizedMCP.Body.String())
	}
	authorizedResponse := decodeTestJSONObject(t, authorizedMCP.Body.Bytes())
	if _, exists := authorizedResponse["error"]; exists {
		t.Fatalf("authorized MCP response = %#v", authorizedResponse)
	}
	structured := authorizedResponse["result"].(map[string]interface{})["structuredContent"].(map[string]interface{})
	toolResult := structured["result"].(map[string]interface{})
	if toolResult["echo"] != "hello" || toolResult["api"] != "oauth_e2e_target" || toolResult["username"] != "integration-user" || toolResult["clientId"] != clientID || toolResult["hasInjectedMode"] != false || toolResult["hasInjectedRequest"] != false {
		t.Fatalf("authorized MCP structured result = %#v", toolResult)
	}

	refreshTokenRequest := func(refreshValue, requestClientID, resource, requestedScope string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshValue},
			"client_id":     {requestClientID},
			"resource":      {resource},
		}
		if requestedScope != "" {
			form.Set("scope", requestedScope)
		}
		return performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), nil)
	}

	wrongClientRefresh := refreshTokenRequest(refreshToken, clientID+"-other", oauthIntegrationTestResource, "")
	if wrongClientRefresh.Code != http.StatusBadRequest || decodeTestJSONObject(t, wrongClientRefresh.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("wrong client refresh response = status:%d body:%s", wrongClientRefresh.Code, wrongClientRefresh.Body.String())
	}
	wrongResourceRefresh := refreshTokenRequest(refreshToken, clientID, "https://server.example/wrong-resource", "")
	if wrongResourceRefresh.Code != http.StatusBadRequest || decodeTestJSONObject(t, wrongResourceRefresh.Body.Bytes())["error"] != "invalid_target" {
		t.Fatalf("wrong resource refresh response = status:%d body:%s", wrongResourceRefresh.Code, wrongResourceRefresh.Body.String())
	}
	elevatedScopeRefresh := refreshTokenRequest(refreshToken, clientID, oauthIntegrationTestResource, "stamps:read offline_access stamps:write")
	if elevatedScopeRefresh.Code != http.StatusBadRequest || decodeTestJSONObject(t, elevatedScopeRefresh.Body.Bytes())["error"] != "invalid_scope" {
		t.Fatalf("elevated scope refresh response = status:%d body:%s", elevatedScopeRefresh.Code, elevatedScopeRefresh.Body.String())
	}
	if err := testDB.QueryRow(`SELECT consumed_at FROM oauth_refresh_tokens WHERE id = ?`, initialRefreshID).Scan(&refreshConsumedAt); err != nil {
		t.Fatal(err)
	}
	if refreshConsumedAt.Valid {
		t.Fatal("refresh token was consumed by a rejected refresh request")
	}

	rotatedResponse := refreshTokenRequest(refreshToken, clientID, oauthIntegrationTestResource, "stamps:read")
	if rotatedResponse.Code != http.StatusOK {
		t.Fatalf("refresh rotation status = %d; body=%s", rotatedResponse.Code, rotatedResponse.Body.String())
	}
	rotatedBody := decodeTestJSONObject(t, rotatedResponse.Body.Bytes())
	rotatedAccessToken, _ := rotatedBody["access_token"].(string)
	rotatedRefreshToken, _ := rotatedBody["refresh_token"].(string)
	if !strings.HasPrefix(rotatedAccessToken, "nyan_at_") || !strings.HasPrefix(rotatedRefreshToken, "nyan_rt_") || rotatedAccessToken == accessToken || rotatedRefreshToken == refreshToken || rotatedBody["scope"] != "stamps:read" {
		t.Fatalf("refresh rotation response = %#v", rotatedBody)
	}

	if err := testDB.QueryRow(`SELECT consumed_at, revoked_at FROM oauth_refresh_tokens WHERE id = ?`, initialRefreshID).Scan(&refreshConsumedAt, &refreshRevokedAt); err != nil {
		t.Fatal(err)
	}
	if !refreshConsumedAt.Valid || refreshRevokedAt.Valid {
		t.Fatalf("rotated source refresh token = consumed:%#v revoked:%#v", refreshConsumedAt, refreshRevokedAt)
	}
	var rotatedRefreshID int64
	var rotatedRefreshFamilyID int64
	var rotatedRefreshParentID sql.NullInt64
	var rotatedRefreshHash string
	var rotatedRefreshScope string
	var rotatedFamilyScope string
	if err := testDB.QueryRow(`
		SELECT rt.id, rt.family_id, rt.parent_id, rt.token_hash, rt.scope, rf.scope
		FROM oauth_refresh_tokens AS rt
		JOIN oauth_refresh_token_families AS rf ON rf.id = rt.family_id
		WHERE rt.token_hash = ?`, sha256Hash(rotatedRefreshToken)).Scan(
		&rotatedRefreshID,
		&rotatedRefreshFamilyID,
		&rotatedRefreshParentID,
		&rotatedRefreshHash,
		&rotatedRefreshScope,
		&rotatedFamilyScope,
	); err != nil {
		t.Fatal(err)
	}
	if rotatedRefreshFamilyID != initialRefreshFamilyID || !rotatedRefreshParentID.Valid || rotatedRefreshParentID.Int64 != initialRefreshID || rotatedRefreshHash != sha256Hash(rotatedRefreshToken) || rotatedRefreshHash == rotatedRefreshToken || rotatedRefreshScope != "stamps:read offline_access" || rotatedFamilyScope != "stamps:read offline_access" {
		t.Fatalf("rotated refresh token = id:%d family:%d parent:%#v hash:%q scope:%q familyScope:%q", rotatedRefreshID, rotatedRefreshFamilyID, rotatedRefreshParentID, rotatedRefreshHash, rotatedRefreshScope, rotatedFamilyScope)
	}
	var rotatedAccessFamilyID sql.NullInt64
	if err := testDB.QueryRow(`SELECT refresh_family_id FROM oauth_access_tokens WHERE token_hash = ?`, sha256Hash(rotatedAccessToken)).Scan(&rotatedAccessFamilyID); err != nil {
		t.Fatal(err)
	}
	if !rotatedAccessFamilyID.Valid || rotatedAccessFamilyID.Int64 != initialRefreshFamilyID {
		t.Fatalf("rotated access-token family = %#v, want %d", rotatedAccessFamilyID, initialRefreshFamilyID)
	}
	rotatedMCP := performOAuthTestMCPRequest(t, mcpCallBody, "Bearer "+rotatedAccessToken)
	if rotatedMCP.Code != http.StatusOK {
		t.Fatalf("rotated access-token MCP status = %d; body=%s", rotatedMCP.Code, rotatedMCP.Body.String())
	}
	rotatedElevatedScope := refreshTokenRequest(rotatedRefreshToken, clientID, oauthIntegrationTestResource, "stamps:read offline_access stamps:write")
	if rotatedElevatedScope.Code != http.StatusBadRequest || decodeTestJSONObject(t, rotatedElevatedScope.Body.Bytes())["error"] != "invalid_scope" {
		t.Fatalf("rotated token elevated-scope response = status:%d body:%s", rotatedElevatedScope.Code, rotatedElevatedScope.Body.String())
	}
	var rotatedConsumedAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT consumed_at FROM oauth_refresh_tokens WHERE id = ?`, rotatedRefreshID).Scan(&rotatedConsumedAt); err != nil {
		t.Fatal(err)
	}
	if rotatedConsumedAt.Valid {
		t.Fatal("rotated refresh token was consumed by an excessive-scope request")
	}

	replayedRefresh := refreshTokenRequest(refreshToken, clientID, oauthIntegrationTestResource, "")
	if replayedRefresh.Code != http.StatusBadRequest || decodeTestJSONObject(t, replayedRefresh.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("refresh replay response = status:%d body:%s", replayedRefresh.Code, replayedRefresh.Body.String())
	}
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_refresh_token_families WHERE id = ?`, initialRefreshFamilyID).Scan(&refreshFamilyRevokedAt); err != nil {
		t.Fatal(err)
	}
	if !refreshFamilyRevokedAt.Valid {
		t.Fatal("refresh-token replay did not revoke its family")
	}
	var activeRefreshTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE family_id = ? AND revoked_at IS NULL`, initialRefreshFamilyID).Scan(&activeRefreshTokens); err != nil {
		t.Fatal(err)
	}
	var activeAccessTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_access_tokens WHERE refresh_family_id = ? AND revoked_at IS NULL`, initialRefreshFamilyID).Scan(&activeAccessTokens); err != nil {
		t.Fatal(err)
	}
	if activeRefreshTokens != 0 || activeAccessTokens != 0 {
		t.Fatalf("active family credentials after replay = refresh:%d access:%d", activeRefreshTokens, activeAccessTokens)
	}
	rotatedAfterReplay := refreshTokenRequest(rotatedRefreshToken, clientID, oauthIntegrationTestResource, "")
	if rotatedAfterReplay.Code != http.StatusBadRequest || decodeTestJSONObject(t, rotatedAfterReplay.Body.Bytes())["error"] != "invalid_grant" {
		t.Fatalf("rotated token after replay response = status:%d body:%s", rotatedAfterReplay.Code, rotatedAfterReplay.Body.String())
	}

	replayedFamilyMCP := performOAuthTestMCPRequest(t, mcpCallBody, "Bearer "+rotatedAccessToken)
	if replayedFamilyMCP.Code != http.StatusUnauthorized {
		t.Fatalf("replayed-family MCP status = %d, want %d; body=%s", replayedFamilyMCP.Code, http.StatusUnauthorized, replayedFamilyMCP.Body.String())
	}
	if !strings.Contains(replayedFamilyMCP.Header().Get("WWW-Authenticate"), `error="invalid_token"`) ||
		!strings.Contains(replayedFamilyMCP.Header().Get("WWW-Authenticate"), `error_description="`) {
		t.Fatalf("replayed-family MCP challenge = %q", replayedFamilyMCP.Header().Get("WWW-Authenticate"))
	}
	replayedFamilyResult := decodeTestJSONObject(t, replayedFamilyMCP.Body.Bytes())["result"].(map[string]interface{})
	if replayedFamilyResult["isError"] != true || len(replayedFamilyResult["_meta"].(map[string]interface{})["mcp/www_authenticate"].([]interface{})) != 1 {
		t.Fatalf("replayed-family MCP result = %#v", replayedFamilyResult)
	}

	secondAuthorizeGET := performOAuthTestHTTPRequest(t, http.MethodGet, authorizationTarget(callbackURL, oauthIntegrationTestResource), "", "", nil)
	if secondAuthorizeGET.Code != http.StatusOK {
		t.Fatalf("second authorize GET status = %d; body=%s", secondAuthorizeGET.Code, secondAuthorizeGET.Body.String())
	}
	secondRequestID := extractTestHTMLInputValue(t, secondAuthorizeGET.Body.String(), "request_id")
	var secondCSRFCookie *http.Cookie
	for _, cookie := range secondAuthorizeGET.Result().Cookies() {
		if cookie.Name == "nyan_oauth_csrf_"+sha256Hash(secondRequestID)[:32] {
			secondCSRFCookie = cookie
			break
		}
	}
	if secondCSRFCookie == nil {
		t.Fatal("second authorization CSRF cookie is missing")
	}
	secondAuthorizeForm := url.Values{
		"request_id": {secondRequestID},
		"decision":   {"allow"},
		"username":   {"integration-user"},
		"password":   {"correct horse battery staple"},
	}
	secondAuthorizePOST := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/authorize", "application/x-www-form-urlencoded", secondAuthorizeForm.Encode(), func(req *http.Request) {
		req.AddCookie(secondCSRFCookie)
	})
	if secondAuthorizePOST.Code != http.StatusSeeOther {
		t.Fatalf("second authorize POST status = %d; body=%s", secondAuthorizePOST.Code, secondAuthorizePOST.Body.String())
	}
	secondCallback, err := url.Parse(secondAuthorizePOST.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	secondCode := secondCallback.Query().Get("code")
	secondTokenResponse := tokenRequest(secondCode, verifier, callbackURL, oauthIntegrationTestResource)
	if secondTokenResponse.Code != http.StatusOK {
		t.Fatalf("second token status = %d; body=%s", secondTokenResponse.Code, secondTokenResponse.Body.String())
	}
	secondTokenBody := decodeTestJSONObject(t, secondTokenResponse.Body.Bytes())
	secondAccessToken, _ := secondTokenBody["access_token"].(string)
	secondRefreshToken, _ := secondTokenBody["refresh_token"].(string)
	if secondAccessToken == "" || secondRefreshToken == "" {
		t.Fatalf("second token response = %#v", secondTokenBody)
	}
	var secondRefreshFamilyID int64
	if err := testDB.QueryRow(`SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = ?`, sha256Hash(secondRefreshToken)).Scan(&secondRefreshFamilyID); err != nil {
		t.Fatal(err)
	}
	revokeForm := url.Values{
		"token":           {secondRefreshToken},
		"client_id":       {clientID},
		"token_type_hint": {"refresh_token"},
	}
	revoke := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/revoke", "application/x-www-form-urlencoded", revokeForm.Encode(), nil)
	if revoke.Code != http.StatusOK || revoke.Body.Len() != 0 {
		t.Fatalf("refresh revoke response = status:%d body:%q", revoke.Code, revoke.Body.String())
	}
	var explicitlyRevokedFamilyAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_refresh_token_families WHERE id = ?`, secondRefreshFamilyID).Scan(&explicitlyRevokedFamilyAt); err != nil {
		t.Fatal(err)
	}
	var explicitlyRevokedRefreshAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_refresh_tokens WHERE token_hash = ?`, sha256Hash(secondRefreshToken)).Scan(&explicitlyRevokedRefreshAt); err != nil {
		t.Fatal(err)
	}
	var explicitlyRevokedAccessAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_access_tokens WHERE token_hash = ?`, sha256Hash(secondAccessToken)).Scan(&explicitlyRevokedAccessAt); err != nil {
		t.Fatal(err)
	}
	if !explicitlyRevokedFamilyAt.Valid || !explicitlyRevokedRefreshAt.Valid || !explicitlyRevokedAccessAt.Valid {
		t.Fatalf("explicit refresh revocation = family:%#v refresh:%#v access:%#v", explicitlyRevokedFamilyAt, explicitlyRevokedRefreshAt, explicitlyRevokedAccessAt)
	}
	revokedMCP := performOAuthTestMCPRequest(t, mcpCallBody, "Bearer "+secondAccessToken)
	if revokedMCP.Code != http.StatusUnauthorized {
		t.Fatalf("explicitly revoked-family MCP status = %d, want %d; body=%s", revokedMCP.Code, http.StatusUnauthorized, revokedMCP.Body.String())
	}
}

func TestOAuthRefreshTokenRejectsExpiredAndDisabledPrincipals(t *testing.T) {
	t.Skip("OAuth運用資材をNyanQL本体から分離しているため一時停止")
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	migrateOAuthTestDatabase(t, testDB)

	const clientID = "refresh-validation-client"
	if _, err := testDB.Exec(`INSERT INTO oauth_users(id, username, password_hash) VALUES (1, 'refresh-validation-user', 'unused')`); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_clients(client_id, client_name, token_endpoint_auth_method, grant_types, response_types, scope) VALUES (?, 'Refresh validation', 'none', '["authorization_code","refresh_token"]', '["code"]', 'stamps:read offline_access')`, clientID); err != nil {
		t.Fatal(err)
	}
	targetScript := writeTestScript(t, `JSON.stringify({success:true,status:200,result:{}});`)
	setTestAPISnapshot(t, newOAuthIntegrationTestSnapshot(t, targetScript))

	refreshRequest := func(token string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {clientID},
			"resource":      {oauthIntegrationTestResource},
		}
		return performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), nil)
	}
	assertRejectedWithoutConsumption := func(label, token string, tokenID int64) {
		t.Helper()
		response := refreshRequest(token)
		if response.Code != http.StatusBadRequest || decodeTestJSONObject(t, response.Body.Bytes())["error"] != "invalid_grant" {
			t.Fatalf("%s response = status:%d body:%s", label, response.Code, response.Body.String())
		}
		var consumedAt sql.NullInt64
		if err := testDB.QueryRow(`SELECT consumed_at FROM oauth_refresh_tokens WHERE id = ?`, tokenID).Scan(&consumedAt); err != nil {
			t.Fatal(err)
		}
		if consumedAt.Valid {
			t.Fatalf("%s token was consumed: %#v", label, consumedAt)
		}
	}

	logWriter := log.Writer()
	var capturedLogs strings.Builder
	log.SetOutput(&capturedLogs)
	t.Cleanup(func() { log.SetOutput(logWriter) })

	expiredToken, _, expiredTokenID := seedOAuthRefreshTokenTestRecord(t, testDB, clientID, "expired", time.Now().Add(-time.Minute).Unix())
	assertRejectedWithoutConsumption("expired refresh token", expiredToken, expiredTokenID)

	disabledUserToken, _, disabledUserTokenID := seedOAuthRefreshTokenTestRecord(t, testDB, clientID, "disabled-user", time.Now().Add(time.Hour).Unix())
	if _, err := testDB.Exec(`UPDATE oauth_users SET enabled = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	assertRejectedWithoutConsumption("disabled user", disabledUserToken, disabledUserTokenID)
	if _, err := testDB.Exec(`UPDATE oauth_users SET enabled = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}

	disabledClientToken, _, disabledClientTokenID := seedOAuthRefreshTokenTestRecord(t, testDB, clientID, "disabled-client", time.Now().Add(time.Hour).Unix())
	if _, err := testDB.Exec(`UPDATE oauth_clients SET enabled = 0 WHERE client_id = ?`, clientID); err != nil {
		t.Fatal(err)
	}
	assertRejectedWithoutConsumption("disabled client", disabledClientToken, disabledClientTokenID)
	if _, err := testDB.Exec(`UPDATE oauth_clients SET enabled = 1 WHERE client_id = ?`, clientID); err != nil {
		t.Fatal(err)
	}

	nearExpiry := time.Now().Add(120 * time.Second).Unix()
	nearExpiryToken, nearExpiryFamilyID, _ := seedOAuthRefreshTokenTestRecord(t, testDB, clientID, "near-expiry", nearExpiry)
	nearExpiryResponse := refreshRequest(nearExpiryToken)
	if nearExpiryResponse.Code != http.StatusOK {
		t.Fatalf("near-expiry refresh response = status:%d body:%s", nearExpiryResponse.Code, nearExpiryResponse.Body.String())
	}
	nearExpiryBody := decodeTestJSONObject(t, nearExpiryResponse.Body.Bytes())
	nearExpiryAccessToken, _ := nearExpiryBody["access_token"].(string)
	expiresIn, _ := nearExpiryBody["expires_in"].(float64)
	if nearExpiryAccessToken == "" || expiresIn <= 0 || expiresIn > 120 {
		t.Fatalf("near-expiry token response = %#v", nearExpiryBody)
	}
	var accessExpiresAt int64
	if err := testDB.QueryRow(`SELECT expires_at FROM oauth_access_tokens WHERE token_hash = ? AND refresh_family_id = ?`, sha256Hash(nearExpiryAccessToken), nearExpiryFamilyID).Scan(&accessExpiresAt); err != nil {
		t.Fatal(err)
	}
	if accessExpiresAt > nearExpiry {
		t.Fatalf("near-expiry access expiration = %d, family expiration = %d", accessExpiresAt, nearExpiry)
	}
	revokeAccessForm := url.Values{
		"token":           {nearExpiryAccessToken},
		"client_id":       {clientID},
		"token_type_hint": {"access_token"},
	}
	revokeAccessResponse := performOAuthTestHTTPRequest(t, http.MethodPost, "/oauth/revoke", "application/x-www-form-urlencoded", revokeAccessForm.Encode(), nil)
	if revokeAccessResponse.Code != http.StatusOK || revokeAccessResponse.Body.Len() != 0 {
		t.Fatalf("family-bound access-token revoke response = status:%d body:%q", revokeAccessResponse.Code, revokeAccessResponse.Body.String())
	}
	var nearExpiryFamilyRevokedAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_refresh_token_families WHERE id = ?`, nearExpiryFamilyID).Scan(&nearExpiryFamilyRevokedAt); err != nil {
		t.Fatal(err)
	}
	var activeNearExpiryRefreshTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE family_id = ? AND revoked_at IS NULL`, nearExpiryFamilyID).Scan(&activeNearExpiryRefreshTokens); err != nil {
		t.Fatal(err)
	}
	var activeNearExpiryAccessTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_access_tokens WHERE refresh_family_id = ? AND revoked_at IS NULL`, nearExpiryFamilyID).Scan(&activeNearExpiryAccessTokens); err != nil {
		t.Fatal(err)
	}
	if !nearExpiryFamilyRevokedAt.Valid || activeNearExpiryRefreshTokens != 0 || activeNearExpiryAccessTokens != 0 {
		t.Fatalf("family-bound access-token revocation = family:%#v activeRefresh:%d activeAccess:%d", nearExpiryFamilyRevokedAt, activeNearExpiryRefreshTokens, activeNearExpiryAccessTokens)
	}

	for _, credential := range []string{expiredToken, disabledUserToken, disabledClientToken, nearExpiryToken} {
		if strings.Contains(capturedLogs.String(), credential) {
			t.Fatalf("refresh token plaintext was written to logs: %q", credential)
		}
	}
}

func TestOAuthConcurrentRefreshAllowsOneRotationThenRevokesFamily(t *testing.T) {
	t.Skip("OAuth運用資材をNyanQL本体から分離しているため一時停止")
	resetJavascriptInclude(t)
	oldDB := db
	oldDBType := dbType
	databasePath := filepath.Join(t.TempDir(), "oauth-refresh-concurrency.db")
	testDB, err := sql.Open("sqlite3", databasePath+"?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	testDB.SetMaxOpenConns(4)
	testDB.SetMaxIdleConns(4)
	if err := testDB.Ping(); err != nil {
		_ = testDB.Close()
		t.Fatal(err)
	}
	db = testDB
	dbType = "sqlite3"
	t.Cleanup(func() {
		_ = testDB.Close()
		db = oldDB
		dbType = oldDBType
	})
	migrateOAuthTestDatabase(t, testDB)

	firstConnection, err := testDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondConnection, err := testDB.Conn(context.Background())
	if err != nil {
		_ = firstConnection.Close()
		t.Fatal(err)
	}
	if stats := testDB.Stats(); stats.MaxOpenConnections < 2 || stats.OpenConnections < 2 {
		_ = secondConnection.Close()
		_ = firstConnection.Close()
		t.Fatalf("SQLite pool does not permit concurrent refresh transactions: %#v", stats)
	}
	if err := secondConnection.Close(); err != nil {
		_ = firstConnection.Close()
		t.Fatal(err)
	}
	if err := firstConnection.Close(); err != nil {
		t.Fatal(err)
	}

	const clientID = "refresh-concurrency-client"
	if _, err := testDB.Exec(`INSERT INTO oauth_users(id, username, password_hash) VALUES (1, 'refresh-concurrency-user', 'unused')`); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_clients(client_id, client_name, token_endpoint_auth_method, grant_types, response_types, scope) VALUES (?, 'Refresh concurrency', 'none', '["authorization_code","refresh_token"]', '["code"]', 'stamps:read offline_access')`, clientID); err != nil {
		t.Fatal(err)
	}
	targetScript := writeTestScript(t, `JSON.stringify({success:true,status:200,result:{}});`)
	setTestAPISnapshot(t, newOAuthIntegrationTestSnapshot(t, targetScript))

	refreshToken, familyID, _ := seedOAuthRefreshTokenTestRecord(t, testDB, clientID, "concurrent", time.Now().Add(time.Hour).Unix())
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"resource":      {oauthIntegrationTestResource},
	}
	type refreshResult struct {
		status int
		body   []byte
	}
	results := make(chan refreshResult, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			unifiedHandler(recorder, request)
			results <- refreshResult{status: recorder.Code, body: append([]byte(nil), recorder.Body.Bytes()...)}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	rejections := 0
	var successfulAccessToken string
	for result := range results {
		body := decodeTestJSONObject(t, result.body)
		switch {
		case result.status == http.StatusOK:
			successes++
			successfulAccessToken, _ = body["access_token"].(string)
		case result.status == http.StatusBadRequest && body["error"] == "invalid_grant":
			rejections++
		default:
			t.Fatalf("concurrent refresh response = status:%d body:%s", result.status, result.body)
		}
	}
	if successes != 1 || rejections != 1 || successfulAccessToken == "" {
		t.Fatalf("concurrent refresh outcomes = successes:%d rejections:%d accessToken:%q", successes, rejections, successfulAccessToken)
	}

	var familyRevokedAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_refresh_token_families WHERE id = ?`, familyID).Scan(&familyRevokedAt); err != nil {
		t.Fatal(err)
	}
	var activeRefreshTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE family_id = ? AND revoked_at IS NULL`, familyID).Scan(&activeRefreshTokens); err != nil {
		t.Fatal(err)
	}
	var activeAccessTokens int
	if err := testDB.QueryRow(`SELECT COUNT(*) FROM oauth_access_tokens WHERE refresh_family_id = ? AND revoked_at IS NULL`, familyID).Scan(&activeAccessTokens); err != nil {
		t.Fatal(err)
	}
	if !familyRevokedAt.Valid || activeRefreshTokens != 0 || activeAccessTokens != 0 {
		t.Fatalf("concurrent replay family state = revoked:%#v activeRefresh:%d activeAccess:%d", familyRevokedAt, activeRefreshTokens, activeAccessTokens)
	}
	var successfulAccessRevokedAt sql.NullInt64
	if err := testDB.QueryRow(`SELECT revoked_at FROM oauth_access_tokens WHERE token_hash = ?`, sha256Hash(successfulAccessToken)).Scan(&successfulAccessRevokedAt); err != nil {
		t.Fatal(err)
	}
	if !successfulAccessRevokedAt.Valid {
		t.Fatal("access token returned by concurrent rotation survived replay detection")
	}
}

func TestMCPRateLimit(t *testing.T) {
	mcpRateBuckets.Lock()
	oldBuckets := mcpRateBuckets.Buckets
	oldCleanup := mcpRateBuckets.LastCleanup
	mcpRateBuckets.Buckets = make(map[string]mcpRateBucket)
	mcpRateBuckets.LastCleanup = time.Time{}
	mcpRateBuckets.Unlock()
	t.Cleanup(func() {
		mcpRateBuckets.Lock()
		mcpRateBuckets.Buckets = oldBuckets
		mcpRateBuckets.LastCleanup = oldCleanup
		mcpRateBuckets.Unlock()
	})

	rateLimited := &HTTPRateLimitConfig{Requests: 2, Window: "1m"}
	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	if allowed, _ := configuredRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:1000", now); !allowed {
		t.Fatal("first rate-limited request was rejected")
	}
	if allowed, _ := configuredRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:2000", now.Add(time.Second)); !allowed {
		t.Fatal("second request from same IP was rejected")
	}
	if allowed, retryAfter := configuredRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:3000", now.Add(2*time.Second)); allowed || retryAfter <= 0 {
		t.Fatalf("third request allowed=%t retryAfter=%s", allowed, retryAfter)
	}
	if allowed, _ := configuredRateLimitAllows("oauth_register", rateLimited, "192.0.2.2:1000", now.Add(2*time.Second)); !allowed {
		t.Fatal("different IP incorrectly shared a rate-limit bucket")
	}
	if allowed, _ := configuredRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:4000", now.Add(time.Minute)); !allowed {
		t.Fatal("request after rate-limit window was rejected")
	}

}

func TestMCPOriginPolicies(t *testing.T) {
	mcpRequest := httptest.NewRequest(http.MethodPost, "https://server.example/mcp", nil)
	for _, testCase := range []struct {
		name    string
		origin  string
		allowed bool
	}{
		{name: "same origin", origin: "https://server.example", allowed: true},
		{name: "configured ChatGPT origin", origin: "https://platform.openai.com", allowed: true},
		{name: "unconfigured loopback", origin: "http://127.0.0.1:3000", allowed: false},
		{name: "unconfigured origin", origin: "https://attacker.example", allowed: false},
	} {
		t.Run("mcp "+testCase.name, func(t *testing.T) {
			mcpRequest.Header.Set("Origin", testCase.origin)
			if got := validateMCPOrigin(mcpRequest, "https://server.example/mcp", []string{"https://platform.openai.com"}); got != testCase.allowed {
				t.Fatalf("validateMCPOrigin(%q) = %t, want %t", testCase.origin, got, testCase.allowed)
			}
		})
	}
}

func TestAPIConfigRejectsUnknownAndMisplacedSecurityFields(t *testing.T) {
	_, err := decodeSQLFiles([]byte(`{
		"endpoint": {
			"script": "./endpoint.js",
			"http": {"path":"/endpoint","access":"anonymous","allowedOrigns":[]}
		}
	}`), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `unsupported field "http"`) {
		t.Fatalf("unknown security field error = %v", err)
	}

	definitions, err := decodeSQLFiles([]byte(`{
		"endpoint": {
			"script": "./endpoint.js",
			"allowedOrigins": ["https://chatgpt.com"]
		}
	}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfiguredAPIExtensions(definitions); err == nil || !strings.Contains(err.Error(), "MCP fields are only allowed") {
		t.Fatalf("misplaced security field error = %v", err)
	}
}

func TestOAuthScopeTokenValidation(t *testing.T) {
	for _, value := range []string{"stamps:read", "a!#$%&'()*+,-./:;<=>?@[]^_`{|}~"} {
		if !isValidOAuthScopeToken(value) {
			t.Fatalf("isValidOAuthScopeToken(%q) = false", value)
		}
	}
	for _, value := range []string{"", "stamps read", "quoted\"scope", `back\\slash`, "日本語"} {
		if isValidOAuthScopeToken(value) {
			t.Fatalf("isValidOAuthScopeToken(%q) = true", value)
		}
	}
}

func TestVPSAPIConfigurationLoads(t *testing.T) {
	t.Skip("VPS固有設定をNyanQL本体から分離しているため一時停止")
	apiPath := oauthTestAssetPath(t, "api.vps.json")
	loadResult, err := loadAPIConfigFile(apiPath)
	if err != nil {
		t.Fatalf("loadAPIConfigFile(%q): %v", apiPath, err)
	}
	serverConfig, exists := loadResult.Snapshot.Definitions["mcp"]
	if !exists || serverConfig.Transport != "streamable_http" || serverConfig.Path != "" || serverConfig.Resource != "" {
		t.Fatalf("VPS MCP configuration = %#v", serverConfig)
	}
	if len(serverConfig.Tools) != 1 || serverConfig.Tools[0].Name != "list_stamps" || serverConfig.Tools[0].API != "list_stamps" {
		t.Fatalf("VPS MCP tools = %#v", serverConfig.Tools)
	}
	if serverConfig.OAuth.AuthorizationServerMetadata != ".well-known/oauth-authorization-server" ||
		serverConfig.OAuth.ProtectedResourceMetadata != ".well-known/oauth-protected-resource/mcp" ||
		serverConfig.OAuth.VerifyAccess != "oauth/verify-access" {
		t.Fatalf("VPS MCP OAuth references = %#v", serverConfig.OAuth)
	}
	tool := loadResult.Snapshot.Definitions["list_stamps"]
	if tool.Script == "" || !reflect.DeepEqual(mcpRequiredScopes(tool.SecuritySchemes), []string{"stamps:read"}) {
		t.Fatalf("VPS MCP tool = %#v", tool)
	}
	verify := loadResult.Snapshot.Definitions["oauth/verify-access"]
	if !reflect.DeepEqual(verify.Scopes, []string{"stamps:read", "offline_access"}) {
		t.Fatalf("VPS verifyAccess scopes = %#v", verify.Scopes)
	}
}

func TestVPSServiceCanBindStandardHTTPSPort(t *testing.T) {
	t.Skip("VPS固有設定をNyanQL本体から分離しているため一時停止")
	servicePath := oauthTestAssetPath(t, "ansible", "templates", "nyanql.service.j2")
	contents, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	service := string(contents)
	for _, required := range []string{
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("%s is missing %q", servicePath, required)
		}
	}
}

func TestVPSDeploymentUsesDomainCertificate(t *testing.T) {
	t.Skip("VPS固有設定をNyanQL本体から分離しているため一時停止")
	deployPath := oauthTestAssetPath(t, "ansible", "deploy.yml")
	deployContents, err := os.ReadFile(deployPath)
	if err != nil {
		t.Fatal(err)
	}
	deploy := string(deployContents)
	for _, required := range []string{
		`nyanql_public_hostname: "stamp.necomori.asia"`,
		`nyanql_public_origin: "https://{{ nyanql_public_hostname }}"`,
		"- --domains",
		`- "{{ nyanql_public_hostname }}"`,
		`- "{{ letsencrypt_cert_name }}"`,
	} {
		if !strings.Contains(deploy, required) {
			t.Fatalf("%s is missing %q", deployPath, required)
		}
	}
	for _, forbidden := range []string{"--ip-address", "preferred-profile", "shortlived"} {
		if strings.Contains(deploy, forbidden) {
			t.Fatalf("%s still contains obsolete IP certificate option %q", deployPath, forbidden)
		}
	}

	renewPath := oauthTestAssetPath(t, "ansible", "templates", "nyanql-certbot-renew.service.j2")
	renewContents, err := os.ReadFile(renewPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(renewContents), "renew --cert-name {{ letsencrypt_cert_name }} --quiet") {
		t.Fatalf("%s does not limit renewal to the configured domain certificate", renewPath)
	}

	hookPath := oauthTestAssetPath(t, "ansible", "templates", "install-certificate.sh.j2")
	hookContents, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hookContents), `expected_lineage="{{ letsencrypt_live_dir }}"`) {
		t.Fatalf("%s does not reject unrelated certificate lineages", hookPath)
	}
}

func TestVPSDeploymentAppliesRefreshMigrationOnlyWhenPending(t *testing.T) {
	t.Skip("OAuth運用資材をNyanQL本体から分離しているため一時停止")
	deployPath := oauthTestAssetPath(t, "ansible", "deploy.yml")
	contents, err := os.ReadFile(deployPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	applyMarker := "    - name: Apply OAuth migration 003"
	applyStart := strings.Index(text, applyMarker)
	if applyStart < 0 {
		t.Fatalf("%s does not define OAuth migration 003 deployment", deployPath)
	}
	applyBlock := text[applyStart:]
	if nextTask := strings.Index(applyBlock[len(applyMarker):], "\n    - name:"); nextTask >= 0 {
		applyBlock = applyBlock[:len(applyMarker)+nextTask]
	}
	for _, required := range []string{
		".read {{ nyanql_source_dir }}/sql/oauth/003_add_refresh_tokens.sql",
		`when: "'3' not in oauth_migration_versions.stdout_lines"`,
	} {
		if !strings.Contains(applyBlock, required) {
			t.Fatalf("OAuth migration 003 task is missing %q:\n%s", required, applyBlock)
		}
	}
}

func TestSQLAndMCPResponseSizeLimits(t *testing.T) {
	testDB := setTestSQLiteDB(t)
	rows, err := testDB.Query(`SELECT zeroblob(?) AS oversized`, maxSQLJSONBytes+1)
	if err != nil {
		t.Fatal(err)
	}
	_, rowsErr := RowsToJSON(rows)
	closeErr := rows.Close()
	if rowsErr == nil || !strings.Contains(rowsErr.Error(), "maximum JSON size") {
		t.Fatalf("RowsToJSON oversized error = %v", rowsErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	recorder := httptest.NewRecorder()
	writeMCPResult(recorder, json.RawMessage(`"large"`), map[string]interface{}{
		"data": strings.Repeat("x", maxConfiguredHTTPResponseBytes+1),
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("oversized MCP status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeTestJSONObject(t, recorder.Body.Bytes())
	if response["error"].(map[string]interface{})["message"] != "Response is too large" {
		t.Fatalf("oversized MCP response = %#v", response)
	}
}

func TestOAuthCleanupRemovesExpiredStateAndInactiveClient(t *testing.T) {
	t.Skip("OAuth運用資材をNyanQL本体から分離しているため一時停止")
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	migrateOAuthTestDatabase(t, testDB)

	passwordHash := "$argon2id$v=19$m=65536,t=3,p=2$GbP1xKkH/FbDk3bytDlq1Q$1jcT6iSqZ9N0I3LuX7w/pGjJgWVCTbTr9WhK7r91gV8"
	if _, err := testDB.Exec(`INSERT INTO oauth_users(id, username, password_hash) VALUES (1, 'cleanup-user', ?)`, passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_clients(client_id, client_name, token_endpoint_auth_method, grant_types, response_types, scope, created_at) VALUES ('cleanup-client', 'Cleanup', 'none', '["authorization_code","refresh_token"]', '["code"]', 'stamps:read offline_access', 1)`); err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("A", 43)
	if _, err := testDB.Exec(`INSERT INTO oauth_authorization_requests(request_hash, csrf_hash, client_id, redirect_uri, resource, scope, code_challenge, code_challenge_method, expires_at) VALUES (?, ?, 'cleanup-client', 'https://chatgpt.com/connector/oauth/cleanup', 'https://server.example/mcp', 'stamps:read', ?, 'S256', 1)`, strings.Repeat("a", 64), strings.Repeat("b", 64), challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_authorization_codes(code_hash, user_id, client_id, redirect_uri, resource, scope, code_challenge, code_challenge_method, expires_at) VALUES (?, 1, 'cleanup-client', 'https://chatgpt.com/connector/oauth/cleanup', 'https://server.example/mcp', 'stamps:read', ?, 'S256', 1)`, strings.Repeat("c", 64), challenge); err != nil {
		t.Fatal(err)
	}
	refreshFamilyResult, err := testDB.Exec(`INSERT INTO oauth_refresh_token_families(user_id, client_id, resource, scope, expires_at, revoked_at) VALUES (1, 'cleanup-client', 'https://server.example/mcp', 'stamps:read offline_access', 1, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	refreshFamilyID, err := refreshFamilyResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_refresh_tokens(token_hash, family_id, scope, expires_at, revoked_at) VALUES (?, ?, 'stamps:read offline_access', 1, 1)`, strings.Repeat("e", 64), refreshFamilyID); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO oauth_access_tokens(token_hash, user_id, client_id, resource, scope, expires_at, refresh_family_id) VALUES (?, 1, 'cleanup-client', 'https://server.example/mcp', 'stamps:read', 1, ?)`, strings.Repeat("d", 64), refreshFamilyID); err != nil {
		t.Fatal(err)
	}

	runtimeConfig := APIRuntimeConfig{
		Capabilities: []string{"sql"},
		SQLFiles: oauthTestSQLAssetPaths(t,
			"cleanup_authorization_requests.sql",
			"cleanup_authorization_codes.sql",
			"cleanup_access_tokens.sql",
			"cleanup_refresh_tokens.sql",
			"cleanup_refresh_token_families.sql",
			"cleanup_clients.sql",
		),
		Settings: map[string]interface{}{
			"retentionDays":       float64(7),
			"clientRetentionDays": float64(180),
		},
	}
	result, err := runScriptWithRuntimeWithSnapshot(
		newAPIConfigSnapshot(nil, "", [sha256.Size]byte{}),
		[]string{oauthTestAssetPath(t, "javascript", "oauth", "cleanup.js")},
		map[string]interface{}{},
		runtimeConfig,
		true,
	)
	if err != nil {
		t.Fatalf("OAuth cleanup: %v", err)
	}
	cleanupResult := decodeTestJSONObject(t, []byte(result))
	for _, key := range []string{"authorizationRequests", "authorizationCodes", "accessTokens", "refreshTokens", "refreshTokenFamilies", "clients"} {
		if cleanupResult[key] != float64(1) {
			t.Fatalf("cleanup result[%q] = %#v; result=%#v", key, cleanupResult[key], cleanupResult)
		}
	}
}

const (
	oauthIntegrationTestIssuer   = "https://server.example"
	oauthIntegrationTestResource = "https://server.example/mcp"
)

func newOAuthIntegrationTestSnapshot(t *testing.T, targetScript string) *APIConfigSnapshot {
	t.Helper()
	scopes := []interface{}{"stamps:read", "offline_access"}
	definitions := map[string]APIConfig{
		"oauth_protected_resource_metadata": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "protected_resource_metadata.js"),
			Runtime: APIRuntimeConfig{Settings: map[string]interface{}{
				"issuer":   oauthIntegrationTestIssuer,
				"resource": oauthIntegrationTestResource,
				"scopes":   scopes,
			}},
		},
		"oauth_authorization_server_metadata": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "authorization_server_metadata.js"),
			Runtime: APIRuntimeConfig{Settings: map[string]interface{}{
				"issuer":                oauthIntegrationTestIssuer,
				"authorizationEndpoint": oauthIntegrationTestIssuer + "/oauth/authorize",
				"tokenEndpoint":         oauthIntegrationTestIssuer + "/oauth/token",
				"registrationEndpoint":  oauthIntegrationTestIssuer + "/oauth/register",
				"revocationEndpoint":    oauthIntegrationTestIssuer + "/oauth/revoke",
				"scopes":                scopes,
			}},
		},
		"oauth_register": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "register.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "crypto"},
				SQLFiles: oauthTestSQLAssetPaths(t,
					"insert_client.sql",
					"insert_client_redirect_uri.sql",
				),
				Settings: map[string]interface{}{
					"scopes":                 scopes,
					"redirectURIAllowlist":   []interface{}{"https://chatgpt.com/connector/oauth/integration-callback"},
					"allowLoopbackRedirects": false,
					"maxClients":             float64(1),
				},
			},
		},
		"oauth_authorize": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "authorize.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "crypto", "password"},
				SQLFiles: oauthTestSQLAssetPaths(t,
					"select_client_redirect_uri.sql",
					"insert_authorization_request.sql",
					"select_authorization_request.sql",
					"consume_authorization_request.sql",
					"select_user_by_username.sql",
					"increment_authorization_attempt.sql",
					"upsert_consent.sql",
					"insert_authorization_code.sql",
				),
				Settings: map[string]interface{}{
					"resource":                oauthIntegrationTestResource,
					"authorizationEndpoint":   oauthIntegrationTestIssuer + "/oauth/authorize",
					"authorizationCookiePath": "/oauth/authorize",
					"scopes":                  scopes,
					"redirectURIAllowlist":    []interface{}{"https://chatgpt.com/connector/oauth/integration-callback"},
					"allowLoopbackRedirects":  false,
					"dummyPasswordHash":       "$argon2id$v=19$m=65536,t=3,p=2$GbP1xKkH/FbDk3bytDlq1Q$1jcT6iSqZ9N0I3LuX7w/pGjJgWVCTbTr9WhK7r91gV8",
				},
			},
		},
		"oauth_token": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "token.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "crypto"},
				SQLFiles: oauthTestSQLAssetPaths(t,
					"select_authorization_code.sql",
					"consume_authorization_code.sql",
					"insert_access_token.sql",
					"insert_refresh_token_family.sql",
					"insert_refresh_token.sql",
					"lock_refresh_token.sql",
					"select_refresh_token.sql",
					"consume_refresh_token.sql",
					"revoke_refresh_token_family.sql",
					"revoke_refresh_tokens_in_family.sql",
					"revoke_access_tokens_in_refresh_family.sql",
				),
				Settings: map[string]interface{}{
					"resource":                    oauthIntegrationTestResource,
					"accessTokenLifetimeSeconds":  float64(3600),
					"refreshTokenLifetimeSeconds": float64(2592000),
				},
			},
		},
		"oauth_revoke": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "revoke.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "crypto"},
				SQLFiles: oauthTestSQLAssetPaths(t,
					"revoke_access_token.sql",
					"select_refresh_token.sql",
					"revoke_refresh_token_family.sql",
					"revoke_refresh_tokens_in_family.sql",
					"revoke_access_tokens_in_refresh_family.sql",
				),
			},
		},
		"oauth_bootstrap_user": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "bootstrap_user.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "password"},
				SQLFiles:     oauthTestSQLAssetPaths(t, "upsert_user.sql"),
			},
		},
		"oauth_verify_access": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "verify_access.js"),
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "crypto"},
				SQLFiles:     oauthTestSQLAssetPaths(t, "select_access_token.sql"),
				Settings: map[string]interface{}{
					"resource":                  oauthIntegrationTestResource,
					"protectedResourceMetadata": oauthIntegrationTestIssuer + "/.well-known/oauth-protected-resource/mcp",
				},
			},
		},
		"oauth_e2e_target": {
			Script:      targetScript,
			Description: "OAuth integration target",
		},
	}
	readOnly := true
	destructive := false
	openWorld := false
	definitions["server_mcp_http"] = APIConfig{
		Type:             apiTypeMCP,
		Path:             "/mcp",
		Transport:        "streamable_http",
		ProtocolVersions: []string{mcpProtocolVersion20251125},
		Resource:         oauthIntegrationTestResource,
		Guard:            MCPGuardConfig{API: "oauth_verify_access"},
		Tools: []MCPToolConfig{{
			Name:        "oauth_e2e",
			API:         "oauth_e2e_target",
			Title:       "OAuth E2E",
			Description: "OAuth SQLite integration target",
			SecuritySchemes: []MCPSecurityScheme{{
				Type:   "oauth2",
				Scopes: []string{"stamps:read"},
			}},
			Annotations: MCPToolAnnotations{ReadOnlyHint: &readOnly, DestructiveHint: &destructive, OpenWorldHint: &openWorld},
		}},
	}
	return newAPIConfigSnapshot(definitions, "", [sha256.Size]byte{})
}

func oauthTestAssetPath(t *testing.T, elements ...string) string {
	t.Helper()
	pathValue, err := filepath.Abs(filepath.Join(elements...))
	if err != nil {
		t.Fatalf("resolve OAuth test asset %v: %v", elements, err)
	}
	if info, err := os.Stat(pathValue); err != nil || info.IsDir() {
		t.Fatalf("OAuth test asset %q is unavailable: info=%#v error=%v", pathValue, info, err)
	}
	return pathValue
}

func oauthTestSQLAssetPaths(t *testing.T, names ...string) []string {
	t.Helper()
	paths := make([]string, len(names))
	for index, name := range names {
		paths[index] = oauthTestAssetPath(t, "sql", "oauth", name)
	}
	return paths
}

func seedOAuthRefreshTokenTestRecord(t *testing.T, testDB *sql.DB, clientID, label string, expiresAt int64) (string, int64, int64) {
	t.Helper()
	result, err := testDB.Exec(`
		INSERT INTO oauth_refresh_token_families(user_id, client_id, resource, scope, expires_at)
		VALUES (1, ?, ?, 'stamps:read offline_access', ?)`, clientID, oauthIntegrationTestResource, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	familyID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	refreshToken := "nyan_rt_test_" + label + "_" + strings.Repeat("R", 48)
	result, err = testDB.Exec(`
		INSERT INTO oauth_refresh_tokens(token_hash, family_id, scope, expires_at)
		VALUES (?, ?, 'stamps:read offline_access', ?)`, sha256Hash(refreshToken), familyID, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	refreshTokenID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return refreshToken, familyID, refreshTokenID
}

func migrateOAuthTestDatabase(t *testing.T, testDB *sql.DB) {
	t.Helper()
	migrationPattern, err := filepath.Abs(filepath.Join("sql", "oauth", "[0-9][0-9][0-9]_*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	migrationPaths, err := filepath.Glob(migrationPattern)
	if err != nil || len(migrationPaths) == 0 {
		t.Fatalf("find OAuth migrations %q: paths=%v error=%v", migrationPattern, migrationPaths, err)
	}
	for _, migrationPath := range migrationPaths {
		migration, err := os.ReadFile(migrationPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testDB.Exec(string(migration)); err != nil {
			t.Fatalf("apply OAuth migration %s: %v", migrationPath, err)
		}
	}
	var latestVersion int
	if err := testDB.QueryRow(`SELECT MAX(version) FROM oauth_schema_migrations`).Scan(&latestVersion); err != nil || latestVersion != 3 {
		t.Fatalf("OAuth schema version = %d, want 3; error=%v", latestVersion, err)
	}
}

func performOAuthTestHTTPRequest(t *testing.T, method, target, contentType, body string, configure func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if configure != nil {
		configure(req)
	}
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	return rec
}

func performOAuthTestMCPRequest(t *testing.T, body, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion20251125)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	return rec
}

func extractTestHTMLInputValue(t *testing.T, document, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	start := strings.Index(document, marker)
	if start < 0 {
		t.Fatalf("HTML input %q not found in %q", name, document)
	}
	start += len(marker)
	end := strings.Index(document[start:], `"`)
	if end < 0 {
		t.Fatalf("HTML input %q has no closing quote in %q", name, document)
	}
	return document[start : start+end]
}

func performTestMCPRequest(t *testing.T, snapshot *APIConfigSnapshot, serverConfig APIConfig, body, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	return performTestMCPRequestWithProtocol(t, snapshot, serverConfig, body, authorization, mcpProtocolVersion20251125)
}

func performTestMCPRequestWithProtocol(t *testing.T, snapshot *APIConfigSnapshot, serverConfig APIConfig, body, authorization, protocolVersion string) *httptest.ResponseRecorder {
	t.Helper()
	if len(serverConfig.ProtocolVersions) == 0 {
		serverConfig.ProtocolVersions = []string{mcpProtocolVersion20251125}
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", protocolVersion)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handleMCPRequestWithSnapshot(snapshot, rec, req, "test_mcp", serverConfig)
	return rec
}

func decodeTestJSONObject(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode JSON object %q: %v", string(data), err)
	}
	return result
}

func resetJavascriptInclude(t *testing.T) {
	t.Helper()
	oldIncludes := config.JavascriptInclude
	config.JavascriptInclude = nil
	t.Cleanup(func() {
		config.JavascriptInclude = oldIncludes
	})
}

func writeTestScript(t *testing.T, content string) string {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), "check.js")
	if err := os.WriteFile(scriptPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return scriptPath
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newWebSocketRuntimeTestServer(t *testing.T) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	connected := make(chan struct{}, 4)
	disconnected := make(chan struct{}, 4)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connected <- struct{}{}
		defer func() {
			_ = conn.Close()
			disconnected <- struct{}{}
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http"), connected, disconnected
}

func waitForSignal(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func waitForCondition(t *testing.T, label string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", label)
}

func setTestSQLFiles(t *testing.T, files map[string]APIConfig) {
	t.Helper()
	oldFiles := currentSQLFiles()
	setSQLFiles(files)
	t.Cleanup(func() {
		setSQLFiles(oldFiles)
	})
}

func loadTestAPIConfig(t *testing.T, path string) *apiConfigLoadResult {
	t.Helper()
	result, err := loadAPIConfigFile(path)
	if err != nil {
		t.Fatalf("loadAPIConfigFile() error = %v", err)
	}
	return result
}

func setTestAPISnapshot(t *testing.T, snapshot *APIConfigSnapshot) {
	t.Helper()
	oldSnapshot := currentAPISnapshot()
	oldBackgroundRuntimes := backgroundRuntimes
	backgroundRuntimes = nil
	setAPISnapshot(snapshot)
	t.Cleanup(func() {
		setAPISnapshot(oldSnapshot)
		backgroundRuntimes = oldBackgroundRuntimes
	})
}

func setTestSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB := db
	oldDBType := dbType
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	testDB.SetMaxOpenConns(1)
	if err := testDB.Ping(); err != nil {
		_ = testDB.Close()
		t.Fatal(err)
	}
	db = testDB
	dbType = "sqlite3"
	t.Cleanup(func() {
		_ = testDB.Close()
		db = oldDB
		dbType = oldDBType
	})
	return testDB
}

func TestParamCheckRejectionPreservesResultAndError(t *testing.T) {
	for _, route := range []string{"http", "root", "jsonrpc", "nyanCallMe", "websocket", "mcp_http", "mcp_stdio"} {
		for _, checkOnly := range []bool{false, true} {
			for _, test := range []struct {
				name, response, want string
				status               int
				jsonString           bool
			}{
				{"both", `{"success":false,"status":403,"result":{"contactAdmin":true},"error":{"code":"DISABLED","message":"disabled"}}`, `{"success":false,"status":403,"result":{"contactAdmin":true},"error":{"code":"DISABLED","message":"disabled"}}`, 403, false},
				{"result_only", `{"success":false,"status":403,"result":["id","name"]}`, `{"success":false,"status":403,"result":["id","name"],"error":"Request check failed"}`, 403, true},
				{"error_only", `{"success":false,"status":403,"error":"denied"}`, `{"success":false,"status":403,"error":"denied"}`, 403, false},
				{"null", `{"success":false,"status":403,"result":null,"error":null}`, `{"success":false,"status":403,"result":null,"error":"Request check failed"}`, 403, false},
				{"false_and_empty", `{"success":false,"status":403,"result":false,"error":""}`, `{"success":false,"status":403,"result":false,"error":""}`, 403, true},
				{"returned_500", `{"success":false,"status":500,"result":{"retryable":true},"error":{"message":"unavailable"}}`, `{"success":false,"status":500,"result":{"retryable":true},"error":{"message":"unavailable"}}`, 500, false},
			} {
				t.Run(fmt.Sprintf("%s/checkOnly=%t/%s", route, checkOnly, test.name), func(t *testing.T) {
					resetJavascriptInclude(t)
					setTestSQLiteDB(t)
					oldHub := hub
					hub = NewHub()
					t.Cleanup(func() { hub = oldHub })
					dir := t.TempDir()
					mark := func(stage string) string {
						return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"),%q);`, filepath.Join(dir, stage))
					}
					check := "(" + test.response + ");"
					if test.jsonString {
						check = fmt.Sprintf("%q;", test.response)
					}
					setTestSQLFiles(t, map[string]APIConfig{
						"target": {ParamCheck: writeTestScript(t, mark("param")+check), Script: writeTestScript(t, mark("body")+`({success:true});`), OutCheck: writeTestScript(t, mark("out")+`({success:true,status:200});`), Push: "events"},
						"events": {Script: writeTestScript(t, mark("push")+`({success:true});`)},
					})
					params := map[string]interface{}{"api": "target"}
					if checkOnly {
						params["nyan_mode"] = "checkOnly"
					}
					args, _ := json.Marshal(params)
					var response map[string]interface{}
					switch route {
					case "http", "root", "jsonrpc":
						path := "/target"
						if route == "root" {
							path = "/"
						}
						body := args
						if route == "jsonrpc" {
							path = "/nyan-rpc"
							body, _ = json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "target", "params": params})
						}
						r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
						r.Header.Set("Content-Type", "application/json")
						r.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
						w := httptest.NewRecorder()
						if route == "jsonrpc" {
							handleJSONRPC(w, r)
						} else {
							unifiedHandler(w, r)
						}
						response = decodeTestJSONObject(t, w.Body.Bytes())
						wantStatus := test.status
						if route == "jsonrpc" {
							wantStatus = 400
							failure := response["error"].(map[string]interface{})
							data := failure["data"].(map[string]interface{})
							if failure["code"] != float64(-32602) || data["message"] != "Request check failed" {
								t.Fatalf("RPC contract changed: %#v", response)
							}
							original := decodeTestJSONObject(t, []byte(test.response))
							if !reflect.DeepEqual(data["detail"], original["error"]) {
								t.Fatalf("RPC detail changed: %#v", data)
							}
							response = data["checkResult"].(map[string]interface{})
						}
						if w.Code != wantStatus {
							t.Fatalf("HTTP %d want %d: %s", w.Code, wantStatus, w.Body.String())
						}
					case "nyanCallMe":
						vm := goja.New()
						registerNyanFuncs(vm, currentAPISnapshot(), nil, nil)
						value, err := vm.RunString("JSON.stringify(nyanCallMe(" + string(args) + "));")
						if err != nil {
							t.Fatalf("valid rejection became an exception: %v", err)
						}
						response = decodeTestJSONObject(t, []byte(value.String()))
					case "websocket":
						r := httptest.NewRequest(http.MethodGet, "/channel", nil)
						r.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
						response = decodeTestJSONObject(t, executeWebSocketAPIMessage(r, args))
					case "mcp_http", "mcp_stdio":
						server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", Tools: []MCPToolConfig{{API: "target"}}}
						message, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]interface{}{"name": "target", "arguments": params}})
						if route == "mcp_http" {
							w := performTestMCPRequest(t, currentAPISnapshot(), server, string(message), "")
							response = decodeTestJSONObject(t, w.Body.Bytes())
						} else {
							server.Transport = "stdio"
							state := mcpStdioReady
							response, _ = handleMCPStdioMessage(currentAPISnapshot(), "test_mcp", server, &state, message)
						}
						tool := response["result"].(map[string]interface{})
						if tool["isError"] != true {
							t.Fatalf("MCP rejection not marked as error: %#v", tool)
						}
						response = tool["structuredContent"].(map[string]interface{})
					}
					if want := decodeTestJSONObject(t, []byte(test.want)); !reflect.DeepEqual(response, want) {
						t.Fatalf("response=%#v want %#v", response, want)
					}
					for stage, want := range map[string]bool{"param": true, "body": false, "out": false, "push": false} {
						_, err := os.Stat(filepath.Join(dir, stage))
						if err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						if (err == nil) != want {
							t.Fatalf("stage %s executed=%t want %t", stage, err == nil, want)
						}
					}
				})
			}
		}
	}
}

func TestParamCheckExceptionRemainsException(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLFiles(t, map[string]APIConfig{"target": {ParamCheck: writeTestScript(t, `throw new Error("check exploded");`)}})
	vm := goja.New()
	registerNyanFuncs(vm, currentAPISnapshot(), nil, nil)
	v, err := vm.RunString(`let caught=false;try{nyanCallMe({api:"target"});}catch(e){caught=String(e).includes("check exploded");}caught;`)
	if err != nil || !v.ToBoolean() {
		t.Fatalf("check exception not caught: %v %v", v, err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/target", nil)
	handleRequest(w, r)
	response := decodeTestJSONObject(t, w.Body.Bytes())
	if w.Code != 500 || response["success"] != false || response["error"] == nil {
		t.Fatalf("exception response: %d %s", w.Code, w.Body.String())
	}
	if _, exists := response["result"]; exists {
		t.Fatal("execution exception acquired a result")
	}
}

func TestCheckOnlyRunsOnlyParamCheck(t *testing.T) {
	oldHub := hub
	hub = NewHub()
	t.Cleanup(func() { hub = oldHub })
	for _, route := range []string{"http", "jsonrpc", "nyanCallMe", "websocket", "mcp_http", "mcp_stdio"} {
		for _, checkField := range []string{"paramCheck", "check", "missing"} {
			for _, bodyType := range []string{"script", "sql"} {
				t.Run(route+"/"+checkField+"/"+bodyType, func(t *testing.T) {
					resetJavascriptInclude(t)
					testDB := setTestSQLiteDB(t)
					if _, err := testDB.Exec(`CREATE TABLE executed (value INTEGER);`); err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					marker := func(stage string) string {
						return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("executed"), %q);`, filepath.Join(dir, stage))
					}
					const allow = `({success:true,status:200,result:{checked:true}});`
					target := APIConfig{
						OutCheck: writeTestScript(t, marker("out")+allow),
						Push:     "events",
					}
					switch checkField {
					case "paramCheck":
						target.ParamCheck = writeTestScript(t, marker("param")+allow)
					case "check":
						target.Check = writeTestScript(t, marker("param")+allow)
					}
					if bodyType == "script" {
						target.Script = writeTestScript(t, marker("body")+`({success:true,status:200});`)
					} else {
						target.SQL = []string{filepath.Join(dir, "run.sql")}
						writeTestFile(t, target.SQL[0], `INSERT INTO executed (value) VALUES (1) RETURNING value;`)
					}
					setTestSQLFiles(t, map[string]APIConfig{
						"target": target,
						"events": {
							ParamCheck: writeTestScript(t, marker("push_param")+allow),
							Script:     writeTestScript(t, marker("push_body")+allow),
							OutCheck:   writeTestScript(t, marker("push_out")+allow),
						},
					})
					var response map[string]interface{}
					var callErr error
					switch route {
					case "http", "jsonrpc":
						request := httptest.NewRequest(http.MethodGet, "/target?nyan_mode=checkOnly", nil)
						if route == "jsonrpc" {
							request = httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","method":"target","params":{"nyan_mode":"checkOnly"},"id":1}`))
							request.Header.Set("Content-Type", "application/json")
						}
						request.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
						recorder := httptest.NewRecorder()
						if route == "jsonrpc" {
							handleJSONRPC(recorder, request)
						} else {
							unifiedHandler(recorder, request)
						}
						response = decodeTestJSONObject(t, recorder.Body.Bytes())
						if route == "jsonrpc" && response["error"] == nil {
							response = response["result"].(map[string]interface{})
						}
					case "nyanCallMe":
						vm := goja.New()
						registerNyanFuncs(vm, currentAPISnapshot(), map[string]interface{}{}, nil)
						value, err := vm.RunString(`JSON.stringify(nyanCallMe({api:"target",nyan_mode:"checkOnly"}));`)
						callErr = err
						if err == nil {
							response = decodeTestJSONObject(t, []byte(value.String()))
						}
					case "websocket":
						request := httptest.NewRequest(http.MethodGet, "/events", nil)
						request.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
						response = decodeTestJSONObject(t, executeWebSocketAPIMessage(request, []byte(`{"api":"target","nyan_mode":"checkOnly"}`)))
					case "mcp_http", "mcp_stdio":
						server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{API: "target"}}}
						message := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"target","arguments":{"nyan_mode":"checkOnly"}}}`
						if route == "mcp_stdio" {
							server.Transport = "stdio"
							state := mcpStdioReady
							response, _ = handleMCPStdioMessage(currentAPISnapshot(), "test_mcp", server, &state, []byte(message))
						} else {
							rec := performTestMCPRequest(t, currentAPISnapshot(), server, message, "")
							response = decodeTestJSONObject(t, rec.Body.Bytes())
						}
						result := response["result"].(map[string]interface{})
						if result["isError"] == true {
							callErr = fmt.Errorf("MCP Tool error: %v", result)
						} else {
							response = result["structuredContent"].(map[string]interface{})
						}
					}
					if checkField == "missing" {
						if callErr == nil && response["error"] == nil && response["success"] != false {
							t.Errorf("missing paramCheck did not return an error: %#v", response)
						}
					} else if callErr != nil || !reflect.DeepEqual(response, decodeTestJSONObject(t, []byte(`{"success":true,"status":200,"result":{"checked":true}}`))) {
						t.Errorf("checkOnly did not return the paramCheck result: response=%#v, err=%v", response, callErr)
					}
					for _, stage := range []string{"param", "body", "out", "push_param", "push_body", "push_out"} {
						_, err := os.Stat(filepath.Join(dir, stage))
						if err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						want := stage == "param" && checkField != "missing"
						if (err == nil) != want {
							t.Errorf("%s executed=%v, want %v", stage, err == nil, want)
						}
					}
					var count int
					if err := testDB.QueryRow(`SELECT COUNT(*) FROM executed;`).Scan(&count); err != nil || count != 0 {
						t.Errorf("SQL body executed: row count=%d, err=%v", count, err)
					}
				})
			}
		}
	}
}

// A real WebSocket over net.Pipe makes backpressure deterministic: writes
// cannot finish until the peer reads, regardless of OS socket buffer sizes.
type hubTestConn struct {
	net.Conn
	writes chan struct{}
}

func (c *hubTestConn) Write(data []byte) (int, error) {
	select {
	case c.writes <- struct{}{}:
	default:
	}
	return c.Conn.Write(data)
}

type hubTestResponseWriter struct {
	*httptest.ResponseRecorder
	conn   net.Conn
	reader *bufio.Reader
}

func (w *hubTestResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn)), nil
}

func newHubTestPair(t *testing.T) (*websocket.Conn, *websocket.Conn, <-chan struct{}) {
	t.Helper()
	local, remote := net.Pipe()
	observed := &hubTestConn{Conn: local, writes: make(chan struct{}, 1)}
	t.Cleanup(func() { local.Close(); remote.Close() })
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
	type accepted struct {
		conn *websocket.Conn
		err  error
	}
	peerReady := make(chan accepted, 1)
	go func() {
		reader := bufio.NewReader(observed)
		request, err := http.ReadRequest(reader)
		if err != nil {
			peerReady <- accepted{err: err}
			return
		}
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(&hubTestResponseWriter{httptest.NewRecorder(), observed, reader}, request, nil)
		peerReady <- accepted{conn, err}
	}()
	address, _ := url.Parse("ws://hub.test/events")
	connection, _, err := websocket.NewClient(remote, address, nil, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peerReady
	if peer.err != nil {
		t.Fatal(peer.err)
	}
	_ = local.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	<-observed.writes // discard the opening handshake notification
	return peer.conn, connection, observed.writes
}

func assertHubDelivery(t *testing.T, send func(), peers []*websocket.Conn, want string) {
	t.Helper()
	type frame struct {
		kind int
		data []byte
		err  error
	}
	frames := make(chan frame, len(peers))
	for _, peer := range peers {
		go func(conn *websocket.Conn) {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			kind, data, err := conn.ReadMessage()
			frames <- frame{kind, data, err}
		}(peer)
	}
	done := make(chan struct{})
	go func() { defer close(done); send() }()
	for range peers {
		got := <-frames
		if got.err != nil || got.kind != websocket.TextMessage || string(got.data) != want {
			t.Fatalf("frame=%q type=%d err=%v, want %q", got.data, got.kind, got.err, want)
		}
	}
	waitForSignal(t, done, "Hub delivery completion")
}

func TestHubFailedConnectionRemovalAndReconnect(t *testing.T) {
	h := NewHub()
	old, _, _ := newHubTestPair(t)
	a, pa, _ := newHubTestPair(t)
	c, pc, _ := newHubTestPair(t)
	replacement, pr, _ := newHubTestPair(t)
	for _, conn := range []*websocket.Conn{old, a, c, replacement} {
		h.AddClient("events", conn)
	}
	h.AddClient("other", old)
	_ = old.Close()
	assertHubDelivery(t, func() { h.Broadcast("events", []byte("first")) }, []*websocket.Conn{pa, pc, pr}, "first")
	h.mu.Lock()
	_, oldPresent := h.connections[old]
	_, otherPresent := h.clients["other"]
	remaining := len(h.clients["events"])
	h.mu.Unlock()
	if oldPresent || otherPresent || remaining != 3 {
		t.Fatalf("failed connection retained: old=%v other=%v remaining=%d", oldPresent, otherPresent, remaining)
	}
	// The old read loop may finish after the replacement has been registered.
	h.RemoveClient("events", old)
	h.RemoveClient("events", a)
	assertHubDelivery(t, func() { h.Broadcast("events", []byte("second")) }, []*websocket.Conn{pc, pr}, "second")
	h.RemoveClient("events", c)
	assertHubDelivery(t, func() { h.Broadcast("events", []byte("third")) }, []*websocket.Conn{pr}, "third")
	h.RemoveClient("events", replacement)
	h.RemoveClient("events", replacement)
	if len(h.clients) != 0 || len(h.connections) != 0 {
		t.Fatal("last subscriber was not removed")
	}
	if err := h.Send(replacement, []byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late reply error=%v", err)
	}
}

func TestHubBlockedWriteDoesNotHoldRegistryLock(t *testing.T) {
	h := NewHub()
	slow, _, writes := newHubTestPair(t)
	fast, peer, _ := newHubTestPair(t)
	newcomer, _, _ := newHubTestPair(t)
	h.AddClient("slow", slow)
	h.AddClient("fast", fast)
	done := make(chan struct{})
	go func() { defer close(done); h.Broadcast("slow", []byte("blocked")) }()
	waitForSignal(t, writes, "blocked write started")
	changed := make(chan struct{})
	go func() { defer close(changed); h.AddClient("new", newcomer); h.RemoveClient("new", newcomer) }()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("registration waited for an unrelated write")
	}
	assertHubDelivery(t, func() { h.Broadcast("fast", []byte("push")) }, []*websocket.Conn{peer}, "push")
	assertHubDelivery(t, func() {
		if err := h.Send(fast, []byte("reply")); err != nil {
			t.Error(err)
		}
	}, []*websocket.Conn{peer}, "reply")
	// Unregistering must also interrupt the pending write without waiting for
	// its per-connection write lock or for the five-second deadline.
	removed := make(chan struct{})
	go func() { defer close(removed); h.RemoveClient("slow", slow) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("removal waited for the blocked write")
	}
	waitForSignal(t, done, "blocked write interrupted")
}

func TestHubWriteTimeoutRemovesOnlyFailedConnection(t *testing.T) {
	for _, mode := range []string{"reply", "push"} {
		t.Run(mode, func(t *testing.T) {
			h := NewHub()
			h.writeTimeout = 50 * time.Millisecond
			slow, slowPeer, _ := newHubTestPair(t)
			fast, fastPeer, _ := newHubTestPair(t)
			h.AddClient("events", slow)
			h.AddClient("events", fast)
			if mode == "reply" {
				err := h.Send(slow, []byte("blocked"))
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("write did not time out: %v", err)
				}
			} else {
				assertHubDelivery(t, func() { h.Broadcast("events", []byte("broadcast")) }, []*websocket.Conn{fastPeer}, "broadcast")
			}
			if len(h.connections) != 1 || len(h.clients["events"]) != 1 || h.connections[slow] != nil {
				t.Fatal("timeout removed healthy peer or retained failed peer")
			}
			_ = slowPeer.SetReadDeadline(time.Now().Add(time.Second))
			_, _, readErr := slowPeer.ReadMessage()
			var timeout net.Error
			if readErr == nil || (errors.As(readErr, &timeout) && timeout.Timeout()) {
				t.Fatalf("timed-out connection was not closed: %v", readErr)
			}
			assertHubDelivery(t, func() { h.Broadcast("events", []byte("next")) }, []*websocket.Conn{fastPeer}, "next")
		})
	}
}

func TestHubConcurrentRepliesPushAndSubscriptions(t *testing.T) {
	h := NewHub()
	conn, peer, _ := newHubTestPair(t)
	h.AddClient("a", conn)
	h.AddClient("b", conn)
	const count = 20
	var workers sync.WaitGroup
	errorsFound := make(chan error, count)
	for _, kind := range []string{"reply", "a", "b"} {
		workers.Add(1)
		go func(kind string) {
			defer workers.Done()
			for i := 0; i < count; i++ {
				if kind == "reply" {
					if err := h.Send(conn, []byte(kind)); err != nil {
						errorsFound <- err
					}
				} else {
					h.Broadcast(kind, []byte(kind))
				}
			}
		}(kind)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < count; i++ {
			h.AddClient("temporary", conn)
			h.RemoveClient("temporary", conn)
		}
	}()
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	counts := map[string]int{}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 3*count; i++ {
		kind, data, err := peer.ReadMessage()
		if err != nil || kind != websocket.TextMessage {
			t.Fatalf("concurrent write failed: type=%d err=%v", kind, err)
		}
		counts[string(data)]++
	}
	waitForSignal(t, done, "concurrent Hub operations")
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	for _, kind := range []string{"reply", "a", "b"} {
		if counts[kind] != count {
			t.Fatalf("lost or duplicated frames: %v", counts)
		}
	}
	if len(h.connections) != 1 || len(h.clients) != 2 {
		t.Fatalf("subscription changes damaged the registry: %v", h.clients)
	}
	assertHubDelivery(t, func() { h.Broadcast("a", []byte("complete")) }, []*websocket.Conn{peer}, "complete")
}

func TestPushSourceResultAcrossTransports(t *testing.T) {
	for _, route := range []string{"http", "root", "jsonrpc", "websocket", "nyanCallMe", "mcp_http", "mcp_stdio"} {
		for _, test := range []struct {
			name, body string
			status     int
			push       bool
		}{
			{"ok", `{"success":true,"status":200}`, 200, true},
			{"created", `{"status":201}`, 201, true},
			{"redirect", `{"status":302}`, 302, true},
			{"upper_success", `{"status":399}`, 399, true},
			{"bad_request", `{"status":400}`, 400, false},
			{"conflict", `{"success":false,"status":409}`, 409, false},
			{"server_error", `{"status":500}`, 500, false},
			{"unavailable", `{"success":true,"status":503}`, 503, false},
			{"false_with_ok", `{"success":false,"status":200}`, 200, false},
			{"false_without_status", `{"success":false}`, 200, false},
			{"missing_fields", `{"items":[1,2]}`, 200, true},
			{"nested_failure", `{"result":{"success":false,"status":503}}`, 200, true},
			{"string_false", `{"success":"false"}`, 200, true},
			{"plain_text", `plain text`, 200, true},
		} {
			if test.name == "plain_text" && (route == "jsonrpc" || strings.HasPrefix(route, "mcp_")) {
				continue
			}
			t.Run(route+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				dir := t.TempDir()
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode((nyanGetFile(%q)||"")+"x"),%q);`, filepath.Join(dir, stage), filepath.Join(dir, stage))
				}
				const allow = `({success:true,status:200});`
				// An error notification from the Push target is intentional: only
				// the originating API result controls whether to start the Push.
				const outputAllow = `({success:true,status:201,result:"check result must not replace body"});`
				const pushed = `{"success":false,"status":503,"result":"notification"}`
				setTestSQLFiles(t, map[string]APIConfig{
					"origin": {ParamCheck: writeTestScript(t, mark("input")+allow), Script: writeTestScript(t, mark("body")+fmt.Sprintf(`%q;`, test.body)), OutCheck: writeTestScript(t, mark("output")+fmt.Sprintf(`if(nyanAllParams.nyan_output.body!==%q || nyanAllParams.nyan_output.status!==%d || nyanAllParams.nyan_output_status!==%d) throw new Error("source result changed");`, test.body, test.status, test.status)+outputAllow), Push: "events"},
					"events": {ParamCheck: writeTestScript(t, mark("push_input")+allow), Script: writeTestScript(t, mark("push_body")+fmt.Sprintf(`%q;`, pushed)), OutCheck: writeTestScript(t, mark("push_output")+`if(nyanAllParams.nyan_output.status!==503 || nyanAllParams.nyan_output_status!==503) throw new Error("wrong Push output status");`+outputAllow)},
				})
				conn, testHub := newPushCheckSubscriber(t, "events")
				var body string
				switch route {
				case "http", "root", "jsonrpc":
					path := "/origin"
					if route == "root" {
						path = "/?api=origin"
					}
					req := httptest.NewRequest(http.MethodGet, path, nil)
					if route == "jsonrpc" {
						req = httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"origin","params":{}}`))
					}
					rec := httptest.NewRecorder()
					if route == "jsonrpc" {
						handleJSONRPC(rec, req)
					} else {
						handleRequest(rec, req)
					}
					body = rec.Body.String()
					if route == "jsonrpc" {
						want := decodeTestJSONObject(t, []byte(test.body))
						delete(want, "status")
						if rec.Code != http.StatusCreated || !reflect.DeepEqual(decodeTestJSONObject(t, []byte(body))["result"], want) {
							t.Fatalf("RPC response changed: status=%d body=%s", rec.Code, body)
						}
					} else if rec.Code != http.StatusCreated || body != test.body {
						t.Fatalf("HTTP response changed: status=%d body=%s", rec.Code, body)
					}
				case "websocket":
					req := httptest.NewRequest(http.MethodGet, "/events", nil)
					req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
					body = string(executeWebSocketAPIMessage(req, []byte(`{"api":"origin"}`)))
					if body != test.body {
						t.Fatalf("WebSocket response changed: %s", body)
					}
				case "nyanCallMe":
					vm := goja.New()
					registerNyanFuncs(vm, currentAPISnapshot(), map[string]interface{}{}, nil)
					value, err := vm.RunString(`const result=nyanCallMe({api:"origin"}); typeof result === "string" ? result : JSON.stringify(result);`)
					if err != nil {
						t.Fatal(err)
					}
					body = value.String()
					if test.name == "plain_text" {
						if body != test.body {
							t.Fatalf("internal response changed: %s", body)
						}
					} else if !reflect.DeepEqual(decodeTestJSONObject(t, []byte(body)), decodeTestJSONObject(t, []byte(test.body))) {
						t.Fatalf("internal response changed: %s", body)
					}
				case "mcp_http", "mcp_stdio":
					server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{API: "origin"}}}
					message := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"origin","arguments":{}}}`
					var response map[string]interface{}
					if route == "mcp_stdio" {
						server.Transport = "stdio"
						state := mcpStdioReady
						response, _ = handleMCPStdioMessage(currentAPISnapshot(), "mcp", server, &state, []byte(message))
					} else {
						rec := performTestMCPRequest(t, currentAPISnapshot(), server, message, "")
						response = decodeTestJSONObject(t, rec.Body.Bytes())
					}
					result := response["result"].(map[string]interface{})
					if !reflect.DeepEqual(result["structuredContent"], decodeTestJSONObject(t, []byte(test.body))) {
						t.Fatalf("MCP response changed: %v", result)
					}
					wantError := decodeTestJSONObject(t, []byte(test.body))["success"] == false
					if (result["isError"] == true) != wantError {
						t.Fatalf("MCP error flag does not match original result: %v", result)
					}
				}
				for _, stage := range []string{"input", "body", "output", "push_input", "push_body", "push_output"} {
					data, err := os.ReadFile(filepath.Join(dir, stage))
					want := !strings.HasPrefix(stage, "push_") || test.push
					if want {
						if err != nil || string(data) != "x" {
							t.Errorf("%s must run once: %q %v", stage, data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Errorf("%s ran on failed source: %q %v", stage, data, err)
					}
				}
				// Broadcast is synchronous. A sentinel proves there was no unwanted
				// or duplicate frame, without relying on a short receive timeout.
				testHub.Broadcast("events", []byte("complete"))
				if test.push {
					assertPushCheckFrame(t, conn, pushed)
				}
				assertPushCheckFrame(t, conn, "complete")
			})
		}
	}
}

func TestSuccessfulOutCheckSetsFinalStatus(t *testing.T) {
	for _, kind := range []string{"script", "sql"} {
		for _, route := range []string{"http", "root", "jsonrpc", "internal"} {
			for _, status := range []int{201, 503} {
				t.Run(fmt.Sprintf("%s/%s/%d", kind, route, status), func(t *testing.T) {
					resetJavascriptInclude(t)
					setTestSQLiteDB(t)
					dir := t.TempDir()
					marker := filepath.Join(dir, "push")
					target := APIConfig{OutCheck: writeTestScript(t, fmt.Sprintf(`
if(nyanAllParams.nyan_output.status!==200) throw new Error("wrong body status");
({success:true,status:%d,result:"must not replace body"});`, status)), Push: "events"}
					if kind == "script" {
						target.Script = writeTestScript(t, `({success:true,status:200,result:[{value:7}]});`)
					} else {
						path := filepath.Join(dir, "select.sql")
						writeTestFile(t, path, "SELECT 7 AS value;")
						target.SQL = []string{path}
					}
					setTestSQLFiles(t, map[string]APIConfig{
						"target": target,
						"events": {Script: writeTestScript(t, fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"),%q); ({status:200});`, marker))},
					})
					var body map[string]interface{}
					if route == "internal" {
						result, err := executeAPIWithSnapshot(currentAPISnapshot(), "target", nil)
						if err != nil || result.CheckRejected || result.Status != status {
							t.Fatalf("execution=%+v err=%v", result, err)
						}
						value, err := callNyanAPIFromVMWithSnapshot(currentAPISnapshot(), "target", nil)
						if err != nil {
							t.Fatal(err)
						}
						body = decodeTestJSONObject(t, []byte(value))
					} else {
						path := "/target"
						if route == "root" {
							path = "/?api=target"
						}
						r := httptest.NewRequest(http.MethodGet, path, nil)
						w := httptest.NewRecorder()
						if route == "jsonrpc" {
							r = httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"target","params":{}}`))
							handleJSONRPC(w, r)
						} else {
							handleRequest(w, r)
						}
						if w.Code != status {
							t.Fatalf("HTTP %d, want %d: %s", w.Code, status, w.Body.String())
						}
						body = decodeTestJSONObject(t, w.Body.Bytes())
						if route == "jsonrpc" {
							body = body["result"].(map[string]interface{})
						}
					}
					if body["success"] != true || !reflect.DeepEqual(body["result"], []interface{}{map[string]interface{}{"value": float64(7)}}) || (route != "jsonrpc" && body["status"] != float64(200)) {
						t.Fatalf("original body changed: %#v", body)
					}
					data, err := os.ReadFile(marker)
					if status == 201 {
						if err != nil || string(data) != "ran" {
							t.Fatalf("Push did not run: %q %v", data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("Push ran despite final HTTP 503: %q %v", data, err)
					}
				})
			}
		}
	}
}

func TestAPIResponseStatusLargeNumbers(t *testing.T) {
	if _, err := apiResponseStatus([]byte(`{"status":1e400}`)); err == nil {
		t.Fatal("overflowing status was accepted")
	}
	if status, err := apiResponseStatus([]byte(`{"status":503,"result":1e400}`)); err != nil || status != 503 {
		t.Fatalf("unrelated large number changed status: status=%d err=%v", status, err)
	}
}

func TestAPIResponseStatusAndOutputChecks(t *testing.T) {
	for _, route := range []string{"http", "root", "internal", "jsonrpc"} {
		for _, test := range []struct {
			name, body, out string
			status          int
			invalid, push   bool
		}{
			{name: "created_without_check", body: `{"status":201}`, status: 201, push: true},
			{name: "failure_without_check", body: `{"success":false,"status":503}`, status: 503},
			{name: "missing_status", body: `{"value":7}`, status: 200, push: true},
			{name: "array", body: `[{"status":503}]`, status: 200, push: true},
			{name: "output_rejected", body: `{"status":201}`, out: `({success:false,status:409,result:"denied"});`, status: 409},
			{name: "output_exception", body: `{"status":201}`, out: `throw new Error("output check failed");`, status: 500},
			{name: "informational", body: `{"status":199}`, status: 500, invalid: true},
			{name: "negative", body: `{"status":-1}`, status: 500, invalid: true},
			{name: "out_of_range", body: `{"status":600}`, status: 500, invalid: true},
			{name: "fractional", body: `{"status":201.5}`, status: 500, invalid: true},
			{name: "string", body: `{"status":"503"}`, status: 500, invalid: true},
			{name: "null", body: `{"status":null}`, status: 500, invalid: true},
			{name: "boolean", body: `{"status":true}`, status: 500, invalid: true},
			{name: "huge_number", body: `{"status":1e100}`, status: 500, invalid: true},
		} {
			if route == "jsonrpc" && test.name == "array" {
				continue // JSON-RPC requires an object result independently of status.
			}
			t.Run(route+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				setTestSQLiteDB(t)
				dir := t.TempDir()
				mark := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"),%q);`, filepath.Join(dir, stage))
				}
				target := APIConfig{Script: writeTestScript(t, fmt.Sprintf(`%q;`, test.body)), Push: "events"}
				if test.out != "" || test.invalid {
					target.OutCheck = writeTestScript(t, mark("out")+`
if (nyanAllParams.nyan_output.status !== 201 || nyanAllParams.nyan_output_status !== 201) throw new Error("wrong output status");
`+test.out)
				}
				setTestSQLFiles(t, map[string]APIConfig{
					"target": target,
					"events": {Script: writeTestScript(t, mark("push")+`({status:200});`)},
				})
				if route == "internal" {
					body, err := callNyanAPIFromVMWithSnapshot(currentAPISnapshot(), "target", nil)
					if test.invalid || test.name == "output_exception" {
						if err == nil {
							t.Fatalf("expected execution error, body=%s", body)
						}
					} else if err != nil {
						t.Fatal(err)
					} else if test.out == "" && body != test.body {
						t.Fatalf("body changed: %s", body)
					} else if test.out != "" && decodeTestJSONObject(t, []byte(body))["status"] != float64(test.status) {
						t.Fatalf("wrong output rejection: %s", body)
					}
				} else {
					path := "/target"
					if route == "root" {
						path = "/?api=target"
					}
					req := httptest.NewRequest(http.MethodGet, path, nil)
					rec := httptest.NewRecorder()
					if route == "jsonrpc" {
						req = httptest.NewRequest(http.MethodPost, "/nyan-rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"target","params":{}}`))
						handleJSONRPC(rec, req)
					} else {
						handleRequest(rec, req)
					}
					if rec.Code != test.status {
						t.Fatalf("status=%d, want %d: %s", rec.Code, test.status, rec.Body.String())
					}
					if route != "jsonrpc" && !test.invalid && test.out == "" && rec.Body.String() != test.body {
						t.Fatalf("body changed: %s", rec.Body.String())
					}
					if test.invalid && !strings.Contains(rec.Body.String(), "API response status") {
						t.Fatalf("missing status validation error: %s", rec.Body.String())
					}
				}
				for stage, want := range map[string]bool{"out": test.out != "", "push": test.push} {
					data, err := os.ReadFile(filepath.Join(dir, stage))
					if want {
						if err != nil || string(data) != "ran" {
							t.Fatalf("%s did not run: %q %v", stage, data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("unexpected %s execution: %q %v", stage, data, err)
					}
				}
			})
		}
	}
}

func TestInternalPushSourceAndParentAreIndependent(t *testing.T) {
	for _, test := range []struct {
		name, child, parent string
		want                string
	}{
		{"both_success", `({success:true,status:200});`, `({success:true,status:200});`, "child,after,parent,"},
		{"child_failed", `({success:false,status:200});`, `({success:true,status:200});`, "after,parent,"},
		{"child_unavailable", `({success:true,status:503});`, `({success:true,status:200});`, "after,parent,"},
		{"parent_failed", `({success:true,status:200});`, `({success:false,status:200});`, "child,after,"},
		{"parent_exception", `({success:true,status:200});`, `throw new Error("parent failed");`, "child,after,"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t).SetMaxOpenConns(8)
			trace := filepath.Join(t.TempDir(), "trace")
			mark := func(stage string) string {
				return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode((nyanGetFile(%q)||"")+%q),%q);`, trace, stage+",", trace)
			}
			setTestSQLFiles(t, map[string]APIConfig{
				"parent":       {Script: writeTestScript(t, `nyanCallMe({api:"child"});`+mark("after")+test.parent), Push: "parent_event"},
				"child":        {Script: writeTestScript(t, test.child), Push: "child_event"},
				"child_event":  {Script: writeTestScript(t, mark("child")+`({ok:true});`)},
				"parent_event": {Script: writeTestScript(t, mark("parent")+`({ok:true});`)},
			})
			rec := httptest.NewRecorder()
			handleRequest(rec, httptest.NewRequest(http.MethodGet, "/parent", nil))
			data, err := os.ReadFile(trace)
			if err != nil || string(data) != test.want {
				t.Fatalf("trace=%q want=%q err=%v", data, test.want, err)
			}
			if (rec.Code == http.StatusInternalServerError) != (test.name == "parent_exception") {
				t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPushChecksPreserveOriginResponse(t *testing.T) {
	const originBody = `{"success":true,"status":200,"result":{"message":"origin"}}`
	const pushedBody = `{"success":true,"status":200,"result":[{"value":7}]}`
	const allow = `({success:true,status:200});`
	for _, test := range []struct {
		name        string
		paramCheck  string
		outCheck    string
		sql         bool
		bodyError   bool
		cycleParams bool
		wantBody    bool
		wantOut     bool
		wantPush    bool
	}{
		{name: "javascript_success", paramCheck: allow, outCheck: allow, wantBody: true, wantOut: true, wantPush: true},
		{name: "sql_success", paramCheck: allow, outCheck: allow, sql: true, wantOut: true, wantPush: true},
		{name: "param_rejected", paramCheck: `({success:false,status:403,error:"denied"});`, outCheck: allow},
		{name: "param_exception", paramCheck: `throw new Error("input check failed");`, outCheck: allow},
		{name: "param_result_getter_exception", paramCheck: `({get success(){throw new Error("input result failed");},status:200});`, outCheck: allow},
		{name: "javascript_exception", paramCheck: allow, outCheck: allow, bodyError: true, wantBody: true},
		{name: "sql_exception", paramCheck: allow, outCheck: allow, sql: true, bodyError: true},
		{name: "out_rejected", paramCheck: allow, outCheck: `({success:false,status:409,error:"denied"});`, wantBody: true, wantOut: true},
		{name: "out_exception", paramCheck: allow, outCheck: `throw new Error("output check failed");`, wantBody: true, wantOut: true},
		{name: "out_result_getter_exception", paramCheck: allow, outCheck: `({get success(){throw new Error("output result failed");},status:200});`, wantBody: true, wantOut: true},
		{name: "out_success_202", paramCheck: allow, outCheck: `({success:true,status:202});`, wantBody: true, wantOut: true, wantPush: true},
		{name: "out_success_503", paramCheck: allow, outCheck: `({success:true,status:503});`, wantBody: true, wantOut: true, wantPush: true},
		{name: "cyclic_origin_parameters", paramCheck: allow, outCheck: allow, cycleParams: true},
	} {
		for _, route := range []string{"http", "nyanCallMe"} {
			t.Run(test.name+"/"+route, func(t *testing.T) {
				resetJavascriptInclude(t)
				testDB := setTestSQLiteDB(t)
				if _, err := testDB.Exec(`CREATE TABLE origin_changes (value INTEGER);`); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				marker := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("executed"), %q);`, filepath.Join(dir, stage))
				}
				paramCheck := writeTestScript(t, marker("param")+`
if (nyanAllParams.api !== "events" || nyanAllParams.value !== "7") {
  throw new Error("Push changed the original parameters");
}
`+test.paramCheck)
				outCheck := writeTestScript(t, marker("out")+fmt.Sprintf(`
if (nyanAllParams.api !== "events" || nyanAllParams.value !== "7" ||
    nyanAllParams.nyan_output_status !== 200 ||
    nyanAllParams.nyan_output_content_type !== "application/json" ||
    nyanAllParams.nyan_output_body !== %q ||
    nyanAllParams.nyan_output.body !== %q) {
  throw new Error("outCheck received unexpected Push output or parameters");
}
`, pushedBody, pushedBody)+test.outCheck)
				target := APIConfig{ParamCheck: paramCheck, OutCheck: outCheck, Push: "nested"}
				if test.sql {
					target.SQL = []string{filepath.Join(dir, "list.sql")}
					query := `SELECT CAST(/*value*/0 AS INTEGER) AS value;`
					if test.bodyError {
						query = `SELECT * FROM missing_push_table;`
					}
					writeTestFile(t, target.SQL[0], query)
				} else {
					body := fmt.Sprintf(`%q;`, pushedBody)
					if test.bodyError {
						body = `throw new Error("Push body failed");`
					}
					target.Script = writeTestScript(t, marker("body")+body)
				}
				insertSQL := filepath.Join(dir, "origin_insert.sql")
				writeTestFile(t, insertSQL, `INSERT INTO origin_changes (value) VALUES (1);`)
				originScript := fmt.Sprintf(`nyanRunSQL(%q);`, insertSQL)
				if test.cycleParams {
					originScript += `nyanAllParams.loop = nyanAllParams;`
				}
				originScript += fmt.Sprintf(`%q;`, originBody)
				setTestSQLFiles(t, map[string]APIConfig{
					"origin": {Script: writeTestScript(t, originScript), Push: "events"},
					"events": target,
					"nested": {Script: writeTestScript(t, marker("nested")+`"nested";`)},
				})
				snapshot := currentAPISnapshot()
				conn, testHub := newPushCheckSubscriber(t, "events")
				switch route {
				case "http":
					request := httptest.NewRequest(http.MethodPost, "/origin?value=7", nil)
					request.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
					recorder := httptest.NewRecorder()
					unifiedHandler(recorder, request)
					if recorder.Code != http.StatusOK || recorder.Body.String() != originBody {
						t.Fatalf("Push changed origin response: HTTP %d, body=%s", recorder.Code, recorder.Body.String())
					}
				case "nyanCallMe":
					vm := goja.New()
					registerNyanFuncs(vm, snapshot, map[string]interface{}{}, nil)
					value, err := vm.RunString(`JSON.stringify(nyanCallMe({api:"origin",value:"7"}));`)
					if err != nil {
						t.Fatalf("Push error reached nyanCallMe caller: %v", err)
					}
					if !reflect.DeepEqual(decodeTestJSONObject(t, []byte(value.String())), decodeTestJSONObject(t, []byte(originBody))) {
						t.Fatalf("Push changed nyanCallMe result: %s", value.String())
					}
				}
				var committedChanges int
				if err := testDB.QueryRow(`SELECT COUNT(*) FROM origin_changes;`).Scan(&committedChanges); err != nil {
					t.Fatal(err)
				}
				if committedChanges != 1 {
					t.Fatalf("Push changed origin database update: got %d rows, want 1", committedChanges)
				}
				for stage, want := range map[string]bool{"param": !test.cycleParams, "body": test.wantBody, "out": test.wantOut, "nested": false} {
					_, err := os.Stat(filepath.Join(dir, stage))
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					if got := err == nil; got != want {
						t.Errorf("%s executed=%v, want %v", stage, got, want)
					}
				}
				// Push is synchronous. A marker sent afterward must be the next
				// frame when the Push was rejected; no timeout is needed to prove absence.
				const sentinel = "push-check-complete"
				testHub.Broadcast("events", []byte(sentinel))
				if test.wantPush {
					assertPushCheckFrame(t, conn, pushedBody)
				}
				assertPushCheckFrame(t, conn, sentinel)
			})
		}
	}
}

func TestPushSQLMatchesDirectAPIExecution(t *testing.T) {
	const expected = `{"success":true,"status":200,"result":[{"id":3,"value":16}]}`
	for _, test := range []struct {
		name       string
		failSQL    int
		rejectIn   bool
		rejectOut  bool
		wantRows   int
		wantOutput bool
		wantPush   bool
	}{
		{name: "all_files_in_order", wantRows: 1, wantOutput: true, wantPush: true},
		{name: "second_file_fails", failSQL: 2},
		{name: "last_file_fails", failSQL: 3},
		{name: "input_rejected", rejectIn: true},
		{name: "output_rejected", rejectOut: true, wantRows: 1, wantOutput: true},
	} {
		for _, route := range []string{"http", "nyanCallMe", "push"} {
			t.Run(test.name+"/"+route, func(t *testing.T) {
				resetJavascriptInclude(t)
				testDB := setTestSQLiteDB(t)
				for _, query := range []string{`CREATE TABLE items (id INTEGER, value INTEGER);`, `CREATE TABLE origin_changes (value INTEGER);`} {
					if _, err := testDB.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				dir := t.TempDir()
				marker := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode((nyanGetFile(%q) || "") + "x"), %q);`, filepath.Join(dir, stage), filepath.Join(dir, stage))
				}
				paramResult := `({success:true,status:200});`
				if test.rejectIn {
					paramResult = `({success:false,status:403,error:"input rejected"});`
				}
				paramCheck := writeTestScript(t, marker("param")+`
if (nyanAllParams.api !== "events" || Number(nyanAllParams.value) !== 7) throw new Error("wrong parameters");
nyanAllParams.value = Number(nyanAllParams.value) + 1;
`+paramResult)
				outResult := `({success:true,status:200});`
				if test.rejectOut {
					outResult = `({success:false,status:409,error:"output rejected"});`
				}
				outCheck := writeTestScript(t, fmt.Sprintf(`
if (nyanAllParams.api !== "events" || nyanAllParams.value !== 8 || nyanAllParams.nyan_output.body !== %q) {
  throw new Error("SQL order, parameters, or final output differs");
}
`, expected)+marker("out")+outResult)
				queries := []string{
					`INSERT INTO items (id, value) VALUES (/*id*/0, /*value*/0) RETURNING id, value;`,
					`UPDATE items SET value = value * 2 WHERE id = /*id*/0;`,
					`SELECT id, value FROM items
/*BEGIN*/
WHERE
/*IF id != null*/
  id = /*id*/0
/*END*/
/*IF omitted != null*/
  AND value = /*omitted*/0
/*END*/
/*END*/;`,
				}
				paths := make([]string, len(queries))
				for index, query := range queries {
					if test.failSQL == index+1 {
						query = `SELECT * FROM missing_table;`
					}
					paths[index] = filepath.Join(dir, fmt.Sprintf("%d.sql", index+1))
					writeTestFile(t, paths[index], query)
				}
				originSQL := filepath.Join(dir, "origin.sql")
				writeTestFile(t, originSQL, `INSERT INTO origin_changes (value) VALUES (1);`)
				const originBody = `{"origin":"ok"}`
				setTestSQLFiles(t, map[string]APIConfig{
					"origin": {Script: writeTestScript(t, fmt.Sprintf(`nyanRunSQL(%q); %q;`, originSQL, originBody)), Push: "events"},
					"events": {SQL: paths, ParamCheck: paramCheck, OutCheck: outCheck},
				})
				var body string
				var callErr error
				if route == "push" {
					conn, testHub := newPushCheckSubscriber(t, "events")
					req := httptest.NewRequest(http.MethodPost, "/origin?id=3&value=7", nil)
					req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
					rec := httptest.NewRecorder()
					unifiedHandler(rec, req)
					if rec.Code != http.StatusOK || rec.Body.String() != originBody {
						t.Fatalf("Push affected origin: status=%d body=%s", rec.Code, rec.Body.String())
					}
					var originCount int
					if err := testDB.QueryRow(`SELECT COUNT(*) FROM origin_changes`).Scan(&originCount); err != nil || originCount != 1 {
						t.Fatalf("origin update count=%d err=%v", originCount, err)
					}
					const sentinel = "sql-push-complete"
					testHub.Broadcast("events", []byte(sentinel))
					if test.wantPush {
						assertPushCheckFrame(t, conn, expected)
					}
					assertPushCheckFrame(t, conn, sentinel)
				} else if route == "http" {
					req := httptest.NewRequest(http.MethodPost, "/events?id=3&value=7", nil)
					req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
					rec := httptest.NewRecorder()
					unifiedHandler(rec, req)
					body = rec.Body.String()
				} else {
					body, callErr = callNyanAPIFromVMWithSnapshot(currentAPISnapshot(), "events", map[string]interface{}{"id": 3, "value": 7})
				}
				if route != "push" {
					if test.wantPush && (callErr != nil || body != expected) {
						t.Fatalf("direct API result=%s err=%v", body, callErr)
					}
					if !test.wantPush && callErr == nil && decodeTestJSONObject(t, []byte(body))["success"] != false {
						t.Fatalf("direct API failure was not reported: %s", body)
					}
				}
				var rows int
				if err := testDB.QueryRow(`SELECT COUNT(*) FROM items`).Scan(&rows); err != nil || rows != test.wantRows {
					t.Fatalf("committed SQL rows=%d, want %d; err=%v", rows, test.wantRows, err)
				}
				for stage, want := range map[string]bool{"param": true, "out": test.wantOutput} {
					data, err := os.ReadFile(filepath.Join(dir, stage))
					if want {
						if err != nil || string(data) != "x" {
							t.Errorf("%s must run exactly once: marker=%q err=%v", stage, data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Errorf("%s should not run: marker=%q err=%v", stage, data, err)
					}
				}
			})
		}
	}
}

func TestAPIWithoutBody(t *testing.T) {
	for _, route := range []string{"http", "root", "callme"} {
		for _, test := range []struct {
			name, check string
			checkOnly   bool
			status      int
		}{
			{name: "no_check", status: 400},
			{name: "allowed", check: `({success:true,status:200,result:{checked:true}});`, status: 400},
			{name: "denied", check: `({success:false,status:403,result:{checked:true}});`, status: 403},
			{name: "check_only", check: `({success:true,status:200,result:{checked:true}});`, checkOnly: true, status: 200},
			{name: "check_only_missing", checkOnly: true, status: 404},
		} {
			t.Run(route+"/"+test.name, func(t *testing.T) {
				resetJavascriptInclude(t)
				dir := t.TempDir()
				marker := func(stage string) string {
					return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("ran"), %q);`, filepath.Join(dir, stage))
				}
				target := APIConfig{
					OutCheck: writeTestScript(t, marker("out")+`({success:true,status:200});`),
					Push:     "events",
				}
				if test.check != "" {
					target.ParamCheck = writeTestScript(t, marker("param")+test.check)
				}
				setTestSQLFiles(t, map[string]APIConfig{
					"target": target,
					"events": {Script: writeTestScript(t, marker("push")+`({success:true,status:200});`)},
				})
				var body map[string]interface{}
				if route == "callme" {
					vm := goja.New()
					registerNyanFuncs(vm, currentAPISnapshot(), nil, nil)
					argument := `{"api":"target"}`
					if test.checkOnly {
						argument = `{"api":"target","nyan_mode":"checkOnly"}`
					}
					value, err := vm.RunString("JSON.stringify(nyanCallMe(" + argument + "))")
					if test.status == 400 || test.status == 404 {
						want := "No script or SQL defined"
						if test.status == 404 {
							want = "No check script"
						}
						if err == nil || !strings.Contains(err.Error(), want) {
							t.Fatalf("expected JavaScript exception %q, value=%v err=%v", want, value, err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						body = decodeTestJSONObject(t, []byte(value.String()))
					}
				} else {
					url := "/target?value=1"
					if route == "root" {
						url = "/?api=target"
					}
					if test.checkOnly {
						url += "&nyan_mode=checkOnly"
					}
					req := httptest.NewRequest(http.MethodGet, url, nil)
					req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
					rec := httptest.NewRecorder()
					unifiedHandler(rec, req)
					if rec.Code != test.status {
						t.Fatalf("status=%d, want %d: %s", rec.Code, test.status, rec.Body.String())
					}
					body = decodeTestJSONObject(t, rec.Body.Bytes())
				}
				if body != nil {
					if body["status"] != float64(test.status) || body["success"] != (test.status == 200) {
						t.Fatalf("unexpected response: %#v", body)
					}
					if test.status == 200 || test.status == 403 {
						if !reflect.DeepEqual(body["result"], map[string]interface{}{"checked": true}) {
							t.Fatalf("check result lost: %#v", body)
						}
					} else if body["result"] != nil || body["error"] == nil {
						t.Fatalf("expected error without check result: %#v", body)
					}
				}
				for _, stage := range []string{"param", "out", "push"} {
					data, err := os.ReadFile(filepath.Join(dir, stage))
					if stage == "param" && test.check != "" {
						if err != nil || string(data) != "ran" {
							t.Fatalf("paramCheck did not run: data=%q err=%v", data, err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("unexpected %s execution: data=%q err=%v", stage, data, err)
					}
				}
			})
		}
	}
}

func TestPushRejectsAPIWithoutBody(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	const body = `{"success":true,"status":200,"result":{"value":7}}`
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			marker := filepath.Join(dir, fmt.Sprint(reject))
			setTestSQLFiles(t, map[string]APIConfig{
				"events": {
					ParamCheck: writeTestScript(t, fmt.Sprintf(`%q;`, body)),
					OutCheck: writeTestScript(t, fmt.Sprintf(`
if (nyanAllParams.nyan_output.body !== %q) throw new Error("wrong output");
nyanSaveFile(nyanBase64Encode("checked"), %q);
({success:%t,status:%d});`, body, marker, !reject, map[bool]int{false: 200, true: 409}[reject])),
				},
			})
			conn, testHub := newPushCheckSubscriber(t, "events")
			performPush(currentAPISnapshot(), APIConfig{Push: "events"}, map[string]interface{}{})
			data, err := os.ReadFile(marker)
			if !os.IsNotExist(err) {
				t.Fatalf("outCheck ran without an API body: marker=%q err=%v", data, err)
			}
			const sentinel = "param-only-push-complete"
			testHub.Broadcast("events", []byte(sentinel))
			assertPushCheckFrame(t, conn, sentinel)
		})
	}
}

func TestPushChecksDoNotMutateOriginParameters(t *testing.T) {
	for _, stage := range []string{"paramCheck", "outCheck"} {
		t.Run(stage, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			params := map[string]interface{}{
				"api": "origin",
				"nested": map[string]interface{}{
					"value": "original",
					"items": []interface{}{map[string]interface{}{"value": "original"}},
				},
			}
			want := map[string]interface{}{
				"api": "origin",
				"nested": map[string]interface{}{
					"value": "original",
					"items": []interface{}{map[string]interface{}{"value": "original"}},
				},
			}
			marker := filepath.Join(t.TempDir(), "executed")
			check := writeTestScript(t, fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("executed"), %q);`, marker)+`
nyanAllParams.api = "changed";
nyanAllParams.nested.value = "changed";
nyanAllParams.nested.items[0].value = "changed";
({success:false,status:403});
`)
			target := APIConfig{Script: writeTestScript(t, `"result";`)}
			if stage == "paramCheck" {
				target.ParamCheck = check
			} else {
				target.OutCheck = check
			}
			setTestSQLFiles(t, map[string]APIConfig{"events": target})
			performPush(currentAPISnapshot(), APIConfig{Push: "events"}, params)
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("Push %s was not executed: %v", stage, err)
			}
			if !reflect.DeepEqual(params, want) {
				t.Fatalf("Push %s mutated origin parameters: got %#v, want %#v", stage, params, want)
			}
		})
	}
}

func newPushCheckSubscriber(t *testing.T, channel string) (*websocket.Conn, *Hub) {
	t.Helper()
	oldHub := hub
	testHub := NewHub()
	hub = testHub
	t.Cleanup(func() { hub = oldHub })
	finished := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { finished <- struct{}{} }()
		// This fixture tests Push execution checks, independently of connection checks.
		handleWebSocketWithSnapshot(&APIConfigSnapshot{}, w, r)
	}))
	t.Cleanup(server.Close)
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/"+channel, http.Header{"Origin": []string{server.URL}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("WebSocket handshake failed: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		waitForSignal(t, finished, "Push test WebSocket handler exit")
	})
	waitForCondition(t, "Push test WebSocket registration", func() bool {
		testHub.mu.Lock()
		defer testHub.mu.Unlock()
		return len(testHub.clients[channel]) == 1
	})
	return conn, testHub
}

func assertPushCheckFrame(t *testing.T, conn *websocket.Conn, want string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Push frame read failed: %v", err)
	}
	if messageType != websocket.TextMessage || string(message) != want {
		t.Fatalf("Push frame: type=%d body=%s, want %s", messageType, message, want)
	}
}

func TestNyanCallMeUsesAPINameWithoutFilePathResolution(t *testing.T) {
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	testDB.SetMaxOpenConns(2)
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "api.json")
	targetScript := filepath.Join(dir, "child", "target.js")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child/api.json"}}`)
	writeTestFile(t, filepath.Join(dir, "child", "api.json"), `{"target":{"script":"target.js"},"caller":{"script":"caller.js"}}`)
	writeTestFile(t, targetScript, `({called:nyanAllParams.api});`)
	writeTestFile(t, filepath.Join(dir, "child", "caller.js"), `nyanCallMe({api:nyanAllParams.target});`)
	snapshot := loadTestAPIConfig(t, rootPath).Snapshot
	for _, name := range []string{
		"sub/target", "target", "./sub/target", "sub/../sub/target", targetScript,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := callNyanAPIFromVMWithSnapshot(snapshot, "sub/caller", map[string]interface{}{"target": name})
			if name != "sub/target" {
				if err == nil || !strings.Contains(err.Error(), "API config not found") {
					t.Fatalf("nonexistent API name %q: result=%q error=%v", name, result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeTestJSONObject(t, []byte(result)); got["called"] != name {
				t.Fatalf("called API=%v, want %q", got["called"], name)
			}
		})
	}
}

func TestRuntimeFilePathsUseRootAPIThroughIncludes(t *testing.T) {
	resetJavascriptInclude(t)
	testDB := setTestSQLiteDB(t)
	// The caller and its nested API each hold a script transaction.
	testDB.SetMaxOpenConns(2)
	rootDir, workingDir := t.TempDir(), t.TempDir()
	childDir := filepath.Join(rootDir, "nested", "deep")
	rootPath := filepath.Join(rootDir, "api.json")
	writeTestFile(t, rootPath, `{
  "nested":{"type":"include","path":"nested/api.json"},
  "root":{"script":"nested/deep/main.js","paramCheck":"nested/deep/param.js","outCheck":"nested/deep/out.js"},
  "caller":{"script":"caller.js"}
}`)
	writeTestFile(t, filepath.Join(rootDir, "nested", "api.json"), `{"deep":{"type":"include","path":"deep/api.json"}}`)
	writeTestFile(t, filepath.Join(childDir, "api.json"), `{"run":{"script":"main.js","paramCheck":"param.js","outCheck":"out.js"}}`)
	writeTestFile(t, filepath.Join(rootDir, "data", "input.txt"), "root")
	writeTestFile(t, filepath.Join(rootDir, "sql", "value.sql"), `SELECT 7 AS value;`)
	for _, otherDir := range []string{childDir, workingDir} {
		writeTestFile(t, filepath.Join(otherDir, "data", "input.txt"), "wrong base")
		writeTestFile(t, filepath.Join(otherDir, "sql", "value.sql"), `SELECT 99 AS value;`)
	}
	phaseScript := func(phase, result string) string {
		return fmt.Sprintf(`
if (nyanGetFile("./data/input.txt") !== "root") throw new Error("wrong read base");
if (nyanRunSQL("./sql/value.sql", {})[0].value !== 7) throw new Error("wrong SQL base");
const destination = "./output/" + nyanAllParams.prefix + "-%s.txt";
nyanSaveFile(nyanBase64Encode("%s"), destination);
if (nyanGetFile(destination) !== "%s") throw new Error("saved file was not readable");
%s;
`, phase, phase, phase, result)
	}
	writeTestFile(t, filepath.Join(childDir, "param.js"), phaseScript("param", `({success:true,status:200})`))
	writeTestFile(t, filepath.Join(childDir, "main.js"), phaseScript("body", `({value:7})`))
	writeTestFile(t, filepath.Join(childDir, "out.js"), phaseScript("out", `({success:true,status:200})`))
	writeTestFile(t, filepath.Join(rootDir, "caller.js"), `
nyanSaveFile(nyanBase64Encode("caller"), "./output/caller.txt");
nyanCallMe({api:"nested/deep/run",prefix:nyanAllParams.prefix});
`)
	snapshot := loadTestAPIConfig(t, rootPath).Snapshot
	// An already captured execution must retain its root after another snapshot is published.
	otherRoot := filepath.Join(t.TempDir(), "api.json")
	writeTestFile(t, otherRoot, `{}`)
	setTestAPISnapshot(t, loadTestAPIConfig(t, otherRoot).Snapshot)
	t.Chdir(workingDir)
	for _, test := range []struct{ api, prefix string }{
		{"root", "root"}, {"nested/deep/run", "included"}, {"caller", "internal"},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			result, err := callNyanAPIFromVMWithSnapshot(snapshot, test.api, map[string]interface{}{"prefix": test.prefix})
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeTestJSONObject(t, []byte(result)); got["value"] != float64(7) {
				t.Fatalf("API result=%s", result)
			}
			for _, phase := range []string{"param", "body", "out"} {
				content, err := os.ReadFile(filepath.Join(rootDir, "output", test.prefix+"-"+phase+".txt"))
				if err != nil || string(content) != phase {
					t.Fatalf("%s output=%q, err=%v", phase, content, err)
				}
			}
		})
	}
	for _, wrongDir := range []string{childDir, workingDir, filepath.Dir(otherRoot)} {
		if _, err := os.Stat(filepath.Join(wrongDir, "output")); !os.IsNotExist(err) {
			t.Fatalf("output was created outside the captured root: %s (err=%v)", wrongDir, err)
		}
	}
	if content, err := os.ReadFile(filepath.Join(rootDir, "output", "caller.txt")); err != nil || string(content) != "caller" {
		t.Fatalf("caller output=%q, err=%v", content, err)
	}
}

func TestRuntimeFilePathsKeepAbsolutePaths(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	rootPath := filepath.Join(t.TempDir(), "api.json")
	writeTestFile(t, rootPath, `{}`)
	snapshot := loadTestAPIConfig(t, rootPath).Snapshot
	externalDir := t.TempDir()
	destination := filepath.Join(externalDir, "saved", "hello.txt")
	sqlFile := filepath.Join(externalDir, "value.sql")
	writeTestFile(t, sqlFile, `SELECT 'absolute' AS value;`)
	script := writeTestScript(t, fmt.Sprintf(`
nyanSaveFile(nyanBase64Encode("hello"), %q);
({text:nyanGetFile(%q), value:nyanRunSQL(%q, {})[0].value,
  missing:nyanGetFile("./missing.txt"), directory:nyanGetFile(%q)});
`, destination, destination, sqlFile, externalDir))
	result, err := runScriptWithSnapshot(snapshot, []string{script}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeTestJSONObject(t, []byte(result))
	if got["text"] != "hello" || got["value"] != "absolute" || got["missing"] != nil || got["directory"] != nil {
		t.Fatalf("absolute path results=%s", result)
	}
	if content, err := os.ReadFile(destination); err != nil || string(content) != "hello" {
		t.Fatalf("saved absolute path content=%q err=%v", content, err)
	}
}

func TestRuntimeFilePathsPreserveSQLAllowlist(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "api.json")
	writeTestFile(t, rootPath, `{"sub":{"type":"include","path":"child/api.json"}}`)
	writeTestFile(t, filepath.Join(dir, "child", "api.json"), `{
  "run":{"script":"run.js","runtime":{"capabilities":["sql"],"sqlFiles":["../sql/allowed.sql"]}}
}`)
	writeTestFile(t, filepath.Join(dir, "sql", "allowed.sql"), `SELECT 'allowed' AS value;`)
	writeTestFile(t, filepath.Join(dir, "sql", "denied.sql"), `SELECT 'denied' AS value;`)
	writeTestFile(t, filepath.Join(dir, "child", "run.js"), `
({value:nyanRunSQL(nyanAllParams.path, {})[0].value, readType:typeof nyanGetFile, saveType:typeof nyanSaveFile});
`)
	snapshot := loadTestAPIConfig(t, rootPath).Snapshot
	definition := snapshot.Definitions["sub/run"]
	result, err := runScriptWithRuntimeWithSnapshot(snapshot, []string{definition.Script}, map[string]interface{}{"path": "./sql/allowed.sql"}, definition.Runtime, true)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeTestJSONObject(t, []byte(result))
	if got["value"] != "allowed" || got["readType"] != "undefined" || got["saveType"] != "undefined" {
		t.Fatalf("restricted result=%s", result)
	}
	if _, err := runScriptWithRuntimeWithSnapshot(snapshot, []string{definition.Script}, map[string]interface{}{"path": "./sql/denied.sql"}, definition.Runtime, true); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unlisted SQL error=%v", err)
	}
}

func TestRuntimeFilePathsUseRootSymlinkLocation(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	linkDir, targetDir := t.TempDir(), t.TempDir()
	targetPath := filepath.Join(targetDir, "api.json")
	rootPath := filepath.Join(linkDir, "api.json")
	writeTestFile(t, targetPath, `{}`)
	if err := os.Symlink(targetPath, rootPath); err != nil {
		t.Fatal(err)
	}
	snapshot := loadTestAPIConfig(t, rootPath).Snapshot
	script := writeTestScript(t, `nyanSaveFile("aGVsbG8=", "./hello.txt"); nyanGetFile("./hello.txt");`)
	result, err := runScriptWithSnapshot(snapshot, []string{script}, nil)
	if err != nil || result != "hello" {
		t.Fatalf("result=%q err=%v", result, err)
	}
	if content, err := os.ReadFile(filepath.Join(linkDir, "hello.txt")); err != nil || string(content) != "hello" {
		t.Fatalf("root symlink folder content=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "hello.txt")); !os.IsNotExist(err) {
		t.Fatalf("file was saved under symlink target folder: %v", err)
	}
}

type symlinkReloadFixture struct {
	rootPath, linkPath, firstPath, secondPath, apiName string
}

func newSymlinkReloadFixture(t *testing.T, included bool) symlinkReloadFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := symlinkReloadFixture{
		rootPath: filepath.Join(dir, "api.json"), linkPath: filepath.Join(dir, "current.json"),
		firstPath: filepath.Join(dir, "v1.json"), secondPath: filepath.Join(dir, "v2.json"),
		apiName: "item",
	}
	writeTestFile(t, fixture.firstPath, `{"item":{"description":"initial"}}`)
	writeTestFile(t, fixture.secondPath, `{"item":{"description":"initial"}}`)
	replaceTestSymlink(t, fixture.linkPath, "v1.json")
	if included {
		writeTestFile(t, fixture.rootPath, `{"sub":{"type":"include","path":"current.json"}}`)
		fixture.apiName = "sub/item"
	} else {
		fixture.rootPath = fixture.linkPath
	}
	return fixture
}

func replaceTestSymlink(t *testing.T, linkPath, target string) {
	t.Helper()
	temporary := linkPath + ".next"
	if err := os.Symlink(target, temporary); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := os.Rename(temporary, linkPath); err != nil {
		t.Fatalf("replace symlink: %v", err)
	}
}

func TestReloadAPIConfigGraphRetargetsRootAndIncludeSymlinks(t *testing.T) {
	for _, included := range []bool{false, true} {
		name := "root"
		if included {
			name = "include"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newSymlinkReloadFixture(t, included)
			initial := loadTestAPIConfig(t, fixture.rootPath)
			setTestAPISnapshot(t, initial.Snapshot)
			// The bytes are identical, but subsequent edits must follow the new target.
			replaceTestSymlink(t, fixture.linkPath, "v2.json")
			if err := verifyAPIFileStates(initial.Snapshot.Files); err == nil {
				t.Fatal("retargeted symlink was accepted as the original file state")
			}
			observed, reloaded, err := reloadAPIConfigGraphIfChanged(fixture.rootPath, initial.Snapshot.Files)
			if err != nil || !reloaded {
				t.Fatalf("retarget with identical content: reloaded=%t err=%v", reloaded, err)
			}
			writeTestFile(t, fixture.firstPath, `{"item":{"description":"old target changed"}}`)
			observed, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
			if err != nil || reloaded {
				t.Fatalf("unreferenced old target triggered reload: reloaded=%t err=%v", reloaded, err)
			}
			writeTestFile(t, fixture.secondPath, `{"item":{"description":"new target changed"}}`)
			_, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
			if err != nil || !reloaded {
				t.Fatalf("new target edit: reloaded=%t err=%v", reloaded, err)
			}
			if got := currentSQLFiles()[fixture.apiName].Description; got != "new target changed" {
				t.Fatalf("description=%q, want new target changed", got)
			}
		})
	}
}

func TestReloadAPIConfigGraphWatchesEachSymlinkToSharedTarget(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "api.json")
	firstLink := filepath.Join(dir, "first.json")
	secondLink := filepath.Join(dir, "second.json")
	writeTestFile(t, rootPath, `{"first":{"type":"include","path":"first.json"},"second":{"type":"include","path":"second.json"}}`)
	writeTestFile(t, filepath.Join(dir, "shared.json"), `{"item":{"description":"shared"}}`)
	writeTestFile(t, filepath.Join(dir, "new.json"), `{"item":{"description":"new"}}`)
	replaceTestSymlink(t, firstLink, "shared.json")
	replaceTestSymlink(t, secondLink, "shared.json")
	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)

	replaceTestSymlink(t, firstLink, "new.json")
	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("retarget first alias: reloaded=%t err=%v", reloaded, err)
	}
	if currentSQLFiles()["first/item"].Description != "new" || currentSQLFiles()["second/item"].Description != "shared" {
		t.Fatal("retargeting one alias did not preserve the other mount")
	}
	writeTestFile(t, filepath.Join(dir, "shared.json"), `{"item":{"description":"shared updated"}}`)
	_, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("edit remaining shared target: reloaded=%t err=%v", reloaded, err)
	}
	if currentSQLFiles()["first/item"].Description != "new" || currentSQLFiles()["second/item"].Description != "shared updated" {
		t.Fatal("remaining alias no longer follows its target")
	}
}

func TestReloadAPIConfigGraphSymlinkFailureRetainsSnapshotAndRecovers(t *testing.T) {
	for _, included := range []bool{false, true} {
		name := "root"
		if included {
			name = "include"
		}
		for _, failure := range []string{"missing", "invalid", "cycle"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				fixture := newSymlinkReloadFixture(t, included)
				initial := loadTestAPIConfig(t, fixture.rootPath)
				setTestAPISnapshot(t, initial.Snapshot)
				badPath := filepath.Join(filepath.Dir(fixture.linkPath), "bad.json")
				wantError := "file not found"
				switch failure {
				case "invalid":
					writeTestFile(t, badPath, `{"broken":`)
					wantError = ""
				case "cycle":
					writeTestFile(t, badPath, `{"again":{"type":"include","path":"current.json"}}`)
					wantError = "cycle"
				}
				replaceTestSymlink(t, fixture.linkPath, "bad.json")
				observed, reloaded, err := reloadAPIConfigGraphIfChanged(fixture.rootPath, initial.Snapshot.Files)
				if err == nil || !strings.Contains(err.Error(), wantError) || reloaded {
					t.Fatalf("invalid target: reloaded=%t err=%v, want error containing %q", reloaded, err, wantError)
				}
				if currentAPISnapshot() != initial.Snapshot {
					t.Fatal("failed reload replaced the active snapshot")
				}
				observed, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
				if err != nil || reloaded {
					t.Fatalf("unchanged failed target was retried: reloaded=%t err=%v", reloaded, err)
				}
				if failure == "missing" {
					// A dangling link must also recover when its target is created.
					writeTestFile(t, badPath, `{"item":{"description":"recovered"}}`)
				} else {
					// Keep the bad target unchanged and recover by switching the link.
					writeTestFile(t, fixture.secondPath, `{"item":{"description":"recovered"}}`)
					replaceTestSymlink(t, fixture.linkPath, "v2.json")
				}
				_, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
				if err != nil || !reloaded {
					t.Fatalf("recovery: reloaded=%t err=%v", reloaded, err)
				}
				if got := currentSQLFiles()[fixture.apiName].Description; got != "recovered" {
					t.Fatalf("description=%q, want recovered", got)
				}
			})
		}
	}
}

func TestReloadAPIConfigGraphRetargetsDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "current")
	rootPath := filepath.Join(linkPath, "api.json")
	for _, version := range []string{"v1", "v2"} {
		writeTestFile(t, filepath.Join(dir, version, "api.json"), `{"sub":{"type":"include","path":"child.json"}}`)
		writeTestFile(t, filepath.Join(dir, version, "child.json"), `{"item":{"description":"`+version+`"}}`)
	}
	replaceTestSymlink(t, linkPath, "v1")
	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	replaceTestSymlink(t, linkPath, "v2")
	_, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("directory symlink switch: reloaded=%t err=%v", reloaded, err)
	}
	if got := currentSQLFiles()["sub/item"].Description; got != "v2" {
		t.Fatalf("description=%q, want v2", got)
	}
}

func TestWebSocketAPIChecks(t *testing.T) {
	const allow = `({success:true,status:200});`
	for _, test := range []struct {
		name, paramResult, outResult         string
		sql, bodyError, paramOnly, checkOnly bool
		wantBody, wantOut                    bool
		wantStatus                           int
	}{
		{name: "script", paramResult: allow, outResult: allow, wantBody: true, wantOut: true},
		{name: "sql", paramResult: allow, outResult: allow, sql: true, wantBody: true, wantOut: true},
		{name: "input_rejected", paramResult: `({success:false,status:403,error:"denied"});`, outResult: allow, wantStatus: 403},
		{name: "input_exception", paramResult: `throw new Error("input error");`, outResult: allow, wantStatus: 500},
		{name: "input_export_exception", paramResult: `({get success(){throw new Error("input export error");}});`, outResult: allow, wantStatus: 500},
		{name: "body_exception", paramResult: allow, outResult: allow, bodyError: true, wantBody: true, wantStatus: 500},
		{name: "output_rejected", paramResult: allow, outResult: `({success:false,status:409,error:"denied"});`, wantBody: true, wantOut: true, wantStatus: 409},
		{name: "output_exception", paramResult: allow, outResult: `throw new Error("output error");`, wantBody: true, wantOut: true, wantStatus: 500},
		{name: "output_export_exception", paramResult: allow, outResult: `({get success(){throw new Error("output export error");}});`, wantBody: true, wantOut: true, wantStatus: 500},
		{name: "missing_body", paramResult: allow, outResult: `({success:false,status:409,error:"denied"});`, paramOnly: true, wantStatus: 500},
		{name: "check_only_without_body", paramResult: allow, outResult: allow, paramOnly: true, checkOnly: true, wantStatus: 200},
		{name: "check_only", paramResult: allow, outResult: allow, checkOnly: true, wantStatus: 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			testDB := setTestSQLiteDB(t)
			if _, err := testDB.Exec(`CREATE TABLE executed (value INTEGER);`); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			marker := func(stage string) string {
				return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("done"), %q);`, filepath.Join(dir, stage))
			}
			input := marker("param") + `
if (nyanAllParams.api !== "sub/target" || nyanAllParams.value !== 7) throw new Error("Wrong API parameters");
nyanAllParams.checked = true;
` + test.paramResult
			output := marker("out")
			if !test.paramOnly {
				output += `
const result = JSON.parse(nyanAllParams.nyan_output.body);
if (!nyanAllParams.checked || (result.value !== 7 && (!result.result || result.result[0].value !== 7))) {
  throw new Error("Wrong output check context");
}
`
			}
			output += test.outResult
			target := APIConfig{ParamCheck: writeTestScript(t, input), OutCheck: writeTestScript(t, output)}
			if test.sql {
				sqlFile := filepath.Join(dir, "run.sql")
				writeTestFile(t, sqlFile, `INSERT INTO executed (value) VALUES (/*value*/0) RETURNING value;`)
				target.SQL = []string{sqlFile}
			} else if !test.paramOnly {
				body := marker("body") + `
if (!nyanAllParams.checked) throw new Error("paramCheck did not run before the body");
({value:nyanAllParams.value});
`
				if test.bodyError {
					body = marker("body") + `throw new Error("body error");`
				}
				target.Script = writeTestScript(t, body)
			}
			if test.checkOnly {
				target.Push = "events"
			}
			setTestSQLFiles(t, map[string]APIConfig{
				"channel": {}, "sub/target": target,
				"healthy": {Script: writeTestScript(t, `({value:9});`)},
				"events":  {Script: writeTestScript(t, marker("push")+`({value:1});`)},
			})
			conn, _ := newWebSocketAPITestClient(t, true)
			params := map[string]interface{}{"api": "sub/target", "value": 7}
			if test.checkOnly {
				params["nyan_mode"] = "checkOnly"
			}
			if err := conn.WriteJSON(params); err != nil {
				t.Fatal(err)
			}
			response := readWebSocketAPIResponse(t, conn)
			if test.wantStatus != 0 {
				if response["status"] != float64(test.wantStatus) {
					t.Fatalf("response = %#v, want status %d", response, test.wantStatus)
				}
				if _, leaked := response["value"]; leaked {
					t.Fatalf("unchecked body leaked: %#v", response)
				}
			} else if test.sql {
				if response["success"] != true || response["result"].([]interface{})[0].(map[string]interface{})["value"] != float64(7) {
					t.Fatalf("SQL result = %#v", response)
				}
			} else if response["value"] != float64(7) {
				t.Fatalf("script result = %#v", response)
			}
			for stage, want := range map[string]bool{"param": true, "body": test.wantBody && !test.sql, "out": test.wantOut, "push": false} {
				_, err := os.Stat(filepath.Join(dir, stage))
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if (err == nil) != want {
					t.Errorf("%s executed=%v, want %v", stage, err == nil, want)
				}
			}
			if test.sql {
				var count int
				if err := testDB.QueryRow(`SELECT COUNT(*) FROM executed;`).Scan(&count); err != nil || count != 1 {
					t.Fatalf("SQL body execution count=%d, err=%v", count, err)
				}
			}
			// Each call selects its own API; a rejected call keeps the connection usable.
			if err := conn.WriteJSON(map[string]interface{}{"api": "healthy"}); err != nil {
				t.Fatal(err)
			}
			if next := readWebSocketAPIResponse(t, conn); next["value"] != float64(9) {
				t.Fatalf("next call failed: %#v", next)
			}
		})
	}
}

func TestWebSocketAPIRequestValidation(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{
		"api": {},
		"job": {Type: apiTypeSchedule}, "client": {Type: apiTypeWSClient},
	})
	for _, test := range []struct {
		message       string
		authenticated bool
		status        int
	}{
		{`{"api":"api"}`, false, 401},
		{`{"api":null}`, true, 400}, {`{"api":" "}`, true, 400},
		{`invalid`, true, 400}, {`[]`, true, 400}, {`null`, true, 400},
		{`{"api":"missing"}`, true, 404},
		{`{"api":"job"}`, true, 404}, {`{"api":"client"}`, true, 404},
		{`{"api":"api","mcp_principal":{}}`, true, 400},
		{`{"api":"api","nyan_request":{}}`, true, 400},
		{`{"api":"api","nyan_guard":{}}`, true, 400},
		{`{"heartbeat":true}`, false, 0},
	} {
		t.Run(test.message, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/channel", nil)
			if test.authenticated {
				request.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
			}
			response := executeWebSocketAPIMessage(request, []byte(test.message))
			if test.status == 0 {
				if response != nil {
					t.Fatalf("non-API message produced a response: %s", response)
				}
				return
			}
			if got := decodeTestJSONObject(t, response); got["status"] != float64(test.status) {
				t.Fatalf("response=%s, want status %d", response, test.status)
			}
		})
	}
}

func TestWebSocketAPIRepliesAndPushShareConnection(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	setTestSQLFiles(t, map[string]APIConfig{"channel": {}, "api": {Script: writeTestScript(t, `({reply:true});`)}})
	conn, testHub := newWebSocketAPITestClient(t, true)
	const count = 30
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < count; i++ {
			testHub.Broadcast("channel", []byte(`{"push":true}`))
		}
	}()
	t.Cleanup(func() { waitForSignal(t, finished, "concurrent Push completion") })
	for i := 0; i < count; i++ {
		if err := conn.WriteJSON(map[string]interface{}{"api": "api"}); err != nil {
			t.Fatal(err)
		}
	}
	var replies, pushes int
	for i := 0; i < 2*count; i++ {
		response := readWebSocketAPIResponse(t, conn)
		if response["reply"] == true {
			replies++
		}
		if response["push"] == true {
			pushes++
		}
	}
	if replies != count || pushes != count {
		t.Fatalf("replies=%d, pushes=%d", replies, pushes)
	}
}

func newWebSocketAPITestClient(t *testing.T, authenticated bool) (*websocket.Conn, *Hub) {
	t.Helper()
	oldHub := hub
	testHub := NewHub()
	hub = testHub
	t.Cleanup(func() { hub = oldHub })
	finished := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { finished <- struct{}{} }()
		unifiedHandler(w, r)
	}))
	t.Cleanup(server.Close)
	header := http.Header{"Origin": []string{server.URL}}
	if authenticated {
		request := httptest.NewRequest(http.MethodGet, server.URL, nil)
		request.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
		header.Set("Authorization", request.Header.Get("Authorization"))
	}
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/channel", header)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); waitForSignal(t, finished, "WebSocket API handler exit") })
	waitForCondition(t, "WebSocket API subscription", func() bool {
		testHub.mu.Lock()
		defer testHub.mu.Unlock()
		return len(testHub.clients["channel"]) == 1
	})
	return conn, testHub
}

func readWebSocketAPIResponse(t *testing.T, conn *websocket.Conn) map[string]interface{} {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.TextMessage {
		t.Fatalf("response message type=%d", messageType)
	}
	return decodeTestJSONObject(t, message)
}

func TestUnifiedHandlerWebSocketReceivesPushFromIncludedAPI(t *testing.T) {
	for _, mount := range []string{"", "sub/", "sub/admin/"} {
		t.Run("mount="+mount, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			dir := t.TempDir()
			root := filepath.Join(dir, "api.json")
			writeTestFile(t, filepath.Join(dir, "list.sql"), `SELECT 7 AS value;`)
			writeTestFile(t, filepath.Join(dir, "emit.js"), `JSON.stringify({success:true});`)
			channel := mount + "listItems"
			leaf := fmt.Sprintf(`{"listItems":{"sql":["list.sql"]},"emit":{"script":"emit.js","push":%q}}`, channel)
			switch mount {
			case "":
				writeTestFile(t, root, leaf)
			case "sub/":
				writeTestFile(t, root, `{"sub":{"type":"include","path":"child.json"}}`)
				writeTestFile(t, filepath.Join(dir, "child.json"), leaf)
			case "sub/admin/":
				writeTestFile(t, root, `{"sub":{"type":"include","path":"child.json"}}`)
				writeTestFile(t, filepath.Join(dir, "child.json"), `{"admin":{"type":"include","path":"grandchild.json"}}`)
				writeTestFile(t, filepath.Join(dir, "grandchild.json"), leaf)
			}
			loaded := loadTestAPIConfig(t, root)
			setTestAPISnapshot(t, loaded.Snapshot)
			oldHub := hub
			testHub := NewHub()
			hub = testHub
			t.Cleanup(func() { hub = oldHub })
			finished := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if isWebSocketRequest(r) {
					defer func() { finished <- struct{}{} }()
				}
				unifiedHandler(w, r)
			}))
			t.Cleanup(server.Close)
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/" + channel
			conn, response, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{server.URL}})
			if err != nil {
				status := 0
				if response != nil {
					status = response.StatusCode
					_ = response.Body.Close()
				}
				t.Fatalf("WebSocket handshake failed: HTTP %d: %v", status, err)
			}
			t.Cleanup(func() {
				_ = conn.Close()
				waitForSignal(t, finished, "WebSocket handler exit")
			})
			waitForCondition(t, "WebSocket client registration", func() bool {
				testHub.mu.Lock()
				defer testHub.mu.Unlock()
				return len(testHub.clients[channel]) == 1
			})
			req, err := http.NewRequest(http.MethodPost, server.URL+"/"+mount+"emit", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
			client := server.Client()
			client.Timeout = 3 * time.Second
			httpResponse, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(httpResponse.Body)
			_ = httpResponse.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if httpResponse.StatusCode != http.StatusOK {
				t.Fatalf("emitter: HTTP %d: %s", httpResponse.StatusCode, body)
			}
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("Push read failed: %v", err)
			}
			if messageType != websocket.TextMessage || string(message) != `{"success":true,"status":200,"result":[{"value":7}]}` {
				t.Fatalf("unexpected Push: type=%d body=%s", messageType, message)
			}
		})
	}
}

func TestWebSocketEndpointConfiguredUsesCompleteAPIName(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{
		"top": {}, "sub/list": {}, "sub/admin/list": {}, "direct/name": {},
		"sub/scheduled": {Type: apiTypeSchedule},
		"sub/assets":    {Type: apiTypePublic},
		"sub/mcp":       {Type: apiTypeMCP},
		"client":        {Type: apiTypeWSClient, ConnectURL: "ws://localhost:8443/legacy/channel"},
	})
	for _, test := range []struct {
		path string
		want bool
	}{
		{"/top", true}, {"/sub/list", true}, {"/sub/admin/list", true}, {"/direct/name", true},
		{"/missing", false}, {"/sub/missing", false},
		{"/sub/scheduled", false}, {"/sub/assets", false}, {"/sub/mcp", false}, {"/client", false},
		{"/sub/list/", false}, {"/top/", false}, {"//top", false}, {"/sub//list", false},
		{"/legacy/channel", true},
	} {
		t.Run(test.path, func(t *testing.T) {
			if got := webSocketEndpointConfigured(currentAPISnapshot(), test.path); got != test.want {
				t.Fatalf("allowed=%v want %v", got, test.want)
			}
		})
	}
}

func TestUnifiedHandlerMountedWebSocketRejectsForeignOrigin(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{"sub/list": {}})
	request := httptest.NewRequest(http.MethodGet, "http://localhost/sub/list", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Origin", "https://foreign.example")
	recorder := httptest.NewRecorder()
	unifiedHandler(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", recorder.Code)
	}
}

func TestWebSocketConnectionChecks(t *testing.T) {
	const allow = `({success:true,status:200,result:{checked:true}});`
	const deny = `({success:false,status:403,result:{reason:"denied"},error:"denied"});`
	for _, test := range []struct {
		name, script, query, path                        string
		status                                           int
		legacyCheck, noCheck, missingFile, foreignOrigin bool
	}{
		{name: "allow", script: allow, status: 101},
		{name: "allow_non_200", script: `({success:true,status:201});`, status: 101},
		{name: "deny", script: deny, status: 403},
		{name: "exception", script: `throw new Error("private check detail");`, status: 500},
		{name: "export_exception", script: `({get success(){throw new Error("private check detail");}});`, status: 500},
		{name: "missing_file", missingFile: true, status: 500},
		{name: "missing_status", script: `({success:true});`, status: 500},
		{name: "informational_status", script: `({success:true,status:101});`, status: 500},
		{name: "invalid_status", script: `({success:false,status:600});`, status: 500},
		{name: "fractional_status", script: `({success:true,status:200.5});`, status: 500},
		{name: "invalid_json", script: `"not JSON";`, status: 500},
		{name: "check_only", script: allow, query: "&nyan_mode=checkOnly", status: 200},
		{name: "check_only_denied", script: deny, query: "&nyan_mode=checkOnly", status: 403},
		{name: "check_only_unset", noCheck: true, query: "&nyan_mode=checkOnly", status: 404},
		{name: "invalid_mode", script: allow, query: "&nyan_mode=unknown", status: 400},
		{name: "duplicate_mode", script: allow, query: "&nyan_mode=checkOnly&nyan_mode=", status: 400},
		{name: "empty_mode", script: allow, query: "&nyan_mode=", status: 101},
		{name: "invalid_query", script: allow, query: "&token=%ZZ", status: 400},
		{name: "query_api_cannot_bypass", script: deny, query: "&api=unchecked", status: 403},
		{name: "no_check", noCheck: true, status: 101},
		{name: "legacy_check", script: deny, legacyCheck: true, status: 403},
		{name: "legacy_subscription", path: "/legacy/channel", noCheck: true, status: 101},
		{name: "legacy_check_only", path: "/legacy/channel", noCheck: true, query: "&nyan_mode=checkOnly", status: 404},
		{name: "foreign_origin", script: allow, foreignOrigin: true, status: 403},
		{name: "unknown_endpoint", script: allow, path: "/unknown", status: 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetJavascriptInclude(t)
			dir := t.TempDir()
			marker := func(stage string) string {
				return fmt.Sprintf(`nyanSaveFile(nyanBase64Encode("done"), %q);`, filepath.Join(dir, stage))
			}
			target := APIConfig{
				Script:   writeTestScript(t, marker("body")+`({success:true});`),
				OutCheck: writeTestScript(t, marker("out")+allow), Push: "events",
			}
			if !test.noCheck {
				target.ParamCheck = writeTestScript(t, marker("param")+`
if (nyanAllParams.api !== "sub/events" || nyanAllParams.token !== "secret" ||
    JSON.stringify(nyanAllParams.tag) !== '["a","b"]') throw new Error("wrong connection parameters");
`+test.script)
			}
			if test.legacyCheck {
				target.Check, target.ParamCheck = target.ParamCheck, ""
			}
			if test.missingFile {
				target.ParamCheck = filepath.Join(dir, "missing.js")
			}
			setTestSQLFiles(t, map[string]APIConfig{
				"sub/events": target, "unchecked": {},
				"events": {Script: writeTestScript(t, marker("push")+allow)},
				"client": {Type: apiTypeWSClient, ConnectURL: "ws://localhost/legacy/channel"},
			})
			oldHub := hub
			testHub := NewHub()
			hub = testHub
			t.Cleanup(func() { hub = oldHub })
			finished := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() { finished <- struct{}{} }()
				unifiedHandler(w, r)
			}))
			t.Cleanup(server.Close)
			path := test.path
			if path == "" {
				path = "/sub/events"
			}
			origin := server.URL
			if test.foreignOrigin {
				origin = "https://foreign.example"
			}
			conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+path+"?token=secret&tag=a&tag=b"+test.query, http.Header{"Origin": []string{origin}})
			if conn != nil {
				t.Cleanup(func() { _ = conn.Close() })
			}
			if response == nil {
				t.Fatalf("no handshake response: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status=%d want %d: %v", response.StatusCode, test.status, err)
			}
			if test.status == 101 {
				if err != nil || conn == nil {
					t.Fatalf("connection failed: %v", err)
				}
				waitForCondition(t, "checked subscription registration", func() bool {
					testHub.mu.Lock()
					defer testHub.mu.Unlock()
					return len(testHub.clients[strings.TrimPrefix(path, "/")]) == 1
				})
				_ = conn.Close()
			} else {
				if err == nil || conn != nil {
					t.Fatal("rejected connection was upgraded")
				}
				body, readErr := io.ReadAll(response.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if (test.status == 200 || test.status == 403) && !test.foreignOrigin {
					result := decodeTestJSONObject(t, body)
					if _, exists := result["result"]; !exists {
						t.Fatalf("check result lost: %s", body)
					}
				}
				if strings.Contains(string(body), "private check detail") {
					t.Fatalf("exception detail exposed: %s", body)
				}
			}
			waitForSignal(t, finished, "connection check handler exit")
			testHub.mu.Lock()
			count := len(testHub.connections)
			testHub.mu.Unlock()
			if count != 0 {
				t.Fatalf("connections remaining: %d", count)
			}
			wantParam := !test.noCheck && !test.missingFile && !test.foreignOrigin && test.path == "" && test.status != 400
			for stage, want := range map[string]bool{"param": wantParam, "body": false, "out": false, "push": false} {
				_, statErr := os.Stat(filepath.Join(dir, stage))
				if statErr != nil && !os.IsNotExist(statErr) {
					t.Fatal(statErr)
				}
				if (statErr == nil) != want {
					t.Fatalf("%s executed=%v want %v", stage, statErr == nil, want)
				}
			}
		})
	}
}

func TestWebSocketConnectionCheckDoesNotReplaceMessageCheck(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	setTestSQLFiles(t, map[string]APIConfig{
		"channel": {
			ParamCheck: writeTestScript(t, `({success:nyanAllParams.token === undefined,status:nyanAllParams.token === undefined ? 200 : 403});`),
			Script:     writeTestScript(t, `({value:"executed"});`),
		},
	})
	conn, _ := newWebSocketAPITestClient(t, true)
	if err := conn.WriteJSON(map[string]interface{}{"api": "channel", "token": "rejected"}); err != nil {
		t.Fatal(err)
	}
	response := readWebSocketAPIResponse(t, conn)
	if response["status"] != float64(403) || response["success"] != false {
		t.Fatalf("message check bypassed after accepted connection: %#v", response)
	}
	if err := conn.WriteJSON(map[string]interface{}{"api": "channel"}); err != nil {
		t.Fatal(err)
	}
	if response := readWebSocketAPIResponse(t, conn); response["value"] != "executed" {
		t.Fatalf("connection unusable after rejection: %#v", response)
	}
}

func TestWebSocketConnectionCheckUsesCapturedSnapshot(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	snapshot := &APIConfigSnapshot{Definitions: map[string]APIConfig{
		"channel": {ParamCheck: writeTestScript(t, `nyanCallMe({api:"nested",nyan_mode:"checkOnly"});`)},
		"nested":  {ParamCheck: writeTestScript(t, `({success:true,status:200,result:"captured"});`)},
	}}
	setTestSQLFiles(t, map[string]APIConfig{
		"nested": {ParamCheck: writeTestScript(t, `({success:false,status:403,result:"new"});`)},
	})
	request := httptest.NewRequest(http.MethodGet, "/channel?nyan_mode=checkOnly", nil)
	recorder := httptest.NewRecorder()
	if checkWebSocketConnection(snapshot, recorder, request) {
		t.Fatal("checkOnly allowed an upgrade")
	}
	response := decodeTestJSONObject(t, recorder.Body.Bytes())
	if recorder.Code != http.StatusOK || response["result"] != "captured" {
		t.Fatalf("check used a different configuration snapshot: %d %s", recorder.Code, recorder.Body.String())
	}
}

func contextTestRequest(method, path, contentType, body string) *http.Request {
	r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("User-Agent", "context-test")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Add("X-Multi", "one")
	r.Header.Add("X-Multi", "two")
	r.AddCookie(&http.Cookie{Name: "session", Value: "real-cookie"})
	return r
}

func assertScriptRequestContext(t *testing.T, value interface{}, path string) map[string]interface{} {
	t.Helper()
	c, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("request context: %#v", value)
	}
	if c["path"] != path || c["remoteIP"] != "2001:db8::1" || c["remoteAddress"] != "[2001:db8::1]:1234" || c["userAgent"] != "context-test" {
		t.Fatalf("wrong request origin: %#v", c)
	}
	if c["cookies"].(map[string]interface{})["session"] != "real-cookie" {
		t.Fatalf("wrong cookies: %#v", c)
	}
	headers := c["headers"].(map[string]interface{})
	if headers["user-agent"] != "context-test" || headers["User-Agent"] != "context-test" || len(headers["x-multi"].([]interface{})) != 2 {
		t.Fatalf("wrong headers: %#v", headers)
	}
	return c
}

func TestRequestContextHTTPInternalCallsAndPush(t *testing.T) {
	for _, route := range []string{"http", "root", "form", "query", "rpc"} {
		t.Run(route, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t).SetMaxOpenConns(4)
			oldHub := hub
			hub = NewHub()
			t.Cleanup(func() { hub = oldHub })
			dir := t.TempDir()
			pushScript := func(name string) string {
				return writeTestScript(t, fmt.Sprintf(`
if (nyanAllParams.onlyInResult !== undefined || nyanAllParams.nyan_output !== undefined) throw new Error("result leaked into Push arguments");
nyanSaveFile(nyanBase64Encode(JSON.stringify({params:nyanAllParams,request:nyanRequest})), %q);
nyanRequest.pushMutation = true;
({success:true});`, filepath.Join(dir, name)))
			}
			setTestSQLFiles(t, map[string]APIConfig{
				"parent": {
					ParamCheck: writeTestScript(t, `
if (nyanRequest.remoteIP !== "2001:db8::1") throw new Error("spoofed request");
nyanRequest.checkMarker = true;
if (nyanAllParams.nyan_request.checkMarker !== true) throw new Error("alias missing");
nyanAllParams.checked = true;
({success:true,status:200});`),
					Script: writeTestScript(t, `
const args = {api:"child", id:2, nyan_request:{remoteIP:"forged"}};
const child = nyanCallMe(args);
if (args.nyan_request.remoteIP !== "forged") throw new Error("caller arguments mutated");
if (!nyanAllParams.checked || !nyanRequest.checkMarker || nyanRequest.pushMutation) throw new Error("context changed");
({success:true,child:child,request:nyanRequest,onlyInResult:true});`),
					OutCheck: writeTestScript(t, `if (!nyanRequest.checkMarker) throw new Error("outCheck lost context"); ({success:true,status:200});`),
					Push:     "parentEvents",
				},
				"child": {Script: writeTestScript(t, `
if (nyanAllParams.parentOnly !== undefined || nyanAllParams.checked !== undefined) throw new Error("implicit business arguments");
if (nyanAllParams.id !== 2 || !nyanRequest.checkMarker) throw new Error("child input changed");
({request:nyanRequest,id:nyanAllParams.id});`), Push: "childEvents"},
				"parentEvents": {Script: pushScript("parent.json")},
				"childEvents":  {Script: pushScript("child.json")},
			})
			path, method, contentType := "/parent", "POST", "application/json"
			body := `{"id":1,"parentOnly":true,"nyan_request":{"remoteIP":"forged"}}`
			switch route {
			case "root":
				path = "/"
				body = `{"api":"parent","id":1,"parentOnly":true,"nyan_request":{"remoteIP":"forged"}}`
			case "form":
				contentType = "application/x-www-form-urlencoded"
				body = "id=1&parentOnly=true&nyan_request=forged"
			case "query":
				method = "GET"
				contentType = ""
				body = ""
			case "rpc":
				path = "/rpc"
				body = `{"jsonrpc":"2.0","id":1,"method":"parent","params":{"id":1,"parentOnly":true,"nyan_request":{"remoteIP":"forged"}}}`
			}
			r := contextTestRequest(method, path+"?q=one&q=two&nyan_request=forged", contentType, body)
			w := httptest.NewRecorder()
			if route == "rpc" {
				handleJSONRPC(w, r)
			} else {
				handleRequest(w, r)
			}
			if w.Code != 200 {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
			}
			response := decodeTestJSONObject(t, w.Body.Bytes())
			if route == "rpc" {
				response = response["result"].(map[string]interface{})
			}
			ctx := assertScriptRequestContext(t, response["request"], path)
			if ctx["method"] != method || ctx["checkMarker"] != true || ctx["body"] != body {
				t.Fatalf("context: %#v", ctx)
			}
			if len(ctx["query"].(map[string]interface{})["q"].([]interface{})) != 2 {
				t.Fatal("query values lost")
			}
			if route == "form" && ctx["form"].(map[string]interface{})["id"] != "1" {
				t.Fatal("form lost")
			}
			if contentType == "application/json" && ctx["json"] == nil {
				t.Fatal("JSON lost")
			}
			assertScriptRequestContext(t, response["child"].(map[string]interface{})["request"], path)
			for _, name := range []string{"parent", "child"} {
				b, err := os.ReadFile(filepath.Join(dir, name+".json"))
				if err != nil {
					t.Fatal(err)
				}
				pushed := decodeTestJSONObject(t, b)
				assertScriptRequestContext(t, pushed["request"], path)
				p := pushed["params"].(map[string]interface{})
				if p["api"] != name+"Events" {
					t.Fatalf("Push api: %#v", p)
				}
				if name == "child" && (p["id"] != float64(2) || p["parentOnly"] != nil) {
					t.Fatalf("child Push args: %#v", p)
				}
				if name == "parent" && route != "query" && p["parentOnly"] == nil {
					t.Fatalf("parent Push args lost: %#v", p)
				}
			}
		})
	}
}

func TestRequestContextWebSocketAndPublic(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	check := writeTestScript(t, `({success:true,status:200,result:nyanRequest});`)
	setTestSQLFiles(t, map[string]APIConfig{"events": {ParamCheck: check}, "target": {Script: writeTestScript(t, `({request:nyanRequest});`)}})
	r := contextTestRequest("GET", "/events?nyan_mode=checkOnly&nyan_request=forged", "", "")
	r.SetBasicAuth(config.BasicAuth.Username, config.BasicAuth.Password)
	w := httptest.NewRecorder()
	if checkWebSocketConnection(currentAPISnapshot(), w, r) {
		t.Fatal("checkOnly upgraded")
	}
	assertScriptRequestContext(t, decodeTestJSONObject(t, w.Body.Bytes())["result"], "/events")
	response := executeWebSocketAPIMessage(r, []byte(`{"api":"target"}`))
	assertScriptRequestContext(t, decodeTestJSONObject(t, response)["request"], "/events")
	response = executeWebSocketAPIMessage(r, []byte(`{"api":"target","nyan_request":{}}`))
	if decodeTestJSONObject(t, response)["status"] != float64(400) {
		t.Fatal("reserved message accepted")
	}
	w = httptest.NewRecorder()
	r = contextTestRequest("GET", "/assets?nyan_mode=checkOnly&nyan_request=forged", "", "")
	handlePublicRequestWithSnapshot(currentAPISnapshot(), w, r, "assets", "", APIConfig{Path: t.TempDir(), ParamCheck: check})
	assertScriptRequestContext(t, decodeTestJSONObject(t, w.Body.Bytes())["result"], "/assets")
}

func TestRequestContextMCPTransports(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t).SetMaxOpenConns(4)
	setTestSQLFiles(t, map[string]APIConfig{
		"tool":  {ParamCheck: writeTestScript(t, `const nyanInputSchema={type:"object"};({success:true,status:200});`), Script: writeTestScript(t, `nyanCallMe({api:"child",nyan_request:{remoteIP:"forged"}});`)},
		"child": {Script: writeTestScript(t, `({request:nyanRequest});`)},
	})
	server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", ProtocolVersions: []string{mcpProtocolVersion20251125}, Tools: []MCPToolConfig{{Name: "tool", API: "tool"}}}
	message := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool","arguments":{"nyan_request":{"remoteIP":"forged"}}}}`
	r := contextTestRequest("POST", "/mcp", "application/json", message)
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion20251125)
	w := httptest.NewRecorder()
	handleMCPRequestWithSnapshot(currentAPISnapshot(), w, r, "mcp", server)
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	response := decodeTestJSONObject(t, w.Body.Bytes())["result"].(map[string]interface{})
	structured, ok := response["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("Tool failed: %#v", response)
	}
	ctx := assertScriptRequestContext(t, structured["request"], "/mcp")
	if ctx["body"] != message {
		t.Fatal("MCP body not preserved")
	}
	result, err := executeMCPToolForStdio(currentAPISnapshot(), server.Tools[0], map[string]interface{}{"nyan_request": map[string]interface{}{"remoteIP": "forged"}})
	if err != nil {
		t.Fatal(err)
	}
	empty := result["structuredContent"].(map[string]interface{})["request"].(map[string]interface{})
	if len(empty) != 0 {
		t.Fatalf("stdio inherited HTTP context: %#v", empty)
	}
}

func TestRequestContextIsolationAndNoHTTPRequest(t *testing.T) {
	resetJavascriptInclude(t)
	// No global request state: independent VMs may read and mutate their own contexts concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := contextTestRequest("GET", fmt.Sprintf("/request%d", i), "", "")
			p, err := collectRequestParams(r)
			if err != nil {
				t.Error(err)
				return
			}
			vm := goja.New()
			registerNyanFuncs(vm, nil, p, nil)
			v, err := vm.RunString(`nyanRequest.marker=nyanRequest.path;nyanAllParams.nyan_request.marker;`)
			if err != nil || v.String() != r.URL.Path {
				t.Errorf("request mixing: %v %v", v, err)
			}
		}(i)
	}
	wg.Wait()
	vm := goja.New()
	registerNyanFuncs(vm, nil, nil, nil)
	v, err := vm.RunString(`JSON.stringify({request:nyanRequest,alias:nyanAllParams.nyan_request});`)
	if err != nil || v.String() != `{"request":{},"alias":{}}` {
		t.Fatalf("no-request VM: %v %v", v, err)
	}
}

func TestRequestContextOAuthAndTokenVerification(t *testing.T) {
	for _, route := range []string{"authorize", "token", "register", "metadata", "verify"} {
		t.Run(route, func(t *testing.T) {
			resetJavascriptInclude(t)
			setTestSQLiteDB(t)
			validate := `
if (nyanRequest.remoteIP !== "2001:db8::1" || nyanRequest.cookies.session !== "real-cookie" ||
    nyanRequest.headers["user-agent"] !== "context-test" || nyanAllParams.nyan_request.path !== nyanRequest.path) {
  throw new Error("OAuth lost actual request context");
}
`
			definition := APIConfig{
				ParamCheck: writeTestScript(t, validate+`({success:true,status:200,result:nyanRequest});`),
				Script:     writeTestScript(t, validate+`({status:200,body:{request:nyanRequest}});`),
				OutCheck:   writeTestScript(t, validate+`({success:true,status:200});`),
			}
			verify := definition
			verify.Script = writeTestScript(t, validate+`
if (nyanRequest.path !== "/mcp" || nyanRequest.json.method !== "tools/call" || nyanAllParams.nyan_mode !== undefined) throw new Error("wrong verification request");
({authenticated:true,principal:{user_id:"verified"}});`)
			server := APIConfig{Type: apiTypeMCP, Transport: "streamable_http", ProtocolVersions: []string{mcpProtocolVersion20251125},
				OAuth: MCPOAuthConfig{Authorize: "authorize", Token: "token", Register: "register", AuthorizationServerMetadata: "metadata", VerifyAccess: "verify"},
				Tools: []MCPToolConfig{{Name: "tool", API: "tool"}},
			}
			setTestSQLFiles(t, map[string]APIConfig{"authorize": definition, "token": definition, "register": definition, "metadata": definition, "verify": verify, "mcp": server,
				"tool": {Script: writeTestScript(t, validate+`({request:nyanRequest,user:nyanAllParams.mcp_principal.user_id});`)},
			})
			if route == "verify" {
				message := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool","arguments":{"nyan_request":{"remoteIP":"forged"}}}}`
				r := contextTestRequest("POST", "/mcp", "application/json", message)
				r.Header.Set("Accept", "application/json, text/event-stream")
				r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion20251125)
				r.Header.Set("Authorization", "Bearer real-token")
				w := httptest.NewRecorder()
				handleMCPRequestWithSnapshot(currentAPISnapshot(), w, r, "mcp", server)
				response := decodeTestJSONObject(t, w.Body.Bytes())
				if w.Code != 200 {
					t.Fatalf("verification: %d %s", w.Code, w.Body.String())
				}
				toolResult, ok := response["result"].(map[string]interface{})["structuredContent"].(map[string]interface{})
				if !ok || toolResult["user"] != "verified" {
					t.Fatalf("verification/Tool failed: %#v", response)
				}
				assertScriptRequestContext(t, toolResult["request"], "/mcp")
				return
			}
			for _, checkOnly := range []bool{false, true} {
				method, contentType, body, role := "GET", "", "", "oauthAuthorize"
				switch route {
				case "token":
					method, contentType, body, role = "POST", "application/x-www-form-urlencoded", "nyan_request=forged&value=body", "oauthToken"
				case "register":
					method, contentType, body, role = "POST", "application/json", `{"nyan_request":{"remoteIP":"forged"},"value":"body"}`, "oauthRegister"
				case "metadata":
					role = "authorizationServerMetadata"
				}
				path := "/" + route + "?nyan_request=forged"
				if checkOnly {
					path += "&nyan_mode=checkOnly"
				}
				r := contextTestRequest(method, path, contentType, body)
				w := httptest.NewRecorder()
				handleMCPOAuthHTTPRequest(currentAPISnapshot(), w, r, "mcp", server, route, role)
				if w.Code != 200 {
					t.Fatalf("OAuth %s checkOnly=%t: %d %s", route, checkOnly, w.Code, w.Body.String())
				}
				response := decodeTestJSONObject(t, w.Body.Bytes())
				if route == "metadata" && !checkOnly {
					continue
				}
				key := "request"
				if checkOnly {
					key = "result"
				}
				ctx := assertScriptRequestContext(t, response[key], "/"+route)
				if ctx["body"] != body {
					t.Fatalf("OAuth body lost: %#v", ctx)
				}
				if route == "token" && ctx["form"].(map[string]interface{})["value"] != "body" {
					t.Fatal("OAuth form lost")
				}
				if route == "register" && ctx["json"].(map[string]interface{})["value"] != "body" {
					t.Fatal("OAuth JSON lost")
				}
			}
		})
	}
}
