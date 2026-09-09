package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
