package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

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

	files, _, err := readSQLFiles(apiPath, apiDir)
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

	server := httptest.NewServer(http.HandlerFunc(handleWebSocket))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/updates"
	headers := http.Header{"Origin": []string{"https://example.invalid"}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	waitForCondition(t, "WebSocket client registration", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.clients["updates"]) == 1
	})
	hub.Broadcast("updates", []byte("hello"))
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
const nyanOutputColumns = ["id", "name"];
`)
	accepted, columns, err := parseScriptConstants(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if accepted["name"] != "default" || !reflect.DeepEqual(columns, []string{"id", "name"}) {
		t.Fatalf("accepted=%#v columns=%#v", accepted, columns)
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
const nyanOutputColumns = ["id", "name"];
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
		NyanOutputColumns  []string               `json:"nyanOutputColumns"`
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
	if !reflect.DeepEqual(response.NyanOutputColumns, []string{"id", "name"}) {
		t.Fatalf("output columns = %#v", response.NyanOutputColumns)
	}
}

func TestExecuteAPIConfigSupportsSQLAndScript(t *testing.T) {
	setTestSQLiteDB(t)
	resetJavascriptInclude(t)
	sqlPath := filepath.Join(t.TempDir(), "select.sql")
	writeTestFile(t, sqlPath, `SELECT 'sql' AS source`)
	sqlResult, err := executeAPIConfig(APIConfig{SQL: []string{sqlPath}})
	if err != nil {
		t.Fatalf("executeAPIConfig(SQL) error = %v", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(sqlResult, &rows); err != nil || len(rows) != 1 || rows[0]["source"] != "sql" {
		t.Fatalf("SQL result = %q, error = %v", sqlResult, err)
	}

	scriptPath := writeTestScript(t, `JSON.stringify({source: "script"});`)
	scriptResult, err := executeAPIConfig(APIConfig{Script: scriptPath})
	if err != nil {
		t.Fatalf("executeAPIConfig(script) error = %v", err)
	}
	if string(scriptResult) != `{"source":"script"}` {
		t.Fatalf("script result = %q", scriptResult)
	}
	if _, err := executeAPIConfig(APIConfig{}); err == nil {
		t.Fatal("executeAPIConfig(empty) error = nil")
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
	if err == nil {
		t.Fatal("execCommand(failure) error = nil")
	}
	if result.Success || result.ExitCode != 7 {
		t.Fatalf("failure result = %#v", result)
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
