package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		state, exists := result.Snapshot.Files[identity]
		if !exists || !state.Exists || state.Path != identity {
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
	canonicalSecond, err := canonicalExistingAPIFilePath(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := observed[canonicalSecond]; !exists {
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
	canonicalChild, canonicalErr := canonicalExistingAPIFilePath(childPath)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	invalidState, exists := observed[canonicalChild]
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

func TestAPIConfigUnmarshalConfiguredHTTPRuntimeAndMCP(t *testing.T) {
	t.Skip("旧MCP Tool object/path/resource/guard形式は廃止済み")
	data := []byte(`{
		"type":"mcp",
		"path":"/mcp",
		"http":{"path":"/oauth/token","methods":["POST"],"access":"anonymous","responseMode":"raw","rateLimit":{"requests":20,"window":"1m"}},
		"runtime":{"capabilities":["sql","crypto"],"sqlFiles":["./sql/one.sql","./sql/two.sql"],"settings":{"issuer":"https://example.test","nested":{"enabled":true}}},
		"transport":"streamable_http",
		"protocolVersions":["2025-11-25"],
		"resource":"https://example.test/mcp",
		"guard":{"api":"oauth_verify"},
		"rateLimit":{"requests":100,"window":"1m"},
		"maxConcurrent":8,
		"instructions":"Use the configured tools.",
		"tools":[{
			"name":"list_stamps",
			"api":"list",
			"title":"List stamps",
			"securitySchemes":[{"type":"oauth2","scopes":["stamps:read"]}],
			"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}
		}]
	}`)

	var got APIConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.HTTP == nil || got.HTTP.Path != "/oauth/token" || !reflect.DeepEqual(got.HTTP.Methods, []string{"POST"}) || got.HTTP.Access != "anonymous" || got.HTTP.ResponseMode != "raw" {
		t.Fatalf("HTTP config = %#v", got.HTTP)
	}
	if got.HTTP.RateLimit == nil || got.HTTP.RateLimit.Requests != 20 || got.HTTP.RateLimit.Window != "1m" {
		t.Fatalf("HTTP rate limit = %#v", got.HTTP.RateLimit)
	}
	if !reflect.DeepEqual(got.Runtime.Capabilities, []string{"sql", "crypto"}) {
		t.Fatalf("runtime capabilities = %#v", got.Runtime.Capabilities)
	}
	if !reflect.DeepEqual(got.Runtime.SQLFiles, []string{"./sql/one.sql", "./sql/two.sql"}) {
		t.Fatalf("runtime SQL files = %#v", got.Runtime.SQLFiles)
	}
	nested, ok := got.Runtime.Settings["nested"].(map[string]interface{})
	if !ok || nested["enabled"] != true {
		t.Fatalf("runtime settings = %#v", got.Runtime.Settings)
	}
	if got.Transport != "streamable_http" || !reflect.DeepEqual(got.ProtocolVersions, []string{"2025-11-25"}) || got.Resource != "https://example.test/mcp" || got.Guard.API != "oauth_verify" {
		t.Fatalf("MCP config = transport:%q versions:%#v resource:%q guard:%#v", got.Transport, got.ProtocolVersions, got.Resource, got.Guard)
	}
	if got.RateLimit == nil || got.RateLimit.Requests != 100 || got.RateLimit.Window != "1m" || got.MaxConcurrent != 8 {
		t.Fatalf("MCP limits = rate:%#v maxConcurrent:%d", got.RateLimit, got.MaxConcurrent)
	}
	if got.Instructions != "Use the configured tools." || len(got.Tools) != 1 {
		t.Fatalf("MCP instructions/tools = %q / %#v", got.Instructions, got.Tools)
	}
	tool := got.Tools[0]
	if tool.Name != "list_stamps" || tool.API != "list" || tool.Title != "List stamps" {
		t.Fatalf("tool = %#v", tool)
	}
	if len(tool.SecuritySchemes) != 1 || tool.SecuritySchemes[0].Type != "oauth2" || !reflect.DeepEqual(tool.SecuritySchemes[0].Scopes, []string{"stamps:read"}) {
		t.Fatalf("security schemes = %#v", tool.SecuritySchemes)
	}
	if tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
		t.Fatalf("annotations = %#v", tool.Annotations)
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
		HTTP:             &HTTPAPIConfig{Path: "/raw", Methods: []string{"GET"}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw, RateLimit: &HTTPRateLimitConfig{Requests: 10, Window: "1m"}},
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

	original.HTTP.Path = "/mutated"
	original.HTTP.Methods[0] = "DELETE"
	original.HTTP.RateLimit.Requests = 999
	original.HTTP.RateLimit.Window = "24h"
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
	if got.HTTP == original.HTTP || got.HTTP.Path != "/raw" || !reflect.DeepEqual(got.HTTP.Methods, []string{"GET"}) {
		t.Fatalf("snapshot HTTP config = %#v", got.HTTP)
	}
	if got.HTTP.RateLimit == original.HTTP.RateLimit || got.HTTP.RateLimit.Requests != 10 || got.HTTP.RateLimit.Window != "1m" {
		t.Fatalf("snapshot HTTP rate limit = %#v", got.HTTP.RateLimit)
	}
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

func TestLoadAPIConfigFileValidatesConfiguredHTTPAndMCPRoutes(t *testing.T) {
	t.Skip("旧MCP path/resource/guard形式は廃止済み")
	valid := `{
		"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"},"runtime":{"capabilities":["crypto"]}},
		"target":{"script":"target.js","description":"target"},
		"metadata":{"script":"metadata.js","http":{"path":"/.well-known/example","methods":["GET"],"access":"anonymous","responseMode":"raw"}},
		"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://127.0.0.1/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"oauth2","scopes":["target:read"]}]}]}
	}`
	validPath := filepath.Join(t.TempDir(), "api.json")
	writeTestFile(t, validPath, valid)
	loaded, err := loadAPIConfigFile(validPath)
	if err != nil {
		t.Fatalf("valid configured API load error = %v", err)
	}
	if loaded.Snapshot.Definitions["metadata"].HTTP.Path != "/.well-known/example" || loaded.Snapshot.Definitions["server"].Guard.API != "guard" {
		t.Fatalf("loaded configured APIs = %#v", loaded.Snapshot.Definitions)
	}

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "relative HTTP path",
			data: `{"endpoint":{"script":"x.js","http":{"path":"oauth/token","access":"anonymous","responseMode":"raw"}}}`,
			want: "HTTP path must be an absolute path",
		},
		{
			name: "unsupported access",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"public","responseMode":"raw"}}}`,
			want: "unsupported http.access",
		},
		{
			name: "raw without script",
			data: `{"endpoint":{"http":{"path":"/x","access":"anonymous","responseMode":"raw"}}}`,
			want: "raw HTTP responses require script",
		},
		{
			name: "invalid method",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","methods":["GET\\nBAD"],"access":"anonymous","responseMode":"raw"}}}`,
			want: "invalid HTTP method",
		},
		{
			name: "duplicate HTTP route",
			data: `{"first":{"script":"x.js","http":{"path":"/same","access":"anonymous","responseMode":"raw"}},"second":{"script":"y.js","http":{"path":"/same","access":"anonymous","responseMode":"raw"}}}`,
			want: "conflicts with",
		},
		{
			name: "reserved route",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/nyan-rpc","access":"anonymous","responseMode":"raw"}}}`,
			want: "is reserved",
		},
		{
			name: "unsupported runtime capability",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"anonymous","responseMode":"raw"},"runtime":{"capabilities":["host_exec"]}}}`,
			want: "unsupported runtime capability",
		},
		{
			name: "SQL capability requires allowlist",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"anonymous","responseMode":"raw"},"runtime":{"capabilities":["sql"]}}}`,
			want: "runtime.sqlFiles is required",
		},
		{
			name: "SQL allowlist requires capability",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"anonymous","responseMode":"raw"},"runtime":{"sqlFiles":["query.sql"]}}}`,
			want: "runtime.sqlFiles requires the sql capability",
		},
		{
			name: "invalid rate limit requests",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"anonymous","responseMode":"raw","rateLimit":{"requests":0,"window":"1m"}}}}`,
			want: "http.rateLimit.requests",
		},
		{
			name: "invalid rate limit window",
			data: `{"endpoint":{"script":"x.js","http":{"path":"/x","access":"anonymous","responseMode":"raw","rateLimit":{"requests":10,"window":"500ms"}}}}`,
			want: "http.rateLimit.window",
		},
		{
			name: "MCP guard must be internal",
			data: `{"guard":{"script":"guard.js","http":{"path":"/guard","access":"anonymous","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target"}]}}`,
			want: "must be an internal API",
		},
		{
			name: "unsupported MCP protocol version",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2024-11-05"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]}]}}`,
			want: "unsupported protocolVersions entry",
		},
		{
			name: "duplicate MCP protocol version",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-06-18","2025-06-18"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]}]}}`,
			want: "duplicate protocolVersions entry",
		},
		{
			name: "duplicate MCP tool",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]},{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]}]}}`,
			want: "duplicate tool name",
		},
		{
			name: "MCP tool requires one security scheme",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target"}]}}`,
			want: "must declare exactly one security scheme",
		},
		{
			name: "MCP OAuth tool requires scope",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"oauth2"}]}]}}`,
			want: "must declare at least one scope",
		},
		{
			name: "invalid MCP rate limit",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","rateLimit":{"requests":0,"window":"1m"},"guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]}]}}`,
			want: "rateLimit.requests",
		},
		{
			name: "invalid MCP max concurrency",
			data: `{"guard":{"script":"guard.js","http":{"access":"internal","responseMode":"raw"}},"target":{"script":"target.js"},"server":{"type":"mcp","path":"/mcp","transport":"streamable_http","protocolVersions":["2025-11-25"],"resource":"http://localhost/mcp","maxConcurrent":257,"guard":{"api":"guard"},"tools":[{"name":"target","api":"target","securitySchemes":[{"type":"noauth"}]}]}}`,
			want: "maxConcurrent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiPath := filepath.Join(t.TempDir(), "api.json")
			writeTestFile(t, apiPath, tt.data)
			result, err := loadAPIConfigFile(apiPath)
			if err == nil {
				t.Fatalf("loadAPIConfigFile() result = %#v, want error containing %q", result, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadAPIConfigFile() error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestConfiguredHTTPRawResponseRequestContextAndCapabilities(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	script := writeTestScript(t, `
JSON.stringify({
  status: 201,
  headers: {"Content-Type":"application/json", "X-Script":"ok"},
  body: {
    method: nyanRequest.method,
    path: nyanRequest.path,
    query: nyanRequest.query,
    form: nyanRequest.form,
    json: nyanRequest.json,
    requestHeader: nyanRequest.headers["x-test"],
    cookie: nyanRequest.cookies.session,
    rawBody: nyanRequest.body,
    mergedName: nyanAllParams.name,
    cryptoType: typeof nyanCrypto,
    passwordType: typeof nyanPassword,
    sqlType: typeof nyanRunSQL,
	transactionType: typeof nyanTx,
    hostExecType: typeof nyanHostExec,
    fileType: typeof nyanGetFile,
    httpType: typeof nyanGetAPI
  }
});
`)
	setTestSQLFiles(t, map[string]APIConfig{
		"raw_endpoint": {
			Script:  script,
			HTTP:    &HTTPAPIConfig{Path: "/raw", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
			Runtime: APIRuntimeConfig{Capabilities: []string{"crypto"}},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/raw?q=one&q=two", strings.NewReader("name=cat"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test", "header-value")
	req.AddCookie(&http.Cookie{Name: "session", Value: "cookie-value"})
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if rec.Header().Get("X-Script") != "ok" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response headers = %#v", rec.Header())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body = %q: %v", rec.Body.String(), err)
	}
	if body["method"] != http.MethodPost || body["path"] != "/raw" || body["requestHeader"] != "header-value" || body["cookie"] != "cookie-value" || body["rawBody"] != "name=cat" || body["mergedName"] != "cat" {
		t.Fatalf("request context body = %#v", body)
	}
	query := body["query"].(map[string]interface{})
	if !reflect.DeepEqual(query["q"], []interface{}{"one", "two"}) {
		t.Fatalf("query values = %#v", query)
	}
	form := body["form"].(map[string]interface{})
	if form["name"] != "cat" {
		t.Fatalf("form values = %#v", form)
	}
	if body["cryptoType"] != "object" || body["passwordType"] != "undefined" || body["sqlType"] != "undefined" || body["transactionType"] != "undefined" || body["hostExecType"] != "undefined" || body["fileType"] != "undefined" || body["httpType"] != "undefined" {
		t.Fatalf("restricted capability types = %#v", body)
	}
}

func TestConfiguredHTTPRejectsDisallowedMethodBeforeRunningScript(t *testing.T) {
	setTestSQLFiles(t, map[string]APIConfig{
		"post_only": {
			Script: "/script/must-not-run.js",
			HTTP:   &HTTPAPIConfig{Path: "/post-only", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
		},
	})

	rec := httptest.NewRecorder()
	unifiedHandler(rec, httptest.NewRequest(http.MethodGet, "/post-only", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
	}
	if rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow = %q, want %q", rec.Header().Get("Allow"), http.MethodPost)
	}
}

func TestConfiguredHTTPInternalAPICannotUseLegacyHTTPRoute(t *testing.T) {
	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	oldConfig := config
	config.BasicAuth = BasicAuthConfig{Username: "nyan", Password: "secret"}
	t.Cleanup(func() { config = oldConfig })
	script := writeTestScript(t, `JSON.stringify({status:200,headers:{"Content-Type":"application/json"},body:{exposed:true}});`)
	setTestSQLFiles(t, map[string]APIConfig{
		"guard": {
			Script: script,
			HTTP:   &HTTPAPIConfig{Access: configuredHTTPAccessInternal, ResponseMode: configuredHTTPResponseRaw},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/guard", nil)
	req.SetBasicAuth("nyan", "secret")
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("internal API status = %d, want %d; body=%q", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestConfiguredHTTPResponseRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name     string
		response configuredHTTPResponse
	}{
		{name: "hop-by-hop header", response: configuredHTTPResponse{Status: 200, Headers: map[string]interface{}{"Connection": "close"}, Body: "no"}},
		{name: "content length", response: configuredHTTPResponse{Status: 200, Headers: map[string]interface{}{"Content-Length": "2"}, Body: "no"}},
		{name: "header newline", response: configuredHTTPResponse{Status: 200, Headers: map[string]interface{}{"X-Test": "ok\r\nInjected: yes"}, Body: "no"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := writeConfiguredHTTPResponse(rec, httptest.NewRequest(http.MethodGet, "/", nil), tt.response)
			if err == nil {
				t.Fatalf("writeConfiguredHTTPResponse() error = nil for %#v", tt.response)
			}
		})
	}
	if _, err := parseConfiguredHTTPResponse(`{"status":700,"body":"invalid"}`); err == nil {
		t.Fatal("parseConfiguredHTTPResponse() error = nil for out-of-range status")
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
	for _, size := range []int{15, 129} {
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
			HTTP:    &HTTPAPIConfig{Access: configuredHTTPAccessInternal, ResponseMode: configuredHTTPResponseRaw},
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

func TestConfiguredHTTPRateLimitAndAuthorizationHeaderIsolation(t *testing.T) {
	configuredHTTPRateBuckets.Lock()
	oldBuckets := configuredHTTPRateBuckets.Buckets
	oldCleanup := configuredHTTPRateBuckets.LastCleanup
	configuredHTTPRateBuckets.Buckets = make(map[string]configuredHTTPRateBucket)
	configuredHTTPRateBuckets.LastCleanup = time.Time{}
	configuredHTTPRateBuckets.Unlock()
	t.Cleanup(func() {
		configuredHTTPRateBuckets.Lock()
		configuredHTTPRateBuckets.Buckets = oldBuckets
		configuredHTTPRateBuckets.LastCleanup = oldCleanup
		configuredHTTPRateBuckets.Unlock()
	})

	rateLimited := APIConfig{HTTP: &HTTPAPIConfig{RateLimit: &HTTPRateLimitConfig{Requests: 2, Window: "1m"}}}
	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	if allowed, _ := configuredHTTPRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:1000", now); !allowed {
		t.Fatal("first rate-limited request was rejected")
	}
	if allowed, _ := configuredHTTPRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:2000", now.Add(time.Second)); !allowed {
		t.Fatal("second request from same IP was rejected")
	}
	if allowed, retryAfter := configuredHTTPRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:3000", now.Add(2*time.Second)); allowed || retryAfter <= 0 {
		t.Fatalf("third request allowed=%t retryAfter=%s", allowed, retryAfter)
	}
	if allowed, _ := configuredHTTPRateLimitAllows("oauth_register", rateLimited, "192.0.2.2:1000", now.Add(2*time.Second)); !allowed {
		t.Fatal("different IP incorrectly shared a rate-limit bucket")
	}
	if allowed, _ := configuredHTTPRateLimitAllows("oauth_register", rateLimited, "192.0.2.1:4000", now.Add(time.Minute)); !allowed {
		t.Fatal("request after rate-limit window was rejected")
	}

	resetJavascriptInclude(t)
	setTestSQLiteDB(t)
	script := writeTestScript(t, `
JSON.stringify({
  status: 200,
  headers: {"Content-Type":"application/json"},
  body: {
    authorizationType: typeof nyanRequest.headers.authorization,
    visibleHeaderNames: Object.keys(nyanRequest.headers).sort()
  }
});
`)
	setTestSQLFiles(t, map[string]APIConfig{
		"header_probe": {
			Script: script,
			HTTP: &HTTPAPIConfig{
				Path:         "/header-probe",
				Methods:      []string{http.MethodGet},
				Access:       configuredHTTPAccessAnonymous,
				ResponseMode: configuredHTTPResponseRaw,
				RateLimit:    &HTTPRateLimitConfig{Requests: 1, Window: "1m"},
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/header-probe", nil)
	req.Header.Set("Authorization", "Bearer must-not-reach-script")
	req.Header.Set("X-Visible", "yes")
	rec := httptest.NewRecorder()
	unifiedHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("header isolation status = %d; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeTestJSONObject(t, rec.Body.Bytes())
	if body["authorizationType"] != "undefined" {
		t.Fatalf("Authorization header reached raw script: %#v", body)
	}
	if !reflect.DeepEqual(body["visibleHeaderNames"], []interface{}{"x-visible"}) {
		t.Fatalf("visible raw-script headers = %#v", body["visibleHeaderNames"])
	}
	limitedReq := httptest.NewRequest(http.MethodGet, "/header-probe", nil)
	limitedRec := httptest.NewRecorder()
	unifiedHandler(limitedRec, limitedReq)
	if limitedRec.Code != http.StatusTooManyRequests || limitedRec.Header().Get("Retry-After") == "" {
		t.Fatalf("configured HTTP rate-limit response = status:%d headers:%#v body:%s", limitedRec.Code, limitedRec.Header(), limitedRec.Body.String())
	}
}

func TestConfiguredHTTPAndMCPOriginPolicies(t *testing.T) {
	httpConfig := APIConfig{HTTP: &HTTPAPIConfig{
		AllowedOrigins: []string{"https://chatgpt.com"},
	}}
	request := httptest.NewRequest(http.MethodPost, "https://server.example/oauth/token", nil)
	for _, testCase := range []struct {
		name    string
		origin  string
		allowed bool
	}{
		{name: "missing server origin", allowed: true},
		{name: "same origin", origin: "https://server.example", allowed: true},
		{name: "configured origin", origin: "https://chatgpt.com", allowed: true},
		{name: "unconfigured origin", origin: "https://attacker.example", allowed: false},
		{name: "origin with path", origin: "https://chatgpt.com/callback", allowed: false},
	} {
		t.Run("http "+testCase.name, func(t *testing.T) {
			request.Header.Set("Origin", testCase.origin)
			if got := configuredHTTPOriginAllowed(request, httpConfig); got != testCase.allowed {
				t.Fatalf("configuredHTTPOriginAllowed(%q) = %t, want %t", testCase.origin, got, testCase.allowed)
			}
		})
	}

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
	if err == nil || !strings.Contains(err.Error(), `unsupported field "allowedOrigns"`) {
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
			HTTP:   &HTTPAPIConfig{Path: "/.well-known/oauth-protected-resource/mcp", Methods: []string{http.MethodGet}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
			Runtime: APIRuntimeConfig{Settings: map[string]interface{}{
				"issuer":   oauthIntegrationTestIssuer,
				"resource": oauthIntegrationTestResource,
				"scopes":   scopes,
			}},
		},
		"oauth_authorization_server_metadata": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "authorization_server_metadata.js"),
			HTTP:   &HTTPAPIConfig{Path: "/.well-known/oauth-authorization-server", Methods: []string{http.MethodGet}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
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
			HTTP:   &HTTPAPIConfig{Path: "/oauth/register", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
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
			HTTP:   &HTTPAPIConfig{Path: "/oauth/authorize", Methods: []string{http.MethodGet, http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
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
			HTTP:   &HTTPAPIConfig{Path: "/oauth/token", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
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
			HTTP:   &HTTPAPIConfig{Path: "/oauth/revoke", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessAnonymous, ResponseMode: configuredHTTPResponseRaw},
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
			HTTP:   &HTTPAPIConfig{Path: "/oauth/admin/users", Methods: []string{http.MethodPost}, Access: configuredHTTPAccessBasic, ResponseMode: configuredHTTPResponseRaw},
			Runtime: APIRuntimeConfig{
				Capabilities: []string{"sql", "password"},
				SQLFiles:     oauthTestSQLAssetPaths(t, "upsert_user.sql"),
			},
		},
		"oauth_verify_access": {
			Script: oauthTestAssetPath(t, "javascript", "oauth", "verify_access.js"),
			HTTP:   &HTTPAPIConfig{Access: configuredHTTPAccessInternal},
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
