package main

import (
	"crypto/sha256"
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
