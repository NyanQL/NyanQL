package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	setSQLFiles(t, nil)

	loadSQLFiles(apiPath, apiDir)

	apiConfig := sqlFiles["list"]
	scriptConfig := sqlFiles["scripted"]
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

func TestFindPublicAPIForPath(t *testing.T) {
	setSQLFiles(t, map[string]APIConfig{
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
	setSQLFiles(t, map[string]APIConfig{
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
	setSQLFiles(t, map[string]APIConfig{
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
	setSQLFiles(t, map[string]APIConfig{
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

func setSQLFiles(t *testing.T, files map[string]APIConfig) {
	t.Helper()
	oldFiles := sqlFiles
	sqlFiles = files
	t.Cleanup(func() {
		sqlFiles = oldFiles
	})
}
