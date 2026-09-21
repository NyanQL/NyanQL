package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/gorilla/websocket"
)

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
		{name: "out_non_ok_status", paramCheck: allow, outCheck: `({success:true,status:202});`, wantBody: true, wantOut: true},
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
					query := `SELECT 7 AS value;`
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
		handleWebSocket(w, r)
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
