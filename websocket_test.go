package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

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
		"sub/private":   {HTTP: &HTTPAPIConfig{Access: configuredHTTPAccessInternal}},
		"sub/http":      {HTTP: &HTTPAPIConfig{Path: "/custom"}},
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
		{"/missing", false}, {"/sub/missing", false}, {"/sub/private", false}, {"/sub/http", false},
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
