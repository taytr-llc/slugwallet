package legacyrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/websocket"
	"github.com/taytr-llc/slug/btcjson"
)

func restrictedTestServer(t *testing.T, methods []string, websocketLimit int64) (*Server, *httptest.Server) {
	t.Helper()
	s := NewServer(&Options{Username: "fixture-user", Password: "fixture-password", MaxPOSTClients: 4, MaxWebsocketClients: websocketLimit, AllowedMethods: methods}, nil, nil)
	h := httptest.NewServer(s.httpServer.Handler)
	t.Cleanup(func() { h.Close(); s.Stop() })
	return s, h
}
func requestMethod(t *testing.T, h *httptest.Server, method string) *btcjson.RPCError {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": []any{}})
	req, _ := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(data))
	req.SetBasicAuth("fixture-user", "fixture-password")
	resp, err := h.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Error *btcjson.RPCError `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result.Error
}
func TestMethodAllowlistBeforeDispatch(t *testing.T) {
	methods := []string{"getbalance"}
	s, h := restrictedTestServer(t, methods, 0)
	methods[0] = "stop" // Mutating caller storage cannot grant a method.
	for _, method := range []string{"stop", "dumpprivkey", "walletpassphrase", "signmessage", "sendtoaddress", "getblockhash", "help", "GetBalance"} {
		err := requestMethod(t, h, method)
		if err == nil || err.Code != btcjson.ErrRPCMethodNotFound.Code {
			t.Fatalf("%s was dispatched: %v", method, err)
		}
	}
	if err := requestMethod(t, h, "getbalance"); err == nil || err.Code == btcjson.ErrRPCMethodNotFound.Code {
		t.Fatalf("allowed wallet method was not dispatched: %v", err)
	}
	select {
	case <-s.RequestProcessShutdown():
		t.Fatal("denied stop requested shutdown")
	default:
	}
	// Guard also covers direct handler construction, including node passthrough.
	if _, err := s.handlerClosure(&btcjson.Request{Method: "getblockhash"})(); err == nil || err.Code != btcjson.ErrRPCMethodNotFound.Code {
		t.Fatal("passthrough bypass")
	}
}
func TestMethodAllowlistNilAndEmpty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		allowed bool
	}{{"nil", nil, true}, {"empty", []string{}, false}, {"explicit", []string{"stop"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := restrictedTestServer(t, tc.methods, 0)
			err := requestMethod(t, h, "stop")
			if (err == nil) != tc.allowed {
				t.Fatalf("stop result %v", err)
			}
			select {
			case <-s.RequestProcessShutdown():
				if !tc.allowed {
					t.Fatal("unexpected stop")
				}
			default:
				if tc.allowed {
					t.Fatal("legacy stop not delivered")
				}
			}
		})
	}
}
func TestRestrictedTransportAndAuthentication(t *testing.T) {
	_, h := restrictedTestServer(t, []string{"getbalance"}, 0)
	for _, tc := range []struct {
		method, path, origin string
		auth                 bool
		status               int
	}{{"GET", "/", "", true, 400}, {"POST", "/other", "", true, 400}, {"POST", "/?x=1", "", true, 400}, {"POST", "/", "https://example.invalid", true, 400}, {"POST", "/", "", false, 401}, {"GET", "/ws", "", true, 429}} {
		req, _ := http.NewRequest(tc.method, h.URL+tc.path, strings.NewReader(`{"id":1,"method":"getbalance","params":[]}`))
		if tc.auth {
			req.SetBasicAuth("fixture-user", "fixture-password")
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%+v got %d", tc, resp.StatusCode)
		}
	}
}
func TestMethodAllowlistWebsocket(t *testing.T) {
	s, h := restrictedTestServer(t, []string{"getbalance"}, 1)
	headers := http.Header{"Authorization": []string{string(httpBasicAuth("fixture-user", "fixture-password"))}}
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(h.URL, "http")+"/ws", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for _, method := range []string{"stop", "dumpprivkey", "getblockhash"} {
		if err := c.WriteJSON(map[string]any{"id": 1, "method": method, "params": []any{}}); err != nil {
			t.Fatal(err)
		}
		var response struct {
			Error *btcjson.RPCError `json:"error"`
		}
		if err := c.ReadJSON(&response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil || response.Error.Code != btcjson.ErrRPCMethodNotFound.Code {
			t.Fatalf("%s bypassed websocket guard", method)
		}
	}
	select {
	case <-s.RequestProcessShutdown():
		t.Fatal("websocket stop bypass")
	default:
	}
}

func TestRPCShutdownRejectsLateHTTPAndWebsocket(t *testing.T) {
	s, h := restrictedTestServer(t, nil, 1)
	s.Stop()
	for _, path := range []string{"/", "/ws"} {
		req, _ := http.NewRequest(http.MethodPost, h.URL+path, strings.NewReader(`{"id":1,"method":"stop","params":[]}`))
		req.SetBasicAuth("fixture-user", "fixture-password")
		response, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("late %s request status %d", path, response.StatusCode)
		}
	}
	select {
	case <-s.RequestProcessShutdown():
		t.Fatal("late method dispatched after shutdown")
	default:
	}
}

func TestRPCShutdownClosesAcceptedRequestBody(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(&Options{Username: "fixture-user", Password: "fixture-password", MaxPOSTClients: 2}, nil, nil)
	active := make(chan struct{}, 1)
	s.httpServer.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateActive {
			select {
			case active <- struct{}{}:
			default:
			}
		}
	}
	s.listeners = []net.Listener{listener}
	s.serve(listener)
	defer s.Stop()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	// An authenticated request whose declared body has not arrived must not
	// survive shutdown until the inherited ten-second HTTP read timeout.
	fmt.Fprintf(connection, "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\nContent-Length: 100\r\n\r\n{", httpBasicAuth("fixture-user", "fixture-password"))
	select {
	case <-active:
	case <-time.After(3 * time.Second):
		t.Fatal("request was not accepted")
	}
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not close accepted request")
	}
	select {
	case <-s.RequestProcessShutdown():
		t.Fatal("incomplete request was dispatched")
	default:
	}
}
