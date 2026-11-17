//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
)

type sourceRPCRequest struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func sourceRPCResult(t *testing.T, request sourceRPCRequest) any {
	t.Helper()
	switch request.Method {
	case "getcurrentnet":
		return uint32(chaincfg.MainNetParams.Net)
	case "getblockhash":
		return chaincfg.MainNetParams.GenesisHash.String()
	case "getblockchaininfo":
		return map[string]any{"bip9_softforks": map[string]any{"csv": map[string]any{"always_active_height": 62}, "segwit": map[string]any{"always_active_height": 62}, "taproot": map[string]any{"always_active_height": 62}}}
	case "getbestblock":
		return map[string]any{"height": 0, "hash": chaincfg.MainNetParams.GenesisHash.String()}
	case "getblock":
		var params []json.RawMessage
		if json.Unmarshal(request.Params, &params) != nil || len(params) != 2 || string(params[1]) != "0" {
			t.Error("node getblock requires integer verbosity0")
		}
		var raw bytes.Buffer
		if err := chaincfg.MainNetParams.GenesisBlock.Serialize(&raw); err != nil {
			t.Error(err)
		}
		return hex.EncodeToString(raw.Bytes())
	default:
		t.Error("unexpected source method", request.Method)
		return nil
	}
}

func sourceRPCServer(t *testing.T, handler func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fixture" || pass != "PUBLIC-TEST-PASSWORD" || r.URL.Path != "/ws" {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}))
	t.Cleanup(server.Close)
	return server
}

func sourceRPCClient(t *testing.T, server *httptest.Server) *RecoveryRPCSource {
	t.Helper()
	config := RecoveryRPCConfig{URL: "ws" + strings.TrimPrefix(server.URL, "http") + "/ws", Username: "fixture", Password: "PUBLIC-TEST-PASSWORD"}
	if server.TLS != nil {
		config.CACertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	}
	source, err := NewRecoveryRPCSource(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return source
}

func TestRecoveryRPCSourcePinsEveryOwnedConnection(t *testing.T) {
	var mu sync.Mutex
	var sequences [][]string
	server := sourceRPCServer(t, func(conn *websocket.Conn) {
		var sequence []string
		defer func() { mu.Lock(); sequences = append(sequences, sequence); mu.Unlock() }()
		for {
			var request sourceRPCRequest
			if conn.ReadJSON(&request) != nil {
				return
			}
			sequence = append(sequence, request.Method)
			if conn.WriteJSON(map[string]any{"id": request.ID, "result": sourceRPCResult(t, request), "error": nil}) != nil {
				return
			}
		}
	})
	source := sourceRPCClient(t, server)
	identity, err := source.Identity(context.Background())
	if err != nil || identity.Genesis != *chaincfg.MainNetParams.GenesisHash || identity.CSVHeight != 62 {
		t.Fatal("source identity", err)
	}
	tip, err := source.BestBlock(context.Background())
	if err != nil || tip.Height != 0 || tip.Hash != identity.Genesis {
		t.Fatal("source tip", err)
	}
	hash, err := source.BlockHash(context.Background(), 0)
	if err != nil || hash != identity.Genesis {
		t.Fatal("source canonical hash", err)
	}
	block, err := source.Block(context.Background(), hash)
	if err != nil || !reflect.DeepEqual(block, chaincfg.MainNetParams.GenesisBlock) {
		t.Fatal("source owned block", err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		count := len(sequences)
		mu.Unlock()
		if count == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("source left an owned connection open")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, sequence := range sequences {
		if len(sequence) < 3 || !reflect.DeepEqual(sequence[:3], []string{"getcurrentnet", "getblockhash", "getblockchaininfo"}) || len(sequence) > 4 {
			t.Fatal("data read before same-connection identity pinning", sequence)
		}
	}
}

func TestRecoveryRPCSourceRejectsMalformedOrForeignResponses(t *testing.T) {
	for _, mode := range []string{"network", "genesis", "activation", "missing_activation", "wrong_id", "duplicate_id", "server_error", "oversized", "binary", "trailing", "null", "invalid_block"} {
		t.Run(mode, func(t *testing.T) {
			server := sourceRPCServer(t, func(conn *websocket.Conn) {
				for {
					var request sourceRPCRequest
					if conn.ReadJSON(&request) != nil {
						return
					}
					result := sourceRPCResult(t, request)
					id := request.ID
					var rpcError any
					switch {
					case mode == "network" && request.Method == "getcurrentnet":
						result = uint32(0)
					case mode == "genesis" && request.Method == "getblockhash":
						result = strings.Repeat("00", 32)
					case (mode == "activation" || mode == "missing_activation") && request.Method == "getblockchaininfo":
						result = map[string]any{"bip9_softforks": map[string]any{"csv": map[string]any{"always_active_height": 63}}}
					case mode == "wrong_id":
						id = "foreign-response"
					case mode == "server_error":
						rpcError = map[string]any{"code": -1, "message": "SENSITIVE-ERROR-CANARY"}
					case mode == "oversized":
						result = strings.Repeat("x", int(recoveryRPCSmallLimit))
					case mode == "null":
						result = nil
					case mode == "invalid_block" && request.Method == "getblock":
						result = "00"
					}
					raw, _ := json.Marshal(map[string]any{"id": id, "result": result, "error": rpcError})
					kind := websocket.TextMessage
					if mode == "binary" {
						kind = websocket.BinaryMessage
					}
					if mode == "trailing" {
						raw = append(raw, []byte(" {}")...)
					}
					if mode == "duplicate_id" {
						raw = append([]byte(`{"id":"wrong",`), raw[1:]...)
					}
					if conn.WriteMessage(kind, raw) != nil {
						return
					}
				}
			})
			source := sourceRPCClient(t, server)
			block, err := source.Block(context.Background(), *chaincfg.MainNetParams.GenesisHash)
			if !errors.Is(err, ErrRecoverySource) || block != nil || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("source accepted foreign or malformed response", err)
			}
		})
	}
}

func TestRecoveryRPCSourceTLSAndRequiredTipHeight(t *testing.T) {
	server := sourceRPCServer(t, func(conn *websocket.Conn) {
		for {
			var request sourceRPCRequest
			if conn.ReadJSON(&request) != nil {
				return
			}
			result := sourceRPCResult(t, request)
			if request.Method == "getbestblock" {
				result = map[string]any{"hash": chaincfg.MainNetParams.GenesisHash.String()}
			}
			if conn.WriteJSON(map[string]any{"id": request.ID, "result": result, "error": nil}) != nil {
				return
			}
		}
	})
	tlsServer := httptest.NewTLSServer(server.Config.Handler)
	t.Cleanup(tlsServer.Close)
	source := sourceRPCClient(t, tlsServer)
	if _, err := source.Identity(context.Background()); err != nil {
		t.Fatal("trusted TLS source rejected", err)
	}
	if tip, err := source.BestBlock(context.Background()); !errors.Is(err, ErrRecoverySource) || tip != (RecoveryTip{}) {
		t.Fatal("missing height defaulted to genesis", err)
	}
	untrusted, err := NewRecoveryRPCSource(RecoveryRPCConfig{URL: "wss" + strings.TrimPrefix(tlsServer.URL, "https") + "/ws", Username: "fixture", Password: "PUBLIC-TEST-PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if _, err := untrusted.Identity(context.Background()); !errors.Is(err, ErrRecoverySource) {
		t.Fatal("source bypassed certificate verification", err)
	}
}

func TestRecoveryRPCSourceUpgradeHeaderBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", 2*int(recoveryRPCSmallLimit)))
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	source := sourceRPCClient(t, server)
	if _, err := source.Identity(context.Background()); !errors.Is(err, ErrRecoverySource) {
		t.Fatal("oversized upgrade header accepted", err)
	}
}

func TestRecoveryRPCSourceCancellationAndCloseJoinSocket(t *testing.T) {
	for _, closeSource := range []bool{false, true} {
		t.Run(fmt.Sprint(closeSource), func(t *testing.T) {
			entered, socketClosed := make(chan struct{}), make(chan struct{})
			server := sourceRPCServer(t, func(conn *websocket.Conn) {
				defer close(socketClosed)
				var request sourceRPCRequest
				if conn.ReadJSON(&request) != nil {
					return
				}
				close(entered)
				conn.ReadMessage() // No response; the real peer must close on cancel.
			})
			source := sourceRPCClient(t, server)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := source.BestBlock(ctx); result <- err }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("source did not start identity read")
			}
			waiting, stopWaiting := context.WithCancel(context.Background())
			stopWaiting()
			if _, err := source.Identity(waiting); !errors.Is(err, context.Canceled) {
				t.Fatal("queued cancellation", err)
			}
			want := context.Canceled
			if closeSource {
				want = ErrRecoveryClosed
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatal("canceled source result", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("source operation did not join")
			}
			select {
			case <-socketClosed:
			case <-time.After(time.Second):
				t.Fatal("actual socket read outlived cancellation")
			}
			source.Close()
			if _, err := source.BlockHash(context.Background(), 0); !errors.Is(err, ErrRecoveryClosed) {
				t.Fatal("closed source accepted work", err)
			}
		})
	}
}

func TestRecoveryRPCSourceConfigAndNoUncheckedReconnect(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1/ws", "ws://localhost/ws", "ws://192.0.2.1/ws", "ws://u:p@127.0.0.1/ws", "ws://127.0.0.1/ws?token=secret", "ws://127.0.0.1/other", "wss://example.invalid/ws#fragment"} {
		if source, err := NewRecoveryRPCSource(RecoveryRPCConfig{URL: endpoint, Username: "fixture", Password: "PUBLIC-TEST-PASSWORD"}); !errors.Is(err, ErrRecoverySource) || source != nil {
			t.Fatal("accepted invalid source endpoint")
		}
	}
	config := RecoveryRPCConfig{URL: "wss://example.invalid/ws", Username: "SENSITIVE-NAME", Password: "SENSITIVE-PASSWORD"}
	raw, _ := json.Marshal(config)
	if strings.Contains(fmt.Sprintf("%v %+v %#v %s", config, config, config, raw), "SENSITIVE") {
		t.Fatal("source configuration formatted credentials")
	}
	server := sourceRPCServer(t, func(conn *websocket.Conn) {
		var request sourceRPCRequest
		if conn.ReadJSON(&request) == nil {
			conn.WriteJSON(map[string]any{"id": request.ID, "result": sourceRPCResult(t, request), "error": nil})
		}
		// A reconnect must not resume with a genesis/data request under the
		// previous socket's successful network check.
	})
	source := sourceRPCClient(t, server)
	for i := 0; i < 2; i++ {
		if hash, err := source.BlockHash(context.Background(), 0); !errors.Is(err, ErrRecoverySource) || hash != (chainhash.Hash{}) {
			t.Fatal("source resumed onto an unchecked replacement socket", err)
		}
	}
}

func TestRecoveryRPCSourceCancellationDuringHandshake(t *testing.T) {
	for _, phase := range []string{"http-upgrade", "tls-handshake"} {
		for _, closeSource := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/close=%v", phase, closeSource), func(t *testing.T) {
				entered, socketClosed := make(chan struct{}), make(chan struct{})
				var endpoint string
				if phase == "http-upgrade" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						close(entered)
						<-r.Context().Done()
						close(socketClosed)
					}))
					t.Cleanup(server.Close)
					endpoint = "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
				} else {
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					endpoint = "wss://" + listener.Addr().String() + "/ws"
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						close(entered)
						io.Copy(io.Discard, conn)
						close(socketClosed)
					}()
				}
				source, err := NewRecoveryRPCSource(RecoveryRPCConfig{URL: endpoint, Username: "fixture", Password: "PUBLIC-TEST-PASSWORD"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { source.Close() })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := source.Identity(ctx); result <- err }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("handshake never began")
				}
				want := context.Canceled
				closeDone := make(chan struct{})
				if closeSource {
					want = ErrRecoveryClosed
					go func() { source.Close(); close(closeDone) }()
				} else {
					cancel()
					close(closeDone)
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("handshake cancellation did not close socket")
				}
				select {
				case <-socketClosed:
				case <-time.After(time.Second):
					t.Fatal("peer socket remains open")
				}
				select {
				case <-closeDone:
				case <-time.After(time.Second):
					t.Fatal("Close failed to join handshake")
				}
			})
		}
	}
}
