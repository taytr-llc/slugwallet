package chain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/rpcclient"
	"github.com/taytr-llc/slug/wire/v2"
)

type identityNode struct {
	server          *httptest.Server
	mu              sync.Mutex
	connections     int
	calls           []string
	wrongNetwork    bool
	wrongGenesis    bool
	disconnectSpend bool
	badBestBlock    bool
}

func newIdentityNode(t *testing.T) *identityNode {
	t.Helper()
	n := &identityNode{}
	n.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer ws.Close()
		n.mu.Lock()
		n.connections++
		n.mu.Unlock()
		for {
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if ws.ReadJSON(&req) != nil {
				return
			}
			n.mu.Lock()
			n.calls = append(n.calls, req.Method)
			wrongNetwork, wrongGenesis, disconnect := n.wrongNetwork, n.wrongGenesis, n.disconnectSpend
			badBest := n.badBestBlock
			n.mu.Unlock()
			var result any
			switch req.Method {
			case "getcurrentnet":
				// Unsolicited data on an unverified transport must not reach the wallet.
				_ = ws.WriteJSON(map[string]any{"jsonrpc": "1.0", "id": nil, "method": "blockconnected", "params": []any{strings.Repeat("1", 64), 999, int64(1)}})
				result = uint32(chaincfg.MainNetParams.Net)
				if wrongNetwork {
					result = uint32(1)
				}
			case "getblockhash":
				result = chaincfg.MainNetParams.GenesisHash.String()
				if wrongGenesis {
					result = strings.Repeat("2", 64)
				}
			case "getbestblock":
				result = map[string]any{"hash": chaincfg.MainNetParams.GenesisHash.String(), "height": 0}
				if badBest {
					result = false
				}
			case "getinfo":
				result = map[string]any{"version": 270000}
			case "sendrawtransaction":
				if disconnect {
					return
				}
				result = strings.Repeat("3", 64)
			default:
				result = true
			}
			if ws.WriteJSON(map[string]any{"id": req.ID, "result": result, "error": nil}) != nil {
				return
			}
		}
	}))
	t.Cleanup(n.server.Close)
	return n
}
func (n *identityNode) client(t *testing.T) *RPCClient {
	t.Helper()
	c, e := NewRPCClient(&chaincfg.MainNetParams, strings.TrimPrefix(n.server.URL, "http://"), "public-fixture", "public-fixture", nil, true, 1)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Stop(); c.WaitForShutdown() })
	return c
}
func waitIdentityShutdown(t *testing.T, c *RPCClient) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.WaitForShutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wrapper did not drain after transport stopped")
	}
}
func TestIdentityRequiresNetworkAndGenesisBeforeNotification(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-network", "wrong-genesis"} {
		t.Run(kind, func(t *testing.T) {
			n := newIdentityNode(t)
			n.wrongNetwork = kind == "wrong-network"
			n.wrongGenesis = kind == "wrong-genesis"
			c := n.client(t)
			e := c.Start(context.Background())
			if kind != "valid" {
				if e == nil {
					t.Fatal("foreign chain accepted")
				}
				waitIdentityShutdown(t, c)
				if event, ok := <-c.Notifications(); ok {
					t.Fatalf("unverified event escaped: %T", event)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			select {
			case event := <-c.Notifications():
				if _, ok := event.(ClientConnected); !ok {
					t.Fatalf("preidentity notification escaped: %T", event)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connection event missing")
			}
			if !c.verified.Load() {
				t.Fatal("verified event did not open notification gate")
			}
			c.onBlockConnected(chaincfg.MainNetParams.GenesisHash, 0, time.Unix(1, 0))
			select {
			case event := <-c.Notifications():
				if _, ok := event.(BlockConnected); !ok {
					t.Fatalf("validated notification missing: %T", event)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("validated event missing")
			}
		})
	}
}
func TestTransportReplacementRevalidatesWithoutReplayingSpend(t *testing.T) {
	n := newIdentityNode(t)
	n.disconnectSpend = true
	first := n.client(t)
	if e := first.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	<-first.Notifications()
	if _, e := first.SendRawTransaction(wire.NewMsgTx(2), false); e == nil {
		t.Fatal("lost submission incorrectly acknowledged")
	}
	waitIdentityShutdown(t, first)
	n.mu.Lock()
	n.wrongGenesis = true
	n.mu.Unlock()
	second := n.client(t)
	if e := second.Start(context.Background()); e == nil {
		t.Fatal("replacement foreign genesis accepted")
	}
	waitIdentityShutdown(t, second)
	n.mu.Lock()
	defer n.mu.Unlock()
	spends := 0
	for _, method := range n.calls {
		if method == "sendrawtransaction" {
			spends++
		}
	}
	if n.connections != 2 || spends != 1 {
		t.Fatalf("unexpected transport replay: connections=%d spends=%d", n.connections, spends)
	}
}
func TestCustomCallbacksCannotBypassIdentityGate(t *testing.T) {
	_, e := NewRPCClientWithConfig(&RPCClientConfig{Chain: &chaincfg.MainNetParams, Conn: &rpcclient.ConnConfig{DisableTLS: true}, NotificationHandlers: &rpcclient.NotificationHandlers{}})
	if e == nil {
		t.Fatal("custom callbacks bypassed verified queue")
	}
}

func TestInitialBestBlockFailureClosesNotifications(t *testing.T) {
	n := newIdentityNode(t)
	n.badBestBlock = true
	c := n.client(t)
	if e := c.Start(context.Background()); e == nil {
		t.Fatal("invalid initial best block accepted")
	}
	waitIdentityShutdown(t, c)
	if event, open := <-c.Notifications(); open {
		t.Fatalf("terminal notification channel remained open: %T", event)
	}
}

// Cancellation must close the actual transport before the stalled handshake
// completes, without publishing any wallet notification.
func TestCanceledHandshakeCannotAuthorizeLateConnection(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		ws, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer ws.Close()
		for {
			if _, _, e := ws.ReadMessage(); e != nil {
				return
			}
		}
	}))
	defer s.Close()
	c, e := NewRPCClient(&chaincfg.MainNetParams, strings.TrimPrefix(s.URL, "http://"), "fixture", "fixture", nil, true, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Stop()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake was not attempted")
	}
	cancel()
	select {
	case e := <-done:
		if e != context.Canceled {
			t.Fatalf("canceled start: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled startup waited for the stalled handshake")
	}
	waitIdentityShutdown(t, c)
	if c.verified.Load() {
		t.Fatal("canceled connection became verified")
	}
}
