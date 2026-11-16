package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btclog"
)

// The daemon must join its connection loop even when no wallet has yet loaded
// and the node never completes the WebSocket handshake.
func TestConnectionLoopDrainsCanceledHandshake(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}))
	defer node.Close()
	defer close(release)
	previous := cfg
	previousLog := log
	log = btclog.Disabled
	defer func() { log = previousLog }()
	cfg = &config{DisableClientTLS: true, RPCConnect: strings.TrimPrefix(node.URL, "http://"),
		SlugdUsername: "public-fixture", SlugdPassword: "public-fixture"}
	defer func() { cfg = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rpcClientConnectLoop(ctx, nil, nil)
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("node connection was not attempted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon connection loop did not drain after cancellation")
	}
}
