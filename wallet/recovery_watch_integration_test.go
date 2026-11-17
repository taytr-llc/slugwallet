//go:build integration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type maximumWatchRPC struct {
	chain.Interface
	conn                     *websocket.Conn
	id                       uint64
	notifyCalls, rescanCalls int
	notifyBytes, rescanBytes int
	maxNotifyBytes           int
}

func (r *maximumWatchRPC) call(command any, result any) error {
	r.id++
	raw, err := btcjson.MarshalCmd(btcjson.RpcVersion1, r.id, command)
	if err != nil {
		return err
	}
	switch command.(type) {
	case *btcjson.NotifyReceivedCmd:
		r.notifyCalls++
		r.notifyBytes += len(raw)
		if len(raw) > r.maxNotifyBytes {
			r.maxNotifyBytes = len(raw)
		}
	case *btcjson.RescanCmd:
		r.rescanCalls++
		r.rescanBytes += len(raw)
	}
	if err := r.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	if err := r.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		return err
	}
	if err := r.conn.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		return err
	}
	for {
		_, raw, err := r.conn.ReadMessage()
		if err != nil {
			return err
		}
		var reply struct {
			ID     *uint64           `json:"id"`
			Result json.RawMessage   `json:"result"`
			Error  *btcjson.RPCError `json:"error"`
		}
		if json.Unmarshal(raw, &reply) != nil {
			return fmt.Errorf("invalid fixture RPC response")
		}
		if reply.ID == nil {
			continue
		}
		if *reply.ID != r.id || reply.Error != nil {
			return fmt.Errorf("fixture RPC rejected request")
		}
		if result != nil {
			return json.Unmarshal(reply.Result, result)
		}
		return nil
	}
}
func (r *maximumWatchRPC) NotifyReceived(addrs []address.Address) error {
	a := make([]string, len(addrs))
	for i, x := range addrs {
		a[i] = x.EncodeAddress()
	}
	return r.call(btcjson.NewNotifyReceivedCmd(a), nil)
}
func (r *maximumWatchRPC) Rescan(hash *chainhash.Hash, addrs []address.Address, outpoints map[wire.OutPoint]address.Address) error {
	a := make([]string, len(addrs))
	for i, x := range addrs {
		a[i] = x.EncodeAddress()
	}
	o := make([]btcjson.OutPoint, 0, len(outpoints))
	for x := range outpoints {
		o = append(o, btcjson.OutPoint{Hash: x.Hash.String(), Index: x.Index})
	}
	return r.call(btcjson.NewRescanCmd(hash.String(), a, o, nil), nil)
}

func maximumNodeRSS(pid int) int64 {
	output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return -1
	}
	return n * 1024
}

// TestRecoveryMaximumWatchNormalNode is opt-in because it materializes the
// complete65,536-address supported inventory and starts one isolated node.
// It never mines or submits a transaction. Resource measurements are distinct
// from the separately funded normal-PoW restoration/spending acceptance.
func TestRecoveryMaximumWatchNormalNode(t *testing.T) {
	if os.Getenv("SLUG_RECOVERY_BENCH") != "1" {
		t.Skip("explicit maximum-inventory measurement")
	}
	binary := os.Getenv("SLUG_WALLET_NODE")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("SLUG_WALLET_NODE must name the frozen normal node")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() {
		t.Fatal("normal node binary unavailable")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cursors := productionprofile.DefaultCursors()
	cursors[3].NextInternal = waddrmgr.RecoveryAttemptLimit - 8*waddrmgr.RecoveryLookahead
	bundle, err := productionprofile.FixtureExport(ctx, productionprofile.CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLoader(&chaincfg.MainNetParams, filepath.Join(t.TempDir(), "wallet"), true, time.Second, 0)
	s, err := l.BeginCandidateRecovery(ctx, retainedPubPass, retainedPrivPass, bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	steps := 0
	for {
		p, err := s.Step(ctx, source)
		if err != nil {
			t.Fatal(err)
		}
		steps++
		if p.Ready {
			break
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	w, err := l.OpenExistingWallet(retainedPubPass, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.UnloadWallet()
	derivationTime := time.Since(started)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	nodeDir := t.TempDir()
	config := filepath.Join(nodeDir, "slug.conf")
	const password = "PUBLIC-MAXIMUM-WATCH-FIXTURE"
	contents := fmt.Sprintf("rpcuser=fixture\nrpcpass=%s\nnotls=1\nrpclisten=127.0.0.1:%d\nnolisten=1\nnodnsseed=1\nconnect=127.0.0.1:0\ndatadir=%s\nlogdir=%s\n", password, port, filepath.Join(nodeDir, "data"), filepath.Join(nodeDir, "logs"))
	if err := os.WriteFile(config, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(nodeDir, "node.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "--configfile="+config)
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); log.Close() }()
	defer func() {
		_ = command.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("node shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("node required forced stop")
		}
	}()
	dialer := websocket.Dialer{Proxy: nil, HandshakeTimeout: time.Second}
	header := http.Header{"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:"+password))}}
	var conn *websocket.Conn
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		conn, _, err = dialer.DialContext(ctx, fmt.Sprintf("ws://127.0.0.1:%d/ws", port), header)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatal("node startup", err)
	}
	defer conn.Close()
	conn.SetReadLimit(8 << 20)
	rpc := &maximumWatchRPC{conn: conn}
	var network uint32
	var genesis string
	if err := rpc.call(btcjson.NewGetCurrentNetCmd(), &network); err != nil || network != uint32(chaincfg.MainNetParams.Net) {
		t.Fatal("wrong network", err)
	}
	if err := rpc.call(btcjson.NewGetBlockHashCmd(0), &genesis); err != nil || genesis != chaincfg.MainNetParams.GenesisHash.String() {
		t.Fatal("wrong genesis", err)
	}
	var peers []json.RawMessage
	if err := rpc.call(btcjson.NewGetPeerInfoCmd(), &peers); err != nil || len(peers) != 0 {
		t.Fatal("node was not isolated", err)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	rssBefore := maximumNodeRSS(command.Process.Pid)
	var peak atomic.Uint64
	peak.Store(baseline.HeapAlloc)
	monitorStop, monitorDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-monitorStop:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for old := peak.Load(); m.HeapAlloc > old && !peak.CompareAndSwap(old, m.HeapAlloc); old = peak.Load() {
				}
			}
		}
	}()
	stopMonitor := func() {
		select {
		case <-monitorStop:
		default:
			close(monitorStop)
		}
		<-monitorDone
	}
	defer stopMonitor()
	watchStarted := time.Now()
	var addrs []address.Address
	if err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		return w.Manager.ForEachRelevantActiveAddress(tx.ReadBucket(waddrmgrNamespaceKey), func(a address.Address) error { addrs = append(addrs, a); return nil })
	}); err != nil {
		t.Fatal(err)
	}
	if len(addrs) != int(waddrmgr.RecoveryAttemptLimit) {
		t.Fatal("maximum inventory was not exact", len(addrs))
	}
	batch := &rescanBatch{addrs: addrs, outpoints: make(map[wire.OutPoint]address.Address), bs: w.Manager.SyncedTo()}
	for i := 0; i < MaxRecoveryOwnedOutputs; i++ {
		batch.outpoints[wire.OutPoint{Index: uint32(i)}] = addrs[0]
	}
	if err := w.rescanCandidate(rpc, batch); err != nil {
		t.Fatal("actual maximum node watch rejected", err)
	}
	stopMonitor()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if rpc.notifyCalls != 512 || rpc.rescanCalls != 1 || rpc.rescanBytes > MaxRecoveryWatchRequestBytes {
		t.Fatal("unexpected maximum watch calls", rpc.notifyCalls, rpc.rescanCalls, rpc.rescanBytes)
	}
	report := map[string]any{"fixture_only": true, "normal_node_binary": binary, "addresses": len(addrs), "watched_outpoints": len(batch.outpoints), "steps": steps, "derivation_and_open_seconds": derivationTime.Seconds(), "watch_seconds": time.Since(watchStarted).Seconds(), "notify_calls": rpc.notifyCalls, "notify_json_bytes": rpc.notifyBytes, "max_notify_json_bytes": rpc.maxNotifyBytes, "rescan_calls": rpc.rescanCalls, "rescan_json_bytes": rpc.rescanBytes, "wallet_heap_before_bytes": baseline.HeapAlloc, "wallet_heap_peak_sampled_bytes": peak.Load(), "wallet_heap_after_gc_bytes": after.HeapAlloc, "node_rss_before_bytes": rssBefore, "node_rss_after_bytes": maximumNodeRSS(command.Process.Pid), "node_go_heap_measured": false, "note": "Node pprof binds all interfaces; it was not enabled. RSS is not Go heap. No blocks mined or transactions submitted.", "elapsed_seconds": time.Since(started).Seconds()}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
	if path := os.Getenv("SLUG_RECOVERY_BENCH_REPORT"); path != "" {
		if !filepath.IsAbs(path) {
			t.Fatal("report path must be absolute")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write(append(raw, '\n'))
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(writeErr, closeErr)
		}
	}
	runtime.KeepAlive(batch)
}
