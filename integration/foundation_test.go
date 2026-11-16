//go:build integration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.
package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/rpc/legacyrpc"
	"github.com/taytr-llc/slugwallet/wallet"
	_ "github.com/taytr-llc/slugwallet/walletdb/bdb"
)

// All credentials and seed material in this package are published fixtures.
const fixturePass = "PUBLIC-FIXTURE-ONLY-NOT-A-WALLET"
const genesis = "7893676099cf9985bb198dfb6a347d9422a19f2422cf3326a999a7230ce246cd"

type vectors struct {
	FixtureOnly  bool                                           `json:"fixture_only"`
	Seed         string                                         `json:"seed"`
	Addresses    []struct{ Type, Branch, Path, Address string } `json:"addresses"`
	ExternalSink string                                         `json:"external_sink"`
}

func fixtureVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/addresses_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value vectors
	if err = json.Unmarshal(raw, &value); err != nil || !value.FixtureOnly {
		t.Fatal("invalid fixture", err)
	}
	return value
}

type rpc struct {
	url    string
	client *http.Client
}

func newRPC(url string) rpc {
	return rpc{url, &http.Client{Transport: &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true}, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (r rpc) call(method string, params []any, result any) error {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
	request, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.SetBasicAuth("fixture", fixturePass)
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("RPC HTTP %d", response.StatusCode)
	}
	var envelope struct {
		ID     int
		Result json.RawMessage
		Error  *struct {
			Code    int
			Message string
		}
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.ID != 1 {
		return fmt.Errorf("RPC correlation")
	}
	if envelope.Error != nil {
		return fmt.Errorf("RPC %s (%d): %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}
func (r rpc) must(t *testing.T, method string, params []any, result any) {
	t.Helper()
	if err := r.call(method, params, result); err != nil {
		t.Fatal(err)
	}
}
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

type node struct {
	rpc  rpc
	cmd  *exec.Cmd
	done chan error
	once sync.Once
}

func startNode(t *testing.T, binary, payout string) *node {
	t.Helper()
	root := t.TempDir()
	port := freePort(t)
	config := fmt.Sprintf("rpcuser=fixture\nrpcpass=%s\nnotls=1\nrpclisten=127.0.0.1:%d\nnolisten=1\nnodnsseed=1\nconnect=127.0.0.1:0\ndatadir=%s\nlogdir=%s\nminingaddr=%s\ntxindex=1\n", fixturePass, port, filepath.Join(root, "chain"), filepath.Join(root, "logs"), payout)
	path := filepath.Join(root, "slug.conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(root, "node.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--configfile="+path)
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	n := &node{rpc: newRPC(fmt.Sprintf("http://127.0.0.1:%d", port)), cmd: cmd, done: make(chan error, 1)}
	go func() { n.done <- cmd.Wait(); log.Close() }()
	t.Cleanup(func() {
		n.once.Do(func() {
			_ = n.rpc.call("stop", nil, nil)
			select {
			case err := <-n.done:
				if err != nil {
					t.Errorf("node shutdown: %v", err)
				}
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				<-n.done
				t.Error("node needed forced shutdown")
			}
			n.rpc.client.CloseIdleConnections()
		})
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		var height int
		if n.rpc.call("getblockcount", nil, &height) == nil {
			break
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(filepath.Join(root, "node.log"))
			t.Fatalf("node startup failed: %s", raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var magic uint32
	n.rpc.must(t, "getcurrentnet", nil, &magic)
	if magic != 1397511495 {
		t.Fatal("wrong network")
	}
	var first string
	n.rpc.must(t, "getblockhash", []any{0}, &first)
	if first != genesis {
		t.Fatal("wrong genesis")
	}
	var peers []json.RawMessage
	n.rpc.must(t, "getpeerinfo", nil, &peers)
	if len(peers) != 0 {
		t.Fatal("fixture node connected to a peer")
	}
	return n
}

type session struct {
	wallet  *wallet.Wallet
	loader  *wallet.Loader
	backend *chain.RPCClient
	server  *legacyrpc.Server
	rpc     rpc
	once    sync.Once
}

func openWallet(t *testing.T, root string, seed []byte, n *node, create bool) *session {
	t.Helper()
	loader := wallet.NewLoader(&chaincfg.MainNetParams, root, false, 10*time.Second, 20, wallet.WithWalletSyncRetryInterval(50*time.Millisecond))
	var w *wallet.Wallet
	var err error
	if create {
		w, err = loader.CreateNewWallet([]byte(fixturePass), []byte(fixturePass), seed, time.Unix(0, 0))
	} else {
		w, err = loader.OpenExistingWallet([]byte(fixturePass), false)
	}
	if err != nil {
		t.Fatal("wallet load:", err)
	}
	s := &session{wallet: w, loader: loader}
	t.Cleanup(func() { s.close(t) })
	backend, err := chain.NewRPCClient(&chaincfg.MainNetParams, strings.TrimPrefix(n.rpc.url, "http://"), "fixture", fixturePass, nil, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.backend = backend
	if err = backend.Start(context.Background()); err != nil {
		t.Fatal("chain identity/connect:", err)
	}
	w.SynchronizeRPC(backend)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.server = legacyrpc.NewServer(&legacyrpc.Options{Username: "fixture", Password: fixturePass, MaxPOSTClients: 4, MaxWebsocketClients: 4}, loader, []net.Listener{listener})
	s.server.RegisterWallet(w)
	s.server.SetChainServer(backend)
	s.rpc = newRPC("http://" + listener.Addr().String())
	return s
}
func (s *session) close(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		if s.server != nil {
			s.server.Stop()
		} else if s.backend != nil {
			s.backend.Stop()
			s.backend.WaitForShutdown()
		}
		if err := s.loader.UnloadWallet(); err != nil {
			t.Error("wallet shutdown:", err)
		}
		if s.rpc.client != nil {
			s.rpc.client.CloseIdleConnections()
		}
	})
}
func waitSync(t *testing.T, s *session, height int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if s.wallet.ChainSynced() && s.wallet.Manager.SyncedTo().Height == height {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("wallet sync timeout: got %+v need %d synced=%v", s.wallet.Manager.SyncedTo(), height, s.wallet.ChainSynced())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func mine(t *testing.T, n *node, s *session, count int, height *int32) {
	t.Helper()
	for count > 0 {
		batch := count
		if batch > 10 {
			batch = 10
		}
		var hashes []string
		n.rpc.must(t, "generate", []any{batch}, &hashes)
		if len(hashes) != batch {
			t.Fatal("generate count")
		}
		*height += int32(batch)
		waitSync(t, s, *height)
		count -= batch
		t.Logf("normal Argon2id chain and wallet synced at height %d", *height)
	}
}
func balance(t *testing.T, s *session) int64 {
	t.Helper()
	var value float64
	s.rpc.must(t, "getbalance", []any{"*", 1}, &value)
	return int64(math.Round(value * 1e8))
}
func checkAddresses(t *testing.T, s *session, v vectors) {
	t.Helper()
	for _, expected := range v.Addresses {
		method := "getnewaddress"
		if expected.Branch == "change" {
			method = "getrawchangeaddress"
		}
		var address string
		s.rpc.must(t, method, []any{"default", expected.Type}, &address)
		if address != expected.Address {
			t.Fatalf("independent %s %s: got %s want %s", expected.Type, expected.Path, address, expected.Address)
		}
	}
}
func history(t *testing.T, s *session, txid string) map[string]any {
	t.Helper()
	var result map[string]any
	s.rpc.must(t, "gettransaction", []any{txid}, &result)
	if result["txid"] != txid {
		t.Fatal("missing spend history")
	}
	return result
}

func TestWalletFoundationNormalPoW(t *testing.T) {
	if wire.TestPoW {
		t.Fatal("production PoW required")
	}
	binary := os.Getenv("SLUG_WALLET_NODE")
	if binary == "" {
		t.Skip("set SLUG_WALLET_NODE to an explicitly built normal slugd")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute node binary required")
	}
	version, err := exec.Command(binary, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "slugd version 0.27.0" {
		t.Fatal("normal slugd binary required")
	}
	started := time.Now()
	v := fixtureVectors(t)
	seed, err := hex.DecodeString(v.Seed)
	if err != nil {
		t.Fatal(err)
	}
	n := startNode(t, binary, v.Addresses[0].Address)
	root := filepath.Join(t.TempDir(), "original-wallet")
	s := openWallet(t, root, seed, n, true)
	// A fresh genesis-only node is intentionally not "current" by wallet
	// timestamp policy. Derive addresses first, then mine its first current block.
	checkAddresses(t, s, v)
	var height int32
	mine(t, n, s, 1, &height)
	if got := balance(t, s); got != 0 {
		t.Fatalf("immature spendable balance: %d", got)
	}
	account, err := s.wallet.CalculateAccountBalances(0, 1)
	if err != nil || int64(account.ImmatureReward) != 10e8 {
		t.Fatalf("10 SLUG reward missing: %+v %v", account, err)
	}
	s.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	var early string
	if err = s.rpc.call("sendtoaddress", []any{v.ExternalSink, 1.0}, &early); err == nil {
		t.Fatal("spent immature coinbase")
	}
	mine(t, n, s, 98, &height)
	if got := balance(t, s); got != 0 {
		t.Fatalf("99 confirmations were treated as mature: %d", got)
	}
	mine(t, n, s, 1, &height)
	if got := balance(t, s); got != 10e8 {
		t.Fatalf("100 confirmations maturity: got %d want %d", got, int64(10e8))
	}
	var spend string
	s.rpc.must(t, "sendtoaddress", []any{v.ExternalSink, 1.0}, &spend)
	var mempool []string
	n.rpc.must(t, "getrawmempool", nil, &mempool)
	if len(mempool) != 1 || mempool[0] != spend {
		t.Fatal("signed spend not accepted by normal node")
	}
	mine(t, n, s, 1, &height)
	tx := history(t, s, spend)
	if tx["confirmations"].(float64) < 1 {
		t.Fatal("spend not confirmed")
	}
	originalBalance := balance(t, s)
	if originalBalance <= 18e8 || originalBalance >= 19e8 {
		t.Fatalf("spend/change/fee balance outside expected interval: %d", originalBalance)
	}
	originalHex := tx["hex"]
	s.close(t)
	reopened := openWallet(t, root, nil, n, false)
	waitSync(t, reopened, height)
	if balance(t, reopened) != originalBalance || history(t, reopened, spend)["hex"] != originalHex {
		t.Fatal("restart changed balance or transaction history")
	}
	reopened.close(t)
	restored := openWallet(t, filepath.Join(t.TempDir(), "restored-wallet"), seed, n, true)
	// Recovery scans both branches with the explicit lookahead window; do not
	// race its discovered indexes by asking for a new first address mid-rescan.
	waitSync(t, restored, height)
	var ownership struct {
		IsMine bool `json:"ismine"`
	}
	restored.rpc.must(t, "validateaddress", []any{v.Addresses[0].Address}, &ownership)
	if !ownership.IsMine {
		t.Fatal("restored seed does not own independent receive address")
	}
	if got := balance(t, restored); got != originalBalance {
		t.Fatalf("seed restore balance %d want %d", got, originalBalance)
	}
	if history(t, restored, spend)["hex"] != originalHex {
		t.Fatal("seed restore lost signed spend history")
	}
	restored.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	var restoredSpend string
	restored.rpc.must(t, "sendtoaddress", []any{v.ExternalSink, 0.5}, &restoredSpend)
	mine(t, n, restored, 1, &height)
	if history(t, restored, restoredSpend)["confirmations"].(float64) < 1 {
		t.Fatal("restored seed could not spend")
	}
	t.Logf("foundation gate passed: legacy and slug witness addresses, 10 SLUG reward, exact 100-confirmation maturity, signed spend %s, reopen, seed restore and second spend %s; elapsed %s", spend, restoredSpend, time.Since(started))
}
