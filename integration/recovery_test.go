//go:build integration && recoveryintegration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/rpc/legacyrpc"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/wallet"
)

type recoveryAddress struct {
	Path    string `json:"path"`
	Address string `json:"address"`
}

type recoveryFixture struct {
	Name      string            `json:"name"`
	Entropy   string            `json:"entropy"`
	Export    recovery.Export   `json:"export"`
	Addresses []recoveryAddress `json:"addresses"`
}

func recoveryVectors(t *testing.T) recoveryFixture {
	t.Helper()
	raw, err := os.ReadFile("../recovery/testdata/recovery_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		FixtureOnly bool              `json:"fixture_only"`
		Cases       []recoveryFixture `json:"cases"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || !document.FixtureOnly {
		t.Fatal("invalid independent recovery fixture", err)
	}
	for _, fixture := range document.Cases {
		if fixture.Name == "zero256" {
			extra, err := os.ReadFile("testdata/recovery_highwater_v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var highwater struct {
				FixtureOnly bool              `json:"fixture_only"`
				Entropy     string            `json:"entropy"`
				Addresses   []recoveryAddress `json:"addresses"`
			}
			if err := json.Unmarshal(extra, &highwater); err != nil || !highwater.FixtureOnly || highwater.Entropy != fixture.Entropy {
				t.Fatal("invalid independent high-water fixture", err)
			}
			for _, value := range highwater.Addresses {
				found := false
				for _, existing := range fixture.Addresses {
					if value.Path == existing.Path {
						found = true
						if value.Address != existing.Address {
							t.Fatal("independent fixtures disagree")
						}
					}
				}
				if !found {
					fixture.Addresses = append(fixture.Addresses, value)
				}
			}
			return fixture
		}
	}
	t.Fatal("published zero256 recovery fixture missing")
	return recoveryFixture{}
}

func (fixture recoveryFixture) address(t *testing.T, path string) string {
	t.Helper()
	for _, value := range fixture.Addresses {
		if value.Path == path {
			return value.Address
		}
	}
	t.Fatalf("independent address fixture missing: %s", path)
	return ""
}

// attachRecoveryWallet deliberately shares the existing loopback RPC lifecycle
// without modifying the set-23 foundation gate. Creation and restoration use
// the new library APIs; addresses, balances and spending use wallet RPC.
func attachRecoveryWallet(t *testing.T, loader *wallet.Loader,
	w *wallet.Wallet, n *node) *session {

	t.Helper()
	s := &session{wallet: w, loader: loader}
	t.Cleanup(func() { s.close(t) })
	backend, err := chain.NewRPCClient(&chaincfg.MainNetParams,
		strings.TrimPrefix(n.rpc.url, "http://"), "fixture", fixturePass,
		nil, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.backend = backend
	startup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := backend.Start(startup); err != nil {
		t.Fatal("recovery wallet node identity/connect:", err)
	}
	w.SynchronizeRPC(backend)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.server = legacyrpc.NewServer(&legacyrpc.Options{
		Username: "fixture", Password: fixturePass,
		MaxPOSTClients: 4, MaxWebsocketClients: 4,
	}, loader, []net.Listener{listener})
	s.server.RegisterWallet(w)
	s.server.SetChainServer(backend)
	s.rpc = newRPC("http://" + listener.Addr().String())
	return s
}

func recoveryLoader(path string) *wallet.Loader {
	// A default 20-address lookahead cannot find receive index 25 across an
	// otherwise unused branch. The exported high-water metadata must supply it.
	return wallet.NewLoader(&chaincfg.MainNetParams, path, false,
		10*time.Second, 20, wallet.WithWalletSyncRetryInterval(50*time.Millisecond))
}

func exportRecoveryFixture(t *testing.T, w *wallet.Wallet) recovery.Export {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bundle, err := w.ExportRecovery(ctx)
	if err != nil {
		t.Fatal("retained recovery export:", err)
	}
	return bundle
}

// issueRecoveryAddresses advances every supported scope beyond the ordinary
// recovery gap. Only the selected funding scope receives any coins.
func issueRecoveryAddresses(t *testing.T, s *session, fixture recoveryFixture) {
	t.Helper()
	for _, purpose := range []uint32{44, 49, 84, 86} {
		for branch := 0; branch < 2; branch++ {
			last := 25 + branch
			for index := 0; index <= last; index++ {
				var encoded string
				if purpose == 86 {
					scope := waddrmgr.KeyScopeBIP0086
					if branch == 0 {
						value, err := s.wallet.NewAddress(0, scope)
						if err != nil {
							t.Fatal(err)
						}
						encoded = value.EncodeAddress()
					} else {
						value, err := s.wallet.NewChangeAddress(0, scope)
						if err != nil {
							t.Fatal(err)
						}
						encoded = value.EncodeAddress()
					}
				} else {
					kinds := map[uint32]string{44: "legacy", 49: "p2sh-segwit", 84: "bech32"}
					method := "getnewaddress"
					if branch == 1 {
						method = "getrawchangeaddress"
					}
					s.rpc.must(t, method, []any{"default", kinds[purpose]}, &encoded)
				}
				if index == 0 || index == last {
					path := fmt.Sprintf("m/%d'/0'/0'/%d/%d", purpose, branch, index)
					if encoded != fixture.address(t, path) {
						t.Fatalf("independent address mismatch at %s", path)
					}
				}
			}
		}
	}
}

func assertRecoveryProfile(t *testing.T, actual, expected recovery.Export) {
	t.Helper()
	if actual.Version != expected.Version || actual.Mnemonic != expected.Mnemonic {
		t.Fatal("retained phrase does not match the independent public fixture")
	}
	// The identity/profile must be exact; account cursors reflect actual use.
	actualManifest, expectedManifest := actual.Manifest, expected.Manifest
	actualManifest.Accounts = nil
	expectedManifest.Accounts = nil
	if !reflect.DeepEqual(actualManifest, expectedManifest) {
		t.Fatal("retained profile or public identity differs from independent derivation")
	}
	if len(actual.Manifest.Accounts) != 4 {
		t.Fatal("export omitted a supported derivation scope")
	}
	for index, account := range actual.Manifest.Accounts {
		shape := account
		shape.NextExternal, shape.NextInternal = 0, 0
		want := expected.Manifest.Accounts[index]
		want.NextExternal, want.NextInternal = 0, 0
		if shape != want {
			t.Fatal("export changed the supported account/schema inventory")
		}
		if account.NextExternal < 26 || account.NextInternal < 27 {
			t.Fatalf("export lost beyond-gap high-water indexes: %+v", account)
		}
	}
}

func TestWalletRecoveryNormalPoW(t *testing.T) {
	// The original set24 gate uses legacy funding. The separate activation
	// gate exercises each supported funding type under the node's real rules.
	runWalletRecoveryNormalPoW(t, 44)
}

type recoveryGateHooks struct {
	activation        func(*testing.T, *node, int32)
	firstConfirmation func(*testing.T, *node, *session, *int32, string, string)
	spends            func(*testing.T, uint32, *wire.MsgTx, *wire.MsgTx)
}

// A later activation test can use the same lifecycle with another funding
// scope and explicit RPC support; selecting a scope never changes node rules.
func runWalletRecoveryNormalPoW(t *testing.T, fundingPurpose uint32, optionalHooks ...recoveryGateHooks) {
	var hooks recoveryGateHooks
	if len(optionalHooks) != 0 {
		hooks = optionalHooks[0]
	}
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
	fixture := recoveryVectors(t)
	decoded, err := hex.DecodeString(fixture.Entropy)
	if err != nil || len(decoded) != 32 {
		t.Fatal("invalid public entropy fixture")
	}
	var entropy [32]byte
	copy(entropy[:], decoded)
	payout := fixture.address(t, fmt.Sprintf("m/%d'/0'/0'/0/25", fundingPurpose))
	n := startNode(t, binary, payout)
	originalPath := filepath.Join(t.TempDir(), "original-recovery-wallet")
	loader := recoveryLoader(originalPath)
	w, err := loader.CreateNewRecoveryWallet([]byte(fixturePass),
		[]byte(fixturePass), entropy, time.Unix(0, 0))
	if err != nil {
		t.Fatal("create recovery wallet:", err)
	}
	original := attachRecoveryWallet(t, loader, w, n)
	checkRecoveryGym(t, original.wallet, fixture)
	// Only funding index25 receives coins; all earlier addresses are unused.
	issueRecoveryAddresses(t, original, fixture)
	var height int32
	mine(t, n, original, 1, &height)
	account, err := original.wallet.CalculateAccountBalances(0, 1)
	if err != nil || int64(account.ImmatureReward) != 10e8 || balance(t, original) != 0 {
		t.Fatal("normal 10-SLUG reward missing or prematurely spendable", err)
	}
	if hooks.activation == nil {
		mine(t, n, original, 99, &height)
	} else {
		mine(t, n, original, 59, &height)
		hooks.activation(t, n, height)
		mine(t, n, original, 1, &height)
		hooks.activation(t, n, height)
		mine(t, n, original, 1, &height)
		hooks.activation(t, n, height)
		mine(t, n, original, 38, &height)
	}
	if balance(t, original) != 10e8 {
		t.Fatal("normal 100-confirmation maturity not reached")
	}
	original.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	sink := fixtureVectors(t).ExternalSink
	var firstSpend string
	original.rpc.must(t, "sendtoaddress", []any{sink, 1.0}, &firstSpend)
	if hooks.firstConfirmation == nil {
		mine(t, n, original, 1, &height)
	} else {
		hooks.firstConfirmation(t, n, original, &height, payout, firstSpend)
	}
	firstHistory := history(t, original, firstSpend)
	if firstHistory["confirmations"].(float64) < 1 {
		t.Fatal("original recovery wallet spend was not confirmed")
	}
	originalBalance := balance(t, original)
	if originalBalance <= 18e8 || originalBalance >= 19e8 {
		t.Fatal("confirmed spend/change/fee balance outside expected interval")
	}
	admission := newRecoveryAdmission(t, n, original.wallet, fixture)
	original.close(t)

	// The later export must come from the reopened encrypted database, never
	// from the test's input entropy, mnemonic, or an in-memory original wallet.
	reopened := openWallet(t, originalPath, nil, n, false)
	waitSync(t, reopened, height)
	checkRecoveryGym(t, reopened.wallet, fixture)
	if balance(t, reopened) != originalBalance || history(t, reopened, firstSpend)["hex"] != firstHistory["hex"] {
		t.Fatal("reopen changed exact balance or confirmed transaction history")
	}
	if _, err := reopened.wallet.ExportRecovery(context.Background()); err == nil {
		t.Fatal("locked wallet revealed retained recovery material")
	}
	reopened.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	bundle := exportRecoveryFixture(t, reopened.wallet)
	assertRecoveryProfile(t, bundle, fixture.Export)
	exported, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(t.TempDir(), "PUBLIC-FIXTURE-recovery.json")
	if err := os.WriteFile(exportPath, exported, 0600); err != nil {
		t.Fatal(err)
	}
	reopened.close(t)
	// Remove access to the original wallet path before restore. The fixture's
	// original seed/entropy variables are not inputs to the restoration API.
	if err := os.Rename(originalPath, originalPath+"-closed-original"); err != nil {
		t.Fatal(err)
	}
	fromDisk, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredExport, err := recovery.ParseExport(fromDisk)
	if err != nil {
		t.Fatal(err)
	}
	restoredLoader := recoveryLoader(filepath.Join(t.TempDir(), "restored-recovery-wallet"))
	restoredWallet, err := restoredLoader.RestoreRecoveryWallet(
		[]byte(fixturePass), []byte(fixturePass), restoredExport)
	if err != nil {
		t.Fatal("restore exported recovery:", err)
	}
	restored := attachRecoveryWallet(t, restoredLoader, restoredWallet, n)
	waitSync(t, restored, height)
	checkRecoveryGym(t, restored.wallet, fixture)
	if got := balance(t, restored); got != originalBalance {
		t.Fatalf("export restore balance %d want exactly %d", got, originalBalance)
	}
	if history(t, restored, firstSpend)["hex"] != firstHistory["hex"] {
		t.Fatal("export restore lost the exact confirmed transaction")
	}
	for _, address := range fixture.Addresses {
		var ownership struct {
			IsMine bool `json:"ismine"`
		}
		restored.rpc.must(t, "validateaddress", []any{address.Address}, &ownership)
		if !ownership.IsMine {
			t.Fatalf("restored wallet does not own %s", address.Path)
		}
	}
	restored.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	assertRecoveryProfile(t, exportRecoveryFixture(t, restored.wallet), fixture.Export)
	admission.checkRestored(t, restored.wallet)
	var secondSpend string
	// More than the one remaining mature 10-SLUG coinbase forces recovery
	// and spending of the first transaction's change as well.
	restored.rpc.must(t, "sendtoaddress", []any{sink, 10.5}, &secondSpend)
	mine(t, n, restored, 1, &height)
	secondHistory := history(t, restored, secondSpend)
	if secondHistory["confirmations"].(float64) < 1 {
		t.Fatal("restored exported recovery could not spend")
	}
	secondBytes, err := hex.DecodeString(secondHistory["hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var secondTransaction wire.MsgTx
	if err := secondTransaction.Deserialize(bytes.NewReader(secondBytes)); err != nil {
		t.Fatal(err)
	}
	spentRecoveredChange := false
	for _, input := range secondTransaction.TxIn {
		if input.PreviousOutPoint.Hash.String() == firstSpend {
			spentRecoveredChange = true
		}
	}
	if !spentRecoveredChange {
		t.Fatal("second confirmed spend did not consume the recovered first-spend change")
	}
	if hooks.spends != nil {
		firstBytes, err := hex.DecodeString(firstHistory["hex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var firstTransaction wire.MsgTx
		if err := firstTransaction.Deserialize(bytes.NewReader(firstBytes)); err != nil {
			t.Fatal(err)
		}
		hooks.spends(t, fundingPurpose, &firstTransaction, &secondTransaction)
	}
	t.Logf("recovery gate passed: scope%d funded, retained phrase after reopen, independent four-scope addresses beyond gap20, exact balance/history, same gym identity and automatic authorizations, fresh authority admission and immutable receipt replay, confirmed spends %s and %s; elapsed %s", fundingPurpose, firstSpend, secondSpend, time.Since(started))
}
