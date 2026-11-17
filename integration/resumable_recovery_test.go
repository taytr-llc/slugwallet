//go:build integration && recoveryintegration && candidateintegration && resumablerecoveryintegration && !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/wallet"
	"github.com/taytr-llc/slugwallet/walletdb"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Reopening uses only public encryption access. No fixture entropy is supplied
// after Begin; Status and pending handles never expose a usable wallet.
func runResumableRecovery(t *testing.T, loader *wallet.Loader, current *wallet.RecoverySession, source wallet.RecoveryBlockSource, interrupt bool) {
	t.Helper()
	defer func() {
		if err := current.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	before, err := current.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancelStep := context.WithCancel(ctx)
	cancelStep()
	if _, err := current.Step(canceled, source); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled step", err)
	}
	after, err := current.Status(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("cancellation changed progress", err)
	}
	restartedDerive, restartedScan := false, false
	for steps := 0; steps < 2000; steps++ {
		progress, err := current.Step(ctx, source)
		if err != nil {
			t.Fatalf("recovery step %d: %v", steps, err)
		}
		if progress.Ready {
			if interrupt && (!restartedDerive || !restartedScan) {
				t.Fatal("restart coverage missing")
			}
			t.Logf("resumable recovery ready after %d steps: %+v", steps+1, progress)
			return
		}
		restart := interrupt && ((!restartedDerive && progress.Derived > 0 && progress.Derived < progress.Target) || (!restartedScan && progress.ScannedHeight >= 10))
		if restart {
			if progress.Derived < progress.Target {
				restartedDerive = true
			} else {
				restartedScan = true
			}
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
			if w, err := loader.OpenExistingWallet([]byte(fixturePass), false); err == nil || w != nil {
				t.Fatal("pending wallet opened")
			}
			current, err = loader.OpenCandidateRecovery(ctx, []byte(fixturePass))
			if err != nil {
				t.Fatal("resume", err)
			}
			reopened, err := current.Status(ctx)
			if err != nil || !reflect.DeepEqual(progress, reopened) {
				t.Fatal("restart changed committed progress", err)
			}
		}
	}
	t.Fatal("recovery exceeded bounded step count")
}

func TestResumableRecoveryNormalPoW(t *testing.T) {
	binary := os.Getenv("SLUG_WALLET_NODE")
	if binary == "" {
		t.Skip("set SLUG_WALLET_NODE to an explicitly built normal slugd")
	}
	if !filepath.IsAbs(binary) || wire.TestPoW {
		t.Fatal("absolute production-PoW node required")
	}
	version, err := exec.Command(binary, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "slugd version 0.27.0" {
		t.Fatal("normal slugd binary required")
	}
	started := time.Now()
	var endpoints []string
	var ownedNode *node
	result := map[string]any{"status": "incomplete", "fixture_only": true}
	// Register first so this observes shutdown after the node and every wallet.
	t.Cleanup(func() {
		checks := make([]map[string]any, 0, len(endpoints))
		for _, endpoint := range endpoints {
			u, err := url.Parse(endpoint)
			if err != nil {
				t.Error(err)
				continue
			}
			conn, err := net.DialTimeout("tcp", u.Host, 300*time.Millisecond)
			closed := err != nil
			if conn != nil {
				conn.Close()
				t.Error("fixture listener survived cleanup", u.Host)
			}
			checks = append(checks, map[string]any{"address": u.Host, "closed": closed})
		}
		result["listeners"] = checks
		if ownedNode != nil {
			result["node_pid"] = ownedNode.cmd.Process.Pid
			exited := ownedNode.cmd.ProcessState != nil && ownedNode.cmd.ProcessState.Exited()
			result["node_exited"] = exited
			if !exited {
				t.Error("fixture node did not exit")
			}
		}
		if t.Failed() {
			result["status"] = "failed"
		}
		if directory := os.Getenv("SLUG_RESUMABLE_TEST_ARTIFACTS"); directory != "" {
			if !filepath.IsAbs(directory) {
				t.Error("absolute artifact directory required")
				return
			}
			raw, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(filepath.Join(directory, "result.json"), append(raw, '\n'), 0600); err != nil {
				t.Error(err)
			}
		}
	})
	fixture := candidateReference(t)
	n := startNode(t, binary, fixture.payment(t, 44, 0, 4096).Address)
	ownedNode = n
	endpoints = append(endpoints, n.rpc.url)
	originalPath := filepath.Join(t.TempDir(), "candidate-original")
	loader := recoveryLoader(originalPath)
	source, err := wallet.NewRecoveryRPCSource(wallet.RecoveryRPCConfig{
		URL:      "ws" + strings.TrimPrefix(n.rpc.url, "http") + "/ws",
		Username: "fixture", Password: fixturePass,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Identity(context.Background()); err != nil {
		t.Fatal("actual source identity", err)
	}
	if _, err := source.BestBlock(context.Background()); err != nil {
		t.Fatal("actual source tip", err)
	}
	initialHash, err := source.BlockHash(context.Background(), 0)
	if err != nil {
		t.Fatal("actual source genesis hash", err)
	}
	if _, err := source.Block(context.Background(), initialHash); err != nil {
		t.Fatal("actual source genesis block", err)
	}
	recovering, err := loader.BeginCandidateFixture(context.Background(), []byte(fixturePass), []byte(fixturePass), fixture.Name)
	if err != nil {
		t.Fatal(err)
	}
	runResumableRecovery(t, loader, recovering, source, false)
	w, err := loader.OpenExistingWallet([]byte(fixturePass), false)
	if err != nil {
		t.Fatal(err)
	}
	// Real manager allocations in bounded transactions advance the unused
	// prefix. No direct database cursor patch and no claimed RPC issuance.
	if err := w.Unlock([]byte(fixturePass), nil); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []uint32{44, 49, 84, 86} {
		manager, err := w.Manager.FetchScopedKeyManager(waddrmgr.KeyScope{Purpose: purpose, Coin: productionprofile.CandidateCoinType})
		if err != nil {
			t.Fatal(err)
		}
		for branch := uint32(0); branch < 2; branch++ {
			for next := uint32(0); next < 4096; next += 128 {
				err := walletdb.Update(w.Database(), func(tx walletdb.ReadWriteTx) error {
					ns := tx.ReadWriteBucket([]byte("waddrmgr"))
					var addresses []waddrmgr.ManagedAddress
					var err error
					if branch == 0 {
						addresses, err = manager.NextExternalAddresses(ns, 0, 128)
					} else {
						addresses, err = manager.NextInternalAddresses(ns, 0, 128)
					}
					if err == nil && len(addresses) != 128 {
						return fmt.Errorf("short actual allocation")
					}
					return err
				})
				if err != nil {
					t.Fatal(purpose, branch, next, err)
				}
			}
		}
	}
	if err := loader.UnloadWallet(); err != nil {
		t.Fatal(err)
	}
	original := openWallet(t, originalPath, nil, n, false)
	endpoints = append(endpoints, original.rpc.url)
	w = original.wallet
	// Genesis has an old timestamp; normal backend readiness starts after
	// the first freshly mined private block, as in the existing foundation gate.
	identity, err := w.CandidateGymIdentity(context.Background())
	if err != nil || identity.GymID != fixture.Export.Manifest.GymID || identity.PublicKey != fixture.Export.Manifest.GymPublicKey {
		t.Fatal("candidate gym differs from independent fixture", err)
	}
	if _, err := w.GymIdentity(context.Background()); err == nil {
		t.Fatal("candidate entered old fixture signer profile")
	}

	types := map[uint32]string{44: "legacy", 49: "p2sh-segwit", 84: "bech32", 86: "bech32m"}
	recipients := make(map[string]float64)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		for branch := uint32(0); branch < 2; branch++ {
			method := "getnewaddress"
			if branch == 1 {
				method = "getrawchangeaddress"
			}
			params := []any{"default", types[purpose]}
			if purpose == 84 {
				if branch == 0 {
					params = []any{"default"}
				} else {
					params = nil
				}
			}
			var addr string
			original.rpc.must(t, method, params, &addr)
			if addr != fixture.payment(t, purpose, branch, 4096).Address {
				t.Fatalf("high-index RPC mismatch %d/%d", purpose, branch)
			}
			recipients[addr] = 1
		}
	}
	var height int32
	mine(t, n, original, 100, &height)
	if balance(t, original) != 10e8 {
		t.Fatal("resumable index4096 reward maturity mismatch")
	}
	original.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	var funding string
	original.rpc.must(t, "sendmany", []any{"default", recipients}, &funding)
	mine(t, n, original, 1, &height)
	fundingTx := candidateTransaction(t, original, funding)
	if len(fundingTx.TxOut) != 9 {
		t.Fatal("eight funded scope/branch outputs plus native change expected")
	}
	fundedScripts := make(map[string]uint32)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		for branch := uint32(0); branch < 2; branch++ {
			fundedScripts[fixture.payment(t, purpose, branch, 4096).ScriptPubKey] = purpose
		}
	}
	fundedOutpoints := make(map[uint32]uint32)
	for i, out := range fundingTx.TxOut {
		if purpose, ok := fundedScripts[hex.EncodeToString(out.PkScript)]; ok {
			if out.Value != 1e8 {
				t.Fatal("funded amount")
			}
			fundedOutpoints[uint32(i)] = purpose
		} else if txscript.GetScriptClass(out.PkScript) != txscript.WitnessV0PubKeyHashTy {
			t.Fatal("candidate transaction change is not native84")
		}
	}
	if len(fundedOutpoints) != 8 {
		t.Fatal("candidate did not fund all four independent scripts")
	}
	// The self-funding transaction spends one 10-SLUG reward. Its fee
	// returns in block101's coinbase, so gross credits are101 rewards+10.
	expectedReceived := int64(height+1) * 10e8
	candidateAccountReporting(t, original, expectedReceived)
	originalBalance := balance(t, original)
	original.close(t)

	reopened := openWallet(t, originalPath, nil, n, false)
	endpoints = append(endpoints, reopened.rpc.url)
	waitSync(t, reopened, height)
	if balance(t, reopened) != originalBalance {
		t.Fatal("candidate reopen balance changed")
	}
	if got, err := reopened.wallet.ExportCandidateRecovery(context.Background()); err == nil || got.Mnemonic != "" {
		t.Fatal("locked candidate revealed recovery")
	}
	reopened.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	bundle, err := reopened.wallet.ExportCandidateRecovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := fixture.Export
	for i := range want.Manifest.Accounts {
		want.Manifest.Accounts[i].NextExternal = 4097
		want.Manifest.Accounts[i].NextInternal = 4097
		if want.Manifest.Accounts[i].Purpose == 84 {
			want.Manifest.Accounts[i].NextInternal = 4098
		}
	}
	if !reflect.DeepEqual(bundle, want) {
		t.Fatal("retained candidate export differs from independent metadata/highwater")
	}
	raw, err := productionprofile.MarshalExport(bundle)
	if err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(t.TempDir(), "PUBLIC-CANDIDATE-FIXTURE-ONLY.json")
	if err := os.WriteFile(exportPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reopened.close(t)
	if err := os.Rename(originalPath, originalPath+"-inaccessible"); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredBundle, err := productionprofile.ParseExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	restoredLoader := recoveryLoader(filepath.Join(t.TempDir(), "candidate-restored"))
	recovering, err = restoredLoader.BeginCandidateRecovery(context.Background(), []byte(fixturePass), []byte(fixturePass), restoredBundle)
	if err != nil {
		t.Fatal(err)
	}
	runResumableRecovery(t, restoredLoader, recovering, source, true)
	restoredWallet, err := restoredLoader.OpenExistingWallet([]byte(fixturePass), false)
	if err != nil {
		t.Fatal(err)
	}
	// Check the scanner's durable ledger before ordinary live rescan can
	// repair it, then separately verify the connected RPC composition.
	preAttachBalance, err := restoredWallet.CalculateBalance(1)
	if err != nil || int64(preAttachBalance) != originalBalance {
		t.Fatal("ready scanner balance before live sync", preAttachBalance, err)
	}
	fundingHash, err := chainhash.NewHashFromStr(funding)
	if err != nil {
		t.Fatal(err)
	}
	err = walletdb.View(restoredWallet.Database(), func(tx walletdb.ReadTx) error {
		detail, err := restoredWallet.TxStore.TxDetails(tx.ReadBucket([]byte("wtxmgr")), fundingHash)
		if err != nil {
			return err
		}
		if detail == nil || !reflect.DeepEqual(&detail.MsgTx, fundingTx) {
			return fmt.Errorf("ready scanner lost exact funding transaction")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	restored := attachRecoveryWallet(t, restoredLoader, restoredWallet, n)
	endpoints = append(endpoints, restored.rpc.url)
	waitSync(t, restored, height)
	if balance(t, restored) != originalBalance {
		t.Fatal("candidate file-only restore lost exact balance")
	}
	if !reflect.DeepEqual(candidateTransaction(t, restored, funding), fundingTx) {
		t.Fatal("candidate file-only restore lost exact history")
	}
	restoredIdentity, err := restored.wallet.CandidateGymIdentity(context.Background())
	if err != nil || !reflect.DeepEqual(identity, restoredIdentity) {
		t.Fatal("candidate restore changed gym", err)
	}
	candidateAccountReporting(t, restored, expectedReceived)
	selected := candidateSelectCoins(t, restored, func(c btcjson.ListUnspentResult) bool {
		_, ok := fundedOutpoints[c.Vout]
		return c.TxID == funding && ok
	})
	if len(selected) != 8 {
		t.Fatal("candidate rescan did not retain all four funded outputs")
	}
	restored.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	sink := fixtureVectors(t).ExternalSink
	var spend string
	restored.rpc.must(t, "sendtoaddress", []any{sink, 7.5}, &spend)
	mine(t, n, restored, 1, &height)
	tx := candidateTransaction(t, restored, spend)
	if len(tx.TxIn) != 8 || tx.LockTime != 61 {
		t.Fatal("candidate mixed-scope transaction inputs/activation floor")
	}
	seen := make(map[uint32]uint32)
	for _, in := range tx.TxIn {
		purpose, ok := fundedOutpoints[in.PreviousOutPoint.Index]
		if !ok || in.PreviousOutPoint.Hash.String() != funding || seen[purpose] >= 2 || in.Sequence != wire.MaxTxInSequenceNum-1 {
			t.Fatal("candidate spend did not consume exact funded classes")
		}
		seen[purpose]++
		switch purpose {
		case 44:
			if len(in.SignatureScript) == 0 || len(in.Witness) != 0 {
				t.Fatal("legacy spend encoding")
			}
		case 49:
			if len(in.SignatureScript) == 0 || len(in.Witness) != 2 {
				t.Fatal("nested witness spend encoding")
			}
		case 84:
			if len(in.SignatureScript) != 0 || len(in.Witness) != 2 {
				t.Fatal("native witness spend encoding")
			}
		case 86:
			if len(in.SignatureScript) != 0 || len(in.Witness) != 1 {
				t.Fatal("taproot spend encoding")
			}
		}
	}
	var changeIndex uint32
	changes := 0
	for i, out := range tx.TxOut {
		if txscript.GetScriptClass(out.PkScript) == txscript.WitnessV0PubKeyHashTy {
			changeIndex = uint32(i)
			changes++
		}
	}
	if changes != 1 {
		t.Fatal("candidate RPC spend lacks exact native84 change")
	}
	selected = candidateSelectCoins(t, restored, func(c btcjson.ListUnspentResult) bool { return c.TxID == spend && c.Vout == changeIndex })
	if len(selected) != 1 {
		t.Fatal("native candidate change is not owned")
	}
	var spendChange string
	restored.rpc.must(t, "sendtoaddress", []any{sink, 0.25}, &spendChange)
	mine(t, n, restored, 1, &height)
	next := candidateTransaction(t, restored, spendChange)
	if len(next.TxIn) != 1 || next.TxIn[0].PreviousOutPoint.Hash.String() != spend || next.TxIn[0].PreviousOutPoint.Index != changeIndex {
		t.Fatal("candidate second spend did not consume native change")
	}
	result["status"] = "passed"
	result["all_eight_high_index_outputs_spent"] = true
	result["same_root_and_gym"] = true
	result["pre_live_sync_balance_and_history_verified"] = true
	result["file_only_cancel_and_restart_verified"] = true
	result["native_change_spent"] = true
	result["final_height"] = height
	result["funding_transaction"] = funding
	result["spend_transaction"] = spend
	result["change_spend_transaction"] = spendChange
	result["duration_seconds"] = time.Since(started).Seconds()
	t.Logf("resumable gate passed: actual manager prefix issuance; independent RPC index4096 on all eight branches; interrupted file-only restore; all eight outputs signed together; native change spent; same root/gym; height=%d txs=%s,%s,%s elapsed=%s", height, funding, spend, spendChange, time.Since(started))
}
