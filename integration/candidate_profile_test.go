//go:build integration && recoveryintegration && candidateintegration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
)

type candidateFixture struct {
	Name     string                            `json:"name"`
	Export   productionprofile.Export          `json:"export"`
	Payments []productionprofile.PaymentPublic `json:"payments"`
}

func candidateReference(t *testing.T) candidateFixture {
	t.Helper()
	raw, err := os.ReadFile("../productionprofile/testdata/candidate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		FixtureOnly bool               `json:"candidate_fixtures_only"`
		Production  bool               `json:"production_issuance_enabled"`
		Cases       []candidateFixture `json:"cases"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || !document.FixtureOnly || document.Production {
		t.Fatal("invalid independent candidate fixtures", err)
	}
	for _, fixture := range document.Cases {
		if fixture.Name == productionprofile.CandidateZero256 {
			return fixture
		}
	}
	t.Fatal("published candidate fixture missing")
	return candidateFixture{}
}

func (f candidateFixture) payment(t *testing.T, purpose, branch, index uint32) productionprofile.PaymentPublic {
	t.Helper()
	for _, p := range f.Payments {
		if p.Purpose == purpose && p.Branch == branch && p.Index == index {
			return p
		}
	}
	t.Fatalf("independent payment missing: %d/%d/%d", purpose, branch, index)
	return productionprofile.PaymentPublic{}
}

func candidateTransaction(t *testing.T, s *session, txid string) *wire.MsgTx {
	t.Helper()
	h := history(t, s, txid)
	if h["confirmations"].(float64) < 1 {
		t.Fatal("candidate transaction is not confirmed")
	}
	raw, err := hex.DecodeString(h["hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return &tx
}

// Lock only test-owned coins so the next real RPC send must exercise the exact
// funded script classes, rather than choosing another mature fixture reward.
func candidateSelectCoins(t *testing.T, s *session, keep func(btcjson.ListUnspentResult) bool) []btcjson.ListUnspentResult {
	t.Helper()
	var coins []btcjson.ListUnspentResult
	s.rpc.must(t, "listunspent", []any{1}, &coins)
	var selected []btcjson.ListUnspentResult
	var lock, unlock []btcjson.TransactionInput
	for _, coin := range coins {
		input := btcjson.TransactionInput{Txid: coin.TxID, Vout: coin.Vout}
		if keep(coin) {
			selected = append(selected, coin)
			unlock = append(unlock, input)
		} else {
			lock = append(lock, input)
		}
	}
	if len(lock) > 0 {
		s.rpc.must(t, "lockunspent", []any{false, lock}, nil)
	}
	if len(unlock) > 0 {
		s.rpc.must(t, "lockunspent", []any{true, unlock}, nil)
	}
	return selected
}

func candidateAccountReporting(t *testing.T, s *session, expectedReceived int64) {
	t.Helper()
	var accounts map[string]float64
	s.rpc.must(t, "listaccounts", []any{1}, &accounts)
	if got := int64(math.Round(accounts["default"] * 1e8)); got != balance(t, s) {
		t.Fatalf("candidate listaccounts omitted a scope: %d", got)
	}
	var received float64
	s.rpc.must(t, "getreceivedbyaccount", []any{"default", 1}, &received)
	var listed []btcjson.ListReceivedByAccountResult
	s.rpc.must(t, "listreceivedbyaccount", []any{1, true}, &listed)
	found := false
	for _, result := range listed {
		if result.Account == "default" {
			found = true
			if result.Amount != received {
				t.Fatal("candidate received account reports disagree")
			}
		}
	}
	if !found || int64(math.Round(received*1e8)) != expectedReceived {
		t.Fatalf("candidate received account amount: found=%v got=%d want=%d", found, int64(math.Round(received*1e8)), expectedReceived)
	}
}

func TestCandidateProfileNormalPoW(t *testing.T) {
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
	fixture := candidateReference(t)
	n := startNode(t, binary, fixture.payment(t, 44, 0, 25).Address)
	originalPath := filepath.Join(t.TempDir(), "candidate-original")
	loader := recoveryLoader(originalPath)
	w, err := loader.CreateCandidateFixtureWallet([]byte(fixturePass), []byte(fixturePass), fixture.Name)
	if err != nil {
		t.Fatal(err)
	}
	original := attachRecoveryWallet(t, loader, w, n)
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
		for index := uint32(0); index <= 25; index++ {
			var addr string
			params := []any{"default", types[purpose]}
			if purpose == 84 {
				params = []any{"default"}
			} // Real RPC native receive default.
			original.rpc.must(t, "getnewaddress", params, &addr)
			if index == 0 || index == 25 {
				if addr != fixture.payment(t, purpose, 0, index).Address {
					t.Fatalf("independent candidate receive mismatch %d/%d", purpose, index)
				}
			}
			if index == 25 {
				recipients[addr] = 1.0
			}
		}
	}
	for index := uint32(0); index <= 26; index++ {
		var addr string
		original.rpc.must(t, "getrawchangeaddress", nil, &addr) // Real RPC native change default.
		if index == 0 || index == 25 || index == 26 {
			if addr != fixture.payment(t, 84, 1, index).Address {
				t.Fatalf("independent native change mismatch %d", index)
			}
		}
	}
	var height int32
	mine(t, n, original, 100, &height)
	if balance(t, original) != 10e8 {
		t.Fatal("candidate index25 reward maturity mismatch")
	}
	original.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	var funding string
	original.rpc.must(t, "sendmany", []any{"default", recipients}, &funding)
	mine(t, n, original, 1, &height)
	fundingTx := candidateTransaction(t, original, funding)
	if len(fundingTx.TxOut) != 5 {
		t.Fatal("four funded scopes plus native change expected")
	}
	fundedScripts := make(map[string]uint32)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		fundedScripts[fixture.payment(t, purpose, 0, 25).ScriptPubKey] = purpose
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
	if len(fundedOutpoints) != 4 {
		t.Fatal("candidate did not fund all four independent scripts")
	}
	// The self-funding transaction spends one 10-SLUG reward. Its fee
	// returns in block101's coinbase, so gross credits are101 rewards+10.
	expectedReceived := int64(height+1) * 10e8
	candidateAccountReporting(t, original, expectedReceived)
	originalBalance := balance(t, original)
	original.close(t)

	reopened := openWallet(t, originalPath, nil, n, false)
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
		want.Manifest.Accounts[i].NextExternal = 26
		want.Manifest.Accounts[i].NextInternal = 0
		if want.Manifest.Accounts[i].Purpose == 84 {
			want.Manifest.Accounts[i].NextInternal = 28
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
	restoredWallet, err := restoredLoader.RestoreCandidateFixtureWallet([]byte(fixturePass), []byte(fixturePass), restoredBundle)
	if err != nil {
		t.Fatal(err)
	}
	restored := attachRecoveryWallet(t, restoredLoader, restoredWallet, n)
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
	if len(selected) != 4 {
		t.Fatal("candidate rescan did not retain all four funded outputs")
	}
	restored.rpc.must(t, "walletpassphrase", []any{fixturePass, 600}, nil)
	sink := fixtureVectors(t).ExternalSink
	var spend string
	restored.rpc.must(t, "sendtoaddress", []any{sink, 3.5}, &spend)
	mine(t, n, restored, 1, &height)
	tx := candidateTransaction(t, restored, spend)
	if len(tx.TxIn) != 4 || tx.LockTime != 61 {
		t.Fatal("candidate mixed-scope transaction inputs/activation floor")
	}
	seen := make(map[uint32]bool)
	for _, in := range tx.TxIn {
		purpose, ok := fundedOutpoints[in.PreviousOutPoint.Index]
		if !ok || in.PreviousOutPoint.Hash.String() != funding || seen[purpose] || in.Sequence != wire.MaxTxInSequenceNum-1 {
			t.Fatal("candidate spend did not consume exact funded classes")
		}
		seen[purpose] = true
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
	t.Logf("candidate gate passed: exact independent four-scope addresses beyond gap20; native84 receive/change RPC defaults; all four funded scripts restored from retained file only and signed together; native change spent; same root/gym; height=%d txs=%s,%s,%s elapsed=%s", height, funding, spend, spendChange, time.Since(started))
}
