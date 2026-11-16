package wallet

import (
	"testing"
	"time"

	"github.com/taytr-llc/slug/blockchain"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestSpendOptionsFourScopesAndActivationFinality(t *testing.T) {
	l := retainedLoader(t)
	w := retainedCreate(t, l, retainedRecoveryFixture(t, "zero256"))
	retainedUnlock(t, w, retainedPrivPass)
	w.chainClientLock.Lock()
	w.chainClient = &mockChainClient{}
	w.chainClientLock.Unlock()
	custom := waddrmgr.KeyScope{Purpose: 1000, Coin: 0}
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		_, err := w.Manager.NewScopedKeyManager(tx.ReadWriteBucket(waddrmgrNamespaceKey), custom, waddrmgr.ScopeAddrSchema{ExternalAddrType: waddrmgr.PubKeyHash, InternalAddrType: waddrmgr.PubKeyHash})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044, waddrmgr.KeyScopeBIP0084} {
		if _, err := w.NextAccount(scope, "named fixture"); err != nil {
			t.Fatal(err)
		}
	}
	creditScript := func(scope waddrmgr.KeyScope, account uint32) []byte {
		t.Helper()
		manager, err := w.Manager.FetchScopedKeyManager(scope)
		if err != nil {
			t.Fatal(err)
		}
		var script []byte
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addresses, err := manager.NextExternalAddresses(tx.ReadWriteBucket(waddrmgrNamespaceKey), account, 1)
			if err != nil {
				return err
			}
			script, err = txscript.PayToAddrScript(addresses[0].Address())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return script
	}
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044, waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScopeBIP0086}
	funding := wire.NewMsgTx(1)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 3}, nil, nil))
	for _, scope := range scopes {
		funding.AddTxOut(wire.NewTxOut(100000, creditScript(scope, 0)))
	}
	funding.AddTxOut(wire.NewTxOut(10000000, creditScript(custom, 0)))
	funding.AddTxOut(wire.NewTxOut(1000000, creditScript(waddrmgr.KeyScopeBIP0044, 1)))
	funding.AddTxOut(wire.NewTxOut(20000000, creditScript(waddrmgr.KeyScopeBIP0084, 1)))
	addUtxo(t, w, funding)
	output := wire.NewTxOut(350000, creditScript(waddrmgr.KeyScopeBIP0044, 0))
	scopeOption := WithCoinSelectionScopes(scopes...)
	scopes[0] = custom // Option must own its allowlist before the serialized request.
	tx, err := w.CreateSimpleTx(nil, 0, []*wire.TxOut{output}, 1, 1000, CoinSelectionLargest, false, scopeOption, WithCustomChangeScope(&waddrmgr.KeyScopeBIP0044), WithMinBlockHeight(62))
	if err != nil {
		t.Fatal("mixed-scope authoring", err)
	}
	if len(tx.Tx.TxIn) != 4 {
		t.Fatal("wrong account/custom scope selected", len(tx.Tx.TxIn))
	}
	seen := map[uint32]bool{}
	for _, in := range tx.Tx.TxIn {
		if in.PreviousOutPoint.Hash != funding.TxHash() || in.PreviousOutPoint.Index >= 4 {
			t.Fatal("selected another account or custom scope")
		}
		seen[in.PreviousOutPoint.Index] = true
		if in.Sequence != wire.MaxTxInSequenceNum-1 {
			t.Fatal("absolute height lock sequence incorrect")
		}
	}
	if len(seen) != 4 || !tx.Tx.HasWitness() {
		t.Fatal("mixed script inputs not all signed")
	}
	if tx.ChangeIndex < 0 || !txscript.IsPayToPubKeyHash(tx.Tx.TxOut[tx.ChangeIndex].PkScript) {
		t.Fatal("change is not explicit legacy")
	}
	if tx.Tx.LockTime != 61 {
		t.Fatal("wrong activation locktime")
	}
	if blockchain.IsFinalizedTransaction(btcutil.NewTx(tx.Tx), 61, time.Unix(0, 0)) {
		t.Fatal("transaction can be mined before activation")
	}
	if !blockchain.IsFinalizedTransaction(btcutil.NewTx(tx.Tx), 62, time.Unix(0, 0)) {
		t.Fatal("transaction not final at activation")
	}
	if err := validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues); err != nil {
		t.Fatal("signature/fee authoring invalid", err)
	}
	// A named account in44 must never borrow a same-numbered84 account, even
	// though the latter has a larger coin and would win largest-first selection.
	named, err := w.CreateSimpleTx(&waddrmgr.KeyScopeBIP0044, 1, []*wire.TxOut{wire.NewTxOut(900000, output.PkScript)}, 1, 1000, CoinSelectionLargest, false, WithCoinSelectionScopes(waddrmgr.KeyScopeBIP0044), WithCustomChangeScope(&waddrmgr.KeyScopeBIP0044))
	if err != nil {
		t.Fatal(err)
	}
	if len(named.Tx.TxIn) != 1 || named.Tx.TxIn[0].PreviousOutPoint.Index != 5 {
		t.Fatal("named account crossed scope")
	}
	if named.Tx.LockTime != 0 || named.Tx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		t.Fatal("ordinary legacy finality changed")
	}
	if _, err := w.CreateSimpleTx(nil, 0, []*wire.TxOut{output}, 1, 1000, CoinSelectionLargest, false, WithCoinSelectionScopes(), WithCustomChangeScope(&waddrmgr.KeyScopeBIP0044)); err == nil {
		t.Fatal("empty explicit allowlist became unrestricted")
	}
	if _, err := w.CreateSimpleTx(nil, 0, []*wire.TxOut{output}, 1, 1000, CoinSelectionLargest, false, WithMinBlockHeight(txscript.LockTimeThreshold+1)); err == nil {
		t.Fatal("timestamp interpreted as height floor")
	}
}
