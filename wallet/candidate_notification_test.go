// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// This is the real transaction notification path with a synthetic unconfirmed
// transaction. The separate normal-PoW gate proves node acceptance and rescan.
func TestCandidateNotificationCreditsAllPaymentScopes(t *testing.T) {
	loader := retainedLoader(t)
	w, err := loader.CreateCandidateFixtureWallet(retainedPubPass, retainedPrivPass, productionprofile.CandidateZero256)
	if err != nil {
		t.Fatal(err)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{42}}})
	for _, purpose := range []uint32{44, 49, 84, 86} {
		scope, err := w.Manager.PaymentScope(purpose)
		if err != nil {
			t.Fatal(err)
		}
		addr, err := address.DecodeAddress(retainedAddress(t, w, scope, false), w.ChainParams())
		if err != nil {
			t.Fatal(err)
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatal(err)
		}
		tx.AddTxOut(wire.NewTxOut(1e8, script))
	}
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error { return w.addRelevantTx(dbtx, rec, nil) }); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		detail, err := w.TxStore.TxDetails(dbtx.ReadBucket(wtxmgrNamespaceKey), &rec.Hash)
		if err != nil {
			return err
		}
		if detail == nil || len(detail.Credits) != 4 {
			t.Fatal("candidate notification discarded a compiled payment scope")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
