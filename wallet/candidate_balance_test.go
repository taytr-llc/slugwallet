// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// This is a transaction-store reporting test. Synthetic block IDs avoid any
// claim of chain validation; the separate normal-PoW gate covers real funds.
func candidateBalanceCredits(t *testing.T, w *Wallet) []waddrmgr.KeyScope {
	t.Helper()
	var scopes []waddrmgr.KeyScope
	var scripts [][]byte
	for _, purpose := range []uint32{44, 49, 84, 86} {
		scope, err := w.Manager.PaymentScope(purpose)
		if err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, scope)
		addr, err := address.DecodeAddress(retainedAddress(t, w, scope, false), w.ChainParams())
		if err != nil {
			t.Fatal(err)
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, script)
	}
	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		if err := w.Manager.SetSyncedTo(dbtx.ReadWriteBucket(waddrmgrNamespaceKey), &waddrmgr.BlockStamp{
			Height: 200, Hash: chainhash.Hash{200}, Timestamp: time.Unix(1700000000, 0),
		}); err != nil {
			return err
		}
		for i, credit := range []struct {
			height   int32
			base     int64
			coinbase bool
		}{
			{100, 1000, false},   // Confirmed ordinary outputs.
			{1, 10000, true},     // Mature coinbase outputs.
			{200, 100000, true},  // Immature rewards are not account balance.
			{-1, 1000000, false}, // Unconfirmed ordinary outputs need minconf 0.
		} {
			tx := wire.NewMsgTx(2)
			input := &wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}}
			if credit.coinbase {
				input.PreviousOutPoint = wire.OutPoint{Index: wire.MaxPrevOutIndex}
			}
			tx.AddTxIn(input)
			for n, script := range scripts {
				tx.AddTxOut(&wire.TxOut{Value: credit.base * int64(n+1), PkScript: script})
			}
			rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Unix(1700000000+int64(i), 0))
			if err != nil {
				return err
			}
			var block *wtxmgr.BlockMeta
			if credit.height >= 0 {
				block = &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: chainhash.Hash{byte(credit.height)}, Height: credit.height}, Time: time.Unix(1700000000, 0)}
			}
			ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
			if err := w.TxStore.InsertTx(ns, rec, block); err != nil {
				return err
			}
			for n := range scripts {
				if err := w.TxStore.AddCredit(ns, rec, block, uint32(n), false); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return scopes
}

func TestCandidateAccountBalancesAggregatePaymentScopes(t *testing.T) {
	for _, candidate := range []bool{true, false} {
		name := "candidate-v2"
		if !candidate {
			name = "preserved-fixture-v1"
		}
		t.Run(name, func(t *testing.T) {
			loader := retainedLoader(t)
			var w *Wallet
			if candidate {
				var err error
				w, err = loader.CreateCandidateFixtureWallet(retainedPubPass, retainedPrivPass, productionprofile.CandidateZero256)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				w = retainedCreate(t, loader, retainedRecoveryFixture(t, "official-leading-zero-account"))
			}
			retainedUnlock(t, w, retainedPrivPass)
			scopes := candidateBalanceCredits(t, w)
			for i, scope := range scopes {
				multiplier := btcutil.Amount(i + 1)
				if candidate {
					multiplier = 10 // 1+2+3+4, once per compiled scope.
				}
				for _, test := range []struct {
					confs int32
					base  btcutil.Amount
				}{{0, 1011000}, {1, 11000}, {102, 10000}, {201, 0}} {
					balances, err := w.AccountBalances(scope, test.confs)
					if err != nil || len(balances) != 2 {
						t.Fatalf("scope %v: account projection: %v, %v", scope, balances, err)
					}
					if balances[0].AccountNumber != 0 || balances[0].AccountBalance != multiplier*test.base || balances[1].AccountBalance != 0 {
						t.Fatalf("scope %v minconf %d: got %v, want %d", scope, test.confs, balances, multiplier*test.base)
					}
				}
				// The existing received-history path already uses root AddrAccount;
				// account0 is aggregated for both profiles, including immature funds.
				for _, test := range []struct {
					confs int32
					want  btcutil.Amount
				}{{0, 11110000}, {1, 1110000}} {
					received, err := w.TotalReceivedForAccounts(scope, test.confs)
					if err != nil || len(received) != 2 || received[0].TotalReceived != test.want || received[1].TotalReceived != 0 {
						t.Fatalf("scope %v received minconf %d: %v, %v", scope, test.confs, received, err)
					}
				}
			}
		})
	}
}
