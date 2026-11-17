// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"context"
	"errors"
	"testing"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// A count-consistent skip marker is not evidence that BIP32 derivation failed.
// This real public fixture has a valid first child; removing its address and
// declaring it invalid must not silently make that address unwatchable.
func TestResumableRejectsForgedInvalidChild(t *testing.T) {
	db, manager := resumableManager(t, productionprofile.DefaultCursors())
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if _, err := manager.DeriveRecoveryChunk(context.Background(), ns); err != nil {
			return err
		}
		scope := KeyScope{Purpose: 44, Coin: productionprofile.CandidateCoinType}
		bucket, err := fetchWriteScopeBucket(ns, &scope)
		if err != nil {
			return err
		}
		addresses := bucket.NestedReadWriteBucket(addrBucketName)
		var remove []byte
		if err := addresses.ForEach(func(key, value []byte) error {
			row, err := deserializeAddressRow(value)
			if err != nil {
				return err
			}
			address, err := deserializeChainedAddress(row)
			if err != nil {
				return err
			}
			if address.branch == 0 && address.index == 0 {
				remove = append([]byte(nil), key...)
			}
			return nil
		}); err != nil {
			return err
		}
		if remove == nil {
			return errors.New("fixture's valid first address was not materialized")
		}
		if err := addresses.Delete(remove); err != nil {
			return err
		}
		state, err := fetchRecoveryProgress(ns)
		if err != nil {
			return err
		}
		state.AddressCount--
		if err := putRecoveryProgress(ns, state); err != nil {
			return err
		}
		return putRecoveryInvalid(ns, scope, 0, 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		reopened, err := OpenCandidateRecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if reopened != nil {
			reopened.Close()
		}
		return err
	})
	if !errors.Is(err, ErrRecoveryState) {
		t.Fatalf("coherent forged invalid-child skip accepted: %v", err)
	}
}
