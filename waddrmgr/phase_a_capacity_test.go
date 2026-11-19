// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestPhaseARecoveryMaximumInventoryFrozenChunks(t *testing.T) {
	corpus := phaseAReferenceRead(t)
	want := make(map[int]string)
	var initial string
	for _, plan := range corpus.Plans {
		if plan.Name != "uniform_4096" {
			continue
		}
		initial = plan.Initial.Hex
		for _, selected := range plan.Selected {
			want[selected.Step] = selected.Hex
		}
	}
	if initial == "" || want[256] == "" {
		t.Fatal("frozen maximum plan is missing")
	}
	accounts := recovery.DefaultAccounts()
	for i := range accounts {
		accounts[i].NextExternal, accounts[i].NextInternal = 4096, 4096
	}
	db, manager := phaseAManager(t, accounts)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	compare := func(expected string) {
		t.Helper()
		state := progressState(t, db, manager)
		raw, err := encodeRecoveryProgressFor(state, phaseARecoveryPolicy())
		if err != nil || hex.EncodeToString(raw) != expected {
			t.Fatal("maximum progress differs from independently frozen arithmetic", err)
		}
	}
	compare(initial)
	var total uint32
	for step := 1; step <= 256; step++ {
		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			rows, err := manager.DeriveRecoveryChunk(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey))
			if err != nil {
				return err
			}
			// The independently frozen model covers this published fixture as
			// valid raw children. Never replace an unexpected result with a new
			// implementation-derived expected count or skipped child.
			if len(rows) != 128 {
				t.Fatalf("chunk%d returned%d rows, want128", step, len(rows))
			}
			for _, row := range rows {
				if row.Scope.Coin != 0 || row.Branch > 1 || row.Index >= 4096 {
					t.Fatal("maximum derivation escaped the Phase-A profile")
				}
			}
			total += uint32(len(rows))
			return nil
		})
		if err != nil {
			t.Fatal("bounded maximum derivation", err)
		}
		if expected := want[step]; expected != "" {
			compare(expected)
		}
	}
	state := progressState(t, db, manager)
	if total != 32768 || state.AddressCount != 32768 || state.Ready {
		t.Fatal("address derivation omitted inventory or asserted chain readiness", total, state.AddressCount, state.Ready)
	}
	for _, branch := range state.Branches {
		if branch.ImportedNext != 4096 || branch.IssuedNext != 4096 || branch.DerivedNext != 4096 || branch.TargetNext != 4096 {
			t.Fatal("maximum cursor changed", branch)
		}
	}
	for _, scope := range manager.scopedManagers {
		if len(scope.addrs) != 0 || len(scope.deriveOnUnlock) != 0 {
			t.Fatal("bounded reconstruction populated ordinary live key caches")
		}
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if _, err := RecoveryAccounts(ns); err != nil {
			return err
		}
		opened, err := Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if opened != nil {
			opened.Close()
		}
		if !errors.Is(err, ErrRecoveryInProgress) {
			t.Fatal("maximum derivation alone enabled ordinary open", err)
		}
		return nil
	}); err != nil {
		t.Fatal("maximum persisted inventory audit", err)
	}
	// Reopening the actual schema12 manager audits all stored rows and the
	// same original public fixture. It still cannot unlock or sign.
	manager.Close()
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := OpenPhaseARecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if opened != nil {
			defer opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal("maximum pending manager did not reopen", err)
	}
}

func TestPhaseARecoveryRejectsCoherentForgedInvalidChild(t *testing.T) {
	db, manager := phaseAManager(t, recovery.DefaultAccounts())
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if _, err := manager.DeriveRecoveryChunk(t.Context(), ns); err != nil {
			return err
		}
		// Mixed49 internal child0 is already a real valid native-witness row
		// in the first128 attempts. Remove it and forge a count-consistent skip.
		scope := KeyScope{Purpose: 49, Coin: 0}
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
			child, err := deserializeChainedAddress(row)
			if err != nil {
				return err
			}
			if child.branch == 1 && child.index == 0 {
				remove = append([]byte(nil), key...)
			}
			return nil
		}); err != nil {
			return err
		}
		if remove == nil {
			t.Fatal("known valid mixed49 child was not materialized")
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
		if err := putRecoveryInvalid(ns, scope, 1, 0); err != nil {
			return err
		}
		// The structural/count checks deliberately pass. Only independent
		// public BIP32 derivation can refute the invented invalid-child claim.
		return validateRecoveryInvalid(ns, state)
	})
	if err != nil {
		t.Fatal("coherent corruption fixture", err)
	}
	manager.Close()
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := OpenPhaseARecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if opened != nil {
			opened.Close()
		}
		return err
	})
	if !errors.Is(err, ErrRecoveryState) {
		t.Fatal("schema12 accepted a forged valid-child skip", err)
	}
}
