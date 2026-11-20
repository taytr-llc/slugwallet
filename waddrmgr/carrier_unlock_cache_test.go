// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcec/v2/ecdsa"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// Reproduce the funded live order without a node: existing issued-address read
// while locked, then committed carrier-return allocation invalidating acctInfo,
// then the first reviewed unlock. All paths come from frozen public fixtures.
func TestCarrierManagerUnlockAfterGuardedCacheInvalidation(t *testing.T) {
	db, m, locked, returned := carrierManagerFixture(t)
	ctx := context.Background()
	local := []byte(HostedAllocationNamespace2)
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return m.BindHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), locked, returned.BindingID)
	}); e != nil {
		t.Fatal(e)
	}
	old := hostedManagerReference(t, "zero256/receive-complete")
	var recipientScript string
	for i, raw := range old.Snapshot.Links {
		v := hostedManagerRecord(t, raw)
		kind := "receive"
		if i == 0 {
			kind = "pool_recipient"
			recipientScript = v.Script
		}
		link := HostedAllocationRecord2{Version: 2, InventoryID: locked.InventoryID, BindingID: returned.BindingID, Sequence: v.Sequence, AllocationID: v.AllocationID, ReservationDigest: v.ReservationDigest, RequestDigest: v.RequestDigest, Outcome: v.Outcome, Purpose: v.Purpose, Branch: v.Branch, StartIndex: v.StartIndex, EndIndex: v.EndIndex, SelectedIndex: v.SelectedIndex, InvalidIndices: v.InvalidIndices, Address: v.Address, Script: v.Script, CursorsBefore: v.CursorsBefore, CursorsAfter: v.CursorsAfter, ConsumerKind: kind, ConsumerID: v.AllocationID}
		if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			p, _, e := m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(local), 84, 0)
			if e != nil {
				return e
			}
			return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), p, link)
		}); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := hex.DecodeString(recipientScript)
	if e != nil || len(raw) != 22 {
		t.Fatal("frozen native84 recipient")
	}
	addr, e := address.NewAddressWitnessPubKeyHash(raw[2:], &chaincfg.MainNetParams)
	if e != nil {
		t.Fatal(e)
	}
	var managed ManagedPubKeyAddress
	if e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ma, e := m.Address(tx.ReadBucket(waddrmgrNamespaceKey), addr)
		if e != nil {
			return e
		}
		var ok bool
		managed, ok = ma.(ManagedPubKeyAddress)
		if !ok {
			t.Fatal("native84 managed address")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	sm := m.scopedManagers[KeyScopeBIP0084]
	if !m.IsLocked() || len(sm.deriveOnUnlock) == 0 || sm.acctInfo[0] == nil {
		t.Fatal("expected locked public-read queue and account cache")
	}
	if e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		p, _, e := m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(local), 84, 1)
		if e != nil {
			return e
		}
		return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), p, returned)
	}); e != nil {
		t.Fatal(e)
	}
	if sm.acctInfo[0] != nil || len(sm.deriveOnUnlock) == 0 {
		t.Fatal("committed allocation must reproduce invalidated account with retained queue")
	}
	if e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), []byte("wrong guarded wallet passphrase"))
	}); !IsError(e, ErrWrongPassphrase) || !m.IsLocked() {
		t.Fatal("wrong password must leave guarded manager locked", e)
	}
	if _, e = managed.PrivKey(); !IsError(e, ErrLocked) {
		t.Fatal("wrong password exposed a queued private key", e)
	}
	if e = walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) }); e != nil {
		t.Fatal(e)
	}
	if m.IsLocked() || len(sm.deriveOnUnlock) != 0 {
		t.Fatal("unlock did not finish exact queue")
	}
	key, e := managed.PrivKey()
	if e != nil {
		t.Fatal("retained issued address private key", e)
	}
	got := address.Hash160(key.PubKey().SerializeCompressed())
	digest := sha256.Sum256([]byte("SLUG guarded cache unlock regression"))
	signature := ecdsa.Sign(key, digest[:])
	usable := signature.Verify(digest[:], key.PubKey())
	key.Zero()
	if !usable {
		t.Fatal("queued original key cannot sign after successful unlock")
	}
	if !bytes.Equal(got, raw[2:]) {
		t.Fatal("private derivation differs from original public path")
	}
	if e = m.Lock(); e != nil {
		t.Fatal(e)
	}
	if e = walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) }); e != nil {
		t.Fatal("second unlock", e)
	}
	if e = m.Lock(); e != nil {
		t.Fatal(e)
	}
}
