// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func resumableManager(t *testing.T, cursors []productionprofile.Cursor) (walletdb.DB, *Manager) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal-chain candidate fixture")
	}
	ctx := context.Background()
	manifest, err := productionprofile.FixtureManifest(ctx, productionprofile.CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	public, err := productionprofile.MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entropy, _ := productionprofile.FixtureEntropy(productionprofile.CandidateZero256)
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	private := make([]byte, 68)
	defer clear(private)
	binary.LittleEndian.PutUint32(private, 2)
	copy(private[4:36], entropy[:])
	hash := sha256.Sum256(public)
	copy(private[36:], hash[:])
	db, err := walletdb.Create("bdb", filepath.Join(t.TempDir(), "recovery.db"), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	var mgr *Manager
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := CreateWithResumableCandidateRecovery(ctx, ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, public, private); err != nil {
			return err
		}
		mgr, err = OpenCandidateRecovery(ns, pubPassphrase, &chaincfg.MainNetParams)
		return err
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close(); db.Close() })
	return db, mgr
}

func progressState(t *testing.T, db walletdb.DB, mgr *Manager) RecoveryState {
	t.Helper()
	var s RecoveryState
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		var err error
		s, err = mgr.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func deriveAllRecovery(t *testing.T, db walletdb.DB, mgr *Manager) {
	t.Helper()
	for {
		before := progressState(t, db, mgr)
		done := true
		var previous uint32
		for _, b := range before.Branches {
			done = done && b.DerivedNext == b.TargetNext
			previous += b.DerivedNext
		}
		if done {
			return
		}
		if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			rows, err := mgr.DeriveRecoveryChunk(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey))
			if len(rows) > int(RecoveryChunkSize) {
				t.Fatal("unbounded chunk")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		after := progressState(t, db, mgr)
		var next uint32
		for _, b := range after.Branches {
			next += b.DerivedNext
		}
		if next <= previous || next-previous > RecoveryChunkSize {
			t.Fatal("attempt budget violated")
		}
	}
}

func TestResumableManagerBeyond4096(t *testing.T) {
	cursors := productionprofile.DefaultCursors()
	cursors[2].NextExternal = 4097
	db, mgr := resumableManager(t, cursors)
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if got, err := Open(ns, pubPassphrase, &chaincfg.MainNetParams); !errors.Is(err, ErrRecoveryInProgress) || got != nil {
			t.Fatal("pending ordinary open", err)
		}
		if err := mgr.Unlock(ns, privPassphrase); !errors.Is(err, ErrRecoveryInProgress) {
			t.Fatal("pending unlock", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := progressState(t, db, mgr)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		_, err := mgr.DeriveRecoveryChunk(cancelled, tx.ReadWriteBucket(waddrmgrNamespaceKey))
		return err
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled derivation", err)
	}
	if !reflect.DeepEqual(before, progressState(t, db, mgr)) {
		t.Fatal("cancelled step advanced")
	}
	deriveAllRecovery(t, db, mgr)
	s := progressState(t, db, mgr)
	if s.Branches[4].IssuedNext != 4097 || s.Branches[4].DerivedNext != 4117 || s.AddressCount != 4257 {
		t.Fatal("cursor/lookahead mismatch", s)
	}
	for _, sm := range mgr.scopedManagers {
		if len(sm.addrs) != 0 || len(sm.deriveOnUnlock) != 0 {
			t.Fatal("derivation filled live key caches")
		}
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return mgr.SetCandidateRecoveryReady(tx.ReadWriteBucket(waddrmgrNamespaceKey))
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if err == nil {
			opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal("ready reopen", err)
	}
}

func TestResumableLookaheadDoesNotBecomeIssued(t *testing.T) {
	db, mgr := resumableManager(t, productionprofile.DefaultCursors())
	deriveAllRecovery(t, db, mgr)
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		expanded, err := mgr.ObserveRecoveryAddress(tx.ReadWriteBucket(waddrmgrNamespaceKey), KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType}, 0, 19)
		if !expanded {
			t.Fatal("found lookahead did not extend")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s := progressState(t, db, mgr)
	if s.Branches[4].IssuedNext != 20 || s.Branches[4].TargetNext != 40 {
		t.Fatal("used address highwater", s)
	}
	deriveAllRecovery(t, db, mgr)
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return mgr.SetCandidateRecoveryReady(tx.ReadWriteBucket(waddrmgrNamespaceKey))
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		sm, err := mgr.FetchScopedKeyManager(KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType})
		if err != nil {
			return err
		}
		rows, err := sm.NextExternalAddresses(ns, 0, 1)
		if err != nil {
			return err
		}
		_, path, _ := rows[0].(ManagedPubKeyAddress).DerivationInfo()
		if path.Index != 20 {
			t.Fatal("reused used index", path.Index)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s = progressState(t, db, mgr)
	if s.Branches[4].IssuedNext != 21 || s.Branches[4].DerivedNext != 40 || s.AddressCount != 180 {
		t.Fatal("live issuance counted existing lookahead twice", s)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumableQuotaPreflight(t *testing.T) {
	for _, n := range []uint32{RecoveryAttemptLimit, productionprofile.MaxNextIndex} {
		c := productionprofile.DefaultCursors()
		c[0].NextExternal = n
		m, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateZero256, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CandidateRecoveryPlan(context.Background(), m); !errors.Is(err, ErrRecoveryQuota) {
			t.Fatal("quota accepted", n, err)
		}
	}
}

func TestResumableReadyAllocationRetainsRestoreReserve(t *testing.T) {
	cursors := productionprofile.DefaultCursors()
	cursors[0].NextExternal = RecoveryAttemptLimit - 8*RecoveryLookahead - 1
	db, mgr := resumableManager(t, cursors)
	deriveAllRecovery(t, db, mgr)
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return mgr.SetCandidateRecoveryReady(tx.ReadWriteBucket(waddrmgrNamespaceKey))
	}); err != nil {
		t.Fatal(err)
	}
	scope := KeyScope{Purpose: 44, Coin: productionprofile.CandidateCoinType}
	allocate := func() error {
		return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			sm, err := mgr.FetchScopedKeyManager(scope)
			if err != nil {
				return err
			}
			_, err = sm.NextExternalAddresses(tx.ReadWriteBucket(waddrmgrNamespaceKey), 0, 1)
			return err
		})
	}
	if err := allocate(); err != nil {
		t.Fatal("final supported allocation rejected", err)
	}
	before := progressState(t, db, mgr)
	if err := allocate(); !errors.Is(err, ErrRecoveryQuota) {
		t.Fatal("allocation spent restore reserve", err)
	}
	if !reflect.DeepEqual(before, progressState(t, db, mgr)) {
		t.Fatal("quota rejection consumed cursor")
	}
	for i := range cursors {
		cursors[i].NextExternal = before.Branches[2*i].IssuedNext
		cursors[i].NextInternal = before.Branches[2*i+1].IssuedNext
	}
	manifest, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CandidateRecoveryPlan(context.Background(), manifest); err != nil {
		t.Fatal("successfully issued highwater cannot restore", err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if err == nil {
			opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal("quota boundary cannot reopen", err)
	}
}
