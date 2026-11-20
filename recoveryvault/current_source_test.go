//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/wallet"
	"github.com/taytr-llc/slugwallet/walletdb"
	_ "github.com/taytr-llc/slugwallet/walletdb/bdb"
)

func currentFixtureWallet(t *testing.T) (*wallet.Wallet, walletdb.DB) {
	t.Helper()
	db, err := walletdb.Create("bdb", filepath.Join(t.TempDir(), "fixture.db"), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := wallet.NewLoaderWithDB(&chaincfg.MainNetParams, 0, db, func() (bool, error) { return false, nil })
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	// This is the already-published zero256 fixture, never a real wallet key.
	w, err := loader.CreateNewRecoveryWallet([]byte("public fixture"), []byte("fixture private password"), [32]byte{}, time.Unix(0, 0))
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loader.UnloadWallet(); err != nil {
			t.Error(err)
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return w, db
}
func currentAllocate(t *testing.T, w *wallet.Wallet, db walletdb.DB) {
	t.Helper()
	mgr, err := w.Manager.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	if err != nil {
		t.Fatal(err)
	}
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket([]byte("waddrmgr"))
		if _, e := mgr.NextExternalAddresses(ns, 0, 1); e != nil {
			return e
		}
		_, e := mgr.NextInternalAddresses(ns, 0, 1)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
}
func currentPin(t *testing.T, path string) CurrentDestinationPin {
	t.Helper()
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	f, _, err := currentWalk(parent, false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := currentStampFile(f)
	ce := f.Close()
	if err != nil || ce != nil {
		t.Fatal("parent stamp")
	}
	return CurrentDestinationPin{Version1, path, st.identity.Device, st.identity.Inode}
}
func currentSetup(t *testing.T) (*vaultHarness, *HostedVault, *CurrentStore, gymaccount.Session, []CurrentBinding) {
	t.Helper()
	h, v := htSetup(t)
	a, b := vtLogin(t, h, "alice", 1), vtLogin(t, h, "bob", 1)
	ra, rb := htReady(t, h, v, a), htReady(t, h, v, b)
	bindings := []CurrentBinding{{Version1, v.header.HostedVaultID, ra.Binding, ra.RetentionID, strings.Repeat("1", 64), strings.Repeat("a", 64)}, {Version1, v.header.HostedVaultID, rb.Binding, rb.RetentionID, strings.Repeat("2", 64), strings.Repeat("a", 64)}}
	s, err := CreateCurrentStore(context.Background(), filepath.Join(filepath.Dir(h.path), "current"), v, bindings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return h, v, s, a, bindings
}
func TestHostedCurrentConcreteCaptureExportResetAndReplay(t *testing.T) {
	h, v, s, login, bindings := currentSetup(t)
	w, db := currentFixtureWallet(t)
	ctx := context.Background()
	currentAllocate(t, w, db)
	src, err := s.AttachSource(ctx, login.Token, bindings[0], w, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	if _, err = s.AttachSource(ctx, login.Token, bindings[0], w, hostedEpoch); !errors.Is(err, ErrBusy) {
		t.Fatal("duplicate live attachment", err)
	}
	if _, err = s.AttachSource(ctx, login.Token, bindings[1], w, hostedEpoch); err == nil {
		t.Fatal("cross account attached")
	}
	if _, found, err := src.CurrentCheckpoint(ctx); err != nil || found {
		t.Fatal("empty head", err)
	}
	beforeRecovery, beforeGym := h.w.counts()
	foreign, err := w.CaptureCurrentRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = src.Checkpoint(ctx, 0, foreign); !errors.Is(err, ErrConflict) {
		t.Fatal("unadmitted capture accepted", err)
	}
	capture, err := src.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row, created, err := src.Checkpoint(ctx, 0, capture)
	if err != nil || !created || row.Manifest.Accounts[2].NextInternal != 1 || row.Manifest.Accounts[2].NextExternal != 1 {
		t.Fatal("current cursor", err)
	}
	again, changed, err := src.Checkpoint(ctx, 0, capture)
	if err != nil || changed || !reflect.DeepEqual(again, row) {
		t.Fatal("exact replay", err)
	}
	row.Manifest.Accounts[2].NextInternal = 4096
	read, err := src.LookupCheckpoint(ctx, capture.CaptureID())
	if err != nil || read.Manifest.Accounts[2].NextInternal != 1 {
		t.Fatal("row alias", err)
	}
	if r, g := h.w.counts(); r != beforeRecovery || g != beforeGym {
		t.Fatal("public checkpoint unwrapped")
	}
	pin := currentPin(t, filepath.Join(t.TempDir(), "current.json"))
	dest, err := OpenCurrentDestination(ctx, pin, []string{filepath.Dir(h.path)})
	if err != nil {
		t.Fatal(err)
	}
	h.w.setHook(func(context.Context, string) error {
		if _, e := os.Lstat(pin.Path); !os.IsNotExist(e) {
			return errors.New("plaintext before fence")
		}
		return nil
	})
	prepared, err := src.PrepareExport(ctx, capture.CaptureID(), dest)
	h.w.setHook(nil)
	if err != nil {
		dest.Close()
		t.Fatal(err)
	}
	if _, e := os.Lstat(pin.Path); !os.IsNotExist(e) {
		t.Fatal("prepare wrote plaintext")
	}
	if err = prepared.Publish(ctx); err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	if err = prepared.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pin.Path)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := recovery.ParseExport(raw)
	clear(raw)
	if err != nil || !reflect.DeepEqual(bundle.Manifest, capture.Manifest()) {
		t.Fatal("export current manifest", err)
	}
	st, _ := os.Stat(pin.Path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("not private")
	}
	if err = prepared.Publish(ctx); err == nil {
		t.Fatal("export repeated")
	}
	if _, err = OpenCurrentDestination(ctx, pin, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("overwritten destination")
	}
	next, err := src.Capture(ctx)
	if err != nil {
		t.Fatal("closed export stranded source", err)
	}
	if _, _, err = src.Checkpoint(ctx, 1, next); err != nil {
		t.Fatal(err)
	}
	oldReplay, changed, err := src.Checkpoint(ctx, 0, capture)
	if err != nil || changed || !reflect.DeepEqual(oldReplay, read) {
		t.Fatal("old committed action did not replay exactly", err)
	}
	if _, _, err = src.Checkpoint(ctx, 1, capture); !errors.Is(err, ErrConflict) {
		t.Fatal("old id changed expected revision", err)
	}
	oldDest, err := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "old-capture.json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = src.PrepareExport(ctx, capture.CaptureID(), oldDest); !errors.Is(err, ErrConflict) {
		oldDest.Close()
		t.Fatal("old replay became fresh export", err)
	}
	oldDest.Close()
	vtReset(t, h, "alice", 1)
	if _, err = src.Capture(ctx); err == nil {
		t.Fatal("old token accepted after reset")
	}
	if err = src.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := vtLogin(t, h, "alice", 2)
	// Complete only the typed recovery challenge through the gym envelope.
	challenge, err := h.accounts.BeginChallenge(ctx, fresh.Token, "recover")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := v.SignAccountChallenge(ctx, fresh.Token, challenge, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.accounts.CompleteChallenge(ctx, fresh.Token, challenge.ChallengeID, auth); err != nil {
		t.Fatal(err)
	}
	if _, err = v.EnsureEnrollment(ctx, fresh.Token, hostedEpoch); err != nil {
		t.Fatal(err)
	}
	held, err := s.AttachSource(ctx, fresh.Token, bindings[0], w, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	beforeRecovery, _ = h.w.counts()
	hc, err := held.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = held.Checkpoint(ctx, 2, hc); err != nil {
		t.Fatal(err)
	}
	d, err := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "held.json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err = held.PrepareExport(ctx, hc.CaptureID(), d); !errors.Is(err, gymaccount.ErrHeld) {
		t.Fatal("hold export bypass", err)
	}
	if after, _ := h.w.counts(); after != beforeRecovery {
		t.Fatal("held recovery unwrap")
	}
}
func TestHostedCurrentLostCheckpointAckAuditedReopen(t *testing.T) {
	_, v, s, login, bindings := currentSetup(t)
	w, _ := currentFixtureWallet(t)
	ctx := context.Background()
	src, err := s.AttachSource(ctx, login.Token, bindings[0], w, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := src.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original := s.writeBatch
	s.writeBatch = func(b *leveldb.Batch, o *opt.WriteOptions) error {
		if e := original(b, o); e != nil {
			return e
		}
		return errors.New("lost checkpoint ack")
	}
	if _, _, err = src.Checkpoint(ctx, 0, capture); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("uncertain commit", err)
	}
	if _, err = src.Capture(ctx); !errors.Is(err, ErrPoisoned) {
		t.Fatal("poisoned source used", err)
	}
	if err = src.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Close(), ErrPoisoned) {
		t.Fatal("uncertainty lost on close")
	}
	reopened, err := OpenCurrentStore(ctx, s.path, v, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := reopened.AttachSource(ctx, login.Token, bindings[0], w, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	row, err := next.LookupCheckpoint(ctx, capture.CaptureID())
	if err != nil || row.CaptureID != capture.CaptureID() || row.Revision != 1 {
		t.Fatal("audited exact lookup", err)
	}
	if _, _, err = next.Checkpoint(ctx, 0, capture); err == nil {
		t.Fatal("old opaque capture rescued")
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if os.Remove(filepath.Join(s.path, currentMarkerFile)) != nil {
		t.Fatal("marker fixture")
	}
	if _, err = OpenCurrentStore(ctx, s.path, v, bindings); err == nil {
		t.Fatal("nonempty marker loss adopted")
	}
}
