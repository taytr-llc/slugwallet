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
	"sync/atomic"
	"testing"
	"time"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/wallet"
)

// This boundary harness has no installed Wallet. It proves export comes from
// the concrete surviving authority/inventory, not a fabricated local snapshot.
// Actual issued-prefix restore is separately qualified with the allocator/app.
func inventoryExportSetup2(t *testing.T) (*vaultHarness, *HostedVault, *wallet.HostedAllocationInventory2, gymaccount.Session) {
	t.Helper()
	h, v := htSetup(t)
	login := vtLogin(t, h, "alice", 1)
	r := htReady(t, h, v, login)
	b := wallet.AllocationBinding2{Version: 2, InventoryID: strings.Repeat("a", 64), AuthorityID: r.Binding.AuthorityID, AccountID: r.Binding.AccountID, PrincipalID: r.Binding.PrincipalID, ProvisionID: r.Binding.ProvisionID, HostedVaultID: v.header.HostedVaultID, RetentionID: r.RetentionID, WalletOwnerID: strings.Repeat("b", 64), SourceBindingID: strings.Repeat("c", 64), OwnershipPinID: strings.Repeat("d", 64), CarrierJournalID: strings.Repeat("e", 64), WithdrawalJournalID: strings.Repeat("f", 64), ManagerSchema: 14, MaxAllocations: 1024, MaxBytes: 4194304, MaxPlanAttempts: 128, MaxBranchIndex: 4096, InitialManifest: r.Manifest}
	i, e := wallet.CreateHostedAllocationInventory2(context.Background(), filepath.Join(filepath.Dir(h.path), "inventory"), h.accounts, b)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close() })
	return h, v, i, login
}
func TestHostedInventory2ExportWithoutLocalWallet(t *testing.T) {
	h, v, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	head, e := i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if e != nil {
		t.Fatal(e)
	}
	m := head.Manifest()
	m.Accounts[2].NextExternal = 4096
	if head.Manifest().Accounts[2].NextExternal != 0 {
		t.Fatal("head manifest alias")
	}
	pin := currentPin(t, filepath.Join(t.TempDir(), "surviving.json"))
	d, e := OpenCurrentDestination(ctx, pin, []string{filepath.Dir(h.path)})
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	p, e := v.PrepareInventoryExport2(ctx, login.Token, head, d, hostedEpoch)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if _, e = os.Lstat(pin.Path); !os.IsNotExist(e) {
		t.Fatal("plaintext written during preparation")
	}
	if e = p.Publish(ctx); e != nil {
		t.Fatal(e)
	}
	if e = p.Publish(ctx); !errors.Is(e, ErrClosed) {
		t.Fatal("publication replay", e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(pin.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	bundle, e := recovery.ParseExport(raw)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(bundle.Manifest, head.Manifest()) {
		t.Fatal("export differs from inventory head")
	}
	bundle.Mnemonic = ""
	st, e := os.Stat(pin.Path)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("recovery file permissions", e)
	}
	if _, e = i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch)); e != nil {
		t.Fatal("closed export retained inventory permit", e)
	}
}
func TestHostedInventory2OriginalViewAndHold(t *testing.T) {
	h, v, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	var revoked atomic.Bool
	original := func(ctx context.Context, fn func(func() error) error) error {
		return fn(func() error {
			if revoked.Load() {
				return ErrConflict
			}
			return ctx.Err()
		})
	}
	head, e := i.CaptureRecoveryHead(ctx, login.Token, original)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := h.w.counts()
	revoked.Store(true)
	d, e := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "revoked.json")), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = v.PrepareInventoryExport2(ctx, login.Token, head, d, hostedEpoch); e == nil {
		t.Fatal("replacement parent fence rescued revoked head")
	}
	if after, _ := h.w.counts(); after != before {
		t.Fatal("revoked head unwrapped recovery")
	}
	revoked.Store(false)
	if _, e = head.Hold(ctx, strings.Repeat("f", 64)); e == nil {
		t.Fatal("substituted original token")
	}
	vtReset(t, h, "alice", 1)
	fresh := vtLogin(t, h, "alice", 2)
	// View remains available while recovery-required/held. Full material does not.
	held, e := i.CaptureRecoveryHead(ctx, fresh.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if e != nil {
		t.Fatal("held public head", e)
	}
	heldDest, e := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "held.json")), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer heldDest.Close()
	if _, e = v.PrepareInventoryExport2(ctx, fresh.Token, held, heldDest, hostedEpoch); !errors.Is(e, gymaccount.ErrHeld) && !errors.Is(e, gymaccount.ErrForbidden) {
		t.Fatal("held export", e)
	}
	if after, _ := h.w.counts(); after != before {
		t.Fatal("held recovery material unwrapped")
	}
}
func TestHostedInventory2CloseInvalidatesDormantHeadAndJoinsPublication(t *testing.T) {
	_, _, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	head, e := i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if e != nil {
		t.Fatal(e)
	}
	lease, e := head.Hold(ctx, login.Token)
	if e != nil {
		t.Fatal(e)
	}
	work, release, e := lease.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	closed := make(chan error, 1)
	go func() { closed <- i.Close() }()
	select {
	case <-work.Done():
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("close did not cancel active publication")
	}
	select {
	case e := <-closed:
		release()
		t.Fatal("close returned before publication joined", e)
	default:
	}
	if e = lease.Check(); e == nil {
		release()
		t.Fatal("closing lease stayed valid")
	}
	release()
	select {
	case e = <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not join")
	}
	if _, e = head.Hold(ctx, login.Token); e == nil {
		t.Fatal("closed inventory revived head")
	}
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestHostedInventory2VaultCloseErasesPreparedExport(t *testing.T) {
	_, v, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	head, err := i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if err != nil {
		t.Fatal(err)
	}
	pin := currentPin(t, filepath.Join(t.TempDir(), "not-published.json"))
	d, err := OpenCurrentDestination(ctx, pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p, err := v.PrepareInventoryExport2(ctx, login.Token, head, d, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if len(p.raw) == 0 {
		t.Fatal("fixture lacks prepared secret")
	}
	retained := p.raw
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	for _, b := range retained {
		if b != 0 {
			t.Fatal("vault close did not erase prepared bytes")
		}
	}
	if p.raw != nil || !p.closed || len(v.inventoryExports2) != 0 {
		t.Fatal("vault close retained export")
	}
	if err = p.Publish(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("closed export published", err)
	}
	if _, err = os.Lstat(pin.Path); !os.IsNotExist(err) {
		t.Fatal("closed export left plaintext", err)
	}
	if _, err = i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch)); err != nil {
		t.Fatal("vault close retained inventory permit", err)
	}
}

func TestHostedInventory2ResetBeforePublishRefusesExport(t *testing.T) {
	h, v, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	head, err := i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if err != nil {
		t.Fatal(err)
	}
	pin := currentPin(t, filepath.Join(t.TempDir(), "revoked-publication.json"))
	d, err := OpenCurrentDestination(ctx, pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := v.PrepareInventoryExport2(ctx, login.Token, head, d, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	retained := p.raw
	vtReset(t, h, "alice", 1)
	if err = p.Publish(ctx); err == nil {
		t.Fatal("revoked session published prepared recovery")
	}
	if _, err = os.Lstat(pin.Path); !os.IsNotExist(err) {
		t.Fatal("revoked export left plaintext", err)
	}
	for _, b := range retained {
		if b != 0 {
			t.Fatal("failed publication retained secret bytes")
		}
	}
	if err = p.Publish(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("failed action replayed", err)
	}
}

func TestHostedInventory2AndLegacyShareExportExclusion(t *testing.T) {
	h, v, i, login := inventoryExportSetup2(t)
	ctx := context.Background()
	head, err := i.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if err != nil {
		t.Fatal(err)
	}
	d, err := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "current.json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := v.PrepareInventoryExport2(ctx, login.Token, head, d, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	b := head.Binding()
	legacy := wallet.AllocationBinding{Version: 1, InventoryID: strings.Repeat("1", 64), AuthorityID: b.AuthorityID, AccountID: b.AccountID, PrincipalID: b.PrincipalID, ProvisionID: b.ProvisionID, HostedVaultID: b.HostedVaultID, RetentionID: b.RetentionID, WalletOwnerID: b.WalletOwnerID, SourceBindingID: b.SourceBindingID, ManagerSchema: 13, MaxAllocations: 1024, MaxBytes: 4194304, MaxPlanAttempts: 128, MaxBranchIndex: 4096, InitialManifest: b.InitialManifest}
	old, err := wallet.CreateHostedAllocationInventory(ctx, filepath.Join(t.TempDir(), "old"), h.accounts, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldHead, err := old.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch))
	if err != nil {
		t.Fatal(err)
	}
	oldDest, err := OpenCurrentDestination(ctx, currentPin(t, filepath.Join(t.TempDir(), "old.json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer oldDest.Close()
	if got, err := v.PrepareInventoryExport(ctx, login.Token, oldHead, oldDest, hostedEpoch); !errors.Is(err, ErrBusy) {
		if got != nil {
			got.Close()
		}
		t.Fatal("same-account parallel export accepted", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = old.CaptureRecoveryHead(ctx, login.Token, wallet.HostedAllocationEpochFence(hostedEpoch)); err != nil {
		t.Fatal("failed legacy export leaked inventory lease", err)
	}
}
