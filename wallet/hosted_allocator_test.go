// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type allocatorFixture struct {
	accounts  *gymaccount.Store
	session   gymaccount.Session
	inventory *HostedAllocationInventory
	allocator *HostedAllocator
	wallet    *Wallet
	loader    *Loader
	binding   AllocationBinding
	epoch     HostedAllocationEpochFence
	revoked   atomic.Bool
	fixture   string
}

func allocationTestID(n uint64) string { return fmt.Sprintf("%064x", n) }
func allocatorLogin(accounts *gymaccount.Store, fixture string) (gymaccount.Session, error) {
	ctx := context.Background()
	attempt, e := accounts.IssueLogin(ctx, "fixture:allocator")
	if e != nil {
		return gymaccount.Session{}, e
	}
	now := time.Now().UnixMilli()
	return accounts.LoginWithAssertion(ctx, attempt.ID, gymaccount.VerifiedLogin{VerifierConfigHash: strings.Repeat("a", 64), Issuer: "fixture:allocator", Subject: fixture, Nonce: attempt.Nonce, AuthenticatedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000, CredentialEpoch: 1})
}
func newAllocatorFixture(t *testing.T, fixture string) *allocatorFixture {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile required")
	}
	ctx := context.Background()
	h := &allocatorFixture{fixture: fixture}
	cfg := gymaccount.Config{Version: 1, Principals: []gymaccount.FixturePrincipal{{Issuer: "fixture:allocator", Subject: "zero256", Fixture: "zero256"}, {Issuer: "fixture:allocator", Subject: "incrementing256", Fixture: "incrementing256"}}, MaxSessions: 128, MaxChallenges: 64, MaxEvents: 256}
	var e error
	h.accounts, e = gymaccount.CreateIdentity(filepath.Join(t.TempDir(), "accounts"), gymaccount.IdentityConfig{Version: 2, VerifierConfigHash: strings.Repeat("a", 64), MaxLoginAttempts: 128, Accounts: cfg})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if h.allocator != nil {
			_ = h.allocator.Close()
		}
		if h.inventory != nil {
			_ = h.inventory.Close()
		}
		if h.loader != nil {
			if _, ok := h.loader.LoadedWallet(); ok {
				if e := h.loader.UnloadWallet(); e != nil {
					t.Error(e)
				}
			}
		}
		h.accounts.Close()
	})
	h.session, e = allocatorLogin(h.accounts, fixture)
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := h.accounts.BeginChallenge(ctx, h.session.Token, "enroll")
	if e != nil {
		t.Fatal(e)
	}
	entropy := retainedEntropy(t, retainedRecoveryFixture(t, fixture))
	defer clear(entropy[:])
	key, e := deriveRecoveryGymKey(entropy, &chaincfg.MainNetParams)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := gymaccount.SignChallenge(challenge, key)
	key.Zero()
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = h.accounts.CompleteChallenge(ctx, h.session.Token, challenge.ChallengeID, auth); e != nil {
		t.Fatal(e)
	}
	for _, b := range loadAllocationReference(t).Bindings {
		if b.Binding.InitialManifest.GymID == challenge.GymID {
			h.binding = b.Binding
		}
	}
	if h.binding.Version == 0 {
		t.Fatal("independent fixture binding missing")
	}
	h.binding.AuthorityID = h.accounts.AuthorityID()
	h.binding.AccountID = h.session.Account.ID
	h.binding.PrincipalID = h.session.Account.PrincipalID
	h.loader = NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 0)
	h.wallet, e = h.loader.CreateHostedAllocationWallet(ctx, retainedPubPass, retainedPrivPass, entropy, time.Unix(0, 0), allocationGuard(h.binding, false))
	if e != nil {
		t.Fatal(e)
	}
	h.epoch = func(ctx context.Context, fn func(func() error) error) error {
		// Every account fence must be outside the ordinary address mutex.
		if !h.wallet.newAddrMtx.TryLock() {
			return errors.New("account fence holds address mutex")
		}
		h.wallet.newAddrMtx.Unlock()
		check := func() error {
			if h.revoked.Load() {
				return gymaccount.ErrUnauthorized
			}
			return ctx.Err()
		}
		if e := check(); e != nil {
			return e
		}
		return fn(check)
	}
	h.inventory, e = CreateHostedAllocationInventory(ctx, filepath.Join(t.TempDir(), "inventory"), h.accounts, h.binding)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.inventory.BindWallet(ctx, h.wallet, h.session.Token, h.epoch); e != nil {
		t.Fatal(e)
	}
	h.allocator, e = h.inventory.Attach(ctx, h.wallet, h.session.Token, h.epoch)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (h *allocatorFixture) reattach(t *testing.T) {
	t.Helper()
	if e := h.allocator.Close(); e != nil {
		t.Fatal(e)
	}
	a, e := h.inventory.Attach(context.Background(), h.wallet, h.session.Token, h.epoch)
	if e != nil {
		t.Fatal(e)
	}
	h.allocator = a
}
func allocatorLocal(t *testing.T, h *allocatorFixture) waddrmgr.HostedAllocationState {
	t.Helper()
	var out waddrmgr.HostedAllocationState
	e := walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
		var e error
		out, e = h.allocator.auditPair(context.Background(), tx)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func allocatorPool(t *testing.T, h *allocatorFixture) *AllocationAcknowledgement {
	t.Helper()
	ctx := context.Background()
	p, e := h.allocator.PlanRecipient(ctx, allocationTestID(1))
	if e != nil {
		t.Fatal(e)
	}
	r, e := h.allocator.Reserve(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := h.allocator.Consume(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := h.allocator.Acknowledge(ctx, receipt)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range loadAllocationReference(t).States {
		if s.Name == h.fixture+"/pool-complete" {
			want := s.Snapshot.Rows[0].Reservation
			if ack.record.Address != want.Address || ack.record.Script != want.Script || ack.record.SelectedIndex != want.SelectedIndex {
				t.Fatal("pool path differs from independent derivation")
			}
		}
	}
	return ack
}
func TestHostedAllocatorReserveConsumeReopenAndRevocation(t *testing.T) {
	h := newAllocatorFixture(t, "zero256")
	ctx := context.Background()
	a := h.allocator
	p, e := a.PlanRecipient(ctx, allocationTestID(1))
	if e != nil {
		t.Fatal(e)
	}
	if allocatorLocal(t, h).Meta.Cursors != [8]uint32{} {
		t.Fatal("plan mutated cursors")
	}
	r, e := a.Reserve(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	if h.inventory.meta.Cursors[4] != 1 || allocatorLocal(t, h).Meta.Cursors[4] != 0 {
		t.Fatal("reservation must lead local cursor")
	}
	head, e := h.inventory.CaptureRecoveryHead(ctx, h.session.Token, h.epoch)
	if e != nil {
		t.Fatal(e)
	}
	if head.Manifest().Accounts[2].NextExternal != 1 {
		t.Fatal("recovery head omitted pending reservation")
	}
	if _, e = a.Resolve(ctx, allocationTestID(99)); !errors.Is(e, ErrAllocationNotFound) {
		t.Fatal(e)
	}
	if _, e = a.Resolve(ctx, allocationTestID(1)); !errors.Is(e, ErrAllocationResumeRequired) {
		t.Fatal(e)
	}
	h.reattach(t)
	a = h.allocator
	if _, e = a.Consume(ctx, r); !errors.Is(e, ErrAllocationInvalid) {
		t.Fatal("foreign attachment reservation accepted", e)
	}
	r, e = a.Resume(ctx, allocationTestID(1))
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := a.Consume(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if allocatorLocal(t, h).Meta.Cursors[4] != 1 || h.inventory.meta.ActiveAllocationID == "" {
		t.Fatal("local commit must precede inventory acknowledgement")
	}
	h.revoked.Store(true)
	if _, e = a.Acknowledge(ctx, receipt); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked receipt published", e)
	}
	h.revoked.Store(false)
	ack, e := a.Resolve(ctx, allocationTestID(1))
	if e != nil {
		t.Fatal(e)
	}
	if ack.record.SelectedIndex != 0 || h.inventory.meta.ActiveAllocationID != "" || h.inventory.meta.Revision != 2 {
		t.Fatal("exact commit reconciliation")
	}
	if ready, e := a.Finalize(ctx, ack); ready != nil || !errors.Is(e, ErrAllocationUnavailable) {
		t.Fatal("unwatched address disclosed", e)
	}
	if _, e = a.Reserve(ctx, p); !errors.Is(e, ErrAllocationInvalid) {
		t.Fatal("old owner plan accepted", e)
	}
	h.reattach(t)
	a = h.allocator
	again, e := a.Resolve(ctx, allocationTestID(1))
	if e != nil || !reflect.DeepEqual(again.record, ack.record) {
		t.Fatal("reopen changed immutable link", e)
	}
	before := h.inventory.meta
	p, e = a.PlanReceive(ctx, allocationTestID(2))
	if e != nil {
		t.Fatal(e)
	}
	r, e = a.Reserve(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	burn, e := a.Burn(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	done, e := a.Acknowledge(ctx, burn)
	if e != nil {
		t.Fatal(e)
	}
	if done.record.Outcome != "burned" || allocatorLocal(t, h).Meta.Cursors[4] != 2 || h.inventory.meta.Revision != before.Revision+2 {
		t.Fatal("burn reused or omitted range")
	}
	if _, e = a.Finalize(ctx, done); !errors.Is(e, ErrAllocationConflict) {
		t.Fatal("burn disclosed", e)
	}
}
func TestHostedAllocatorOriginalTokenAndJoinedClose(t *testing.T) {
	h := newAllocatorFixture(t, "incrementing256")
	ctx := context.Background()
	allocatorPool(t, h)
	old := h.allocator
	if e := h.accounts.Logout(ctx, h.session.Token); e != nil {
		t.Fatal(e)
	}
	fresh, e := allocatorLogin(h.accounts, h.fixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = old.PlanReceive(ctx, allocationTestID(3)); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("replacement login revived old attachment", e)
	}
	h.session = fresh
	h.reattach(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	original := h.allocator.epoch
	h.allocator.epoch = func(ctx context.Context, fn func(func() error) error) error {
		close(entered)
		<-release
		return original(ctx, fn)
	}
	go func() { _, e := h.allocator.CapturePublicRecovery(ctx); finished <- e }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- h.allocator.Close() }()
	select {
	case <-closed:
		t.Fatal("Close did not join admitted account fence")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if e := <-finished; !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled read returned payload", e)
	}
	if e := <-closed; e != nil {
		t.Fatal(e)
	}
	if _, e := h.allocator.PlanReceive(ctx, allocationTestID(4)); !errors.Is(e, ErrAllocationClosed) {
		t.Fatal(e)
	}
}

func TestHostedAllocatorPoisonRequiresRealWalletReopen(t *testing.T) {
	h := newAllocatorFixture(t, "zero256")
	ctx := context.Background()
	allocatorPool(t, h)
	// Models an already diagnosed ambiguous local commit/watch outcome. Close
	// must join and permit unloading, but cannot clear taint on this Wallet.
	oldWallet := h.wallet
	h.allocator.poisoned.Store(true)
	if e := h.allocator.Close(); !errors.Is(e, ErrAllocationPoisoned) {
		t.Fatal(e)
	}
	if a, e := h.inventory.Attach(ctx, oldWallet, h.session.Token, h.epoch); a != nil || !errors.Is(e, ErrAllocationPoisoned) {
		t.Fatal("same-live-wallet reopened", e)
	}
	if e := h.loader.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
	if e := h.inventory.Close(); e != nil {
		t.Fatal(e)
	}
	inventory, e := OpenHostedAllocationInventory(ctx, h.inventory.path, h.accounts, h.binding)
	if e != nil {
		t.Fatal(e)
	}
	h.inventory = inventory
	w, e := h.loader.OpenHostedAllocationWallet(ctx, retainedPubPass, allocationGuard(h.binding, true))
	if e != nil {
		t.Fatal(e)
	}
	h.wallet = w
	if w == oldWallet || w.hostedAllocationTainted.Load() {
		t.Fatal("loader reused poisoned concrete owner")
	}
	a, e := inventory.Attach(ctx, w, h.session.Token, h.epoch)
	if e != nil {
		t.Fatal(e)
	}
	h.allocator = a
	if _, e = a.Resolve(ctx, allocationTestID(1)); e != nil {
		t.Fatal("audited real reopen lost original link", e)
	}
}
