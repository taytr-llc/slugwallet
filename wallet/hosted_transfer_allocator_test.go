// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
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

type allocatorFixture2 struct {
	accounts  *gymaccount.Store
	session   gymaccount.Session
	inventory *HostedAllocationInventory2
	allocator *HostedAllocator2
	wallet    *Wallet
	loader    *Loader
	binding   AllocationBinding2
	epoch     HostedAllocationEpochFence
	revoked   atomic.Bool
	fixture   string
}

func newAllocatorFixture2(t *testing.T, fixture string) *allocatorFixture2 {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile required")
	}
	ctx := context.Background()
	h := &allocatorFixture2{fixture: fixture}
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
	for _, v := range readTransferAllocationReference(t).Positives {
		if v.Kind != "binding2" {
			continue
		}
		var b AllocationBinding2
		if json.Unmarshal(v.Value, &b) != nil {
			t.Fatal("independent binding2")
		}
		if b.InitialManifest.GymID == challenge.GymID {
			h.binding = b
		}
	}
	if h.binding.Version == 0 {
		t.Fatal("independent fixture binding missing")
	}
	h.binding.AuthorityID = h.accounts.AuthorityID()
	h.binding.AccountID = h.session.Account.ID
	h.binding.PrincipalID = h.session.Account.PrincipalID
	h.loader = NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 0)
	h.wallet, e = h.loader.CreateHostedTransferWallet(ctx, retainedPubPass, retainedPrivPass, entropy, time.Unix(0, 0), allocationGuard2(h.binding, false))
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
	h.inventory, e = CreateHostedAllocationInventory2(ctx, filepath.Join(t.TempDir(), "inventory"), h.accounts, h.binding)
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
func (h *allocatorFixture2) reattach(t *testing.T) {
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
func allocatorLocal2(t *testing.T, h *allocatorFixture2) waddrmgr.HostedAllocationState2 {
	t.Helper()
	var out waddrmgr.HostedAllocationState2
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
func allocatorPool2(t *testing.T, h *allocatorFixture2) *AllocationAcknowledgement2 {
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
