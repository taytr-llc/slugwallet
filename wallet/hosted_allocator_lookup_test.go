// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"github.com/taytr-llc/slug/gymaccount"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHostedAllocatorReceiveLookupNeverAcknowledges(t *testing.T) {
	h := newAllocatorFixture(t, "zero256")
	ctx := context.Background()
	allocatorPool(t, h)
	p, e := h.allocator.PlanReceive(ctx, allocationTestID(2))
	if e != nil {
		t.Fatal(e)
	}
	r, e := h.allocator.Reserve(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.allocator.Consume(ctx, r); e != nil {
		t.Fatal(e)
	}
	beforeMeta := h.inventory.meta
	beforeLocal := allocatorLocal(t, h)
	if beforeMeta.ActiveAllocationID != allocationTestID(2) {
		t.Fatal("fixture is already acknowledged")
	}
	checks := func() {
		t.Helper()
		if e := h.allocator.LookupReceiveAllocation(ctx, allocationTestID(2)); e != nil {
			t.Fatal(e)
		}
		if e := h.allocator.LookupReceiveAllocation(ctx, allocationTestID(1)); !errors.Is(e, ErrAllocationConflict) {
			t.Fatal("foreign kind", e)
		}
		if e := h.allocator.LookupReceiveAllocation(ctx, allocationTestID(99)); !errors.Is(e, ErrAllocationNotFound) {
			t.Fatal("absent", e)
		}
		if !reflect.DeepEqual(beforeMeta, h.inventory.meta) || !reflect.DeepEqual(beforeLocal, allocatorLocal(t, h)) {
			t.Fatal("lookup changed durable state")
		}
	}
	checks()
	// A real schema2 reset gives a held View with no withdrawal capability.
	now := time.Now().UnixMilli()
	reset := gymaccount.VerifiedReset{VerifierConfigHash: strings.Repeat("a", 64), Issuer: "fixture:allocator", Subject: h.fixture, EventID: allocationTestID(90), Stage: "begin", FromEpoch: 1, ToEpoch: 2, VerifiedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000}
	if _, _, e = h.accounts.BeginReset(ctx, reset); e != nil {
		t.Fatal(e)
	}
	reset.Stage = "complete"
	if _, _, e = h.accounts.CompleteReset(ctx, reset); e != nil {
		t.Fatal(e)
	}
	attempt, e := h.accounts.IssueLogin(ctx, "fixture:allocator")
	if e != nil {
		t.Fatal(e)
	}
	now = time.Now().UnixMilli() // Assertion is issued after its fresh login challenge.
	h.session, e = h.accounts.LoginWithAssertion(ctx, attempt.ID, gymaccount.VerifiedLogin{VerifierConfigHash: strings.Repeat("a", 64), Issuer: "fixture:allocator", Subject: h.fixture, Nonce: attempt.Nonce, AuthenticatedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000, CredentialEpoch: 2})
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := h.accounts.BeginChallenge(ctx, h.session.Token, "recover")
	if e != nil {
		t.Fatal(e)
	}
	entropy := retainedEntropy(t, retainedRecoveryFixture(t, h.fixture))
	key, e := deriveRecoveryGymKey(entropy, h.wallet.chainParams)
	clear(entropy[:])
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
	h.reattach(t)

	checks()
	// The final fence also protects a refusal result, not only successful lookup.
	saved := h.allocator.epoch
	calls := 0
	h.allocator.epoch = func(ctx context.Context, fn func(func() error) error) error {
		calls++
		if calls == 2 {
			h.revoked.Store(true)
		}
		return saved(ctx, fn)
	}
	if e := h.allocator.LookupReceiveAllocation(ctx, allocationTestID(99)); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("final fence leaked absence", e)
	}
	h.allocator.epoch = saved
	h.revoked.Store(false)
	if e = h.accounts.Logout(ctx, h.session.Token); e != nil {
		t.Fatal(e)
	}
	if e := h.allocator.LookupReceiveAllocation(ctx, allocationTestID(99)); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked lookup leaked absence", e)
	}
	if _, e := h.allocator.Resolve(ctx, allocationTestID(99)); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked resolve leaked absence", e)
	}
	if _, e := h.allocator.Resume(ctx, allocationTestID(99)); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked resume leaked absence", e)
	}
}
