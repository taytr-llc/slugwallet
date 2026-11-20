// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"github.com/taytr-llc/slug/gymaccount"
	"strings"
	"testing"
	"time"
)

func TestAllocatedWithdrawalHeldBookkeepingIsNotDraftAuthority(t *testing.T) {
	h := newAllocatorFixture(t, "zero256")
	ctx := context.Background()
	allocatorPool(t, h)
	v := allocatedVector(t, h.fixture)
	allocatedFunding(t, h, v)
	s, e := h.allocator.CreateWithdrawals(ctx, v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.Plan(ctx, allocationTestID(10), v.Request)
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
	if _, e = h.allocator.Acknowledge(ctx, receipt); e != nil {
		t.Fatal(e)
	}
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
	s, e = h.allocator.OpenWithdrawals(ctx, v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	if record, e := s.InspectRecord(ctx, v.Request.OperationID); e != nil || record.DraftDigest != v.DraftDigest {
		t.Fatal("held original View lost paired bookkeeping", e)
	}
	ack, e := h.allocator.Resolve(ctx, allocationTestID(10))
	if e != nil {
		t.Fatal("held exact link reconciliation", e)
	}
	if _, e = h.allocator.Finalize(ctx, ack); !errors.Is(e, gymaccount.ErrHeld) {
		t.Fatal("held reconciliation became actionable draft", e)
	}
	if _, e = s.Lookup(ctx, v.Request.OperationID); !errors.Is(e, gymaccount.ErrHeld) {
		t.Fatal("held Lookup disclosed actionable draft", e)
	}
	if _, e = s.Sign(ctx, v.Request.OperationID, v.DraftDigest); !errors.Is(e, gymaccount.ErrHeld) {
		t.Fatal("held Sign accepted", e)
	}
	if e = s.Abandon(ctx, v.Request.OperationID, v.DraftDigest); !errors.Is(e, gymaccount.ErrHeld) {
		t.Fatal("held Abandon mutated", e)
	}
}
