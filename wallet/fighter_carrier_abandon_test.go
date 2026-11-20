//go:build !slugtestpow

package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// This fixture persists a public independently modeled request and its exact
// manager-derived reserved range through the private storage leaf. It models
// the crash between Reserve and Consume, not a public ownership capability or
// a successful live-chain Prepare/watch/sign operation.
func carrierAbandonFixture(t *testing.T) (*allocatorFixture2, *FighterCarrierOwner, fightercarrier.Preparation, *AllocationReservation2) {
	t.Helper()
	ctx := context.Background()
	h := newAllocatorFixture2(t, "zero256")
	allocatorPool2(t, h)
	pin, err := allocationCarrierPin2(h.binding)
	if err != nil {
		t.Fatal(err)
	}
	j, err := fightercarrier.Create(ctx, filepath.Join(t.TempDir(), "carrier"), fightercarrier.Identity{JournalID: h.binding.CarrierJournalID, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	o, err := h.allocator.CreateFighterCarrier(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	var p fightercarrier.Preparation
	if err = json.Unmarshal(carrierReference(t)["zero256/hosted/transfer/one/preparation"].Value, &p); err != nil {
		t.Fatal(err)
	}
	app, err := j.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := app.StageIntent(p.Request)
	publishCarrierFixture(t, staged, err)
	app.Close()
	req := AllocationRequest2{Version: 2, Kind: "carrier_return", ConsumerID: p.Request.RequestID, Purpose: 84, Branch: 1, MinConfirmations: 1, InputPurpose: 84, ChangePurpose: 84, TxVersion: 1, InputSequence: wire.MaxTxInSequenceNum, SighashType: 1, CarrierBindingID: o.binding, OwnershipPinID: o.pin.OwnershipPinID, PriorStateID: p.Request.PriorStateID, RecipientGym: p.Request.RecipientGym, FundingDigest: p.NewFunding.FundingDigest, EscrowAtoms: 500000, CommitFeeAtoms: 10000, SpendFeeAtoms: 10000, MinChangeAtoms: 1000}
	plan := &AllocationPlan2{owner: h.allocator, id: p.Request.RequestID, request: req, sequence: 2}
	err = walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := h.allocator.auditPair(ctx, tx)
		if e != nil {
			return e
		}
		plan.before = state.Meta.Cursors
		plan.managerPlan, plan.candidate, e = h.wallet.Manager.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace2), 84, 1)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	value := plan.row().Reservation
	row, err := h.inventory.commitReservation(ctx, h.session.Token, h.epoch, &h.allocator.account, &value)
	if err != nil {
		t.Fatal(err)
	}
	return h, o, p, &AllocationReservation2{owner: h.allocator, row: row, plan: plan, burnOnly: true}
}

func TestFighterCarrierAbandonUnpreparedReservedAndLostAck(t *testing.T) {
	for _, lostBurnAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-consume-no-local", true: "lost-burn-ack"}[lostBurnAck], func(t *testing.T) {
			ctx := context.Background()
			h, o, p, reservation := carrierAbandonFixture(t)
			id := p.Request.RequestID
			if lostBurnAck {
				if _, err := h.allocator.Burn(ctx, reservation); err != nil {
					t.Fatal(err)
				}
			} else {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				if _, err := h.allocator.Consume(canceled, reservation); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			// Discard every original private plan, like a lost-ack owner restart.
			h.allocator.latest = nil
			reservation = nil
			if err := o.AbandonUnprepared(ctx, id); err != nil {
				t.Fatal(err)
			}
			local := allocatorLocal2(t, h)
			if len(local.Records) != 2 || local.Records[1].Outcome != "burned" || local.Meta.Cursors[5] != 1 || h.inventory.rows[id].Phase != "burned" || h.inventory.meta.ActiveAllocationID != "" || withdrawalExclusions2(t, h) != 0 {
				t.Fatal("exact range not burned and acknowledged")
			}
			before := cloneAllocationRow2(h.inventory.rows[id])
			revision := h.inventory.meta.Revision
			if err := o.AbandonUnprepared(ctx, id); err != nil {
				t.Fatal("burn replay", err)
			}
			if !reflect.DeepEqual(before, h.inventory.rows[id]) || revision != h.inventory.meta.Revision {
				t.Fatal("burn replay mutated inventory")
			}
			app, err := o.journal.TryAcquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			op, err := app.Lookup(id)
			if err != nil || op.Stage != "intent" || op.Preparation != nil {
				t.Fatal("helper published app abandonment", err)
			}
		})
	}
}

func TestFighterCarrierAbandonUnpreparedConsumedAndUnknownRefuse(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "consumed"}[consumed], func(t *testing.T) {
			ctx := context.Background()
			h, o, p, r := carrierAbandonFixture(t)
			if consumed {
				p.BindingID = o.binding
				p.Review.BindingID = o.binding
				p.NewFunding.ReservationDigest = r.row.ReservationDigest
				var err error
				p.ReviewDigest, err = fightercarrier.ReviewDigest(p.Review)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := fightercarrier.PreparationDigest(p)
				if err != nil {
					t.Fatal(err)
				}
				link := allocationLink2(h.inventory, r.row, r.plan.before, "consumed", digest)
				err = walletdb.Update(h.wallet.db, func(tx walletdb.ReadWriteTx) error {
					if e := h.wallet.Manager.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedLocalNamespace2), r.plan.managerPlan, link); e != nil {
						return e
					}
					return o.commitPreparation(ctx, tx, p)
				})
				if err != nil {
					t.Fatal(err)
				}
				// The lost Consume ack is a complete, coherent same-DB commit.
				allocatorLocal2(t, h)
				if err = o.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, fightercarrier.ErrConflict) {
					t.Fatal("consumed preparation was released", err)
				}
			} else {
				h.allocator.poisoned.Store(true)
				if err := o.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, ErrAllocationPoisoned) {
					t.Fatal("unknown owner reused", err)
				}
				h.allocator.poisoned.Store(false) // Restore only the injected test fault.
			}
			if h.inventory.rows[p.Request.RequestID].Phase != "reserved" {
				t.Fatal("refusal acknowledged or burned uncertain range")
			}
		})
	}
}

func TestFighterCarrierAbandonUnpreparedOriginalSession(t *testing.T) {
	ctx := context.Background()
	h, o, p, _ := carrierAbandonFixture(t)
	h.revoked.Store(true)
	if err := o.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked original accepted", err)
	}
	h.revoked.Store(false)
	if o.poisoned.Load() || len(allocatorLocal2(t, h).Records) != 1 {
		t.Fatal("pre-write refusal changed wallet")
	}
	now := time.Now().UnixMilli()
	reset := gymaccount.VerifiedReset{VerifierConfigHash: strings.Repeat("a", 64), Issuer: "fixture:allocator", Subject: "zero256", EventID: allocationTestID(923), Stage: "begin", FromEpoch: 1, ToEpoch: 2, VerifiedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000}
	if _, _, err := h.accounts.BeginReset(ctx, reset); err != nil {
		t.Fatal(err)
	}
	reset.Stage = "complete"
	if _, _, err := h.accounts.CompleteReset(ctx, reset); err != nil {
		t.Fatal(err)
	}
	if err := o.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, gymaccount.ErrUnauthorized) {
		t.Fatal("reset rescued original owner", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.allocator.Close(); err != nil {
		t.Fatal(err)
	}
	attempt, err := h.accounts.IssueLogin(ctx, "fixture:allocator")
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now().UnixMilli()
	h.session, err = h.accounts.LoginWithAssertion(ctx, attempt.ID, gymaccount.VerifiedLogin{VerifierConfigHash: strings.Repeat("a", 64), Issuer: "fixture:allocator", Subject: "zero256", Nonce: attempt.Nonce, AuthenticatedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000, CredentialEpoch: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Reestablish the same gym with the published fixture before isolating
	// the hold check; otherwise the earlier recovery-required guard refuses.
	challenge, err := h.accounts.BeginChallenge(ctx, h.session.Token, "recover")
	if err != nil {
		t.Fatal(err)
	}
	entropy := retainedEntropy(t, retainedRecoveryFixture(t, "zero256"))
	key, err := deriveRecoveryGymKey(entropy, &chaincfg.MainNetParams)
	clear(entropy[:])
	if err != nil {
		t.Fatal(err)
	}
	auth, err := gymaccount.SignChallenge(challenge, key)
	key.Zero()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.accounts.CompleteChallenge(ctx, h.session.Token, challenge.ChallengeID, auth); err != nil {
		t.Fatal(err)
	}
	h.allocator, err = h.inventory.Attach(ctx, h.wallet, h.session.Token, h.epoch)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := h.allocator.OpenFighterCarrier(ctx, o.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer newOwner.Close()
	if err = newOwner.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, gymaccount.ErrHeld) {
		t.Fatal("held session released reservation", err)
	}
	if len(allocatorLocal2(t, h).Records) != 1 || h.inventory.rows[p.Request.RequestID].Phase != "reserved" {
		t.Fatal("reset or hold mutated reservation")
	}
}

func TestFighterCarrierAbandonUnpreparedPostCommitRevocation(t *testing.T) {
	ctx := context.Background()
	h, o, p, _ := carrierAbandonFixture(t)
	original := h.allocator.epoch
	calls := 0
	h.allocator.epoch = func(ctx context.Context, fn func(func() error) error) error {
		// The seventh fence is Burn's post-commit check. The durable assertion
		// below independently proves this schedule reached the private write.
		// No DB read or address mutex is acquired inside the account fence.
		calls++
		if calls == 7 {
			h.revoked.Store(true)
		}
		return original(ctx, fn)
	}
	if err := o.AbandonUnprepared(ctx, p.Request.RequestID); !errors.Is(err, fightercarrier.ErrOutcomeUnknown) || !errors.Is(err, gymaccount.ErrUnauthorized) {
		t.Fatal("postcommit revocation laundered", err)
	}
	if !o.poisoned.Load() || !h.allocator.poisoned.Load() || !h.wallet.hostedAllocationTainted.Load() {
		t.Fatal("uncertain owner remains reusable")
	}
	if h.inventory.rows[p.Request.RequestID].Phase != "reserved" {
		t.Fatal("revoked completion published")
	}
	if err := walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
		state, err := h.wallet.Manager.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace2))
		if err == nil && (len(state.Records) != 2 || state.Records[1].Outcome != "burned") {
			t.Fatal("fault occurred before durable burn")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFighterCarrierAbandonUnpreparedRestoredNoLocal(t *testing.T) {
	ctx := context.Background()
	c := carrierReference(t)["zero256/restored/transfer/one/preparation"]
	if c.Name == "" {
		t.Fatal("frozen restored case missing")
	}
	_, w, j, o, _ := restoredCarrierFixture(t, c, false)
	var p fightercarrier.Preparation
	if err := json.Unmarshal(c.Value, &p); err != nil {
		t.Fatal(err)
	}
	app, err := j.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := app.StageIntent(p.Request)
	publishCarrierFixture(t, staged, err)
	app.Close()
	read := func() carrierWalletState {
		var state carrierWalletState
		err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			var e error
			state, e = readCarrierWalletState(ctx, tx, j.Identity().JournalID, &o.pin)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := read()
	for i := 0; i < 2; i++ {
		if err = o.AbandonUnprepared(ctx, p.Request.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, read()) {
		t.Fatal("restored no-local abandonment changed wallet")
	}
	if err = o.AbandonUnprepared(ctx, allocationTestID(999)); !errors.Is(err, fightercarrier.ErrNotFound) {
		t.Fatal("absent intent accepted", err)
	}
}
