//go:build !slugtestpow

package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func publishCarrierFixture(t *testing.T, p *fightercarrier.PreparedCommit, err error) fightercarrier.Operation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	v, err := p.Publish(func(fn func(func() error) error) error { return fn(func() error { return nil }) })
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// These tests exercise the concrete app-journal reconciliation lease, durable
// wallet records/exclusions and original account fences. The initial prepared
// rows are independently modeled test inputs inserted through the private same-DB
// leaf; they do not manufacture a public ownership capability or claim that a
// live Prepare/watch operation was performed.
func TestFighterCarrierReconciliationOriginalFence(t *testing.T) {
	refs := carrierReference(t)
	for _, retain := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			name := "abandon"
			if retain {
				name = "retain"
			}
			if after {
				name += "/revoked-after-commit"
			} else {
				name += "/live"
			}
			t.Run(name, func(t *testing.T) {
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
				defer j.Close()
				o, err := h.allocator.CreateFighterCarrier(ctx, j)
				if err != nil {
					t.Fatal(err)
				}
				defer o.Close()
				var p fightercarrier.Preparation
				var signed fightercarrier.SignedPackage
				if err = json.Unmarshal(refs["zero256/hosted/transfer/one/preparation"].Value, &p); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(refs["zero256/hosted/transfer/one/package"].Value, &signed); err != nil {
					t.Fatal(err)
				}
				app, err := j.TryAcquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer app.Close()
				staged, err := app.StageIntent(p.Request)
				intent := publishCarrierFixture(t, staged, err)
				time.Sleep(2 * time.Millisecond)
				p.BindingID = o.binding
				p.Review.BindingID = o.binding
				p.PreparedAtMS = time.Now().UnixMilli()
				p.ReviewDigest, err = fightercarrier.ReviewDigest(p.Review)
				if err != nil {
					t.Fatal(err)
				}
				if p.PreparedAtMS <= intent.CreatedAtMS {
					t.Fatal("fixture preparation clock did not advance")
				}
				if err = walletdb.Update(h.wallet.db, func(tx walletdb.ReadWriteTx) error { return o.commitPreparation(ctx, tx, p) }); err != nil {
					t.Fatal(err)
				}
				time.Sleep(2 * time.Millisecond)
				staged, err = app.StagePrepared(p.Request.RequestID, p)
				publishCarrierFixture(t, staged, err)
				time.Sleep(2 * time.Millisecond)
				if retain {
					signed.ReviewDigest = p.ReviewDigest
					staged, err = app.StageSigned(p.Request.RequestID, signed, fightercarrier.AuthorizationInput{ActionID: allocationTestID(31), ReviewID: allocationTestID(32), ViewID: allocationTestID(33), Generation: 1})
				} else {
					staged, err = app.StageAbandon(p.Request.RequestID)
				}
				publishCarrierFixture(t, staged, err)
				// The lost-ack projection is an owned DTO, not a signing capability.
				inspected, err := o.InspectPrepared(ctx, p.Request.RequestID)
				if err != nil || inspected.Request != p.Request || inspected.NewFunding == nil {
					t.Fatal("exact prepared projection unavailable", err)
				}
				inspected.NewFunding.Inputs[0].Atoms++
				again, err := o.InspectPrepared(ctx, p.Request.RequestID)
				if err != nil || again.NewFunding.Inputs[0].Atoms != p.NewFunding.Inputs[0].Atoms {
					t.Fatal("projection aliases retained preparation", err)
				}
				if _, err = o.InspectPrepared(ctx, allocationTestID(999)); !errors.Is(err, fightercarrier.ErrNotFound) {
					t.Fatal("lookup adopted latest preparation", err)
				}
				proof, err := app.Reconciliation(p.Request.RequestID)
				if err != nil {
					t.Fatal(err)
				}
				h.revoked.Store(true)
				if got, e := o.InspectPrepared(ctx, p.Request.RequestID); !errors.Is(e, gymaccount.ErrUnauthorized) || got.Version != 0 {
					t.Fatal("revoked session disclosed preparation", e)
				}
				if err = o.Reconcile(ctx, proof); !errors.Is(err, gymaccount.ErrUnauthorized) {
					t.Fatal("revoked original session reconciled", err)
				}
				if o.poisoned.Load() {
					t.Fatal("pre-write refusal poisoned owner")
				}
				h.revoked.Store(false)
				read := func() (fightercarrier.WalletRecord, int) {
					t.Helper()
					var row fightercarrier.WalletRecord
					var n int
					err := walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
						s, e := readCarrierWalletState(ctx, tx, j.Identity().JournalID, &pin)
						if e != nil {
							return e
						}
						if len(s.records) != 1 {
							t.Fatal("record count")
						}
						row = s.records[0]
						_, xs, e := readPurposeExclusions(ctx, tx, 14, j.Identity().JournalID, h.binding.WithdrawalJournalID)
						n = len(xs)
						return e
					})
					if err != nil {
						t.Fatal(err)
					}
					return row, n
				}
				before, n := read()
				if before.State != "prepared" || n != 1 {
					t.Fatal("pre-write refusal mutated reservation")
				}
				if after {
					original := h.allocator.epoch
					calls := 0
					h.allocator.epoch = func(ctx context.Context, fn func(func() error) error) error {
						calls++
						if calls == 2 {
							h.revoked.Store(true)
						}
						return original(ctx, fn)
					}
					if err = o.Reconcile(ctx, proof); !errors.Is(err, fightercarrier.ErrOutcomeUnknown) || !errors.Is(err, gymaccount.ErrUnauthorized) {
						t.Fatal("post-write revocation did not retain uncertain outcome", err)
					}
					if calls != 2 || !o.poisoned.Load() || !h.allocator.poisoned.Load() || !h.wallet.hostedAllocationTainted.Load() {
						t.Fatal("uncertain owner reusable")
					}
				} else {
					if err = o.Reconcile(ctx, proof); err != nil {
						t.Fatal(err)
					}
					if err = o.Reconcile(ctx, proof); err != nil {
						t.Fatal("exact replay not idempotent", err)
					}
				}
				got, n := read()
				want := "abandoned"
				count := 0
				if retain {
					want = "retained"
					count = 2
				}
				if got.State != want || n != count {
					t.Fatal("committed state/exclusions lost", got.State, n)
				}
				app.Close()
				if err = o.Reconcile(ctx, proof); err == nil {
					t.Fatal("closed journal lease accepted")
				}
			})
		}
	}
}
