// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/taytr-llc/slug/walletwithdraw"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func allocatedJournal2(t *testing.T, h *allocatorFixture2) *walletwithdraw.Journal {
	t.Helper()
	b, m := h.binding, h.binding.InitialManifest
	pin := walletwithdraw.Pin{Version: 1, Network: m.Network, Genesis: m.Genesis, AccountAuthorityID: b.AuthorityID, AccountID: b.AccountID, Fixture: h.fixture, WalletProfile: m.Profile, RootPublicKey: m.RootPublicKey, GymPublicKey: m.GymPublicKey, GymID: m.GymID, PoolSourceBindingID: b.SourceBindingID}
	j, err := walletwithdraw.Create(context.Background(), filepath.Join(t.TempDir(), "withdrawals"), walletwithdraw.Identity{JournalID: b.WithdrawalJournalID, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Error(err)
		}
	})
	return j
}
func publishWithdrawal2(t *testing.T, p *walletwithdraw.PreparedCommit, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = p.Publish(func(fn func(func() error) error) error { return fn(func() error { return nil }) }); err != nil {
		t.Fatal(err)
	}
}
func withdrawalExclusions2(t *testing.T, h *allocatorFixture2) int {
	t.Helper()
	count := 0
	err := walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
		pin, err := allocationCarrierPin2(h.binding)
		if err != nil {
			return err
		}
		if err = auditPurposeExclusions(context.Background(), tx, pin, h.binding.CarrierJournalID, h.binding.WithdrawalJournalID); err != nil {
			return err
		}
		_, rows, err := readPurposeExclusions(context.Background(), tx, 14, h.binding.CarrierJournalID, h.binding.WithdrawalJournalID)
		count = len(rows)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAllocatedWithdrawal2AtomicExclusionsAndJournalReconciliation(t *testing.T) {
	for _, test := range []struct{ retain, revoke bool }{{false, false}, {true, false}, {true, true}} {
		retain := test.retain
		name := "unsigned abandon"
		if retain {
			name = "signed retention"
		}
		if test.revoke {
			name += " with post-commit revocation"
		}
		t.Run(name, func(t *testing.T) {
			h := newAllocatorFixture2(t, "zero256")
			ctx := context.Background()
			allocatorPool2(t, h)
			v := allocatedVector(t, h.fixture)
			// The inherited helper inserts the exact published payout and observed
			// tip. This is local authoring evidence, not a live node/watch claim.
			allocatedFunding(t, &allocatorFixture{wallet: h.wallet}, v)
			j := allocatedJournal2(t, h)
			s, err := h.allocator.CreateWithdrawals(ctx, j.BindingID(), j)
			if err != nil {
				t.Fatal(err)
			}
			req := v.Request
			req.OperationID = allocationTestID(10)
			plan, err := s.Plan(ctx, req.OperationID, req)
			if err != nil {
				t.Fatal(err)
			}
			if withdrawalExclusions2(t, h) != 0 || allocatorLocal2(t, h).Meta.Cursors[5] != 0 {
				t.Fatal("plan mutated wallet")
			}
			res, err := h.allocator.Reserve(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err = h.allocator.Consume(cancelled, res); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if withdrawalExclusions2(t, h) != 0 || allocatorLocal2(t, h).Meta.Cursors[5] != 0 {
				t.Fatal("cancelled consume wrote exclusions")
			}
			receipt, err := h.allocator.Consume(ctx, res)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.allocator.Acknowledge(ctx, receipt); err != nil {
				t.Fatal(err)
			}
			record, err := s.InspectRecord(ctx, req.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if withdrawalExclusions2(t, h) != len(record.Draft.Inputs) || allocatorLocal2(t, h).Meta.Cursors[5] != 1 {
				t.Fatal("draft/link/cursor/exclusions not atomic")
			}
			if record.Draft.UnsignedTxHex != v.Draft.UnsignedTxHex || !reflect.DeepEqual(record.Draft.Inputs, v.Draft.Inputs) || record.Draft.Change != v.Draft.Change {
				t.Fatal("unchanged transaction differs from independent vector")
			}
			if _, err = s.Sign(ctx, req.OperationID, record.DraftDigest); !errors.Is(err, ErrAllocationUnavailable) {
				t.Fatal("unwatched signing", err)
			}
			owner, err := j.TryAcquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			staged, err := owner.StageIntent(walletwithdraw.Request{Version: 1, OperationID: req.OperationID, Recipient: req.Recipient, AmountAtoms: req.AmountAtoms})
			publishWithdrawal2(t, staged, err)
			raw, err := json.Marshal(record.Draft)
			if err != nil {
				t.Fatal(err)
			}
			var draft walletwithdraw.Draft
			if err = json.Unmarshal(raw, &draft); err != nil {
				t.Fatal(err)
			}
			staged, err = owner.StagePrepared(req.OperationID, draft)
			publishWithdrawal2(t, staged, err)
			if retain {
				retainedUnlock(t, h.wallet, retainedPrivPass)
				signed, err := s.base.Sign(ctx, req.OperationID, record.DraftDigest)
				if err != nil {
					t.Fatal(err)
				}
				if signed.RawHex != v.ExpectedSigned.RawHex || signed.TxID != v.ExpectedSigned.TxID {
					t.Fatal("private signer changed independent transaction bytes")
				}
				bytesSigned, err := hex.DecodeString(signed.RawHex)
				if err != nil {
					t.Fatal(err)
				}
				staged, err = owner.StageSigned(req.OperationID, bytesSigned, walletwithdraw.AuthorizationInput{Generation: 1, ViewID: allocationTestID(21), ActionID: allocationTestID(22), ReviewID: allocationTestID(23)})
				publishWithdrawal2(t, staged, err)
			} else {
				staged, err = owner.StageAbandon(req.OperationID)
				publishWithdrawal2(t, staged, err)
			}
			reconciliation, err := owner.Reconciliation(req.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if test.revoke {
				s.base.checkpoint = func(point string) error {
					if point == "after_commit" {
						h.revoked.Store(true)
					}
					return nil
				}
				if err = s.ApplyReconciliation(ctx, reconciliation); !errors.Is(err, ErrAllocationOutcomeUnknown) {
					t.Fatal("post-commit revocation not uncertain", err)
				}
				if !s.base.poisoned.Load() || !h.allocator.poisoned.Load() || withdrawalExclusions2(t, h) != 1 {
					t.Fatal("uncertain retention released funds or owner")
				}
				if _, err = s.InspectRecord(ctx, req.OperationID); !errors.Is(err, ErrAllocationPoisoned) {
					t.Fatal("uncertain owner reused", err)
				}
				return
			}
			if err = s.ApplyReconciliation(ctx, reconciliation); err != nil {
				t.Fatal(err)
			}
			if err = s.ApplyReconciliation(ctx, reconciliation); err != nil {
				t.Fatal("same journal reconciliation not idempotent", err)
			}
			owner.Close()
			if err = s.ApplyReconciliation(ctx, reconciliation); err == nil {
				t.Fatal("closed journal lease reused")
			}
			h.reattach(t)
			s, err = h.allocator.OpenWithdrawals(ctx, j.BindingID(), j)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.InspectRecord(ctx, req.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal([]byte(got.Draft.UnsignedTxHex), []byte(record.Draft.UnsignedTxHex)) {
				t.Fatal("restart changed transaction")
			}
			if retain {
				if got.State != "retained" || withdrawalExclusions2(t, h) != 1 {
					t.Fatal("signed exclusions lost on restart")
				}
				next := req
				next.OperationID = allocationTestID(11)
				if _, err = s.Plan(ctx, next.OperationID, next); !errors.Is(err, ErrWithdrawalUnavailable) {
					t.Fatal("retained input reused", err)
				}
			} else if got.State != "abandoned" || withdrawalExclusions2(t, h) != 0 || allocatorLocal2(t, h).Meta.Cursors[5] != 1 {
				t.Fatal("unsigned abandon lost index or retained exclusions")
			}
		})
	}
}
