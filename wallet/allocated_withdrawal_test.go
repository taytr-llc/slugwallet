// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func allocatedFunding(t *testing.T, h *allocatorFixture, v withdrawalReferenceCase) {
	t.Helper()
	raw, e := os.ReadFile("testdata/candidate-withdrawals/reference-inputs/public/original-set61-payout.json")
	if e != nil {
		t.Fatal(e)
	}
	var original struct {
		Batches []struct {
			Raw string `json:"raw"`
		} `json:"batches"`
	}
	if json.Unmarshal(raw, &original) != nil || len(original.Batches) != 1 {
		t.Fatal("old public payout shape")
	}
	txraw, e := hex.DecodeString(original.Batches[0].Raw)
	if e != nil {
		t.Fatal(e)
	}
	var funding wire.MsgTx
	if e = funding.Deserialize(bytes.NewReader(txraw)); e != nil {
		t.Fatal(e)
	}
	rec, e := wtxmgr.NewTxRecordFromMsgTx(&funding, time.Unix(1700000000, 0))
	if e != nil {
		t.Fatal(e)
	}
	blockHash, _ := chainhash.NewHashFromStr(v.Draft.Inputs[0].BlockHash)
	tipHash, _ := chainhash.NewHashFromStr(v.Draft.TipHash)
	e = walletdb.Update(h.wallet.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		block := &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: *blockHash, Height: v.Draft.Inputs[0].BlockHeight}, Time: time.Unix(1700000000, 0)}
		if e := h.wallet.TxStore.InsertTx(ns, rec, block); e != nil {
			return e
		}
		if e := h.wallet.TxStore.AddCredit(ns, rec, block, v.Draft.Inputs[0].OutputIndex, false); e != nil {
			return e
		}
		return h.wallet.Manager.SetSyncedTo(tx.ReadWriteBucket(waddrmgrNamespaceKey), &waddrmgr.BlockStamp{Hash: *tipHash, Height: v.Draft.TipHeight, Timestamp: time.Unix(1700000000, 0)})
	})
	if e != nil {
		t.Fatal(e)
	}
	h.wallet.SetChainSynced(true)
}
func allocatedVector(t *testing.T, fixture string) withdrawalReferenceCase {
	t.Helper()
	for _, v := range withdrawalVectors(t).Cases {
		if v.Name == fixture+"-original-to-84" {
			return v
		}
	}
	t.Fatal("independent original case missing")
	return withdrawalReferenceCase{}
}
func TestAllocatedWithdrawalIndependentAtomicDraftAndLostPlan(t *testing.T) {
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			h := newAllocatorFixture(t, fixture)
			ctx := context.Background()
			allocatorPool(t, h)
			v := allocatedVector(t, fixture)
			allocatedFunding(t, h, v)
			s, e := h.allocator.CreateWithdrawals(ctx, v.Draft.BindingID)
			if e != nil {
				t.Fatal(e)
			}
			p, e := s.Plan(ctx, allocationTestID(10), v.Request)
			if e != nil {
				t.Fatal(e)
			}
			if p.draft == nil || !reflect.DeepEqual(*p.draft, v.Draft) {
				t.Fatal("private Plan differs from independently frozen draft")
			}
			if allocatorLocal(t, h).Meta.Cursors[5] != 0 {
				t.Fatal("Plan allocated change")
			}
			r, e := h.allocator.Reserve(ctx, p)
			if e != nil {
				t.Fatal(e)
			}
			// Cancellation before transaction entry leaves the reserved range, never a
			// partial address/link/draft. An explicit later consume remains possible.
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, e = h.allocator.Consume(cancelled, r); !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if allocatorLocal(t, h).Meta.Cursors[5] != 0 {
				t.Fatal("cancelled consume wrote local state")
			}
			receipt, e := h.allocator.Consume(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			local := allocatorLocal(t, h)
			if local.Meta.Cursors[5] != 1 || local.Records[1].DraftDigest != v.DraftDigest {
				t.Fatal("atomic draft/link/cursor mismatch")
			}
			beforeAck, e := s.InspectRecord(ctx, v.Request.OperationID)
			if e != nil || !reflect.DeepEqual(beforeAck.Draft, v.Draft) {
				t.Fatal("local recovery audit", e)
			}
			if _, e = s.Lookup(ctx, v.Request.OperationID); !errors.Is(e, ErrAllocationResumeRequired) {
				t.Fatal("draft exposed before acknowledgement", e)
			}
			ack, e := h.allocator.Acknowledge(ctx, receipt)
			if e != nil {
				t.Fatal(e)
			}
			if ack.draft == nil || !reflect.DeepEqual(*ack.draft, v.Draft) {
				t.Fatal("ack lost exact saved draft")
			}
			if _, e = s.Sign(ctx, v.Request.OperationID, v.DraftDigest); !errors.Is(e, ErrAllocationUnavailable) {
				t.Fatal("unwatched signing accepted", e)
			}
			// Exercise the privately factored signer against the old independent signed
			// bytes. This is a local authoring test, not watch/node readiness evidence.
			retainedUnlock(t, h.wallet, retainedPrivPass)
			signed, e := s.base.Sign(ctx, v.Request.OperationID, v.DraftDigest)
			if e != nil || !reflect.DeepEqual(signed, v.ExpectedSigned) {
				t.Fatal("exact independent signature changed", e)
			}
			if e = s.Retain(ctx, v.Request.OperationID, v.DraftDigest, signed.TxID); e != nil {
				t.Fatal(e)
			}
			h.reattach(t)
			s, e = h.allocator.OpenWithdrawals(ctx, v.Draft.BindingID)
			if e != nil {
				t.Fatal(e)
			}
			restored, e := s.InspectRecord(ctx, v.Request.OperationID)
			if e != nil || restored.State != "retained" || restored.RetainedTxID != signed.TxID || !reflect.DeepEqual(restored.Draft, v.Draft) {
				t.Fatal("reopened retained operation changed", e)
			}
			// Burn-only crash case uses a second funded fixture-independent request on
			// the same wallet only after an unsigned prepared record was abandoned. A
			// retained input cannot be silently reused to fund that request.
			next := v.Request
			next.OperationID = allocationTestID(20)
			if _, e = s.Plan(ctx, allocationTestID(20), next); !errors.Is(e, ErrWithdrawalUnavailable) {
				t.Fatal("permanently retained input reused", e)
			}
		})
	}
}
func TestAllocatedWithdrawalLostPlanBurnAndPrivateAudit(t *testing.T) {
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
	if h.inventory.meta.Cursors[5] != 1 {
		t.Fatal("reserved change absent from recovery head")
	}
	h.reattach(t)
	s, e = h.allocator.OpenWithdrawals(ctx, v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.allocator.Consume(ctx, r); !errors.Is(e, ErrAllocationInvalid) {
		t.Fatal("old financial Plan crossed attachment", e)
	}
	r, e = h.allocator.Resume(ctx, allocationTestID(10))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.allocator.Consume(ctx, r); !errors.Is(e, ErrAllocationResumeRequired) {
		t.Fatal("lost financial Plan reselected", e)
	}
	receipt, e := h.allocator.Burn(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.allocator.Acknowledge(ctx, receipt); e != nil {
		t.Fatal(e)
	}
	if empty, e := s.Empty(ctx); e != nil || !empty {
		t.Fatal("burn created draft/input exclusions", e)
	}
	if _, e = s.Plan(ctx, allocationTestID(11), v.Request); !errors.Is(e, ErrAllocationConflict) {
		t.Fatal("terminal consumer got second range", e)
	}
	h.revoked.Store(true)
	if _, e = s.InspectRecord(ctx, v.Request.OperationID); !errors.Is(e, gymaccount.ErrUnauthorized) {
		t.Fatal("revoked audit returned data", e)
	}
	h.revoked.Store(false)
	if allocatorLocal(t, h).Meta.Cursors[5] != 1 {
		t.Fatal("burn failed to preserve index")
	}
}
