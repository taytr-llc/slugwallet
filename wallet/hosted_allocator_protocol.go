// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (a *HostedAllocator) PlanRecipient(ctx context.Context, id string) (*AllocationPlan, error) {
	return a.plan(ctx, id, AllocationRequest{Version: 1, Kind: "pool_recipient", ConsumerID: id, Purpose: 84}, nil, nil)
}
func (a *HostedAllocator) PlanReceive(ctx context.Context, id string) (*AllocationPlan, error) {
	return a.plan(ctx, id, AllocationRequest{Version: 1, Kind: "receive", ConsumerID: id, Purpose: 84}, nil, nil)
}
func (a *HostedAllocator) plan(ctx context.Context, id string, req AllocationRequest, withdrawal *AllocatedWithdrawals, payment *CandidateWithdrawalRequest) (*AllocationPlan, error) {
	if e := validateAllocationRequest(req, id); e != nil {
		return nil, e
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = a.check(work, allocationCapability(req)); e != nil {
		return nil, e
	}
	p := &AllocationPlan{owner: a, id: id, request: req, withdrawal: withdrawal}
	e = walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := a.auditPair(work, tx)
		if e != nil {
			return e
		}
		if old, ok := a.inventory.rows[id]; ok {
			if old.Reservation.Request != req {
				return ErrAllocationConflict
			}
			r := old.Reservation
			p.sequence = r.Sequence
			p.candidate = allocationRange(r)
			for _, l := range state.Records {
				if l.AllocationID == id {
					p.before = l.CursorsBefore
					return nil
				}
			}
			p.before = state.Meta.Cursors
			return nil
		}
		for _, id := range a.inventory.order {
			prior := a.inventory.rows[id].Reservation.Request
			if prior.Kind == req.Kind && prior.ConsumerID == req.ConsumerID {
				return ErrAllocationConflict
			}
		}
		if a.inventory.meta.ActiveAllocationID != "" {
			return ErrAllocationBusy
		}
		if req.Kind == "pool_recipient" && a.inventory.meta.Allocations != 0 || req.Kind != "pool_recipient" && a.inventory.meta.Allocations == 0 {
			return ErrAllocationConflict
		}
		if a.inventory.meta.Allocations >= HostedAllocationMaxRecords {
			return ErrAllocationCapacity
		}
		p.before = state.Meta.Cursors
		p.sequence = a.inventory.meta.Allocations + 1
		p.managerPlan, p.candidate, e = a.manager.PlanHostedAllocation(work, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace), req.Purpose, req.Branch)
		if e != nil {
			return allocationManagerError(e)
		}
		if req.Kind == "pool_recipient" && p.candidate.SelectedIndex != 0 {
			return ErrAllocationConflict
		}
		if withdrawal != nil {
			if payment == nil || withdrawal.owner != a {
				return ErrAllocationConflict
			}
			d, e := withdrawal.planDraft(work, tx, *payment, p.candidate)
			if e != nil {
				return e
			}
			p.draft = &d
		}
		return a.prechargeLocal(state, p.row())
	})
	if e != nil {
		return nil, e
	}
	if e = a.check(work, allocationCapability(req)); e != nil {
		return nil, e
	}
	a.latest = p
	return p, nil
}
func allocationRange(r allocationReservationValue) waddrmgr.HostedAllocationRange {
	return waddrmgr.HostedAllocationRange{Purpose: r.Purpose, Branch: r.Branch, StartIndex: r.StartIndex, EndIndex: r.EndIndex, SelectedIndex: r.SelectedIndex, InvalidIndices: append([]uint32{}, r.InvalidIndices...), Address: r.Address, Script: r.Script}
}
func (p *AllocationPlan) row() allocationRow {
	c := p.candidate
	r := allocationReservationValue{Version: 1, Sequence: p.sequence, AllocationID: p.id, BindingID: p.owner.inventory.bindingID, Request: p.request, Purpose: c.Purpose, Branch: c.Branch, StartIndex: c.StartIndex, EndIndex: c.EndIndex, SelectedIndex: c.SelectedIndex, InvalidIndices: append([]uint32{}, c.InvalidIndices...), Address: c.Address, Script: c.Script}
	h, _ := allocationDomain("reservation", r)
	return allocationRow{Reservation: r, ReservationDigest: h, Phase: "reserved"}
}
func (a *HostedAllocator) Reserve(ctx context.Context, p *AllocationPlan) (*AllocationReservation, error) {
	if p == nil || p.owner != a {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if p != a.latest {
		return nil, ErrAllocationConflict
	}
	if e = a.check(work, allocationCapability(p.request)); e != nil {
		return nil, e
	}
	e = walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error {
		s, e := a.auditPair(work, tx)
		if e != nil {
			return e
		}
		if _, ok := a.inventory.rows[p.id]; ok {
			return nil
		}
		if s.Meta.Cursors != p.before || s.Meta.CompletedSequence+1 != p.sequence {
			return ErrAllocationConflict
		}
		if p.withdrawal != nil {
			if e = p.withdrawal.validatePlanned(work, tx, p); e != nil {
				return e
			}
		}
		return a.prechargeLocal(s, p.row())
	})
	if e != nil {
		return nil, e
	}
	value := p.row().Reservation
	row, e := a.inventory.commitReservation(work, a.token, a.epoch, &a.account, &value)
	if e != nil {
		return nil, e
	}
	return &AllocationReservation{owner: a, row: row, plan: p, burnOnly: p.request.Kind == "withdrawal_change" && p.draft == nil}, nil
}
func (a *HostedAllocator) Consume(ctx context.Context, r *AllocationReservation) (*AllocationReceipt, error) {
	return a.consume(ctx, r, false)
}
func (a *HostedAllocator) Burn(ctx context.Context, r *AllocationReservation) (*AllocationReceipt, error) {
	return a.consume(ctx, r, true)
}
func (a *HostedAllocator) consume(ctx context.Context, r *AllocationReservation, burn bool) (*AllocationReceipt, error) {
	if r == nil || r.owner != a {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	row, ok := a.inventory.rows[r.row.Reservation.AllocationID]
	if !ok || !reflect.DeepEqual(row.Reservation, r.row.Reservation) {
		return nil, ErrAllocationConflict
	}
	if e = a.check(work, allocationCapability(row.Reservation.Request)); e != nil {
		return nil, e
	}
	if !a.wallet.newAddrMtx.TryLock() {
		return nil, ErrAllocationBusy
	}
	var result waddrmgr.HostedAllocationRecord
	e = hostedWalletWrite(work, a.wallet, func() { a.poisoned.Store(true) }, func(tx walletdb.ReadWriteTx) error {
		state, e := a.auditPair(work, tx)
		if e != nil {
			return e
		}
		for _, old := range state.Records {
			if old.AllocationID == row.Reservation.AllocationID {
				if burn && old.Outcome != "burned" || !burn && old.Outcome != "consumed" {
					return ErrAllocationConflict
				}
				result = cloneAllocationLink(old)
				return nil
			}
		}
		if row.Phase != "reserved" || r.plan == nil || r.plan.managerPlan == nil || r.plan.owner != a || r.plan.before != state.Meta.Cursors {
			return ErrAllocationConflict
		}
		outcome := "consumed"
		digest := ""
		if burn {
			outcome = "burned"
		} else if row.Reservation.Request.Kind == "withdrawal_change" {
			if r.burnOnly || r.plan.withdrawal == nil || r.plan.draft == nil {
				return ErrAllocationResumeRequired
			}
			if e = r.plan.withdrawal.validatePlanned(work, tx, r.plan); e != nil {
				return e
			}
			digest, e = CandidateWithdrawalDraftDigest(*r.plan.draft)
			if e != nil {
				return e
			}
		}
		result = allocationLink(a.inventory, row, state.Meta.Cursors, outcome, digest)
		if burn {
			e = a.manager.BurnHostedAllocation(work, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedLocalNamespace), r.plan.managerPlan, result)
		} else {
			e = a.manager.ConsumeHostedAllocation(work, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedLocalNamespace), r.plan.managerPlan, result)
		}
		if e != nil {
			return allocationManagerError(e)
		}
		if !burn && r.plan.withdrawal != nil {
			if e = r.plan.withdrawal.writePlanned(work, tx, r.plan); e != nil {
				return e
			}
		}
		return nil
	})
	a.wallet.newAddrMtx.Unlock()
	if e != nil {
		return nil, e
	}
	// A cancellation/revocation after the private local commit is not an exposed
	// receipt or approval. Exact durable Resolve is required by a later action.
	if e = a.check(work, allocationCapability(row.Reservation.Request)); e != nil {
		return nil, errors.Join(ErrAllocationOutcomeUnknown, e)
	}
	return &AllocationReceipt{owner: a, record: result}, nil
}
func (a *HostedAllocator) Acknowledge(ctx context.Context, r *AllocationReceipt) (*AllocationAcknowledgement, error) {
	if r == nil || r.owner != a {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	return a.resolveHeld(work, r.record.AllocationID, allocationCapability(a.inventory.rows[r.record.AllocationID].Reservation.Request), &r.record)
}
func (a *HostedAllocator) Resolve(ctx context.Context, id string) (*AllocationAcknowledgement, error) {
	if !withdrawalHex(id, 32, true) {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	return a.resolveHeld(work, id, gymaccount.View, nil)
}
func (a *HostedAllocator) resolveHeld(ctx context.Context, id string, cap gymaccount.Capability, expected *waddrmgr.HostedAllocationRecord) (*AllocationAcknowledgement, error) {
	if e := a.check(ctx, cap); e != nil {
		return nil, e
	}
	if _, ok := a.inventory.rows[id]; !ok {
		if e := a.check(ctx, cap); e != nil {
			return nil, e
		}
		return nil, ErrAllocationNotFound
	}
	var link *waddrmgr.HostedAllocationRecord
	var draft *CandidateWithdrawalDraft
	e := walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := a.auditPair(ctx, tx)
		if e != nil {
			return e
		}
		for _, r := range state.Records {
			if r.AllocationID == id {
				x := cloneAllocationLink(r)
				link = &x
				break
			}
		}
		if link == nil {
			return ErrAllocationResumeRequired
		}
		if expected != nil && !reflect.DeepEqual(*expected, *link) {
			return ErrAllocationConflict
		}
		if link.Outcome == "consumed" && link.WithdrawalOperationID != "" {
			r, e := a.readWithdrawalRecord(tx, link.WithdrawalOperationID)
			if e != nil {
				return e
			}
			x := cloneAllocatedDraft(r.Draft)
			draft = &x
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	row, e := a.inventory.commitCompletion(ctx, a.token, a.epoch, &a.account, id, *link, cap)
	if e != nil {
		return nil, e
	}
	return &AllocationAcknowledgement{owner: a, row: row, record: *link, draft: draft}, nil
}
func (a *HostedAllocator) Resume(ctx context.Context, id string) (*AllocationReservation, error) {
	if !withdrawalHex(id, 32, true) {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return nil, e
	}
	row, ok := a.inventory.rows[id]
	if !ok || row.Phase != "reserved" {
		if e = a.check(work, gymaccount.View); e != nil {
			return nil, e
		}
		if !ok {
			return nil, ErrAllocationNotFound
		}
		return nil, ErrAllocationConflict
	}
	if e = a.check(work, allocationCapability(row.Reservation.Request)); e != nil {
		return nil, e
	}
	p := &AllocationPlan{owner: a, id: id, request: row.Reservation.Request, sequence: row.Reservation.Sequence}
	e = walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := a.auditPair(work, tx)
		if e != nil {
			return e
		}
		for _, r := range state.Records {
			if r.AllocationID == id {
				return ErrAllocationConflict
			}
		}
		p.before = state.Meta.Cursors
		p.managerPlan, p.candidate, e = a.manager.PlanHostedAllocation(work, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace), row.Reservation.Purpose, row.Reservation.Branch)
		if e != nil {
			return allocationManagerError(e)
		}
		if !reflect.DeepEqual(p.candidate, allocationRange(row.Reservation)) {
			return ErrAllocationConflict
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if e = a.check(work, allocationCapability(p.request)); e != nil {
		return nil, e
	}
	a.latest = p
	return &AllocationReservation{owner: a, row: cloneAllocationRow(row), plan: p, burnOnly: p.request.Kind == "withdrawal_change"}, nil
}
func (a *HostedAllocator) Finalize(ctx context.Context, ack *AllocationAcknowledgement) (*AcknowledgedAllocation, error) {
	if ack == nil || ack.owner != a {
		return nil, ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	row, ok := a.inventory.rows[ack.row.Reservation.AllocationID]
	if !ok || row.Phase != "consumed" || !reflect.DeepEqual(row, ack.row) {
		return nil, ErrAllocationConflict
	}
	cap := allocationCapability(row.Reservation.Request)
	if e = a.check(work, cap); e != nil {
		return nil, e
	}
	e = walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := a.auditPair(work, tx)
		if e != nil {
			return e
		}
		for _, r := range state.Records {
			if r.AllocationID == ack.record.AllocationID {
				if !reflect.DeepEqual(r, ack.record) {
					return ErrAllocationConflict
				}
				return nil
			}
		}
		return ErrAllocationCorrupt
	})
	if e != nil {
		return nil, e
	}
	if e = a.watch(work, row.Reservation.Address); e != nil {
		return nil, e
	}
	if e = a.check(work, cap); e != nil {
		return nil, e
	}
	r := row.Reservation
	out := &AcknowledgedAllocation{owner: a, kind: r.Request.Kind, address: AllocationAddress{Address: r.Address, Script: r.Script, Purpose: 84, Coin: 0, Account: 0, Branch: r.Branch, Index: r.SelectedIndex, InventoryRevision: a.inventory.meta.Revision}}
	if ack.draft != nil {
		d := cloneAllocatedDraft(*ack.draft)
		out.draft = &d
	}
	return out, nil
}
func (a *HostedAllocator) watch(ctx context.Context, encoded string) error {
	parsed, e := address.DecodeAddress(encoded, a.wallet.chainParams)
	if e != nil || parsed.EncodeAddress() != encoded {
		return ErrAllocationCorrupt
	}
	client, e := a.wallet.requireChainClient()
	if e != nil {
		return ErrAllocationUnavailable
	}
	backend := allocationWatchClient(client)
	if backend == nil || backend.Client == nil || backend.Disconnected() {
		return ErrAllocationUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	joined := make(chan struct{})
	stop := context.AfterFunc(work, func() { backend.Client.Shutdown(); close(joined) })
	e = backend.NotifyReceived([]address.Address{parsed})
	if !stop() {
		<-joined
	}
	if e != nil || work.Err() != nil {
		a.poisoned.Store(true)
		return errors.Join(ErrAllocationUnavailable, e, work.Err())
	}
	return nil
}

// Resolve only the installed owner's concrete RPC backend. In particular, the
// desktop's readiness-only wrapper promotes the backend's self-returning method.
func allocationWatchClient(client chain.Interface) *chain.RPCClient {
	owner, ok := client.(interface {
		AllocationWatchClient() *chain.RPCClient
	})
	if !ok {
		return nil
	}
	return owner.AllocationWatchClient()
}

func (a *HostedAllocator) readWithdrawalRecord(tx walletdb.ReadTx, id string) (CandidateWithdrawalRecord, error) {
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns == nil {
		return CandidateWithdrawalRecord{}, ErrAllocationCorrupt
	}
	key, e := hex.DecodeString(id)
	if e != nil {
		return CandidateWithdrawalRecord{}, ErrAllocationInvalid
	}
	var r CandidateWithdrawalRecord
	ops := ns.NestedReadBucket(withdrawalOperations)
	if ops == nil {
		return r, ErrAllocationCorrupt
	}
	raw := ops.Get(key)
	if raw == nil {
		return r, ErrWithdrawalNotFound
	}
	if e = withdrawalDecode(ops.Get(key), 32768, &r); e != nil {
		return r, e
	}
	return r, nil
}
