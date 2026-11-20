// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"sync/atomic"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// HostedAllocator2 owns one immutable original session and one concrete wallet.
// Opaque operation handles never retain an account lease or database transaction.
type HostedAllocator2 struct {
	owner       allocationLife
	inventory   *HostedAllocationInventory2
	wallet      *Wallet
	manager     *waddrmgr.Manager
	token       string
	epoch       HostedAllocationEpochFence
	account     gymaccount.Account
	poisoned    atomic.Bool
	latest      *AllocationPlan2
	withdrawals *AllocatedWithdrawals2
}
type HostedAllocationSource2 = HostedAllocator2

type AllocationPlan2 struct {
	owner       *HostedAllocator2
	id          string
	request     AllocationRequest2
	managerPlan *waddrmgr.HostedAllocationPlan2
	candidate   waddrmgr.HostedAllocationRange
	before      [8]uint32
	sequence    uint32
	withdrawal  *AllocatedWithdrawals2
	draft       *CandidateWithdrawalDraft
	carrier     *preparedCarrierFunding
}
type AllocationReservation2 struct {
	owner    *HostedAllocator2
	row      allocationRow2
	plan     *AllocationPlan2
	burnOnly bool
}
type AllocationReceipt2 struct {
	owner  *HostedAllocator2
	record waddrmgr.HostedAllocationRecord2
}
type AllocationAcknowledgement2 struct {
	owner   *HostedAllocator2
	row     allocationRow2
	record  waddrmgr.HostedAllocationRecord2
	draft   *CandidateWithdrawalDraft
	carrier *fightercarrier.Preparation
}

type AcknowledgedAllocation2 struct {
	owner   *HostedAllocator2
	address AllocationAddress
	draft   *CandidateWithdrawalDraft
	carrier *fightercarrier.Preparation
	kind    string
}

func (r *AcknowledgedAllocation2) Receive() (string, error) {
	a, e := r.Details()
	if e != nil {
		return "", e
	}
	return a.Address, nil
}
func (r *AcknowledgedAllocation2) Details() (AllocationAddress, error) {
	if r == nil || r.owner == nil || r.owner.alive() != nil || (r.kind != "pool_recipient" && r.kind != "receive") {
		return AllocationAddress{}, ErrAllocationClosed
	}
	return r.address, nil
}
func (r *AcknowledgedAllocation2) Draft() (CandidateWithdrawalDraft, error) {
	if r == nil || r.owner == nil || r.owner.alive() != nil || r.kind != "withdrawal_change" || r.draft == nil {
		return CandidateWithdrawalDraft{}, ErrAllocationClosed
	}
	return cloneAllocatedDraft(*r.draft), nil
}
func cloneAllocationLink2(r waddrmgr.HostedAllocationRecord2) waddrmgr.HostedAllocationRecord2 {
	r.InvalidIndices = append([]uint32{}, r.InvalidIndices...)
	return r
}
func (a *HostedAllocator2) alive() error {
	if a == nil || a.inventory == nil || a.wallet == nil || a.manager == nil || a.wallet.Manager != a.manager || !a.wallet.ownActivityAlive() {
		return ErrAllocationClosed
	}
	if a.poisoned.Load() || a.inventory.poisoned.Load() || a.wallet.hostedAllocationTainted.Load() {
		return ErrAllocationPoisoned
	}
	if a.owner.closing.Load() || a.inventory.owner.closing.Load() {
		return ErrAllocationClosed
	}
	return nil
}
func (a *HostedAllocator2) acquire(ctx context.Context) (context.Context, func(), error) {
	if a == nil {
		return nil, nil, ErrAllocationInvalid
	}
	work, end, e := a.owner.acquire(ctx)
	if e != nil {
		return nil, nil, e
	}
	if e = a.alive(); e != nil {
		end()
		return nil, nil, e
	}
	work, release, e := a.inventory.acquire(work)
	if e != nil {
		end()
		return nil, nil, e
	}
	return work, func() { release(); end() }, nil
}
func (a *HostedAllocator2) Close() error {
	if a == nil {
		return nil
	}
	first, e := a.owner.startClose()
	if !first {
		return e
	}
	a.owner.active.Wait()
	if a.withdrawals != nil {
		e = a.withdrawals.closeOwned()
	}
	if e != nil { // Actual cleanup failure retains the exact owner and lock.
		a.wallet.hostedAllocationTainted.Store(true)
		return a.owner.finishClose(e)
	}
	if a.poisoned.Load() || a.inventory.poisoned.Load() {
		a.wallet.hostedAllocationTainted.Store(true)
		e = ErrAllocationPoisoned
	}
	a.inventory.attachmentsMu.Lock()
	delete(a.inventory.attachments, a)
	a.inventory.attachmentsMu.Unlock()
	a.wallet.hostedAllocationMu.Unlock()
	return a.owner.finishClose(e)
}
