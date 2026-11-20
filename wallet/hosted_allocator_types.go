// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"sync/atomic"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// HostedAllocator owns one immutable original session and one concrete wallet.
// Opaque operation handles never retain an account lease or database transaction.
type HostedAllocator struct {
	owner       allocationLife
	inventory   *HostedAllocationInventory
	wallet      *Wallet
	manager     *waddrmgr.Manager
	token       string
	epoch       HostedAllocationEpochFence
	account     gymaccount.Account
	poisoned    atomic.Bool
	latest      *AllocationPlan
	withdrawals *AllocatedWithdrawals
}
type HostedAllocationSource = HostedAllocator

type AllocationPlan struct {
	owner       *HostedAllocator
	id          string
	request     AllocationRequest
	managerPlan *waddrmgr.HostedAllocationPlan
	candidate   waddrmgr.HostedAllocationRange
	before      [8]uint32
	sequence    uint32
	withdrawal  *AllocatedWithdrawals
	draft       *CandidateWithdrawalDraft
}
type AllocationReservation struct {
	owner    *HostedAllocator
	row      allocationRow
	plan     *AllocationPlan
	burnOnly bool
}
type AllocationReceipt struct {
	owner  *HostedAllocator
	record waddrmgr.HostedAllocationRecord
}
type AllocationAcknowledgement struct {
	owner  *HostedAllocator
	row    allocationRow
	record waddrmgr.HostedAllocationRecord
	draft  *CandidateWithdrawalDraft
}

// AllocationAddress is disclosed only after exact consumed linkage, successful
// owned watch registration and the original View's final authorization.
type AllocationAddress struct {
	Address           string
	Script            string
	Purpose           uint32
	Coin              uint32
	Account           uint32
	Branch            uint32
	Index             uint32
	InventoryRevision uint32
}
type AcknowledgedAllocation struct {
	owner   *HostedAllocator
	address AllocationAddress
	draft   *CandidateWithdrawalDraft
	kind    string
}

func (r *AcknowledgedAllocation) Receive() (string, error) {
	a, e := r.Details()
	if e != nil {
		return "", e
	}
	return a.Address, nil
}
func (r *AcknowledgedAllocation) Details() (AllocationAddress, error) {
	if r == nil || r.owner == nil || r.owner.owner.closing.Load() || r.owner.poisoned.Load() || r.kind == "withdrawal_change" {
		return AllocationAddress{}, ErrAllocationClosed
	}
	return r.address, nil
}
func (r *AcknowledgedAllocation) Draft() (CandidateWithdrawalDraft, error) {
	if r == nil || r.owner == nil || r.owner.owner.closing.Load() || r.owner.poisoned.Load() || r.kind != "withdrawal_change" || r.draft == nil {
		return CandidateWithdrawalDraft{}, ErrAllocationClosed
	}
	return cloneAllocatedDraft(*r.draft), nil
}
func cloneAllocatedDraft(d CandidateWithdrawalDraft) CandidateWithdrawalDraft {
	d.Inputs = append([]CandidateWithdrawalInput(nil), d.Inputs...)
	return d
}
func cloneAllocationLink(r waddrmgr.HostedAllocationRecord) waddrmgr.HostedAllocationRecord {
	r.InvalidIndices = append([]uint32{}, r.InvalidIndices...)
	return r
}
func (a *HostedAllocator) alive() error {
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
func (a *HostedAllocator) acquire(ctx context.Context) (context.Context, func(), error) {
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
func (a *HostedAllocator) Close() error {
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
