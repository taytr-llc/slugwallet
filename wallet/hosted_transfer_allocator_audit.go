// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var hostedLocalNamespace2 = []byte(waddrmgr.HostedAllocationNamespace2)

func allocationGuard2(b AllocationBinding2, bound bool) waddrmgr.HostedAllocationGuard2 {
	h, _ := allocationHash("", b.InitialManifest)
	g := waddrmgr.HostedAllocationGuard2{Version: 2, State: "locked", InventoryID: b.InventoryID, AuthorityID: b.AuthorityID, AccountID: b.AccountID, WalletOwnerID: b.WalletOwnerID, SourceBindingID: b.SourceBindingID, OwnershipPinID: b.OwnershipPinID, CarrierJournalID: b.CarrierJournalID, WithdrawalJournalID: b.WithdrawalJournalID, InitialManifestSHA256: h}
	if bound {
		g.State = "bound"
		g.BindingID, _ = AllocationBindingID2(b)
	}
	return g
}
func (a *HostedAllocator2) check(ctx context.Context, cap gymaccount.Capability) error {
	return a.inventory.authorize(ctx, a.token, a.epoch, cap, &a.account, func(_ gymaccount.Account, check func() error) error { return check() })
}
func allocationCapability2(r AllocationRequest2) gymaccount.Capability {
	if r.Kind == "carrier_return" {
		return gymaccount.FighterTransfer
	}
	if r.Kind == "withdrawal_change" {
		return gymaccount.Withdrawal
	}
	return gymaccount.View
}

// BindWallet accepts only the concrete empty inventory and its expected locked
// wallet. The account fence never contains a wallet/manager/database operation.
func (i *HostedAllocationInventory2) BindWallet(ctx context.Context, w *Wallet, token string, epoch HostedAllocationEpochFence) error {
	if wire.TestPoW {
		return ErrAllocationProfile
	}
	if w != nil && w.hostedAllocationTainted.Load() {
		return ErrAllocationPoisoned
	}
	if w == nil || w.Manager == nil || !w.ownActivityAlive() || !w.hostedAllocationMu.TryLock() {
		return ErrAllocationBusy
	}
	defer w.hostedAllocationMu.Unlock()
	work, end, e := i.acquire(ctx)
	if e != nil {
		return e
	}
	defer end()
	if i.meta.Allocations != 0 || len(i.rows) != 0 {
		return ErrAllocationConflict
	}
	var expected gymaccount.Account
	e = i.authorize(work, token, epoch, gymaccount.View, nil, func(a gymaccount.Account, check func() error) error {
		expected = cloneAllocationAccount(a)
		return check()
	})
	if e != nil {
		return e
	}
	if !w.newAddrMtx.TryLock() {
		return ErrAllocationBusy
	}
	e = hostedWalletWrite(work, w, func() { i.poisoned.Store(true) }, func(tx walletdb.ReadWriteTx) error {
		return allocationManagerError(w.Manager.BindHostedAllocation2(work, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedLocalNamespace2), allocationGuard2(i.binding, false), i.bindingID))
	})
	w.newAddrMtx.Unlock()
	if e != nil {
		return e
	}
	e = i.authorize(work, token, epoch, gymaccount.View, &expected, func(_ gymaccount.Account, check func() error) error { return check() })
	if e != nil {
		i.poisoned.Store(true)
		return errors.Join(ErrAllocationOutcomeUnknown, e)
	}
	return nil
}
func (i *HostedAllocationInventory2) Attach(ctx context.Context, w *Wallet, token string, epoch HostedAllocationEpochFence) (*HostedAllocator2, error) {
	if wire.TestPoW {
		return nil, ErrAllocationProfile
	}
	if w == nil || w.Manager == nil || !w.ownActivityAlive() || epoch == nil || token == "" {
		return nil, ErrAllocationInvalid
	}
	if w.hostedAllocationTainted.Load() {
		return nil, ErrAllocationPoisoned
	}
	if !w.hostedAllocationMu.TryLock() {
		return nil, ErrAllocationBusy
	}
	success := false
	defer func() {
		if !success {
			w.hostedAllocationMu.Unlock()
		}
	}()
	work, end, e := i.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	a := &HostedAllocator2{owner: newAllocationLife(), inventory: i, wallet: w, manager: w.Manager, token: token, epoch: epoch}
	e = i.authorize(work, token, epoch, gymaccount.View, nil, func(account gymaccount.Account, check func() error) error {
		a.account = cloneAllocationAccount(account)
		return check()
	})
	if e == nil {
		e = walletdb.View(w.db, func(tx walletdb.ReadTx) error { _, e := a.auditPair(work, tx); return e })
	}
	if e == nil {
		e = a.check(work, gymaccount.View)
	}
	if e != nil {
		a.owner.cancel()
		return nil, e
	}
	i.attachmentsMu.Lock()
	if i.owner.closing.Load() {
		i.attachmentsMu.Unlock()
		a.owner.cancel()
		return nil, ErrAllocationClosed
	}
	i.attachments[a] = true
	i.attachmentsMu.Unlock()
	success = true
	return a, nil
}
func (a *HostedAllocator2) auditPair(ctx context.Context, tx walletdb.ReadTx) (waddrmgr.HostedAllocationState2, error) {
	state, e := a.manager.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace2))
	if e != nil {
		return state, allocationManagerError(e)
	}
	if state.Guard != allocationGuard2(a.inventory.binding, true) || len(state.Records) > len(a.inventory.order) {
		return state, ErrAllocationCorrupt
	}
	var before [8]uint32
	linked := make(map[string]waddrmgr.HostedAllocationRecord2)
	for n, id := range a.inventory.order {
		if e := ctx.Err(); e != nil {
			return state, e
		}
		row := a.inventory.rows[id]
		r := row.Reservation
		if n >= len(state.Records) {
			if row.Phase != "reserved" || n != len(a.inventory.order)-1 {
				return state, ErrAllocationCorrupt
			}
			continue
		}
		local := state.Records[n]
		want := allocationLink2(a.inventory, row, before, local.Outcome, local.PreparationDigest)
		if !reflect.DeepEqual(local, want) {
			return state, ErrAllocationCorrupt
		}
		if row.Phase != "reserved" {
			digest, _ := allocationDomain2("wallet record", local)
			if row.Phase != local.Outcome || row.WalletRecordDigest != digest || row.PreparationDigest != local.PreparationDigest {
				return state, ErrAllocationCorrupt
			}
		}
		before = local.CursorsAfter
		if r.Request.Kind == "withdrawal_change" || r.Request.Kind == "carrier_return" {
			linked[r.Request.Kind+":"+r.Request.ConsumerID] = local
		}
	}
	if state.Meta.Cursors != before {
		return state, ErrAllocationCorrupt
	}
	if e := a.auditFinancialAllocations2(ctx, tx, linked); e != nil {
		return state, e
	}
	return state, nil
}

func allocationLink2(i *HostedAllocationInventory2, row allocationRow2, before [8]uint32, outcome, draft string) waddrmgr.HostedAllocationRecord2 {
	r := row.Reservation
	requestHash, _ := allocationDomain2("request", r.Request)
	after := before
	after[4+r.Branch] = r.EndIndex
	l := waddrmgr.HostedAllocationRecord2{Version: 2, InventoryID: i.binding.InventoryID, BindingID: i.bindingID, Sequence: r.Sequence, AllocationID: r.AllocationID, ReservationDigest: row.ReservationDigest, RequestDigest: requestHash, Outcome: outcome, Purpose: r.Purpose, Branch: r.Branch, StartIndex: r.StartIndex, EndIndex: r.EndIndex, SelectedIndex: r.SelectedIndex, InvalidIndices: append([]uint32{}, r.InvalidIndices...), Address: r.Address, Script: r.Script, CursorsBefore: before, CursorsAfter: after, ConsumerKind: r.Request.Kind, ConsumerBindingID: allocationConsumerBinding2(r.Request), ConsumerID: r.Request.ConsumerID, PreparationDigest: draft}
	return l
}
func (a *HostedAllocator2) prechargeLocal(state waddrmgr.HostedAllocationState2, row allocationRow2) error {
	draft := ""
	if row.Reservation.Request.Kind == "withdrawal_change" || row.Reservation.Request.Kind == "carrier_return" {
		draft = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	l := allocationLink2(a.inventory, row, state.Meta.Cursors, "consumed", draft)
	raw, e := json.Marshal(l)
	if e != nil || len(raw) > allocationRowMax2 {
		return ErrAllocationCapacity
	}
	// Manager counters may grow within their fixed 2048-byte metadata budget.
	if state.LogicalBytes+uint64(4+len(raw)+2048) > HostedAllocationMaxBytes {
		return ErrAllocationCapacity
	}
	return nil
}

func allocationConsumerBinding2(r AllocationRequest2) string {
	switch r.Kind {
	case "withdrawal_change":
		return r.WithdrawalBindingID
	case "carrier_return":
		return r.CarrierBindingID
	}
	return ""
}
