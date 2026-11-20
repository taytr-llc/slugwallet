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

var hostedLocalNamespace = []byte("slug-hosted-allocation-v1")

func allocationManagerError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	case errors.Is(e, waddrmgr.ErrHostedAllocationCapacity):
		return ErrAllocationCapacity
	case errors.Is(e, waddrmgr.ErrHostedAllocationConflict):
		return ErrAllocationConflict
	case errors.Is(e, waddrmgr.ErrHostedAllocationProfile):
		return ErrAllocationProfile
	case errors.Is(e, waddrmgr.ErrHostedAllocationInvalid):
		return ErrAllocationInvalid
	default:
		return errors.Join(ErrAllocationCorrupt, e)
	}
}
func allocationGuard(b AllocationBinding, bound bool) waddrmgr.HostedAllocationGuard {
	h, _ := allocationHash("", b.InitialManifest)
	g := waddrmgr.HostedAllocationGuard{Version: 1, State: "locked", InventoryID: b.InventoryID, AuthorityID: b.AuthorityID, AccountID: b.AccountID, WalletOwnerID: b.WalletOwnerID, SourceBindingID: b.SourceBindingID, InitialManifestSHA256: h}
	if bound {
		g.State = "bound"
		g.BindingID, _ = AllocationBindingID(b)
	}
	return g
}
func cloneAllocationAccount(a gymaccount.Account) gymaccount.Account {
	if a.Enrollment != nil {
		e := *a.Enrollment
		a.Enrollment = &e
	}
	return a
}
func (a *HostedAllocator) check(ctx context.Context, cap gymaccount.Capability) error {
	return a.inventory.authorize(ctx, a.token, a.epoch, cap, &a.account, func(_ gymaccount.Account, check func() error) error { return check() })
}
func allocationCapability(r AllocationRequest) gymaccount.Capability {
	if r.Kind == "withdrawal_change" {
		return gymaccount.Withdrawal
	}
	return gymaccount.View
}

// BindWallet accepts only the concrete empty inventory and its expected locked
// wallet. The account fence never contains a wallet/manager/database operation.
func (i *HostedAllocationInventory) BindWallet(ctx context.Context, w *Wallet, token string, epoch HostedAllocationEpochFence) error {
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
		return allocationManagerError(w.Manager.BindHostedAllocation(work, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedLocalNamespace), allocationGuard(i.binding, false), i.bindingID))
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
func (i *HostedAllocationInventory) Attach(ctx context.Context, w *Wallet, token string, epoch HostedAllocationEpochFence) (*HostedAllocator, error) {
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
	a := &HostedAllocator{owner: newAllocationLife(), inventory: i, wallet: w, manager: w.Manager, token: token, epoch: epoch}
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
func hostedWalletWrite(ctx context.Context, w *Wallet, poison func(), fn func(walletdb.ReadWriteTx) error) error {
	tx, e := w.db.BeginReadWriteTx()
	if e != nil {
		return ErrAllocationStorage
	}
	abort := func(cause error) error {
		if e := tx.Rollback(); e != nil {
			poison()
			return errors.Join(ErrAllocationOutcomeUnknown, ErrAllocationStorage, cause)
		}
		return cause
	}
	if e = ctx.Err(); e != nil {
		return abort(e)
	}
	if !w.ownActivityAlive() {
		return abort(ErrAllocationClosed)
	}
	if e = fn(tx); e != nil {
		return abort(e)
	}
	if e = ctx.Err(); e != nil {
		return abort(e)
	}
	if !w.ownActivityAlive() {
		return abort(ErrAllocationClosed)
	}
	if e = tx.Commit(); e != nil {
		poison()
		return errors.Join(ErrAllocationOutcomeUnknown, ErrAllocationStorage)
	}
	if e = ctx.Err(); e != nil {
		poison()
		return errors.Join(ErrAllocationOutcomeUnknown, e)
	}
	if !w.ownActivityAlive() {
		poison()
		return errors.Join(ErrAllocationOutcomeUnknown, ErrAllocationClosed)
	}
	return nil
}
func (a *HostedAllocator) auditPair(ctx context.Context, tx walletdb.ReadTx) (waddrmgr.HostedAllocationState, error) {
	state, e := a.manager.AuditHostedAllocation(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace))
	if e != nil {
		return state, allocationManagerError(e)
	}
	if state.Guard != allocationGuard(a.inventory.binding, true) || len(state.Records) > len(a.inventory.order) {
		return state, ErrAllocationCorrupt
	}
	var before [8]uint32
	linked := make(map[string]waddrmgr.HostedAllocationRecord)
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
		want := allocationLink(a.inventory, row, before, local.Outcome, local.DraftDigest)
		if !reflect.DeepEqual(local, want) {
			return state, ErrAllocationCorrupt
		}
		if row.Phase != "reserved" {
			digest, _ := allocationDomain("wallet record", local)
			if row.Phase != local.Outcome || row.WalletRecordDigest != digest || row.DraftDigest != local.DraftDigest {
				return state, ErrAllocationCorrupt
			}
		}
		before = local.CursorsAfter
		if r.Request.Kind == "withdrawal_change" {
			linked[r.Request.ConsumerID] = local
		}
	}
	if state.Meta.Cursors != before {
		return state, ErrAllocationCorrupt
	}
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns == nil {
		for _, link := range linked {
			if link.Outcome != "burned" {
				return state, ErrAllocationCorrupt
			}
		}
		return state, nil
	}
	var meta withdrawalMeta
	if e = withdrawalDecode(ns.Get(withdrawalMetaKey), 2048, &meta); e != nil {
		return state, e
	}
	m := a.inventory.binding.InitialManifest
	identity := withdrawalIdentity{m.Profile, m.Network, m.Genesis, m.RootPublicKey, m.GymPublicKey, m.GymID}
	seam := &CandidateWithdrawals{wallet: a.wallet, binding: meta.BindingID, identity: identity, allocated: a}
	ws, e := seam.audit(ctx, tx)
	if e != nil {
		return state, e
	}
	for id, local := range linked {
		r, exists := ws.records[id]
		if local.Outcome == "burned" {
			if exists {
				return state, ErrAllocationCorrupt
			}
			continue
		}
		if !exists || r.DraftDigest != local.DraftDigest || r.Draft.BindingID != local.WithdrawalBindingID || r.Draft.Change.Index != local.SelectedIndex || r.Draft.Change.Address != local.Address || r.Draft.Change.Script != local.Script {
			return state, ErrAllocationCorrupt
		}
	}
	for id := range ws.records {
		l, ok := linked[id]
		if !ok || l.Outcome != "consumed" {
			return state, ErrAllocationCorrupt
		}
	}
	return state, nil
}
func allocationLink(i *HostedAllocationInventory, row allocationRow, before [8]uint32, outcome, draft string) waddrmgr.HostedAllocationRecord {
	r := row.Reservation
	requestHash, _ := allocationDomain("request", r.Request)
	after := before
	after[4+r.Branch] = r.EndIndex
	l := waddrmgr.HostedAllocationRecord{Version: 1, InventoryID: i.binding.InventoryID, BindingID: i.bindingID, Sequence: r.Sequence, AllocationID: r.AllocationID, ReservationDigest: row.ReservationDigest, RequestDigest: requestHash, Outcome: outcome, Purpose: r.Purpose, Branch: r.Branch, StartIndex: r.StartIndex, EndIndex: r.EndIndex, SelectedIndex: r.SelectedIndex, InvalidIndices: append([]uint32{}, r.InvalidIndices...), Address: r.Address, Script: r.Script, CursorsBefore: before, CursorsAfter: after, DraftDigest: draft}
	if r.Request.Kind == "withdrawal_change" {
		l.WithdrawalBindingID = r.Request.WithdrawalBindingID
		l.WithdrawalOperationID = r.Request.ConsumerID
	}
	return l
}
func (a *HostedAllocator) prechargeLocal(state waddrmgr.HostedAllocationState, row allocationRow) error {
	draft := ""
	if row.Reservation.Request.Kind == "withdrawal_change" {
		draft = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	l := allocationLink(a.inventory, row, state.Meta.Cursors, "consumed", draft)
	raw, e := json.Marshal(l)
	if e != nil || len(raw) > allocationRowMax {
		return ErrAllocationCapacity
	}
	// Manager counters may grow within their fixed 2048-byte metadata budget.
	if state.LogicalBytes+uint64(4+len(raw)+2048) > HostedAllocationMaxBytes {
		return ErrAllocationCapacity
	}
	return nil
}
