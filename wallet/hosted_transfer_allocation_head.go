// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"sync"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

func (i *HostedAllocationInventory2) accountMatches(a gymaccount.Account) bool {
	if a.ID != i.binding.AccountID || a.PrincipalID != i.binding.PrincipalID || a.Enrollment == nil {
		return false
	}
	m := i.binding.InitialManifest
	e := a.Enrollment
	return e.Network == m.Network && e.Genesis == m.Genesis && e.Profile == m.Profile && e.RootPublicKey == m.RootPublicKey && e.GymPublicKey == m.GymPublicKey && e.GymID == m.GymID
}

// authorize assumes the inventory permit is already held. The epoch is a
// synchronous parent fence, never a generic caller's proof of account rights.
func (i *HostedAllocationInventory2) authorize(ctx context.Context, token string, epoch HostedAllocationEpochFence, cap gymaccount.Capability, expected *gymaccount.Account, fn func(gymaccount.Account, func() error) error) error {
	if i == nil || ctx == nil || epoch == nil || fn == nil {
		return ErrAllocationInvalid
	}
	if i.owner.closing.Load() {
		return ErrAllocationClosed
	}
	if i.poisoned.Load() {
		return ErrAllocationPoisoned
	}
	return i.accounts.WithSession(ctx, token, cap, func(a gymaccount.Account, accountCheck func() error) error {
		if !i.accountMatches(a) || expected != nil && (a.ID != expected.ID || a.PrincipalID != expected.PrincipalID || a.Generation != expected.Generation) {
			return ErrAllocationConflict
		}
		// Like the existing vault fence, this private join guard prevents a bad
		// parent callback escaping the concrete account lease. It protects no DB
		// or wallet state and is never contended by an independent operation.
		var mu sync.Mutex
		active := true
		count := 0
		entered := false
		var inner error
		e := epoch(ctx, func(parentCheck func() error) error {
			mu.Lock()
			defer mu.Unlock()
			count++
			if !active || count != 1 || parentCheck == nil {
				inner = ErrAllocationConflict
				return inner
			}
			check := func() error {
				if e := ctx.Err(); e != nil {
					return e
				}
				if i.owner.closing.Load() {
					return ErrAllocationClosed
				}
				if i.poisoned.Load() {
					return ErrAllocationPoisoned
				}
				if e := accountCheck(); e != nil {
					return e
				}
				if e := parentCheck(); e != nil {
					return e
				}
				return ctx.Err()
			}
			if e := check(); e != nil {
				inner = e
				return e
			}
			entered = true
			inner = fn(a, check)
			if e := check(); e != nil {
				inner = errors.Join(inner, e)
			}
			return inner
		})
		mu.Lock()
		defer mu.Unlock()
		active = false
		if count != 1 || e != nil || inner != nil || ctx.Err() != nil {
			cause := errors.Join(e, inner, ctx.Err())
			if cause == nil {
				cause = ErrAllocationConflict
			}
			if entered && (count != 1 || e != nil && inner == nil || ctx.Err() != nil) {
				return errors.Join(ErrAllocationOutcomeUnknown, cause)
			}
			return cause
		}
		return nil
	})
}

// HostedRecoveryHead2 is privately minted by the surviving concrete inventory.
// Its getters expose only owned public copies; JSON cannot create a valid head.
type HostedRecoveryHead2 struct {
	inventory *HostedAllocationInventory2
	token     string
	epoch     HostedAllocationEpochFence
	account   gymaccount.Account
	binding   AllocationBinding2
	manifest  recovery.Manifest
	revision  uint32
}

func (h *HostedRecoveryHead2) Manifest() recovery.Manifest {
	if h == nil {
		return recovery.Manifest{}
	}
	m := h.manifest
	m.Accounts = append([]recovery.Account(nil), m.Accounts...)
	return m
}
func (h *HostedRecoveryHead2) Binding() AllocationBinding2 {
	if h == nil {
		return AllocationBinding2{}
	}
	return cloneAllocationBinding2(h.binding)
}
func (h *HostedRecoveryHead2) Revision() uint32 {
	if h == nil {
		return 0
	}
	return h.revision
}

// WithOriginalEpoch runs only the parent fence captured when this concrete head
// was minted. A consumer cannot substitute a later View during publication.
// This is a lifetime guard, not account authorization or a proof constructor.
func (h *HostedRecoveryHead2) WithOriginalEpoch(ctx context.Context, fn func(func() error) error) error {
	if h == nil || h.inventory == nil || h.epoch == nil || fn == nil {
		return ErrAllocationConflict
	}
	return h.epoch(ctx, fn)
}
func (i *HostedAllocationInventory2) CaptureRecoveryHead(ctx context.Context, token string, epoch HostedAllocationEpochFence) (*HostedRecoveryHead2, error) {
	ctx, done, e := i.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	m, e := allocationManifest2(i.binding, i.meta.Cursors)
	if e != nil {
		return nil, e
	}
	var account gymaccount.Account
	e = i.authorize(ctx, token, epoch, gymaccount.View, nil, func(a gymaccount.Account, check func() error) error { account = a; return check() })
	if e != nil {
		return nil, e
	}
	return &HostedRecoveryHead2{inventory: i, token: token, epoch: epoch, account: account, binding: cloneAllocationBinding2(i.binding), manifest: m, revision: i.meta.Revision}, nil
}

// Hold requires the original credential without exposing it to the consumer.
// The vault independently applies RecoveryExport and its own retained receipt.
func (h *HostedRecoveryHead2) Hold(ctx context.Context, originalToken string) (*HostedRecoveryHeadLease2, error) {
	if h == nil || h.inventory == nil || originalToken != h.token {
		return nil, ErrAllocationConflict
	}
	return h.inventory.HoldRecoveryHead(ctx, h)
}

type HostedRecoveryHeadLease2 struct {
	owner     allocationLife
	inventory *HostedAllocationInventory2
	head      *HostedRecoveryHead2
	ctx       context.Context
	release   func()
}

func (i *HostedAllocationInventory2) HoldRecoveryHead(ctx context.Context, h *HostedRecoveryHead2) (*HostedRecoveryHeadLease2, error) {
	if h == nil || h.inventory != i {
		return nil, ErrAllocationConflict
	}
	ctx, done, e := i.acquire(ctx)
	if e != nil {
		return nil, e
	}
	if h.revision != i.meta.Revision {
		done()
		return nil, ErrAllocationConflict
	}
	l := &HostedRecoveryHeadLease2{owner: newAllocationLife(), inventory: i, head: h, ctx: ctx, release: done}
	i.leasesMu.Lock()
	if i.owner.closing.Load() {
		i.leasesMu.Unlock()
		l.owner.cancel()
		done()
		return nil, ErrAllocationClosed
	}
	i.leases[l] = true
	i.leasesMu.Unlock()
	return l, nil
}

// Acquire registers real publication work before entering an account fence.
// Close invalidates idle handles and joins registered work before release.
func (l *HostedRecoveryHeadLease2) Acquire(ctx context.Context) (context.Context, func(), error) {
	if l == nil {
		return nil, nil, ErrAllocationClosed
	}
	ctx, done, e := l.owner.acquire(ctx)
	if e != nil {
		return nil, nil, e
	}
	if e = l.Check(); e != nil {
		done()
		return nil, nil, e
	}
	return ctx, done, nil
}
func (l *HostedRecoveryHeadLease2) Check() error {
	if l == nil || l.inventory == nil || l.owner.closing.Load() || l.inventory.owner.closing.Load() {
		return ErrAllocationClosed
	}
	if e := l.ctx.Err(); e != nil {
		return e
	}
	if l.inventory.poisoned.Load() {
		return ErrAllocationPoisoned
	}
	if l.inventory.revision.Load() != l.head.revision {
		return ErrAllocationConflict
	}
	return nil
}
func (l *HostedRecoveryHeadLease2) Close() error {
	if l == nil {
		return nil
	}
	first, e := l.owner.startClose()
	if !first {
		return e
	}
	l.owner.active.Wait()
	l.inventory.leasesMu.Lock()
	delete(l.inventory.leases, l)
	l.inventory.leasesMu.Unlock()
	l.release()
	return l.owner.finishClose(nil)
}

func (i *HostedAllocationInventory2) Status(ctx context.Context, token string, epoch HostedAllocationEpochFence) (AllocationInventoryStatus, error) {
	ctx, done, e := i.acquire(ctx)
	if e != nil {
		return AllocationInventoryStatus{}, e
	}
	defer done()
	r := AllocationInventoryStatus{Revision: i.meta.Revision, Allocations: i.meta.Allocations, ObservedAtMS: i.now().UnixMilli()}
	if r.ObservedAtMS < 1 || r.ObservedAtMS > allocationMaxTime || r.ObservedAtMS < i.meta.ClockHighWaterMS {
		return AllocationInventoryStatus{}, ErrAllocationUnavailable
	}
	for _, id := range i.order {
		row := i.rows[id]
		if row.Reservation.Request.Kind != "receive" {
			continue
		}
		if row.Phase == "reserved" {
			r.PendingReceiveID = id
		}
		if row.Phase == "consumed" {
			r.IssuedReceiveID = id
		}
	}
	if e = i.authorize(ctx, token, epoch, gymaccount.View, nil, func(_ gymaccount.Account, check func() error) error { return check() }); e != nil {
		return AllocationInventoryStatus{}, e
	}
	return r, nil
}
