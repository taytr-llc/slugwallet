// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"errors"
	"sync/atomic"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// AllocatedWithdrawals is the schema13-only adapter. Its private base preserves
// the existing transaction codec, but is never exposed as a generic allocator.
type AllocatedWithdrawals struct {
	owner  *HostedAllocator
	base   *CandidateWithdrawals
	closed atomic.Bool
}

func (s *CandidateWithdrawals) profile(ctx context.Context, tx walletdb.ReadTx) (withdrawalIdentity, error) {
	if s.allocated2 != nil {
		if s.allocated != nil {
			return withdrawalIdentity{}, ErrWithdrawalProfile
		}
		return s.profileAllocation2(ctx, tx)
	}
	if s.allocated == nil {
		return withdrawalProfile(tx, s.wallet)
	}
	a := s.allocated
	if a.wallet != s.wallet || a.manager != s.wallet.Manager || !a.manager.HostedAllocation() {
		return withdrawalIdentity{}, ErrWithdrawalProfile
	}
	if e := a.alive(); e != nil {
		return withdrawalIdentity{}, e
	}
	m, e := a.manager.ReadHostedAllocationManifest(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace))
	if e != nil {
		return withdrawalIdentity{}, allocationManagerError(e)
	}
	expected := a.inventory.binding.InitialManifest
	if m.Profile != expected.Profile || m.Network != expected.Network || m.Genesis != expected.Genesis || m.RootPublicKey != expected.RootPublicKey || m.GymPublicKey != expected.GymPublicKey || m.GymID != expected.GymID {
		return withdrawalIdentity{}, ErrWithdrawalProfile
	}
	return withdrawalIdentity{m.Profile, m.Network, m.Genesis, m.RootPublicKey, m.GymPublicKey, m.GymID}, nil
}
func (a *HostedAllocator) CreateWithdrawals(ctx context.Context, binding string) (*AllocatedWithdrawals, error) {
	return a.openWithdrawals(ctx, binding, true)
}
func (a *HostedAllocator) OpenWithdrawals(ctx context.Context, binding string) (*AllocatedWithdrawals, error) {
	return a.openWithdrawals(ctx, binding, false)
}
func (a *HostedAllocator) openWithdrawals(ctx context.Context, binding string, create bool) (*AllocatedWithdrawals, error) {
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if a.withdrawals != nil {
		return nil, ErrAllocationBusy
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return nil, e
	}
	base, e := a.wallet.openCandidateWithdrawalsOwned(work, binding, create, a)
	if e != nil {
		return nil, e
	}
	if e = a.check(work, gymaccount.View); e != nil {
		closeErr := base.Close()
		if create {
			return nil, errors.Join(ErrAllocationOutcomeUnknown, e, closeErr)
		}
		return nil, errors.Join(e, closeErr)
	}
	out := &AllocatedWithdrawals{owner: a, base: base}
	a.withdrawals = out
	return out, nil
}
func (s *AllocatedWithdrawals) live() error {
	if s == nil || s.owner == nil || s.base == nil || s.closed.Load() || s.base.closed.Load() {
		return ErrWithdrawalClosed
	}
	if s.base.poisoned.Load() {
		return ErrAllocationPoisoned
	}
	return s.owner.alive()
}
func (s *AllocatedWithdrawals) Plan(ctx context.Context, id string, r CandidateWithdrawalRequest) (*AllocationPlan, error) {
	if e := s.live(); e != nil {
		return nil, e
	}
	script, e := validateWithdrawalRequest(r)
	if e != nil {
		return nil, e
	}
	request := AllocationRequest{Version: 1, Kind: "withdrawal_change", ConsumerID: r.OperationID, Purpose: 84, Branch: 1, WithdrawalBindingID: s.base.binding, Recipient: r.Recipient, RecipientScript: hex.EncodeToString(script), AmountAtoms: r.AmountAtoms, FeeRateAtomsPerKB: 1000, FeeCeilingAtoms: 100000, MinConfirmations: 1, InputPurpose: 84, ChangePurpose: 84, Account: 0, TxVersion: 1, InputSequence: wire.MaxTxInSequenceNum, LockTime: 0, SighashType: 1}
	return s.owner.plan(ctx, id, request, s, &r)
}

// authorized holds only the admitted allocator/inventory owner gates. Wallet
// locks/transactions are acquired by fn after the original fence has returned.
func (s *AllocatedWithdrawals) authorized(ctx context.Context, cap gymaccount.Capability, fn func(context.Context) error) error {
	if e := s.live(); e != nil {
		return e
	}
	work, end, e := s.owner.acquire(ctx)
	if e != nil {
		return e
	}
	defer end()
	if e = s.live(); e != nil {
		return e
	}
	if e = s.owner.check(work, cap); e != nil {
		return e
	}
	if e = fn(work); e != nil {
		if s.base.poisoned.Load() {
			s.owner.poisoned.Store(true)
		}
		return e
	}
	return s.owner.check(work, cap)
}

// checkedDraft verifies both journals and performs the exact watch before an
// actionable draft or signature is disclosed. It never substitutes a latest ID.
func (s *AllocatedWithdrawals) checkedDraft(ctx context.Context, op string) (CandidateWithdrawalRecord, error) {
	if !withdrawalHex(op, 32, true) {
		return CandidateWithdrawalRecord{}, ErrWithdrawalInvalid
	}
	var record CandidateWithdrawalRecord
	e := walletdb.View(s.owner.wallet.db, func(tx walletdb.ReadTx) error {
		_, e := s.owner.auditPair(ctx, tx)
		if e != nil {
			return e
		}
		r, e := s.owner.readWithdrawalRecord(tx, op)
		if e != nil {
			return e
		}
		record = r
		return nil
	})
	if e != nil {
		return record, e
	}
	var row *allocationRow
	for _, id := range s.owner.inventory.order {
		x := s.owner.inventory.rows[id]
		if x.Reservation.Request.Kind == "withdrawal_change" && x.Reservation.Request.ConsumerID == op {
			copy := x
			row = &copy
			break
		}
	}
	if row == nil || row.Phase != "consumed" || row.DraftDigest != record.DraftDigest {
		return CandidateWithdrawalRecord{}, ErrAllocationResumeRequired
	}
	if e = s.owner.watch(ctx, row.Reservation.Address); e != nil {
		return CandidateWithdrawalRecord{}, e
	}
	return record, nil
}

// InspectRecord returns dated local bookkeeping for the concrete paired app
// journal audit. It creates no finalized handle or watch/readiness assertion.
// A subsequent native review/sign still requires fresh Withdrawal authority.
func (s *AllocatedWithdrawals) InspectRecord(ctx context.Context, op string) (CandidateWithdrawalRecord, error) {
	var out CandidateWithdrawalRecord
	e := s.authorized(ctx, gymaccount.View, func(work context.Context) error {
		var err error
		err = walletdb.View(s.owner.wallet.db, func(tx walletdb.ReadTx) error { _, e := s.owner.auditPair(work, tx); return e })
		if err != nil {
			return err
		}
		out, err = s.base.Lookup(work, op)
		return err
	})
	if e != nil {
		return CandidateWithdrawalRecord{}, e
	}
	out.Draft = cloneAllocatedDraft(out.Draft)
	return out, nil
}
func (s *AllocatedWithdrawals) Lookup(ctx context.Context, op string) (CandidateWithdrawalRecord, error) {
	var out CandidateWithdrawalRecord
	e := s.authorized(ctx, gymaccount.Withdrawal, func(work context.Context) error { var e error; out, e = s.checkedDraft(work, op); return e })
	if e != nil {
		return CandidateWithdrawalRecord{}, e
	}
	out.Draft = cloneAllocatedDraft(out.Draft)
	return out, nil
}
func (s *AllocatedWithdrawals) Sign(ctx context.Context, op, digest string) (CandidateWithdrawalSigned, error) {
	var out CandidateWithdrawalSigned
	e := s.authorized(ctx, gymaccount.Withdrawal, func(work context.Context) error {
		r, e := s.checkedDraft(work, op)
		if e != nil {
			return e
		}
		if r.DraftDigest != digest {
			return ErrWithdrawalConflict
		}
		out, e = s.base.Sign(work, op, digest)
		return e
	})
	if e != nil {
		return CandidateWithdrawalSigned{}, e
	}
	return out, nil
}
func (s *AllocatedWithdrawals) Retain(ctx context.Context, op, digest, txid string) error {
	return s.authorized(ctx, gymaccount.View, func(work context.Context) error { return s.base.Retain(work, op, digest, txid) })
}
func (s *AllocatedWithdrawals) Abandon(ctx context.Context, op, digest string) error {
	return s.authorized(ctx, gymaccount.Withdrawal, func(work context.Context) error { return s.base.Abandon(work, op, digest) })
}
func (s *AllocatedWithdrawals) OperationIDs(ctx context.Context) ([]string, error) {
	var out []string
	e := s.authorized(ctx, gymaccount.View, func(work context.Context) error { var e error; out, e = s.base.OperationIDs(work); return e })
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (s *AllocatedWithdrawals) Empty(ctx context.Context) (bool, error) {
	var out bool
	e := s.authorized(ctx, gymaccount.View, func(work context.Context) error { var e error; out, e = s.base.Empty(work); return e })
	return out, e
}
func (s *AllocatedWithdrawals) closeOwned() error {
	if s == nil || s.closed.Swap(true) {
		return nil
	}
	return s.base.Close()
}
func (s *AllocatedWithdrawals) Close() error {
	if s == nil {
		return nil
	}
	work, end, e := s.owner.acquire(context.Background())
	_ = work
	if e != nil {
		if s.owner.owner.closing.Load() {
			<-s.owner.owner.closed
			return s.owner.owner.closeErr
		}
		return e
	}
	defer end()
	e = s.closeOwned()
	if e == nil {
		s.owner.withdrawals = nil
	}
	return e
}
