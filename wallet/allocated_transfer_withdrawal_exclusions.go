// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/walletwithdraw"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (s *CandidateWithdrawals) profileAllocation2(ctx context.Context, tx walletdb.ReadTx) (withdrawalIdentity, error) {
	a := s.allocated2
	if a == nil || a.wallet != s.wallet || a.manager != s.wallet.Manager || !a.manager.HostedAllocation2() {
		return withdrawalIdentity{}, ErrWithdrawalProfile
	}
	if err := a.alive(); err != nil {
		return withdrawalIdentity{}, err
	}
	m, err := a.manager.ReadHostedAllocationManifest2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedLocalNamespace2))
	if err != nil {
		return withdrawalIdentity{}, allocationManagerError(err)
	}
	b := a.inventory.binding.InitialManifest
	if m.Profile != b.Profile || m.Network != b.Network || m.Genesis != b.Genesis || m.RootPublicKey != b.RootPublicKey || m.GymPublicKey != b.GymPublicKey || m.GymID != b.GymID {
		return withdrawalIdentity{}, ErrWithdrawalProfile
	}
	return withdrawalIdentity{m.Profile, m.Network, m.Genesis, m.RootPublicKey, m.GymPublicKey, m.GymID}, nil
}

func (a *HostedAllocator2) checkWithdrawalJournal2(ctx context.Context, binding string, j *walletwithdraw.Journal, empty bool) error {
	if j == nil || j.BindingID() != binding {
		return ErrWithdrawalConflict
	}
	id := j.Identity()
	p := id.Pin
	b := a.inventory.binding
	m := b.InitialManifest
	if id.JournalID != b.WithdrawalJournalID || p.Version != 1 || p.AccountAuthorityID != b.AuthorityID || p.AccountID != b.AccountID || p.PoolSourceBindingID != b.SourceBindingID || p.Network != m.Network || p.Genesis != m.Genesis || p.WalletProfile != m.Profile || p.RootPublicKey != m.RootPublicKey || p.GymPublicKey != m.GymPublicKey || p.GymID != m.GymID {
		return ErrWithdrawalConflict
	}
	o, err := j.TryAcquire(ctx)
	if err != nil {
		return err
	}
	defer o.Close()
	s, err := o.Snapshot()
	if err != nil {
		return err
	}
	if empty && s.Count != 0 {
		return ErrWithdrawalConflict
	}
	return nil
}

// ApplyReconciliation has no caller-authored release/retain path. The token
// belongs to this owner's exact app journal and keeps its exclusive owner live.
func (s *AllocatedWithdrawals2) ApplyReconciliation(ctx context.Context, r *walletwithdraw.Reconciliation) error {
	if s == nil || s.journal == nil || !s.journal.OwnsReconciliation(r) {
		return ErrWithdrawalConflict
	}
	cap := gymaccount.View
	if r.Kind() == "abandoned" {
		cap = gymaccount.Withdrawal
	} else if r.Kind() != "retained" {
		return ErrWithdrawalConflict
	}
	return s.authorizedOperation(ctx, cap, true, func(work context.Context) error {
		if !s.journal.OwnsReconciliation(r) {
			return ErrWithdrawalConflict
		}
		var err error
		if r.Kind() == "abandoned" {
			err = s.base.Abandon(work, r.OperationID(), r.DraftDigest())
		} else {
			err = s.base.Retain(work, r.OperationID(), r.DraftDigest(), r.TxID())
		}
		if err != nil {
			return err
		}
		if !s.journal.OwnsReconciliation(r) {
			s.owner.poisoned.Store(true)
			return ErrAllocationOutcomeUnknown
		}
		return nil
	})
}

func (s *CandidateWithdrawals) checkWithdrawalExclusions2(ctx context.Context, tx walletdb.ReadTx, r CandidateWithdrawalRecord) error {
	a := s.allocated2
	if a == nil {
		return ErrWithdrawalProfile
	}
	b := a.inventory.binding
	pin, err := allocationCarrierPin2(b)
	if err != nil {
		return err
	}
	if err = auditPurposeExclusions(ctx, tx, pin, b.CarrierJournalID, b.WithdrawalJournalID); err != nil {
		return err
	}
	_, rows, err := readPurposeExclusions(ctx, tx, 14, b.CarrierJournalID, b.WithdrawalJournalID)
	if err != nil {
		return err
	}
	want := purposeExclusion{1, "withdrawal", r.Draft.OperationID, r.Draft.BindingID, r.DraftDigest, r.State}
	for _, in := range r.Draft.Inputs {
		op, err := withdrawalOutpoint(in)
		if err != nil {
			return err
		}
		if rows[string(withdrawalKey(op))] != want {
			return ErrWithdrawalConflict
		}
	}
	return nil
}

func (s *CandidateWithdrawals) reconcilePurposeExclusions2(ctx context.Context, tx walletdb.ReadWriteTx, r CandidateWithdrawalRecord, abandon bool) error {
	a := s.allocated2
	if a == nil {
		return ErrWithdrawalProfile
	}
	b := a.inventory.binding
	if abandon {
		return removePreparedPurposeExclusions(ctx, tx, 14, b.CarrierJournalID, b.WithdrawalJournalID, "withdrawal", r.Draft.OperationID, r.Draft.BindingID, r.DraftDigest)
	}
	ops := make([]wire.OutPoint, 0, len(r.Draft.Inputs))
	for _, in := range r.Draft.Inputs {
		op, err := withdrawalOutpoint(in)
		if err != nil {
			return err
		}
		ops = append(ops, op)
	}
	return putPurposeExclusions(ctx, tx, 14, b.CarrierJournalID, b.WithdrawalJournalID, purposeExclusion{1, "withdrawal", r.Draft.OperationID, r.Draft.BindingID, r.DraftDigest, "retained"}, ops)
}
