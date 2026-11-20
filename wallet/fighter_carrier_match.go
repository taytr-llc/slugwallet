// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// CarrierRecoveryMatchScan is an intent-free, public-path lookup under one
// concrete restored owner and canonical recovery capability. It cannot sign,
// reserve an input, or create a journal operation. Closing joins its current
// bounded Step; a later action still requires an exact durable request.
type CarrierRecoveryMatchScan struct{ scan *CarrierRecoveryScan }

func (o *FighterCarrierOwner) BeginRecoveryMatch(ctx context.Context, public *fighterownership.PreparedRecovery) (*CarrierRecoveryMatchScan, error) {
	if ctx == nil || o == nil || public == nil || o.pin.OwnerMode != "restored" || o.pin.ManagerSchema != 15 {
		return nil, fightercarrier.ErrInvalid
	}
	i := public.Intent()
	if i.PinID != o.pin.OwnershipPinID || i.FromGym != o.pin.GymPublicKey {
		return nil, fightercarrier.ErrConflict
	}
	work, end, err := o.owner.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if err = o.authorize(work); err != nil {
		return nil, err
	}
	if err = public.Check(work); err != nil {
		return nil, err
	}
	if err = o.authorize(work); err != nil {
		return nil, err
	}
	return &CarrierRecoveryMatchScan{scan: &CarrierRecoveryScan{owner: o, public: public}}, nil
}

func (s *CarrierRecoveryMatchScan) Step(ctx context.Context) (CarrierRecoveryProgress, error) {
	if s == nil || s.scan == nil {
		return CarrierRecoveryProgress{}, fightercarrier.ErrInvalid
	}
	return s.scan.Step(ctx)
}

func (s *CarrierRecoveryMatchScan) Close() error {
	if s == nil || s.scan == nil {
		return nil
	}
	return s.scan.Close()
}

// PrepareMatchedRecovery is admitted only after the user selected the exact
// matched commit and reveal/refund kind and the app journal retained its intent.
// The public capability, original inventory and intent are checked again by
// the original preparation path. No parsed match DTO can enter this method.
func (o *FighterCarrierOwner) PrepareMatchedRecovery(ctx context.Context, request CarrierRequest, matched *CarrierRecoveryMatchScan) (*PreparedFighterTransfer, error) {
	if matched == nil || matched.scan == nil || matched.scan.owner != o {
		return nil, fightercarrier.ErrInvalid
	}
	s := matched.scan
	if !s.mu.TryLock() {
		return nil, fightercarrier.ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil, fightercarrier.ErrClosed
	}
	if s.match.Next != s.match.Total || !s.match.FundingFound || !s.match.ReturnFound {
		return nil, fightercarrier.ErrNotFound
	}
	selected, err := o.BeginRecoveryScan(ctx, request, s.public)
	if err != nil {
		return nil, err
	}
	defer selected.Close()
	selected.match = s.match
	return o.PrepareRecovery(ctx, selected)
}

// matchRecoveryStep is a public read leaf shared by intent-free discovery and
// selected recovery. The caller retains the owner and checks the concrete
// public capability around it. It never visits the app journal or writes DBs.
func (o *FighterCarrierOwner) matchRecoveryStep(ctx context.Context, previous waddrmgr.RestoredCarrierMatch, inspection fightertransfer.CommitInspection) (waddrmgr.RestoredCarrierMatch, error) {
	var next waddrmgr.RestoredCarrierMatch
	err := walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
		var err error
		next, err = o.manager.MatchRestoredCarrierKeys(ctx, tx.ReadBucket(waddrmgrNamespaceKey), previous.Next, inspection.FundingKey, inspection.ReturnScript)
		return err
	})
	if err != nil {
		return waddrmgr.RestoredCarrierMatch{}, err
	}
	if previous.FundingFound {
		next.FundingFound, next.FundingBranch, next.FundingIndex = true, previous.FundingBranch, previous.FundingIndex
	}
	if previous.ReturnFound {
		next.ReturnFound, next.ReturnBranch, next.ReturnIndex = true, previous.ReturnBranch, previous.ReturnIndex
	}
	return next, nil
}
