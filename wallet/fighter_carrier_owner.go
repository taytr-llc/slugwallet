// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type CarrierPin = fightercarrier.Pin
type CarrierRequest = fightercarrier.Request
type CarrierReview = fightercarrier.Review
type CarrierPreparation = fightercarrier.Preparation
type CarrierSignedPackage = fightercarrier.SignedPackage
type CarrierAuthorizationRequest = fightercarrier.AuthorizationRequest

// FighterCarrierOwner is a purpose-specific live borrow of one concrete wallet
// and one independently opened app journal. No parsed DTO can construct it.
type FighterCarrierOwner struct {
	owner     allocationLife
	wallet    *Wallet
	manager   *waddrmgr.Manager
	journal   *fightercarrier.Journal
	pin       fightercarrier.Pin
	binding   string
	allocated *HostedAllocator2
	restored  waddrmgr.RestoredCarrierGuard
	poisoned  atomic.Bool
}
type preparedCarrierFunding struct {
	owner     *FighterCarrierOwner
	request   fightercarrier.Request
	inputs    []fightercarrier.OwnedInput
	total     int64
	tipHash   string
	tipHeight int32
	public    *fighterownership.PreparedTransfer
}
type CarrierFundingPlan struct{ funding *preparedCarrierFunding }

func (p *CarrierFundingPlan) Funding() fighterownership.FundingTuple {
	if p == nil || p.funding == nil || p.funding.owner == nil || p.funding.owner.alive() != nil {
		return nil
	}
	v := make(fighterownership.FundingTuple, len(p.funding.inputs))
	for i, x := range p.funding.inputs {
		v[i] = fighterownership.FundingOutpoint{TxID: x.TxID, Index: x.OutputIndex}
	}
	return v
}

type PreparedFighterTransfer struct {
	owner       *FighterCarrierOwner
	preparation fightercarrier.Preparation
	digest      string
	public      *fighterownership.PreparedTransfer
	recovery    *fighterownership.PreparedRecovery
	closed      atomic.Bool
}

func (p *PreparedFighterTransfer) Close() error {
	if p != nil {
		p.closed.Store(true)
	}
	return nil
}
func (p *PreparedFighterTransfer) Pin() CarrierPin {
	if p == nil || p.closed.Load() || p.owner == nil || p.owner.alive() != nil {
		return CarrierPin{}
	}
	return p.owner.pin
}
func (p *PreparedFighterTransfer) AuthorizationRequest() CarrierAuthorizationRequest {
	if p == nil || p.closed.Load() || p.owner == nil || p.owner.alive() != nil {
		return CarrierAuthorizationRequest{}
	}
	v, e := fightercarrier.AuthorizationFor(p.preparation)
	if e != nil {
		return CarrierAuthorizationRequest{}
	}
	return v
}
func (p *PreparedFighterTransfer) Review() (CarrierReview, error) {
	if p == nil || p.closed.Load() || p.owner == nil || p.owner.alive() != nil {
		return CarrierReview{}, fightercarrier.ErrClosed
	}
	return p.preparation.Review, nil
}
func (p *PreparedFighterTransfer) Preparation() (CarrierPreparation, error) {
	if p == nil || p.closed.Load() || p.owner == nil || p.owner.alive() != nil {
		return CarrierPreparation{}, fightercarrier.ErrClosed
	}
	return cloneCarrierPreparation(p.preparation), nil
}
func cloneCarrierPreparation(p fightercarrier.Preparation) fightercarrier.Preparation {
	raw, _ := json.Marshal(p)
	var out fightercarrier.Preparation
	_ = json.Unmarshal(raw, &out)
	return out
}
func (p *PreparedFighterTransfer) Check(ctx context.Context) error {
	if ctx == nil || p == nil || p.owner == nil || p.closed.Load() || (p.public == nil) == (p.recovery == nil) {
		return fightercarrier.ErrClosed
	}
	work, end, e := p.owner.owner.acquire(ctx)
	if e != nil {
		return e
	}
	defer end()
	if e = p.owner.alive(); e != nil {
		return e
	}
	if e = p.checkPublic(work); e != nil {
		return e
	}
	if e = p.owner.authorize(work); e != nil {
		return e
	}
	e = walletdb.View(p.owner.wallet.db, func(tx walletdb.ReadTx) error {
		s, e := readCarrierWalletState(work, tx, p.owner.journal.Identity().JournalID, &p.owner.pin)
		if e != nil {
			return e
		}
		for _, r := range s.records {
			if r.RequestID == p.preparation.Request.RequestID {
				if r.State != "prepared" || r.PreparationDigest != p.digest {
					return fightercarrier.ErrConflict
				}
				if e = p.owner.auditExclusions(work, tx); e != nil {
					return e
				}
				return p.owner.validatePreparedInputs(work, tx, r.Preparation)
			}
		}
		return fightercarrier.ErrNotFound
	})
	if e != nil {
		return e
	}
	if e = p.checkPublic(work); e != nil {
		return e
	}
	return p.owner.authorize(work)
}

func (p *PreparedFighterTransfer) checkPublic(ctx context.Context) error {
	if p.public != nil && p.recovery == nil {
		return p.public.Check(ctx)
	}
	if p.recovery != nil && p.public == nil {
		if e := p.owner.recoveryMatches(p.preparation.Request, p.recovery); e != nil {
			return e
		}
		r := p.preparation.RecoveryFunding
		if r == nil || r.CommitRaw != hex.EncodeToString(p.recovery.CommitRaw()) {
			return fightercarrier.ErrConflict
		}
		return p.recovery.Check(ctx)
	}
	return fightercarrier.ErrInvalid
}
func (o *FighterCarrierOwner) alive() error {
	if o == nil || o.wallet == nil || o.manager == nil || o.wallet.Manager != o.manager || !o.wallet.ownActivityAlive() || o.owner.closing.Load() {
		return fightercarrier.ErrClosed
	}
	if o.poisoned.Load() || o.wallet.hostedAllocationTainted.Load() {
		return fightercarrier.ErrPoisoned
	}
	if o.allocated != nil {
		return o.allocated.alive()
	}
	return nil
}
func (o *FighterCarrierOwner) authorize(ctx context.Context) error {
	if e := o.alive(); e != nil {
		return e
	}
	if o.allocated != nil {
		return o.allocated.check(ctx, gymaccount.FighterTransfer)
	}
	return ctx.Err()
}
func (o *FighterCarrierOwner) auditExclusions(ctx context.Context, tx walletdb.ReadTx) error {
	withdrawal := ""
	if o.allocated != nil {
		withdrawal = o.allocated.inventory.binding.WithdrawalJournalID
	} else if e := auditRestoredCarrierRows(ctx, tx, o.manager, o.wallet.chainParams, o.pin, o.journal.Identity().JournalID); e != nil {
		return e
	}
	return auditPurposeExclusions(ctx, tx, o.pin, o.journal.Identity().JournalID, withdrawal)
}
