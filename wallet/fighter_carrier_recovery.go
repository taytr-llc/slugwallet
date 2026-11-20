// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// CarrierRecoveryScan retains only public lookup state. A step owns the concrete
// wallet operation until it joins; Close cannot leave a derivation in flight.
type CarrierRecoveryScan struct {
	mu      sync.Mutex
	closed  bool
	owner   *FighterCarrierOwner
	request fightercarrier.Request
	public  *fighterownership.PreparedRecovery
	match   waddrmgr.RestoredCarrierMatch
}
type CarrierRecoveryProgress struct {
	Examined, Total   uint32
	Complete, Matched bool
}

func (o *FighterCarrierOwner) recoveryMatches(r fightercarrier.Request, public *fighterownership.PreparedRecovery) error {
	if o == nil || o.pin.OwnerMode != "restored" || o.pin.ManagerSchema != 15 || public == nil || fightercarrier.ValidateRequest(r) != nil || r.Kind != "recover_reveal" && r.Kind != "recover_refund" {
		return fightercarrier.ErrInvalid
	}
	i := public.Intent()
	if r.OwnershipPinID != o.pin.OwnershipPinID || i.PinID != r.OwnershipPinID || i.PriorStateID != r.PriorStateID || i.Recipient != r.RecipientGym || i.FromGym != o.pin.GymPublicKey || public.Commit().TxID != r.CommitTxID {
		return fightercarrier.ErrConflict
	}
	return nil
}
func (o *FighterCarrierOwner) BeginRecoveryScan(ctx context.Context, request CarrierRequest, public *fighterownership.PreparedRecovery) (*CarrierRecoveryScan, error) {
	if e := o.recoveryMatches(request, public); e != nil {
		return nil, e
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	if e = o.requireIntent(work, request); e != nil {
		return nil, e
	}
	if e = public.Check(work); e != nil {
		return nil, e
	}
	return &CarrierRecoveryScan{owner: o, request: request, public: public}, nil
}
func (s *CarrierRecoveryScan) Close() error {
	if s != nil {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
	}
	return nil
}
func (s *CarrierRecoveryScan) Step(ctx context.Context) (CarrierRecoveryProgress, error) {
	var none CarrierRecoveryProgress
	if s == nil || !s.mu.TryLock() {
		return none, fightercarrier.ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return none, fightercarrier.ErrClosed
	}
	work, end, e := s.owner.owner.acquire(ctx)
	if e != nil {
		return none, e
	}
	defer end()
	if e = s.owner.authorize(work); e != nil {
		return none, e
	}
	if e = s.public.Check(work); e != nil {
		return none, e
	}
	i := s.public.Inspection()
	var next waddrmgr.RestoredCarrierMatch
	e = walletdb.View(s.owner.wallet.db, func(tx walletdb.ReadTx) error {
		var e error
		next, e = s.owner.manager.MatchRestoredCarrierKeys(work, tx.ReadBucket(waddrmgrNamespaceKey), s.match.Next, i.FundingKey, i.ReturnScript)
		return e
	})
	if e != nil {
		return none, e
	}
	if e = s.public.Check(work); e != nil {
		return none, e
	}
	if e = s.owner.authorize(work); e != nil {
		return none, e
	}
	if s.match.FundingFound {
		next.FundingFound, next.FundingBranch, next.FundingIndex = true, s.match.FundingBranch, s.match.FundingIndex
	}
	if s.match.ReturnFound {
		next.ReturnFound, next.ReturnBranch, next.ReturnIndex = true, s.match.ReturnBranch, s.match.ReturnIndex
	}
	s.match = next
	done := next.Next == next.Total
	return CarrierRecoveryProgress{next.Next, next.Total, done, done && next.FundingFound && next.ReturnFound}, nil
}

func (o *FighterCarrierOwner) validateRecoveryPaths(ctx context.Context, tx walletdb.ReadTx, p fightercarrier.Preparation) error {
	r := p.RecoveryFunding
	if r == nil || o.pin.OwnerMode != "restored" {
		return fightercarrier.ErrInvalid
	}
	if e := fightercarrier.ValidatePreparation(p, o.pin, o.binding); e != nil {
		return e
	}
	pub, e := hex.DecodeString(r.FundingPublicKey)
	if e != nil {
		return e
	}
	script := append([]byte{0, 20}, address.Hash160(pub)...)
	ns := tx.ReadBucket(waddrmgrNamespaceKey)
	if e = o.manager.CheckRestoredCarrierPath(ctx, ns, r.FundingBranch, r.FundingIndex, pub, script); e != nil {
		return e
	}
	returned, _ := hex.DecodeString(r.ReturnPath.Script)
	return o.manager.CheckRestoredCarrierPath(ctx, ns, r.ReturnPath.Branch, r.ReturnPath.Index, nil, returned)
}

// PrepareRecovery reconstructs ONLY the already committed gym authorization.
// It never signs a funding input or spend, changes a return path, or searches
// alternate signatures. The native economic approval still precedes Sign.
func (o *FighterCarrierOwner) PrepareRecovery(ctx context.Context, s *CarrierRecoveryScan) (*PreparedFighterTransfer, error) {
	if s == nil || s.owner != o || !s.mu.TryLock() {
		return nil, fightercarrier.ErrInvalid
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil, fightercarrier.ErrClosed
	}
	if s.match.Next != s.match.Total || !s.match.FundingFound || !s.match.ReturnFound {
		return nil, fightercarrier.ErrNotFound
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	if e = o.recoveryMatches(s.request, s.public); e != nil {
		return nil, e
	}
	if e = s.public.Check(work); e != nil {
		return nil, e
	}
	if e = o.requireIntent(work, s.request); e != nil {
		return nil, e
	}
	var p fightercarrier.Preparation
	e = func() error {
		lease, e := o.wallet.holdUnlockContext(work)
		if e != nil {
			return e
		}
		defer lease.release()
		return walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
			i := s.public.Inspection()
			env, e := o.restoredEnvelope(work, tx, i.Intent)
			if e != nil {
				return e
			}
			redeem, e := fightertransfer.RedeemScript(env, i.FundingKey)
			if e != nil {
				return e
			}
			a, e := address.NewAddressScriptHash(redeem, o.wallet.chainParams)
			if e != nil {
				return e
			}
			escrow, e := txscript.PayToAddrScript(a)
			if e != nil || !bytes.Equal(escrow, i.CommitScript[:]) {
				return fightercarrier.ErrConflict
			}
			ret, e := address.NewAddressWitnessPubKeyHash(i.ReturnScript[2:], o.wallet.chainParams)
			if e != nil {
				return e
			}
			v, c := s.public.Intent(), s.public.Commit()
			tip := o.manager.SyncedTo()
			if c.Height > uint32(tip.Height) || tip.Height < 0 {
				return fightercarrier.ErrConflict
			}
			r := fightercarrier.Review{Version: 1, RequestID: s.request.RequestID, Kind: s.request.Kind, BindingID: o.binding, OwnershipPinID: s.request.OwnershipPinID, PriorStateID: s.request.PriorStateID, SenderGym: o.pin.GymPublicKey, RecipientGym: s.request.RecipientGym, TransferID: v.TransferID, FundingDigest: v.FundingDigest, InputCount: 1, TotalInputAtoms: 500000, ReturnAddress: ret.EncodeAddress(), ReturnScript: hex.EncodeToString(i.ReturnScript[:]), ReturnBranch: s.match.ReturnBranch, ReturnIndex: s.match.ReturnIndex, EscrowAtoms: 500000, SpendFeeAtoms: 10000, TotalFeeAtoms: 10000, ReturnedAtoms: 490000, CommitTxID: s.request.CommitTxID}
			d, e := fightercarrier.ReviewDigest(r)
			if e != nil {
				return e
			}
			p = fightercarrier.Preparation{Version: 1, BindingID: o.binding, Request: s.request, PreparedAtMS: time.Now().UnixMilli(), TipHash: tip.Hash.String(), TipHeight: tip.Height, OwnershipHeadDigest: s.public.Head().ReplayDigest, RecoveryFunding: &fightercarrier.RecoveryFunding{CommitRaw: c.Raw, CommitTxID: c.TxID, CommitBlockHash: c.BlockHash, CommitHeight: int32(c.Height), CommitPosition: c.TransactionIndex, FundingDigest: v.FundingDigest, TransferID: v.TransferID, FundingPublicKey: hex.EncodeToString(i.FundingKey[:]), FundingBranch: s.match.FundingBranch, FundingIndex: s.match.FundingIndex, ReturnPath: fightercarrier.ReturnPath{Address: r.ReturnAddress, Script: r.ReturnScript, Branch: r.ReturnBranch, Index: r.ReturnIndex}, GymAuthorization: hex.EncodeToString(env.Signature[:])}, Review: r, ReviewDigest: d}
			if e = o.validateRecoveryPaths(work, tx, p); e != nil {
				return e
			}
			return lease.err(work)
		})
	}()
	if e != nil {
		return nil, e
	}
	if e = s.public.Check(work); e != nil {
		return nil, e
	}
	e = hostedWalletWrite(work, o.wallet, func() { o.poisoned.Store(true) }, func(tx walletdb.ReadWriteTx) error {
		if e := o.validateRecoveryPaths(work, tx, p); e != nil {
			return e
		}
		if e := o.auditExclusions(work, tx); e != nil {
			return e
		}
		return o.commitPreparation(work, tx, p)
	})
	if e != nil {
		return nil, e
	}
	if e = s.public.Check(work); e != nil {
		return nil, e
	}
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	d, e := fightercarrier.PreparationDigest(p)
	if e != nil {
		return nil, e
	}
	return &PreparedFighterTransfer{owner: o, preparation: p, digest: d, recovery: s.public}, nil
}

func (o *FighterCarrierOwner) ResumeRecoveryPrepared(ctx context.Context, id string, public *fighterownership.PreparedRecovery) (*PreparedFighterTransfer, error) {
	if o == nil || !withdrawalHex(id, 32, true) || public == nil {
		return nil, fightercarrier.ErrInvalid
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return nil, e
	}
	var p fightercarrier.Preparation
	e = func() error {
		if e := o.authorize(work); e != nil {
			return e
		}
		if e := public.Check(work); e != nil {
			return e
		}
		return walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
			state, e := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
			if e != nil {
				return e
			}
			for _, r := range state.records {
				if r.RequestID == id {
					if r.State != "prepared" {
						return fightercarrier.ErrConflict
					}
					p = cloneCarrierPreparation(r.Preparation)
					if e = o.recoveryMatches(p.Request, public); e != nil {
						return e
					}
					if p.RecoveryFunding == nil || p.RecoveryFunding.CommitRaw != hex.EncodeToString(public.CommitRaw()) {
						return fightercarrier.ErrConflict
					}
					if e = o.auditExclusions(work, tx); e != nil {
						return e
					}
					return o.validateRecoveryPaths(work, tx, p)
				}
			}
			return fightercarrier.ErrNotFound
		})
	}()
	end()
	if e != nil {
		return nil, e
	}
	d, e := fightercarrier.PreparationDigest(p)
	if e != nil {
		return nil, e
	}
	result := &PreparedFighterTransfer{owner: o, preparation: p, digest: d, recovery: public}
	if e = result.Check(ctx); e != nil {
		return nil, e
	}
	return result, nil
}
