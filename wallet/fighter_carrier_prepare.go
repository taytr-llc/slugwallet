// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func (o *FighterCarrierOwner) carrierIDs() (string, string) {
	w := ""
	if o.allocated != nil {
		w = o.allocated.inventory.binding.WithdrawalJournalID
	}
	return o.journal.Identity().JournalID, w
}
func (o *FighterCarrierOwner) validatePreparedInputs(ctx context.Context, tx walletdb.ReadTx, p fightercarrier.Preparation) error {
	if p.NewFunding == nil {
		return o.validateRecoveryPaths(ctx, tx, p)
	}
	return o.validateCarrierInputs(ctx, tx, p.NewFunding.Inputs, p.Request.RequestID, p.Review.InputDetailsDigest)
}
func (o *FighterCarrierOwner) validateCarrierInputs(ctx context.Context, tx walletdb.ReadTx, inputs []fightercarrier.OwnedInput, ownID, digest string) error {
	if len(inputs) < 1 || len(inputs) > 16 || !o.wallet.ChainSynced() {
		return fightercarrier.ErrConflict
	}
	tip := o.manager.SyncedTo()
	j, w := o.carrierIDs()
	_, exclusions, e := readPurposeExclusions(ctx, tx, o.pin.ManagerSchema, j, w)
	if e != nil {
		return e
	}
	reader, e := o.wallet.TxStore.NewCandidateCreditReader(tx.ReadBucket(wtxmgrNamespaceKey))
	if e != nil {
		return withdrawalCreditError(e)
	}
	paths := CandidateWithdrawals{wallet: o.wallet}
	for _, in := range inputs {
		if e = ctx.Err(); e != nil {
			return e
		}
		op, e := carrierOutpoint(in.TxID, in.OutputIndex)
		if e != nil {
			return e
		}
		c, ok, e := reader.Lookup(ctx, op)
		if e != nil {
			return withdrawalCreditError(e)
		}
		if !ok || o.wallet.LockedOutpoint(op) || c.Height > tip.Height || !hasMinConfs(1, c.Height, tip.Height) || c.FromCoinBase && !hasMinConfs(int32(o.wallet.chainParams.CoinbaseMaturity), c.Height, tip.Height) || int64(c.Amount) != in.Atoms || hex.EncodeToString(c.PkScript) != in.Script || c.BlockMeta.Hash.String() != in.BlockHash || c.Height != in.BlockHeight || c.FromCoinBase != in.Coinbase {
			return fightercarrier.ErrConflict
		}
		branch, index, e := paths.path(tx, c.PkScript)
		if e != nil || branch != in.Branch || index != in.Index {
			return fightercarrier.ErrCorrupt
		}
		if row, ok := exclusions[string(withdrawalKey(op))]; ok {
			if ownID == "" || row.OwnerKind != "carrier" || row.RequestID != ownID || row.BindingID != o.binding || row.State != "prepared" {
				return fightercarrier.ErrConflict
			}
		}
	}
	return ctx.Err()
}

// PlanFunding performs only bounded public selection. It does not allocate,
// reserve, sign, or disclose an actionable prepared transaction.
func (o *FighterCarrierOwner) PlanFunding(ctx context.Context, request CarrierRequest) (*CarrierFundingPlan, error) {
	if e := fightercarrier.ValidateRequest(request); e != nil {
		return nil, e
	}
	if o == nil || request.Kind != "transfer" || request.OwnershipPinID != o.pin.OwnershipPinID || request.RecipientGym == o.pin.GymPublicKey {
		return nil, fightercarrier.ErrInvalid
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
	f := &preparedCarrierFunding{owner: o, request: request}
	e = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
		if e != nil {
			return e
		}
		if state.meta.ActiveRequestID != "" {
			return fightercarrier.ErrBusy
		}
		if state.meta.RecordCount >= 128 {
			return fightercarrier.ErrCapacity
		}
		for _, r := range state.records {
			if r.RequestID == request.RequestID {
				return fightercarrier.ErrConflict
			}
		}
		if e = o.auditExclusions(work, tx); e != nil {
			return e
		}
		if !o.wallet.ChainSynced() {
			return fightercarrier.ErrConflict
		}
		tip := o.manager.SyncedTo()
		if tip.Height < 0 {
			return fightercarrier.ErrConflict
		}
		f.tipHash = tip.Hash.String()
		f.tipHeight = tip.Height
		j, w := o.carrierIDs()
		_, excluded, e := readPurposeExclusions(work, tx, o.pin.ManagerSchema, j, w)
		if e != nil {
			return e
		}
		reader, e := o.wallet.TxStore.NewCandidateCreditReader(tx.ReadBucket(wtxmgrNamespaceKey))
		if e != nil {
			return withdrawalCreditError(e)
		}
		paths := CandidateWithdrawals{wallet: o.wallet}
		best := make([]withdrawalSelection, 0, 16)
		e = reader.Visit(work, func(c wtxmgr.Credit) error {
			if c.Height > tip.Height || !hasMinConfs(1, c.Height, tip.Height) || c.FromCoinBase && !hasMinConfs(int32(o.wallet.chainParams.CoinbaseMaturity), c.Height, tip.Height) || o.wallet.LockedOutpoint(c.OutPoint) {
				return nil
			}
			if _, ok := excluded[string(withdrawalKey(c.OutPoint))]; ok {
				return nil
			}
			branch, index, e := paths.path(tx, c.PkScript)
			if errors.Is(e, ErrWithdrawalUnavailable) {
				return nil
			}
			if e != nil {
				return e
			}
			best = append(best, withdrawalSelection{credit: c, input: CandidateWithdrawalInput{TxID: c.Hash.String(), OutputIndex: c.OutPoint.Index, Atoms: int64(c.Amount), Script: hex.EncodeToString(c.PkScript), Branch: branch, Index: index, BlockHash: c.BlockMeta.Hash.String(), BlockHeight: c.Height, Coinbase: c.FromCoinBase}})
			sort.Slice(best, func(i, j int) bool { return withdrawalSelectionLess(best[i], best[j]) })
			if len(best) > 16 {
				best = best[:16]
			}
			return nil
		})
		if e != nil {
			return withdrawalCreditError(e)
		}
		for _, x := range best {
			in := x.input
			if in.Atoms <= 0 || in.Atoms > fightercarrier.MaxMoney-f.total {
				return fightercarrier.ErrCorrupt
			}
			f.total += in.Atoms
			f.inputs = append(f.inputs, fightercarrier.OwnedInput{TxID: in.TxID, OutputIndex: in.OutputIndex, Atoms: in.Atoms, Script: in.Script, Branch: in.Branch, Index: in.Index, BlockHash: in.BlockHash, BlockHeight: in.BlockHeight, Coinbase: in.Coinbase})
			if f.total >= 511000 {
				break
			}
		}
		if f.total < 511000 {
			return fightercarrier.ErrCapacity
		}
		sort.Slice(f.inputs, func(i, j int) bool {
			a, _ := carrierOutpoint(f.inputs[i].TxID, f.inputs[i].OutputIndex)
			b, _ := carrierOutpoint(f.inputs[j].TxID, f.inputs[j].OutputIndex)
			return bytes.Compare(withdrawalKey(a), withdrawalKey(b)) < 0
		})
		return work.Err()
	})
	if e != nil {
		return nil, e
	}
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	return &CarrierFundingPlan{f}, nil
}

func (f *preparedCarrierFunding) intent() (fighterownership.TransferIntent, error) {
	if f == nil || f.owner == nil || f.public == nil {
		return fighterownership.TransferIntent{}, fightercarrier.ErrInvalid
	}
	v := f.public.Intent()
	if v.PinID != f.owner.pin.OwnershipPinID || v.PriorStateID != f.request.PriorStateID || v.FromGym != f.owner.pin.GymPublicKey || v.Recipient != f.request.RecipientGym || len(v.Funding) != len(f.inputs) {
		return v, fightercarrier.ErrConflict
	}
	for i, x := range f.inputs {
		if v.Funding[i].TxID != x.TxID || v.Funding[i].Index != x.OutputIndex {
			return v, fightercarrier.ErrConflict
		}
	}
	return v, nil
}
func (f *preparedCarrierFunding) request2() (AllocationRequest2, error) {
	v, e := f.intent()
	if e != nil {
		return AllocationRequest2{}, e
	}
	return AllocationRequest2{Version: 2, Kind: "carrier_return", ConsumerID: f.request.RequestID, Purpose: 84, Branch: 1, MinConfirmations: 1, InputPurpose: 84, ChangePurpose: 84, TxVersion: 1, InputSequence: wire.MaxTxInSequenceNum, SighashType: 1, CarrierBindingID: f.owner.binding, OwnershipPinID: f.owner.pin.OwnershipPinID, PriorStateID: f.request.PriorStateID, RecipientGym: f.request.RecipientGym, FundingDigest: v.FundingDigest, EscrowAtoms: 500000, CommitFeeAtoms: 10000, SpendFeeAtoms: 10000, MinChangeAtoms: 1000}, nil
}
func (f *preparedCarrierFunding) validatePlannedCarrier(ctx context.Context, a *HostedAllocator2, request AllocationRequest2) error {
	if f == nil || f.owner == nil || f.owner.allocated != a || a == nil || f.owner.wallet != a.wallet {
		return fightercarrier.ErrInvalid
	}
	want, e := f.request2()
	if e != nil || want != request {
		return fightercarrier.ErrConflict
	}
	if e = f.public.Check(ctx); e != nil {
		return e
	}
	if e = f.owner.authorize(ctx); e != nil {
		return e
	}
	return walletdb.View(a.wallet.db, func(tx walletdb.ReadTx) error { return f.owner.validateCarrierInputs(ctx, tx, f.inputs, "", "") })
}
func (f *preparedCarrierFunding) buildCarrierPreparation(ctx context.Context, tx walletdb.ReadTx, r allocationReservationValue2) (fightercarrier.Preparation, string, error) {
	var none fightercarrier.Preparation
	want, e := f.request2()
	if e != nil || want != r.Request || r.AllocationID != f.request.RequestID {
		return none, "", fightercarrier.ErrConflict
	}
	if e = f.owner.validateCarrierInputs(ctx, tx, f.inputs, "", ""); e != nil {
		return none, "", e
	}
	digest, e := allocationHash("SLUG hosted allocation reservation\x00v2\x00", r)
	if e != nil {
		return none, "", e
	}
	p, e := f.preparation(fightercarrier.ReturnPath{Address: r.Address, Script: r.Script, Branch: 1, Index: r.SelectedIndex}, digest, nil)
	if e != nil {
		return none, "", e
	}
	hash, e := fightercarrier.PreparationDigest(p)
	return p, hash, e
}
func (f *preparedCarrierFunding) preparation(path fightercarrier.ReturnPath, reservation string, allocation *fightercarrier.RestoredAllocation) (fightercarrier.Preparation, error) {
	v, e := f.intent()
	if e != nil {
		return fightercarrier.Preparation{}, e
	}
	raw, _ := json.Marshal(f.inputs)
	details := carrierDomain("SLUG fighter carrier owned inputs", raw)
	review := fightercarrier.Review{Version: 1, RequestID: f.request.RequestID, Kind: "transfer", BindingID: f.owner.binding, OwnershipPinID: f.request.OwnershipPinID, PriorStateID: f.request.PriorStateID, SenderGym: f.owner.pin.GymPublicKey, RecipientGym: f.request.RecipientGym, TransferID: v.TransferID, FundingDigest: v.FundingDigest, InputDetailsDigest: details, InputCount: uint32(len(f.inputs)), TotalInputAtoms: f.total, ReturnAddress: path.Address, ReturnScript: path.Script, ReturnBranch: path.Branch, ReturnIndex: path.Index, CommitChangeAtoms: f.total - 510000, EscrowAtoms: 500000, CommitFeeAtoms: 10000, SpendFeeAtoms: 10000, TotalFeeAtoms: 20000, ReturnedAtoms: 490000}
	d, e := fightercarrier.ReviewDigest(review)
	if e != nil {
		return fightercarrier.Preparation{}, e
	}
	tip := f.owner.manager.SyncedTo()
	p := fightercarrier.Preparation{Version: 1, BindingID: f.owner.binding, Request: f.request, PreparedAtMS: time.Now().UnixMilli(), TipHash: tip.Hash.String(), TipHeight: tip.Height, OwnershipHeadDigest: f.public.Head().ReplayDigest, NewFunding: &fightercarrier.NewFunding{Inputs: append([]fightercarrier.OwnedInput(nil), f.inputs...), TotalInputAtoms: f.total, FundingDigest: v.FundingDigest, AllocationID: f.request.RequestID, ReservationDigest: reservation, ReturnPath: path, CommitChangeAtoms: f.total - 510000}, RestoredAllocation: allocation, Review: review, ReviewDigest: d}
	if e = fightercarrier.ValidatePreparation(p, f.owner.pin, f.owner.binding); e != nil {
		return fightercarrier.Preparation{}, e
	}
	return p, nil
}
func carrierDomain(domain string, raw []byte) string {
	return carrierSHA(append(append([]byte(domain), 0, 'v', '1', 0), raw...))
}
func (f *preparedCarrierFunding) commitPreparedCarrier(ctx context.Context, tx walletdb.ReadWriteTx, p fightercarrier.Preparation) error {
	if f == nil || f.owner == nil || p.Request != f.request {
		return fightercarrier.ErrInvalid
	}
	return f.owner.commitPreparation(ctx, tx, p)
}
func (o *FighterCarrierOwner) commitPreparation(ctx context.Context, tx walletdb.ReadWriteTx, p fightercarrier.Preparation) error {
	if e := fightercarrier.ValidatePreparation(p, o.pin, o.binding); e != nil {
		return e
	}
	j, w := o.carrierIDs()
	state, e := readCarrierWalletState(ctx, tx, j, &o.pin)
	if e != nil {
		return e
	}
	if state.meta.ActiveRequestID != "" {
		return fightercarrier.ErrBusy
	}
	if state.meta.RecordCount >= 128 {
		return fightercarrier.ErrCapacity
	}
	for _, old := range state.records {
		if old.RequestID == p.Request.RequestID {
			return fightercarrier.ErrConflict
		}
	}
	d, e := fightercarrier.PreparationDigest(p)
	if e != nil {
		return e
	}
	r := fightercarrier.WalletRecord{Version: 1, Sequence: state.meta.RecordCount + 1, RequestID: p.Request.RequestID, BindingID: o.binding, State: "prepared", Preparation: p, PreparationDigest: d}
	raw, e := json.Marshal(r)
	if e != nil || len(raw)+256 > fightercarrier.MaxWalletRecordBytes || state.bytes+uint64(len(raw))+512 > 4194304 {
		return fightercarrier.ErrCapacity
	}
	inputs := make([]wire.OutPoint, 0, 17)
	if p.NewFunding != nil {
		for _, in := range p.NewFunding.Inputs {
			op, e := carrierOutpoint(in.TxID, in.OutputIndex)
			if e != nil {
				return e
			}
			inputs = append(inputs, op)
		}
	} else if p.RecoveryFunding != nil {
		op, e := carrierOutpoint(p.RecoveryFunding.CommitTxID, 0)
		if e != nil {
			return e
		}
		inputs = append(inputs, op)
	}
	if e = putPurposeExclusions(ctx, tx, o.pin.ManagerSchema, j, w, purposeExclusion{1, "carrier", p.Request.RequestID, o.binding, d, "prepared"}, inputs); e != nil {
		return e
	}
	ns := tx.ReadWriteBucket(carrierWalletNamespace)
	key, _ := hex.DecodeString(p.Request.RequestID)
	if e = ns.NestedReadWriteBucket(carrierRecordsKey).Put(key, raw); e != nil {
		return e
	}
	state.meta.RecordCount++
	state.meta.ActiveRequestID = p.Request.RequestID
	raw, _ = json.Marshal(state.meta)
	return ns.Put(carrierMetaKey, raw)
}
