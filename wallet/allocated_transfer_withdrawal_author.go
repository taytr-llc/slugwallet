// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (s *AllocatedWithdrawals2) planDraft(ctx context.Context, tx walletdb.ReadTx, request CandidateWithdrawalRequest, r waddrmgr.HostedAllocationRange) (CandidateWithdrawalDraft, error) {
	if e := s.live(); e != nil {
		return CandidateWithdrawalDraft{}, e
	}
	state, e := s.base.audit(ctx, tx)
	if e != nil {
		return CandidateWithdrawalDraft{}, e
	}
	if _, ok := state.records[request.OperationID]; ok {
		return CandidateWithdrawalDraft{}, ErrWithdrawalConflict
	}
	if state.meta.ActiveOperationID != "" {
		return CandidateWithdrawalDraft{}, ErrWithdrawalBusy
	}
	if state.meta.RecordCount >= 128 {
		return CandidateWithdrawalDraft{}, ErrWithdrawalCapacity
	}
	recipient, e := validateWithdrawalRequest(request)
	if e != nil {
		return CandidateWithdrawalDraft{}, e
	}
	return s.base.candidateWithdrawalDraft(ctx, tx, request, recipient, func() (CandidateWithdrawalChange, []byte, error) {
		if r.Purpose != 84 || r.Branch != 1 || r.SelectedIndex >= 4096 {
			return CandidateWithdrawalChange{}, nil, ErrAllocationConflict
		}
		script, e := hex.DecodeString(r.Script)
		if e != nil {
			return CandidateWithdrawalChange{}, nil, ErrAllocationCorrupt
		}
		return CandidateWithdrawalChange{Address: r.Address, Script: r.Script, Index: r.SelectedIndex, OutputIndex: -1}, script, nil
	})
}
func (s *AllocatedWithdrawals2) validatePlanned(ctx context.Context, tx walletdb.ReadTx, p *AllocationPlan2) error {
	if e := s.live(); e != nil {
		return e
	}
	if p == nil || p.owner != s.owner || p.withdrawal != s || p.draft == nil {
		return ErrAllocationConflict
	}
	d := p.draft
	if _, e := CandidateWithdrawalDraftDigest(*d); e != nil {
		return ErrWithdrawalCorrupt
	}
	if d.BindingID != s.base.binding || d.OperationID != p.request.ConsumerID || d.Recipient != p.request.Recipient || d.RecipientScript != p.request.RecipientScript || d.AmountAtoms != p.request.AmountAtoms || d.Change.Address != p.candidate.Address || d.Change.Script != p.candidate.Script || d.Change.Index != p.candidate.SelectedIndex {
		return ErrAllocationConflict
	}
	state, e := s.base.audit(ctx, tx)
	if e != nil {
		return e
	}
	if state.meta.ActiveOperationID != "" {
		return ErrWithdrawalBusy
	}
	if state.meta.RecordCount >= 128 {
		return ErrWithdrawalCapacity
	}
	if _, ok := state.records[d.OperationID]; ok {
		return ErrWithdrawalConflict
	}
	if !s.owner.wallet.ChainSynced() {
		return ErrWithdrawalUnavailable
	}
	tip := s.owner.manager.SyncedTo()
	if tip.Height != d.TipHeight || tip.Hash.String() != d.TipHash {
		return ErrWithdrawalUnavailable
	}
	reader, e := s.owner.wallet.TxStore.NewCandidateCreditReader(tx.ReadBucket(wtxmgrNamespaceKey))
	if e != nil {
		return withdrawalCreditError(e)
	}
	b := s.owner.inventory.binding
	_, shared, e := readPurposeExclusions(ctx, tx, 14, b.CarrierJournalID, b.WithdrawalJournalID)
	if e != nil {
		return e
	}
	for _, in := range d.Inputs {
		if e := ctx.Err(); e != nil {
			return e
		}
		op, e := withdrawalOutpoint(in)
		if e != nil {
			return e
		}
		if _, exists := shared[string(withdrawalKey(op))]; exists {
			return ErrWithdrawalConflict
		}
		c, ok, e := reader.Lookup(ctx, op)
		if e != nil {
			return withdrawalCreditError(e)
		}
		if !ok || s.owner.wallet.LockedOutpoint(op) || c.Height > tip.Height || !hasMinConfs(1, c.Height, tip.Height) || c.FromCoinBase && !hasMinConfs(int32(s.owner.wallet.chainParams.CoinbaseMaturity), c.Height, tip.Height) || c.Amount != btcutil.Amount(in.Atoms) || hex.EncodeToString(c.PkScript) != in.Script || c.Height != in.BlockHeight || c.BlockMeta.Hash.String() != in.BlockHash || c.FromCoinBase != in.Coinbase {
			return ErrWithdrawalUnavailable
		}
		reserved, e := candidateWithdrawalReserved(tx, op)
		if e != nil {
			return e
		}
		if reserved {
			return ErrWithdrawalConflict
		}
		branch, index, e := s.base.path(tx, c.PkScript)
		if e != nil || branch != in.Branch || index != in.Index {
			return ErrWithdrawalCorrupt
		}
	}
	if !s.owner.wallet.ChainSynced() || s.owner.manager.SyncedTo() != tip {
		return ErrWithdrawalUnavailable
	}
	return nil
}

// writePlanned is called only after manager Consume, within that same walletdb
// transaction. No cursor, local link, draft or input exclusion can commit alone.
func (s *AllocatedWithdrawals2) writePlanned(ctx context.Context, tx walletdb.ReadWriteTx, p *AllocationPlan2) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if p == nil || p.withdrawal != s || p.draft == nil {
		return ErrAllocationConflict
	}
	d := cloneAllocatedDraft(*p.draft)
	if e := s.base.ownedDraft(tx, d); e != nil {
		return e
	}
	digest, e := CandidateWithdrawalDraftDigest(d)
	if e != nil {
		return e
	}
	ns := tx.ReadWriteBucket(withdrawalNamespace)
	if ns == nil {
		return ErrWithdrawalCorrupt
	}
	var meta withdrawalMeta
	if e = withdrawalDecode(ns.Get(withdrawalMetaKey), 2048, &meta); e != nil {
		return e
	}
	if meta.ActiveOperationID != "" || meta.RecordCount >= 128 || meta.BindingID != s.base.binding {
		return ErrWithdrawalConflict
	}
	record := CandidateWithdrawalRecord{Version: 1, State: "prepared", DraftDigest: digest, Draft: d}
	raw, e := json.Marshal(record)
	if e != nil || len(raw) > 32768 {
		return ErrWithdrawalCapacity
	}
	key, _ := hex.DecodeString(d.OperationID)
	operations := ns.NestedReadWriteBucket(withdrawalOperations)
	prepared := ns.NestedReadWriteBucket(withdrawalPrepared)
	if operations == nil || prepared == nil || operations.Get(key) != nil {
		return ErrWithdrawalCorrupt
	}
	if e = operations.Put(key, raw); e != nil {
		return ErrWithdrawalStorage
	}
	for _, in := range d.Inputs {
		op, _ := withdrawalOutpoint(in)
		if e = prepared.Put(withdrawalKey(op), key); e != nil {
			return ErrWithdrawalStorage
		}
	}
	meta.RecordCount++
	meta.ActiveOperationID = d.OperationID
	raw, _ = json.Marshal(meta)
	if e = ns.Put(withdrawalMetaKey, raw); e != nil {
		return ErrWithdrawalStorage
	}
	b := s.owner.inventory.binding
	ops := make([]wire.OutPoint, 0, len(d.Inputs))
	for _, in := range d.Inputs {
		op, err := withdrawalOutpoint(in)
		if err != nil {
			return err
		}
		ops = append(ops, op)
	}
	return putPurposeExclusions(ctx, tx, 14, b.CarrierJournalID, b.WithdrawalJournalID, purposeExclusion{Version: 1, OwnerKind: "withdrawal", RequestID: d.OperationID, BindingID: s.base.binding, PreparationDigest: digest, State: "prepared"}, ops)
}
