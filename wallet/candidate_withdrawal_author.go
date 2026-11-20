// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/btcutil/v2/txsort"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/wallet/txauthor"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func withdrawalCreditError(e error) error {
	if errors.Is(e, wtxmgr.ErrCandidateCreditCapacity) {
		return ErrWithdrawalCapacity
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	if e != nil {
		return ErrWithdrawalCorrupt
	}
	return nil
}
func (s *CandidateWithdrawals) path(tx walletdb.ReadTx, script []byte) (uint32, uint32, error) {
	if len(script) != 22 || script[0] != 0 || script[1] != 20 {
		return 0, 0, ErrWithdrawalUnavailable
	}
	a, e := address.NewAddressWitnessPubKeyHash(script[2:], s.wallet.chainParams)
	if e != nil {
		return 0, 0, ErrWithdrawalCorrupt
	}
	ma, e := s.wallet.Manager.Address(tx.ReadBucket(waddrmgrNamespaceKey), a)
	if e != nil {
		return 0, 0, ErrWithdrawalCorrupt
	}
	p, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok || !p.Compressed() {
		return 0, 0, ErrWithdrawalCorrupt
	}
	scope, path, known := p.DerivationInfo()
	if !known || scope != waddrmgr.KeyScopeBIP0084 || path.InternalAccount != 0 || path.Account != hdkeychain.HardenedKeyStart || path.Branch > 1 || path.Index >= 4096 {
		return 0, 0, ErrWithdrawalUnavailable
	}
	if !bytes.Equal(address.Hash160(p.PubKey().SerializeCompressed()), script[2:]) {
		return 0, 0, ErrWithdrawalCorrupt
	}
	return path.Branch, path.Index, nil
}
func (s *CandidateWithdrawals) ownedDraft(tx walletdb.ReadTx, d CandidateWithdrawalDraft) error {
	for _, in := range d.Inputs {
		script, e := hex.DecodeString(in.Script)
		if e != nil {
			return ErrWithdrawalCorrupt
		}
		branch, index, e := s.path(tx, script)
		if e != nil || branch != in.Branch || index != in.Index {
			return ErrWithdrawalCorrupt
		}
	}
	script, e := hex.DecodeString(d.Change.Script)
	if e != nil {
		return ErrWithdrawalCorrupt
	}
	branch, index, e := s.path(tx, script)
	if e != nil || branch != 1 || index != d.Change.Index {
		return ErrWithdrawalCorrupt
	}
	return nil
}

type withdrawalSelection struct {
	credit wtxmgr.Credit
	input  CandidateWithdrawalInput
}

func withdrawalSelectionLess(a, b withdrawalSelection) bool {
	if a.credit.Amount != b.credit.Amount {
		return a.credit.Amount > b.credit.Amount
	}
	if a.input.TxID != b.input.TxID {
		return a.input.TxID < b.input.TxID
	}
	return a.input.OutputIndex < b.input.OutputIndex
}
func (s *CandidateWithdrawals) Prepare(ctx context.Context, request CandidateWithdrawalRequest) (CandidateWithdrawalDraft, error) {
	var empty CandidateWithdrawalDraft
	recipient, e := validateWithdrawalRequest(request)
	if e != nil {
		return empty, e
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return empty, e
	}
	defer done()
	if !s.wallet.newAddrMtx.TryLock() {
		return empty, ErrWithdrawalBusy
	}
	defer s.wallet.newAddrMtx.Unlock()
	var result CandidateWithdrawalDraft
	e = s.write(ctx, func(dbtx walletdb.ReadWriteTx) error {
		state, e := s.audit(ctx, dbtx)
		if e != nil {
			return e
		}
		if r, ok := state.records[request.OperationID]; ok {
			if r.State != "prepared" || r.Draft.Recipient != request.Recipient || r.Draft.AmountAtoms != request.AmountAtoms {
				return ErrWithdrawalConflict
			}
			result = r.Draft
			return nil
		}
		if state.meta.ActiveOperationID != "" {
			return ErrWithdrawalBusy
		}
		if state.meta.RecordCount >= 128 {
			return ErrWithdrawalCapacity
		}
		d, e := s.candidateWithdrawalDraft(ctx, dbtx, request, recipient, func() (CandidateWithdrawalChange, []byte, error) {
			manager, e := s.wallet.Manager.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
			if e != nil {
				return CandidateWithdrawalChange{}, nil, ErrWithdrawalCorrupt
			}
			addrs, e := manager.NextInternalAddresses(dbtx.ReadWriteBucket(waddrmgrNamespaceKey), 0, 1)
			if e != nil {
				return CandidateWithdrawalChange{}, nil, ErrWithdrawalCapacity
			}
			p, ok := addrs[0].(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return CandidateWithdrawalChange{}, nil, ErrWithdrawalCorrupt
			}
			scope, path, known := p.DerivationInfo()
			if !known || scope != waddrmgr.KeyScopeBIP0084 || path.Branch != 1 || path.Index >= 4096 {
				return CandidateWithdrawalChange{}, nil, ErrWithdrawalCapacity
			}
			script, e := txscript.PayToAddrScript(p.Address())
			if e != nil || len(script) != 22 {
				return CandidateWithdrawalChange{}, nil, ErrWithdrawalCorrupt
			}
			change := CandidateWithdrawalChange{Address: p.Address().EncodeAddress(), Script: hex.EncodeToString(script), Index: path.Index, OutputIndex: -1}
			return change, script, nil
		})
		if e != nil {
			return e
		}
		digest, e := CandidateWithdrawalDraftDigest(d)
		if e != nil {
			return ErrWithdrawalCorrupt
		}
		record := CandidateWithdrawalRecord{Version: 1, State: "prepared", DraftDigest: digest, Draft: d}
		encoded, e := json.Marshal(record)
		if e != nil || len(encoded) > 32768 {
			return ErrWithdrawalCapacity
		}
		ns := dbtx.ReadWriteBucket(withdrawalNamespace)
		key, _ := hex.DecodeString(request.OperationID)
		if e := ns.NestedReadWriteBucket(withdrawalOperations).Put(key, encoded); e != nil {
			return ErrWithdrawalStorage
		}
		for _, in := range d.Inputs {
			op, _ := withdrawalOutpoint(in)
			if e := ns.NestedReadWriteBucket(withdrawalPrepared).Put(withdrawalKey(op), key); e != nil {
				return ErrWithdrawalStorage
			}
		}
		state.meta.RecordCount++
		state.meta.ActiveOperationID = request.OperationID
		encoded, _ = json.Marshal(state.meta)
		if e := ns.Put(withdrawalMetaKey, encoded); e != nil {
			return ErrWithdrawalStorage
		}
		result = d
		return nil
	})
	if e != nil {
		return empty, e
	}
	return result, nil
}

// candidateWithdrawalDraft factors bounded selection/authoring without owning
// a transaction or publishing a draft. Legacy Prepare supplies its original
// transactional allocator; the hosted path supplies an already planned script.
func (s *CandidateWithdrawals) candidateWithdrawalDraft(ctx context.Context, dbtx walletdb.ReadTx, request CandidateWithdrawalRequest, recipient []byte, changeScript func() (CandidateWithdrawalChange, []byte, error)) (CandidateWithdrawalDraft, error) {
	if !s.wallet.ChainSynced() {
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	tip := s.wallet.Manager.SyncedTo()
	if tip.Height < 0 || !withdrawalHex(tip.Hash.String(), 32, true) {
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	reader, e := s.wallet.TxStore.NewCandidateCreditReader(dbtx.ReadBucket(wtxmgrNamespaceKey))
	if e != nil {
		return CandidateWithdrawalDraft{}, withdrawalCreditError(e)
	}
	best := make([]withdrawalSelection, 0, 16)
	e = reader.Visit(ctx, func(c wtxmgr.Credit) error {
		if c.Height > tip.Height || !hasMinConfs(1, c.Height, tip.Height) || c.FromCoinBase && !hasMinConfs(int32(s.wallet.chainParams.CoinbaseMaturity), c.Height, tip.Height) || s.wallet.LockedOutpoint(c.OutPoint) {
			return nil
		}
		reserved, e := candidateWithdrawalReserved(dbtx, c.OutPoint)
		if e != nil {
			return e
		}
		if reserved {
			return nil
		}
		branch, index, e := s.path(dbtx, c.PkScript)
		if errors.Is(e, ErrWithdrawalUnavailable) {
			return nil
		}
		if e != nil {
			return e
		}
		next := withdrawalSelection{c, CandidateWithdrawalInput{c.Hash.String(), c.OutPoint.Index, int64(c.Amount), hex.EncodeToString(c.PkScript), branch, index, c.BlockMeta.Hash.String(), c.Height, c.FromCoinBase}}
		best = append(best, next)
		sort.Slice(best, func(i, j int) bool { return withdrawalSelectionLess(best[i], best[j]) })
		if len(best) > 16 {
			best = best[:16]
		}
		return nil
	})
	if e != nil {
		if errors.Is(e, ErrWithdrawalCorrupt) || errors.Is(e, ErrWithdrawalUnavailable) {
			return CandidateWithdrawalDraft{}, e
		}
		return CandidateWithdrawalDraft{}, withdrawalCreditError(e)
	}
	if len(best) == 0 {
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	coins := make([]Coin, len(best))
	lookup := make(map[wire.OutPoint]CandidateWithdrawalInput, len(best))
	var available int64
	for i, x := range best {
		if int64(x.credit.Amount) > int64(btcutil.MaxSatoshi)-available {
			return CandidateWithdrawalDraft{}, ErrWithdrawalCorrupt
		}
		available += int64(x.credit.Amount)
		coins[i] = Coin{TxOut: wire.TxOut{Value: int64(x.credit.Amount), PkScript: x.credit.PkScript}, OutPoint: x.credit.OutPoint}
		lookup[x.credit.OutPoint] = x.input
	}
	var change CandidateWithdrawalChange
	source := &txauthor.ChangeSource{ScriptSize: 22, NewScript: func() ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		var script []byte
		var e error
		change, script, e = changeScript()
		return script, e
	}}

	authored, e := txauthor.NewUnsignedTransaction([]*wire.TxOut{wire.NewTxOut(request.AmountAtoms, recipient)}, 1000, makeInputSource(coins), source)
	if e != nil {
		if ctx.Err() != nil {
			return CandidateWithdrawalDraft{}, ctx.Err()
		}
		if errors.Is(e, ErrWithdrawalCapacity) || errors.Is(e, ErrWithdrawalCorrupt) {
			return CandidateWithdrawalDraft{}, e
		}
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	txsort.InPlaceSort(authored.Tx)
	d := CandidateWithdrawalDraft{Version: 1, BindingID: s.binding, OperationID: request.OperationID, Recipient: request.Recipient, RecipientScript: hex.EncodeToString(recipient), AmountAtoms: request.AmountAtoms, FeeRateAtomsPerKB: 1000, FeeCeilingAtoms: 100000, MinConfirmations: 1, TipHash: tip.Hash.String(), TipHeight: tip.Height, TxVersion: 1, InputSequence: wire.MaxTxInSequenceNum, LockTime: 0, SighashType: 1, Change: change}
	d.Inputs = make([]CandidateWithdrawalInput, len(authored.Tx.TxIn))
	for i, in := range authored.Tx.TxIn {
		x, ok := lookup[in.PreviousOutPoint]
		if !ok {
			return CandidateWithdrawalDraft{}, ErrWithdrawalCorrupt
		}
		d.Inputs[i] = x
		d.TotalInputAtoms += x.Atoms
	}
	role := -1
	var sum int64
	for i, out := range authored.Tx.TxOut {
		sum += out.Value
		if role < 0 && out.Value == request.AmountAtoms && bytes.Equal(out.PkScript, recipient) {
			role = i
		}
	}
	if role < 0 {
		return CandidateWithdrawalDraft{}, ErrWithdrawalCorrupt
	}
	d.RecipientOutputIndex = uint32(role)
	if len(authored.Tx.TxOut) == 2 {
		other := 1 - role
		d.Change.OutputIndex = int32(other)
		d.Change.Atoms = authored.Tx.TxOut[other].Value
	}
	d.FeeAtoms = d.TotalInputAtoms - sum
	if d.FeeAtoms > 100000 {
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	var raw bytes.Buffer
	if authored.Tx.SerializeNoWitness(&raw) != nil {
		return CandidateWithdrawalDraft{}, ErrWithdrawalCorrupt
	}
	d.UnsignedTxHex = hex.EncodeToString(raw.Bytes())
	_, e = CandidateWithdrawalDraftDigest(d)
	if e != nil {
		return CandidateWithdrawalDraft{}, ErrWithdrawalCorrupt
	}
	if !s.wallet.ChainSynced() || s.wallet.Manager.SyncedTo() != tip {
		return CandidateWithdrawalDraft{}, ErrWithdrawalUnavailable
	}
	return d, nil
}

// Sign returns scratch only, after the trusted caller has performed its native
// review and original Withdrawal precheck. It neither authorizes nor publishes.
func (s *CandidateWithdrawals) Sign(ctx context.Context, operationID, draftDigest string) (CandidateWithdrawalSigned, error) {
	var empty CandidateWithdrawalSigned
	if !withdrawalHex(operationID, 32, true) || !withdrawalHex(draftDigest, 32, true) {
		return empty, ErrWithdrawalInvalid
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return empty, e
	}
	defer done()
	lease, e := s.wallet.holdUnlockContext(ctx)
	if e != nil {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		return empty, ErrWithdrawalUnavailable
	}
	defer lease.release()
	var result CandidateWithdrawalSigned
	e = walletdb.View(s.wallet.db, func(dbtx walletdb.ReadTx) error {
		state, e := s.audit(ctx, dbtx)
		if e != nil {
			return e
		}
		r, ok := state.records[operationID]
		if !ok {
			return ErrWithdrawalNotFound
		}
		if r.State != "prepared" || r.DraftDigest != draftDigest {
			return ErrWithdrawalConflict
		}
		if !s.wallet.ChainSynced() {
			return ErrWithdrawalUnavailable
		}
		tip := s.wallet.Manager.SyncedTo()
		reader, e := s.wallet.TxStore.NewCandidateCreditReader(dbtx.ReadBucket(wtxmgrNamespaceKey))
		if e != nil {
			return withdrawalCreditError(e)
		}
		scripts := make([][]byte, len(r.Draft.Inputs))
		values := make([]btcutil.Amount, len(scripts))
		for i, in := range r.Draft.Inputs {
			if e := lease.err(ctx); e != nil {
				return e
			}
			op, _ := withdrawalOutpoint(in)
			c, ok, e := reader.Lookup(ctx, op)
			if e != nil {
				return withdrawalCreditError(e)
			}
			if !ok || s.wallet.LockedOutpoint(op) || c.Height > tip.Height || !hasMinConfs(1, c.Height, tip.Height) || c.FromCoinBase && !hasMinConfs(int32(s.wallet.chainParams.CoinbaseMaturity), c.Height, tip.Height) || c.Amount != btcutil.Amount(in.Atoms) || hex.EncodeToString(c.PkScript) != in.Script || c.Height != in.BlockHeight || c.BlockMeta.Hash.String() != in.BlockHash || c.FromCoinBase != in.Coinbase {
				return ErrWithdrawalUnavailable
			}
			scripts[i] = c.PkScript
			values[i] = c.Amount
		}
		tx, e := validateWithdrawalDraft(r.Draft)
		if e != nil {
			return ErrWithdrawalCorrupt
		}
		if s.checkpoint != nil {
			if e := s.checkpoint("before_sign"); e != nil {
				return e
			}
		}
		if e := lease.err(ctx); e != nil {
			return e
		}
		if e := txauthor.AddAllInputScripts(tx, scripts, values, secretSource{s.wallet.Manager, dbtx.ReadBucket(waddrmgrNamespaceKey)}); e != nil {
			return ErrWithdrawalUnavailable
		}
		if validateMsgTx(tx, scripts, values) != nil {
			return ErrWithdrawalCorrupt
		}
		if e := lease.err(ctx); e != nil {
			return e
		}
		var unsigned, raw bytes.Buffer
		if tx.SerializeNoWitness(&unsigned) != nil || hex.EncodeToString(unsigned.Bytes()) != r.Draft.UnsignedTxHex || tx.Serialize(&raw) != nil || len(raw.Bytes()) > 4096 || validateWithdrawalSigned(r.Draft, raw.Bytes()) != nil {
			return ErrWithdrawalCorrupt
		}
		if !s.wallet.ChainSynced() || s.wallet.Manager.SyncedTo() != tip {
			return ErrWithdrawalUnavailable
		}
		result = CandidateWithdrawalSigned{1, operationID, draftDigest, tx.TxHash().String(), hex.EncodeToString(raw.Bytes())}
		return nil
	})
	if e != nil {
		return empty, e
	}
	if e := lease.err(ctx); e != nil {
		return empty, e
	}
	return result, nil
}

// validateWithdrawalSigned checks only the supplied exact draft and signature
// consistency. The live Sign method separately proves current wallet ownership.
func validateWithdrawalSigned(d CandidateWithdrawalDraft, raw []byte) error {
	if !withdrawalFrame(raw, true) {
		return ErrWithdrawalInvalid
	}
	unsigned, err := validateWithdrawalDraft(d)
	if err != nil {
		return err
	}
	tx := wire.NewMsgTx(1)
	if tx.Deserialize(bytes.NewReader(raw)) != nil {
		return ErrWithdrawalInvalid
	}
	var stripped, canonical bytes.Buffer
	if tx.SerializeNoWitness(&stripped) != nil || tx.Serialize(&canonical) != nil || !bytes.Equal(raw, canonical.Bytes()) || hex.EncodeToString(stripped.Bytes()) != d.UnsignedTxHex || tx.TxHash() != unsigned.TxHash() {
		return ErrWithdrawalInvalid
	}
	scripts := make([][]byte, len(d.Inputs))
	values := make([]btcutil.Amount, len(d.Inputs))
	for i, in := range d.Inputs {
		scripts[i], _ = hex.DecodeString(in.Script)
		values[i] = btcutil.Amount(in.Atoms)
	}
	if validateMsgTx(tx, scripts, values) != nil {
		return ErrWithdrawalInvalid
	}
	return nil
}
