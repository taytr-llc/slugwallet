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
	"sync"
	"sync/atomic"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var withdrawalNamespace = []byte("slug-candidate-withdrawal-v1")
var withdrawalMetaKey = []byte("meta")
var withdrawalOperations = []byte("operations")
var withdrawalPrepared = []byte("prepared_inputs")
var withdrawalRetained = []byte("retained_inputs")

type withdrawalIdentity struct {
	Profile       string `json:"profile"`
	Network       uint32 `json:"network"`
	Genesis       string `json:"genesis"`
	RootPublicKey string `json:"root_public_key"`
	GymPublicKey  string `json:"gym_public_key"`
	GymID         string `json:"gym_id"`
}
type withdrawalMeta struct {
	Version           uint32             `json:"version"`
	BindingID         string             `json:"binding_id"`
	Identity          withdrawalIdentity `json:"identity"`
	RecordCount       uint32             `json:"record_count"`
	ActiveOperationID string             `json:"active_operation_id"`
}
type withdrawalState struct {
	meta    withdrawalMeta
	records map[string]CandidateWithdrawalRecord
}

// CandidateWithdrawals borrows an existing wallet. Close it and join operations
// before unloading that wallet. The account/app journal boundary is deliberately
// not an argument to this internal wallet library; the concrete adapter owns it.
type CandidateWithdrawals struct {
	wallet    *Wallet
	binding   string
	identity  withdrawalIdentity
	gate      sync.Mutex
	closed    atomic.Bool
	poisoned  atomic.Bool
	life      context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	// Fault seam owns no expectation data and is nil in production.
	checkpoint func(string) error
}

func (w *Wallet) CreateCandidateWithdrawals(ctx context.Context, bindingID string) (*CandidateWithdrawals, error) {
	return w.openCandidateWithdrawals(ctx, bindingID, true)
}
func (w *Wallet) OpenCandidateWithdrawals(ctx context.Context, bindingID string) (*CandidateWithdrawals, error) {
	return w.openCandidateWithdrawals(ctx, bindingID, false)
}
func (w *Wallet) openCandidateWithdrawals(ctx context.Context, bindingID string, create bool) (result *CandidateWithdrawals, err error) {
	if ctx == nil {
		return nil, ErrWithdrawalInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if wire.TestPoW {
		return nil, ErrWithdrawalProfile
	}
	if w == nil || !withdrawalHex(bindingID, 32, true) {
		return nil, ErrWithdrawalInvalid
	}
	if !w.candidateWithdrawalMu.TryLock() {
		return nil, ErrWithdrawalBusy
	}
	defer func() {
		if err != nil {
			w.candidateWithdrawalMu.Unlock()
		}
	}()
	life, cancel := context.WithCancel(context.Background())
	s := &CandidateWithdrawals{wallet: w, binding: bindingID, life: life, cancel: cancel}
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	if e := s.walletAlive(); e != nil {
		return nil, e
	}
	if create {
		err = s.write(ctx, func(tx walletdb.ReadWriteTx) error {
			if tx.ReadBucket(withdrawalNamespace) != nil {
				return ErrWithdrawalConflict
			}
			identity, e := withdrawalProfile(tx, w)
			if e != nil {
				return e
			}
			s.identity = identity
			ns, e := tx.CreateTopLevelBucket(withdrawalNamespace)
			if e != nil {
				return ErrWithdrawalStorage
			}
			for _, name := range [][]byte{withdrawalOperations, withdrawalPrepared, withdrawalRetained} {
				if _, e := ns.CreateBucket(name); e != nil {
					return ErrWithdrawalStorage
				}
			}
			raw, _ := json.Marshal(withdrawalMeta{Version: 1, BindingID: bindingID, Identity: identity})
			if e := ns.Put(withdrawalMetaKey, raw); e != nil {
				return ErrWithdrawalStorage
			}
			return nil
		})
	} else {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			identity, e := withdrawalProfile(tx, w)
			if e != nil {
				return e
			}
			s.identity = identity
			if tx.ReadBucket(withdrawalNamespace) == nil {
				return ErrWithdrawalNotFound
			}
			_, e = s.audit(ctx, tx)
			return e
		})
	}
	if err != nil {
		return nil, err
	}
	if e := ctx.Err(); e != nil {
		if create {
			return nil, errors.Join(ErrWithdrawalOutcomeUnknown, e)
		}
		return nil, e
	}
	if e := s.walletAlive(); e != nil {
		if create {
			return nil, errors.Join(ErrWithdrawalOutcomeUnknown, e)
		}
		return nil, e
	}
	return s, nil
}
func withdrawalProfile(tx walletdb.ReadTx, w *Wallet) (withdrawalIdentity, error) {
	var empty withdrawalIdentity
	if wire.TestPoW || w == nil || w.Manager == nil || w.Manager.WatchOnly() {
		return empty, ErrWithdrawalProfile
	}
	version, e := new(waddrmgr.MigrationManager).CurrentVersion(tx.ReadBucket(waddrmgrNamespaceKey))
	if e != nil || version != 9 {
		return empty, ErrWithdrawalProfile
	}
	m, e := readRecoveryPublic(tx.ReadBucket(waddrmgrNamespaceKey), w.Manager, w.chainParams)
	if e != nil || m.Version != 1 || m.Profile != recovery.ProfileID || m.Network != recovery.Network || m.Genesis != recovery.Genesis || gymaccount.ValidateFixtureIdentity(m.RootPublicKey, m.GymPublicKey, m.GymID) != nil {
		return empty, ErrWithdrawalProfile
	}
	return withdrawalIdentity{m.Profile, m.Network, m.Genesis, m.RootPublicKey, m.GymPublicKey, m.GymID}, nil
}
func (s *CandidateWithdrawals) walletAlive() error {
	if s.wallet == nil || s.wallet.db == nil {
		return ErrWithdrawalClosed
	}
	if !s.wallet.quitMu.TryLock() {
		return ErrWithdrawalBusy
	}
	started, quit := s.wallet.started, s.wallet.quit
	s.wallet.quitMu.Unlock()
	if !started {
		return ErrWithdrawalClosed
	}
	select {
	case <-quit:
		return ErrWithdrawalClosed
	default:
		return nil
	}
}
func (s *CandidateWithdrawals) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrWithdrawalInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	if wire.TestPoW {
		return nil, nil, ErrWithdrawalProfile
	}
	if s == nil || s.closed.Load() {
		return nil, nil, ErrWithdrawalClosed
	}
	if !s.gate.TryLock() {
		return nil, nil, ErrWithdrawalBusy
	}
	fail := func(e error) (context.Context, func(), error) { s.gate.Unlock(); return nil, nil, e }
	if s.closed.Load() {
		return fail(ErrWithdrawalClosed)
	}
	if s.poisoned.Load() {
		return fail(ErrWithdrawalOutcomeUnknown)
	}
	if e := s.walletAlive(); e != nil {
		return fail(e)
	}
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	return owned, func() { stop(); cancel(); s.gate.Unlock() }, nil
}
func (s *CandidateWithdrawals) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		s.gate.Lock()
		s.gate.Unlock()
		s.wallet.candidateWithdrawalMu.Unlock()
	})
	return nil
}
func (s *CandidateWithdrawals) write(ctx context.Context, fn func(walletdb.ReadWriteTx) error) error {
	tx, e := s.wallet.db.BeginReadWriteTx()
	if e != nil {
		return ErrWithdrawalStorage
	}
	abort := func(cause error) error {
		if e := tx.Rollback(); e != nil {
			s.poisoned.Store(true)
			return errors.Join(ErrWithdrawalOutcomeUnknown, ErrWithdrawalStorage, cause)
		}
		return cause
	}
	if e := ctx.Err(); e != nil {
		return abort(e)
	}
	if e := s.walletAlive(); e != nil {
		return abort(e)
	}
	if e := fn(tx); e != nil {
		return abort(e)
	}
	if e := ctx.Err(); e != nil {
		return abort(e)
	}
	if s.checkpoint != nil {
		if e := s.checkpoint("before_commit"); e != nil {
			return abort(e)
		}
	}
	if e := ctx.Err(); e != nil {
		return abort(e)
	}
	if e := s.walletAlive(); e != nil {
		return abort(e)
	}
	if e := tx.Commit(); e != nil {
		s.poisoned.Store(true)
		return errors.Join(ErrWithdrawalOutcomeUnknown, ErrWithdrawalStorage)
	}
	if s.checkpoint != nil {
		if e := s.checkpoint("after_commit"); e != nil {
			s.poisoned.Store(true)
			return errors.Join(ErrWithdrawalOutcomeUnknown, e)
		}
	}
	if e := ctx.Err(); e != nil {
		s.poisoned.Store(true)
		return errors.Join(ErrWithdrawalOutcomeUnknown, e)
	}
	if e := s.walletAlive(); e != nil {
		s.poisoned.Store(true)
		return errors.Join(ErrWithdrawalOutcomeUnknown, e)
	}
	return nil
}
func (s *CandidateWithdrawals) audit(ctx context.Context, tx walletdb.ReadTx) (withdrawalState, error) {
	var state withdrawalState
	if e := ctx.Err(); e != nil {
		return state, e
	}
	identity, e := withdrawalProfile(tx, s.wallet)
	if e != nil {
		return state, e
	}
	if identity != s.identity {
		return state, ErrWithdrawalCorrupt
	}
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns == nil {
		return state, ErrWithdrawalCorrupt
	}
	count := 0
	if e := ns.ForEach(func(k, v []byte) error {
		count++
		switch string(k) {
		case "meta":
			if v == nil {
				return ErrWithdrawalCorrupt
			}
		case "operations", "prepared_inputs", "retained_inputs":
			if v != nil || ns.NestedReadBucket(k) == nil {
				return ErrWithdrawalCorrupt
			}
		default:
			return ErrWithdrawalCorrupt
		}
		return nil
	}); e != nil || count != 4 {
		return state, ErrWithdrawalCorrupt
	}
	if e := withdrawalDecode(ns.Get(withdrawalMetaKey), 2048, &state.meta); e != nil {
		return state, e
	}
	if state.meta.Version != 1 || state.meta.BindingID != s.binding || state.meta.Identity != s.identity || state.meta.RecordCount > 128 || (state.meta.ActiveOperationID != "" && !withdrawalHex(state.meta.ActiveOperationID, 32, true)) {
		return state, ErrWithdrawalCorrupt
	}
	state.records = make(map[string]CandidateWithdrawalRecord)
	prepared := make(map[string][]byte)
	retained := make(map[string][]byte)
	total := 0
	active := ""
	e = ns.NestedReadBucket(withdrawalOperations).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		total += len(v)
		if len(k) != 32 || v == nil || len(state.records) >= 128 || total > 4<<20 {
			return ErrWithdrawalCorrupt
		}
		var r CandidateWithdrawalRecord
		if e := withdrawalDecode(v, 32768, &r); e != nil {
			return e
		}
		digest, e := CandidateWithdrawalDraftDigest(r.Draft)
		if e != nil || r.Version != 1 || r.Draft.OperationID != hex.EncodeToString(k) || r.Draft.BindingID != s.binding || digest != r.DraftDigest {
			return ErrWithdrawalCorrupt
		}
		unsigned, e := validateWithdrawalDraft(r.Draft)
		if e != nil {
			return ErrWithdrawalCorrupt
		}
		switch r.State {
		case "prepared":
			if active != "" || r.RetainedTxID != "" {
				return ErrWithdrawalCorrupt
			}
			active = r.Draft.OperationID
		case "abandoned":
			if r.RetainedTxID != "" {
				return ErrWithdrawalCorrupt
			}
		case "retained":
			if r.RetainedTxID != unsigned.TxHash().String() {
				return ErrWithdrawalCorrupt
			}
		default:
			return ErrWithdrawalCorrupt
		}
		if e := s.ownedDraft(tx, r.Draft); e != nil {
			return e
		}
		for _, in := range r.Draft.Inputs {
			op, e := withdrawalOutpoint(in)
			if e != nil {
				return e
			}
			key := string(withdrawalKey(op))
			if r.State == "prepared" {
				if _, ok := prepared[key]; ok {
					return ErrWithdrawalCorrupt
				}
				prepared[key] = append([]byte(nil), k...)
			}
			if r.State == "retained" {
				if _, ok := retained[key]; ok {
					return ErrWithdrawalCorrupt
				}
				value := append([]byte(nil), k...)
				d, _ := hex.DecodeString(r.DraftDigest)
				id, _ := hex.DecodeString(r.RetainedTxID)
				value = append(value, d...)
				value = append(value, id...)
				retained[key] = value
			}
		}
		state.records[r.Draft.OperationID] = r
		return nil
	})
	if e != nil {
		return withdrawalState{}, e
	}
	if uint32(len(state.records)) != state.meta.RecordCount || active != state.meta.ActiveOperationID {
		return withdrawalState{}, ErrWithdrawalCorrupt
	}
	for k := range prepared {
		if _, ok := retained[k]; ok {
			return withdrawalState{}, ErrWithdrawalCorrupt
		}
	}
	for _, item := range []struct {
		name   []byte
		values map[string][]byte
		limit  int
	}{{withdrawalPrepared, prepared, 16}, {withdrawalRetained, retained, 2048}} {
		n := 0
		e := ns.NestedReadBucket(item.name).ForEach(func(k, v []byte) error {
			n++
			expected, ok := item.values[string(k)]
			if n > item.limit || len(k) != 36 || !ok || !bytes.Equal(expected, v) {
				return ErrWithdrawalCorrupt
			}
			return nil
		})
		if e != nil || n != len(item.values) {
			return withdrawalState{}, ErrWithdrawalCorrupt
		}
	}
	return state, nil
}
func (s *CandidateWithdrawals) Lookup(ctx context.Context, operationID string) (CandidateWithdrawalRecord, error) {
	var empty CandidateWithdrawalRecord
	if !withdrawalHex(operationID, 32, true) {
		return empty, ErrWithdrawalInvalid
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return empty, e
	}
	defer done()
	var result CandidateWithdrawalRecord
	e = walletdb.View(s.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := s.audit(ctx, tx)
		if e != nil {
			return e
		}
		r, ok := state.records[operationID]
		if !ok {
			return ErrWithdrawalNotFound
		}
		result = r
		return nil
	})
	if e != nil {
		return empty, e
	}
	if e := ctx.Err(); e != nil {
		return empty, e
	}
	if e := s.walletAlive(); e != nil {
		return empty, e
	}
	return result, nil
}
func (s *CandidateWithdrawals) Retain(ctx context.Context, operationID, draftDigest, txID string) error {
	return s.reconcile(ctx, operationID, draftDigest, txID, false)
}
func (s *CandidateWithdrawals) Abandon(ctx context.Context, operationID, draftDigest string) error {
	return s.reconcile(ctx, operationID, draftDigest, "", true)
}
func (s *CandidateWithdrawals) reconcile(ctx context.Context, operationID, draftDigest, txID string, abandon bool) error {
	if !withdrawalHex(operationID, 32, true) || !withdrawalHex(draftDigest, 32, true) || (!abandon && !withdrawalHex(txID, 32, false)) {
		return ErrWithdrawalInvalid
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	return s.write(ctx, func(tx walletdb.ReadWriteTx) error {
		state, e := s.audit(ctx, tx)
		if e != nil {
			return e
		}
		r, ok := state.records[operationID]
		if !ok {
			return ErrWithdrawalNotFound
		}
		if r.DraftDigest != draftDigest {
			return ErrWithdrawalConflict
		}
		target := "retained"
		if abandon {
			target = "abandoned"
		}
		if r.State == target {
			if r.RetainedTxID == txID {
				return nil
			}
			return ErrWithdrawalConflict
		}
		if r.State != "prepared" || state.meta.ActiveOperationID != operationID {
			return ErrWithdrawalConflict
		}
		if !abandon {
			unsigned, e := validateWithdrawalDraft(r.Draft)
			if e != nil || unsigned.TxHash().String() != txID {
				return ErrWithdrawalConflict
			}
		}
		ns := tx.ReadWriteBucket(withdrawalNamespace)
		pre := ns.NestedReadWriteBucket(withdrawalPrepared)
		ret := ns.NestedReadWriteBucket(withdrawalRetained)
		key, _ := hex.DecodeString(operationID)
		for _, in := range r.Draft.Inputs {
			op, _ := withdrawalOutpoint(in)
			k := withdrawalKey(op)
			if e := pre.Delete(k); e != nil {
				return ErrWithdrawalStorage
			}
			if !abandon {
				v := append([]byte(nil), key...)
				d, _ := hex.DecodeString(draftDigest)
				id, _ := hex.DecodeString(txID)
				v = append(v, d...)
				v = append(v, id...)
				if e := ret.Put(k, v); e != nil {
					return ErrWithdrawalStorage
				}
			}
		}
		r.State = target
		r.RetainedTxID = txID
		raw, _ := json.Marshal(r)
		if e := ns.NestedReadWriteBucket(withdrawalOperations).Put(key, raw); e != nil {
			return ErrWithdrawalStorage
		}
		state.meta.ActiveOperationID = ""
		raw, _ = json.Marshal(state.meta)
		if e := ns.Put(withdrawalMetaKey, raw); e != nil {
			return ErrWithdrawalStorage
		}
		return nil
	})
}

// candidateWithdrawalReserved is shared with ordinary coin selection. An
// established malformed namespace fails closed rather than making coins free.
func candidateWithdrawalReserved(tx walletdb.ReadTx, op wire.OutPoint) (bool, error) {
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns == nil {
		return false, nil
	}
	pre, ret := ns.NestedReadBucket(withdrawalPrepared), ns.NestedReadBucket(withdrawalRetained)
	if pre == nil || ret == nil {
		return false, ErrWithdrawalCorrupt
	}
	k := withdrawalKey(op)
	p, r := pre.Get(k), ret.Get(k)
	if (p != nil && len(p) != 32) || (r != nil && len(r) != 96) {
		return false, ErrWithdrawalCorrupt
	}
	return p != nil || r != nil, nil
}

func candidateWithdrawalAuditSelection(tx walletdb.ReadTx, w *Wallet) error {
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns == nil {
		return nil
	}
	var meta withdrawalMeta
	if e := withdrawalDecode(ns.Get(withdrawalMetaKey), 2048, &meta); e != nil {
		return e
	}
	s := &CandidateWithdrawals{wallet: w, binding: meta.BindingID, identity: meta.Identity}
	_, e := s.audit(context.Background(), tx)
	return e
}

// Empty is an audited setup predicate for the original INIT binding. It conveys
// no authorization to initialize, abandon, replace, or repair either journal.
func (s *CandidateWithdrawals) Empty(ctx context.Context) (bool, error) {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return false, e
	}
	defer done()
	empty := false
	e = walletdb.View(s.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := s.audit(ctx, tx)
		if e != nil {
			return e
		}
		empty = len(state.records) == 0 && state.meta.ActiveOperationID == ""
		return nil
	})
	if e != nil {
		return false, e
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if e := s.walletAlive(); e != nil {
		return false, e
	}
	return empty, nil
}

// Privileged supplied-input authoring must respect the same exclusions as
// automatic selection. It cannot turn a prepared/retained input into a new PSBT.
func (w *Wallet) candidateWithdrawalCheckInputs(inputs []*wire.TxIn) error {
	return walletdb.View(w.db, func(tx walletdb.ReadTx) error { return candidateWithdrawalCheckInputsTx(tx, w, inputs) })
}
func candidateWithdrawalCheckInputsTx(tx walletdb.ReadTx, w *Wallet, inputs []*wire.TxIn) error {
	if e := candidateWithdrawalAuditSelection(tx, w); e != nil {
		return e
	}
	for _, in := range inputs {
		reserved, e := candidateWithdrawalReserved(tx, in.PreviousOutPoint)
		if e != nil {
			return e
		}
		if reserved {
			return ErrWithdrawalConflict
		}
	}
	return nil
}

// OperationIDs returns the complete audited wallet side of the paired-journal
// correspondence. IDs are owned, sorted, and include abandoned history.
func (s *CandidateWithdrawals) OperationIDs(ctx context.Context) ([]string, error) {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	ids := make([]string, 0)
	e = walletdb.View(s.wallet.db, func(tx walletdb.ReadTx) error {
		state, e := s.audit(ctx, tx)
		if e != nil {
			return e
		}
		for id := range state.records {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return nil
	})
	if e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := s.walletAlive(); e != nil {
		return nil, e
	}
	return ids, nil
}
