// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"sync"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcec/v2/schnorr"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

const (
	MaxRecoveryTransactions      = 16384
	MaxRecoveryOwnedOutputs      = 16384
	MaxRecoveryTransactionBytes  = 32 << 20
	MaxRecoveryWatchRequestBytes = 8 << 20
)

var (
	phaseARecoveryScanBucket = []byte("slug-phase-a-scanner-v1")
	recoveryScanBucket       = []byte("slug-candidate-scanner-v1")
	recoveryScanMeta         = []byte("progress")
	recoveryScripts          = []byte("scripts")
	recoveryOutputs          = []byte("outputs")
	recoveryTransactions     = []byte("transactions")
)

type recoveryScanState struct {
	Version          uint32 `json:"version"`
	Phase            string `json:"phase"`
	Height           int32  `json:"height"`
	Hash             string `json:"hash"`
	Time             int64  `json:"time"`
	TargetHeight     int32  `json:"target_height"`
	TargetHash       string `json:"target_hash"`
	Transactions     uint32 `json:"transactions"`
	Outputs          uint32 `json:"outputs"`
	TransactionBytes uint64 `json:"transaction_bytes"`
}

type recoveryScript struct {
	Purpose uint32 `json:"purpose"`
	Branch  uint32 `json:"branch"`
	Index   uint32 `json:"index"`
	Script  []byte `json:"script"`
}

// RecoverySession owns an incomplete wallet exclusively. No wallet goroutines,
// private key unlocking, notifications or spending run during reconstruction.
// Each successful Step commits one bounded unit and can be resumed after Close.
type RecoverySession struct {
	db             walletdb.DB
	manager        *waddrmgr.Manager
	txStore        *wtxmgr.Store
	params         *chaincfg.Params
	update         func(func(walletdb.ReadWriteTx) error) error
	checkpoint     func(string)
	onClose        func()
	onCloseFailure func(error) error
	scanBucket     []byte
	gate           chan struct{}
	life           context.Context
	cancel         context.CancelFunc
	closeOnce      sync.Once
	closeDone      chan struct{}
	closeErr       error
	poisoned       bool // protected by gate
}

func initializeCandidateRecovery(tx walletdb.ReadWriteTx) error {
	return initializeRecovery(tx, recoveryScanBucket)
}
func initializeRecovery(tx walletdb.ReadWriteTx, bucket []byte) error {
	if tx.ReadBucket(recoveryScanBucket) != nil || tx.ReadBucket(phaseARecoveryScanBucket) != nil {
		return waddrmgr.ErrRecoveryState
	}
	b, err := tx.CreateTopLevelBucket(bucket)
	if err != nil {
		return err
	}
	for _, name := range [][]byte{recoveryScripts, recoveryOutputs, recoveryTransactions} {
		if _, err := b.CreateBucket(name); err != nil {
			return err
		}
	}
	return putRecoveryScan(b, recoveryScanState{Version: 1, Phase: "deriving", Height: -1, TargetHeight: -1})
}

func validScan(s recoveryScanState) bool {
	if s.Version != 1 || (s.Phase != "deriving" && s.Phase != "scanning" && s.Phase != "complete") || s.Height < -1 || s.TargetHeight < -1 || s.Transactions > MaxRecoveryTransactions || s.Outputs > MaxRecoveryOwnedOutputs || s.TransactionBytes > MaxRecoveryTransactionBytes {
		return false
	}
	validHash := func(h string) bool {
		x, e := chainhash.NewHashFromStr(h)
		return e == nil && len(h) == 64 && x.String() == h
	}
	if (s.Height == -1 && (s.Hash != "" || s.Time != 0)) || (s.Height >= 0 && (!validHash(s.Hash) || s.Time <= 0 || s.Time > math.MaxUint32)) {
		return false
	}
	if (s.TargetHeight == -1 && s.TargetHash != "") || (s.TargetHeight >= 0 && !validHash(s.TargetHash)) {
		return false
	}
	if s.Height > s.TargetHeight || (s.Phase == "complete" && (s.Height < 0 || s.Height != s.TargetHeight || s.Hash != s.TargetHash)) {
		return false
	}
	return true
}

func readRecoveryScan(b walletdb.ReadBucket) (recoveryScanState, error) {
	var s recoveryScanState
	if b == nil {
		return s, waddrmgr.ErrRecoveryState
	}
	raw := b.Get(recoveryScanMeta)
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &s) != nil || !validScan(s) {
		return s, waddrmgr.ErrRecoveryState
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) {
		return s, waddrmgr.ErrRecoveryState
	}
	for _, name := range [][]byte{recoveryScripts, recoveryOutputs, recoveryTransactions} {
		if b.NestedReadBucket(name) == nil {
			return s, waddrmgr.ErrRecoveryState
		}
	}
	return s, nil
}
func putRecoveryScan(b walletdb.ReadWriteBucket, s recoveryScanState) error {
	if b == nil || !validScan(s) {
		return waddrmgr.ErrRecoveryState
	}
	raw, _ := json.Marshal(s)
	return b.Put(recoveryScanMeta, raw)
}

func candidateRecoveryComplete(tx walletdb.ReadTx, mgr *waddrmgr.Manager) error {
	if !mgr.ResumableRecovery() {
		return nil
	}
	if err := recoveryBucketExclusive(tx, mgr); err != nil {
		return err
	}
	state, err := mgr.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
	if err != nil {
		return err
	}
	scan, err := readRecoveryScan(tx.ReadBucket(recoveryBucketFor(mgr)))
	if err != nil {
		return err
	}
	if !state.Ready || scan.Phase != "complete" {
		return ErrRecoveryInProgress
	}
	if mgr.RecoveryVersion() == 1 {
		s := &RecoverySession{manager: mgr, params: mgr.ChainParams(), scanBucket: recoveryBucketFor(mgr)}
		return s.audit(context.Background(), tx)
	}
	return nil
}

func newRecoverySession(ctx context.Context, db walletdb.DB, mgr *waddrmgr.Manager, txs *wtxmgr.Store, params *chaincfg.Params, onClose func()) (*RecoverySession, error) {
	if ctx == nil || wire.TestPoW || db == nil || mgr == nil || txs == nil || params == nil || params.GenesisHash == nil || params.GenesisBlock == nil || !mgr.ResumableRecovery() {
		return nil, ErrRecoveryProfile
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownedParams := *params
	genesis := *params.GenesisHash
	ownedParams.GenesisHash = &genesis
	genesisBlock := *params.GenesisBlock
	ownedParams.GenesisBlock = &genesisBlock
	s := &RecoverySession{db: db, manager: mgr, txStore: txs, params: &ownedParams, onClose: onClose, scanBucket: recoveryBucketFor(mgr), gate: make(chan struct{}, 1), closeDone: make(chan struct{})}
	s.life, s.cancel = context.WithCancel(context.Background())
	s.update = func(f func(walletdb.ReadWriteTx) error) error { return walletdb.Update(db, f) }
	s.txStore.NotifyUnspent = nil
	err := walletdb.View(db, func(tx walletdb.ReadTx) error { return s.audit(ctx, tx) })
	if err != nil {
		s.cancel()
		return nil, err
	}
	return s, nil
}

func (s *RecoverySession) enter(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrRecoveryProfile
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.life.Err() != nil {
		return nil, nil, ErrRecoveryClosed
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-s.life.Done():
		return nil, nil, ErrRecoveryClosed
	}
	if s.life.Err() != nil {
		<-s.gate
		return nil, nil, ErrRecoveryClosed
	}
	if s.poisoned {
		<-s.gate
		return nil, nil, ErrRecoveryPoisoned
	}
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	return op, func() { stop(); cancel(); <-s.gate }, nil
}

func (s *RecoverySession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.gate <- struct{}{}
		s.manager.Close()
		s.closeErr = s.db.Close()
		if s.manager.RecoveryVersion() == 1 && s.closeErr != nil {
			if s.onCloseFailure != nil {
				s.closeErr = s.onCloseFailure(s.closeErr)
			}
		} else if s.onClose != nil {
			s.onClose()
		}
		<-s.gate
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
}

func (s *RecoverySession) status(tx walletdb.ReadTx) (RecoveryProgress, error) {
	var p RecoveryProgress
	m, err := s.manager.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
	if err != nil {
		return p, err
	}
	d, err := readRecoveryScan(tx.ReadBucket(s.scanBucket))
	if err != nil {
		return p, err
	}
	if m.Ready != (d.Phase == "complete") {
		return p, waddrmgr.ErrRecoveryState
	}
	p = RecoveryProgress{Version: 1, Phase: d.Phase, Ready: m.Ready, ScannedHeight: d.Height, ScannedHash: d.Hash, TargetHeight: d.TargetHeight, TargetHash: d.TargetHash, RelevantTransactions: d.Transactions, OwnedOutputs: d.Outputs}
	for _, b := range m.Branches {
		p.Derived += uint64(b.DerivedNext)
		p.Target += uint64(b.TargetNext)
		p.Issued += uint64(b.IssuedNext)
	}
	if (d.Phase == "scanning" && p.Derived != p.Target) || (d.Phase == "deriving" && p.Derived == p.Target) {
		return RecoveryProgress{}, waddrmgr.ErrRecoveryState
	}
	return p, nil
}
func (s *RecoverySession) Status(ctx context.Context) (RecoveryProgress, error) {
	_, leave, err := s.enter(ctx)
	if err != nil {
		return RecoveryProgress{}, err
	}
	defer leave()
	var p RecoveryProgress
	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error { var e error; p, e = s.status(tx); return e })
	return p, err
}
func (s *RecoverySession) committed(stage string, fn func(walletdb.ReadWriteTx) error) error {
	// A write error can occur after the durable commit. Never continue using an
	// ambiguous in-memory manager; reopening audits the actual database state.
	if err := s.update(fn); err != nil {
		s.poisoned = true
		return err
	}
	if s.checkpoint != nil {
		s.checkpoint(stage)
	}
	return nil
}

func decodeRecoveryScript(raw []byte) (recoveryScript, error) {
	return decodeRecoveryScriptLimit(raw, productionprofile.MaxNextIndex)
}
func decodeRecoveryScriptLimit(raw []byte, limit uint32) (recoveryScript, error) {
	var v recoveryScript
	if len(raw) == 0 || len(raw) > 256 || json.Unmarshal(raw, &v) != nil {
		return v, waddrmgr.ErrRecoveryState
	}
	c, _ := json.Marshal(v)
	if !bytes.Equal(c, raw) || v.Branch > 1 || v.Index >= limit || len(v.Script) < 22 || len(v.Script) > 34 {
		return v, waddrmgr.ErrRecoveryState
	}
	switch v.Purpose {
	case 44, 49, 84, 86:
	default:
		return v, waddrmgr.ErrRecoveryState
	}
	return v, nil
}
func recoveryBranchIndex(purpose, branch uint32) int {
	for i, p := range []uint32{44, 49, 84, 86} {
		if p == purpose {
			return i*2 + int(branch)
		}
	}
	return -1
}
func recoveryScriptForKey(key *hdkeychain.ExtendedKey, purpose uint32, params *chaincfg.Params) ([]byte, error) {
	pub, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}
	var a address.Address
	switch purpose {
	case 44:
		a, err = address.NewAddressPubKeyHash(address.Hash160(pub.SerializeCompressed()), params)
	case 49:
		var w *address.AddressWitnessPubKeyHash
		w, err = address.NewAddressWitnessPubKeyHash(address.Hash160(pub.SerializeCompressed()), params)
		if err == nil {
			var p []byte
			p, err = txscript.PayToAddrScript(w)
			if err == nil {
				a, err = address.NewAddressScriptHash(p, params)
			}
		}
	case 84:
		a, err = address.NewAddressWitnessPubKeyHash(address.Hash160(pub.SerializeCompressed()), params)
	case 86:
		a, err = address.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)), params)
	default:
		return nil, waddrmgr.ErrRecoveryState
	}
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(a)
}

func (s *RecoverySession) audit(ctx context.Context, tx walletdb.ReadTx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recoveryBucketExclusive(tx, s.manager); err != nil {
		return err
	}
	p, err := s.status(tx)
	if err != nil {
		return err
	}
	b := tx.ReadBucket(s.scanBucket)
	count := 0
	if err := b.ForEach(func(k, v []byte) error {
		count++
		if bytes.Equal(k, recoveryScanMeta) {
			if v == nil {
				return waddrmgr.ErrRecoveryState
			}
			return nil
		}
		for _, name := range [][]byte{recoveryScripts, recoveryOutputs, recoveryTransactions} {
			if bytes.Equal(k, name) && v == nil {
				return nil
			}
		}
		return waddrmgr.ErrRecoveryState
	}); err != nil || count != 4 {
		return waddrmgr.ErrRecoveryState
	}
	// Ready wallets acquire ordinary transaction/address state after the session
	// closes. The immutable completed scanner checkpoint is not their live ledger.
	if p.Ready {
		if s.manager.RecoveryVersion() == 1 {
			return s.auditPhaseAComplete(ctx, tx, b)
		}
		return nil
	}
	ledgerSummary, err := s.txStore.ValidateRecoveryStore(tx.ReadBucket(wtxmgrNamespaceKey))
	if err != nil {
		return waddrmgr.ErrRecoveryState
	}
	ns := tx.ReadBucket(waddrmgrNamespaceKey)
	m, err := s.manager.CandidateRecoveryState(ns)
	if err != nil {
		return err
	}
	scripts, err := s.auditRecoveryScripts(ctx, tx, b)
	if err != nil {
		return err
	}
	if scripts != m.AddressCount {
		return waddrmgr.ErrRecoveryState
	}
	var outputs, transactions uint32
	var total uint64
	d, err := readRecoveryScan(b)
	if err != nil {
		return err
	}
	if d.Height >= 0 {
		synced := s.manager.SyncedTo()
		if synced.Height != d.Height || synced.Hash.String() != d.Hash || synced.Timestamp.Unix() != d.Time {
			return waddrmgr.ErrRecoveryState
		}
		start := int64(d.Height) - int64(waddrmgr.MaxReorgDepth) + 1
		if start < 0 {
			start = 0
		}
		for height := start; height <= int64(d.Height); height++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			hash, e := s.manager.BlockHash(ns, int32(height))
			if e != nil || (height == int64(d.Height) && hash.String() != d.Hash) {
				return waddrmgr.ErrRecoveryState
			}
		}
	}
	var ledgerCredits uint32
	type observedCredit struct {
		amount int64
		block  wtxmgr.Block
		spent  bool
	}
	ownedCredits := make(map[wire.OutPoint]observedCredit)
	spentOutputs := make(map[wire.OutPoint]bool)
	debitAmounts := make(map[wire.OutPoint]int64)
	err = b.NestedReadBucket(recoveryOutputs).ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		outputs++
		if outputs > MaxRecoveryOwnedOutputs || len(k) != 36 || len(v) != 32 || b.NestedReadBucket(recoveryScripts).Get(v) == nil || b.NestedReadBucket(recoveryTransactions).Get(k[:32]) == nil {
			return waddrmgr.ErrRecoveryState
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = b.NestedReadBucket(recoveryTransactions).ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		transactions++
		if transactions > MaxRecoveryTransactions || len(k) != 32 || len(v) != 8 {
			return waddrmgr.ErrRecoveryState
		}
		n := binary.LittleEndian.Uint64(v)
		if n == 0 || n > wire.MaxBlockPayload {
			return waddrmgr.ErrRecoveryState
		}
		total += n
		if total > MaxRecoveryTransactionBytes {
			return waddrmgr.ErrRecoveryState
		}
		var hash chainhash.Hash
		copy(hash[:], k)
		details, err := s.txStore.TxDetails(tx.ReadBucket(wtxmgrNamespaceKey), &hash)
		if err != nil || details == nil || details.Hash != hash || details.MsgTx.TxHash() != hash || uint64(details.MsgTx.SerializeSize()) != n || details.Block.Height < 1 || details.Block.Height > d.Height {
			return waddrmgr.ErrRecoveryState
		}
		ownedInputs := 0
		for _, input := range details.MsgTx.TxIn {
			if b.NestedReadBucket(recoveryOutputs).Get(recoveryOutpointKey(input.PreviousOutPoint)) != nil {
				if spentOutputs[input.PreviousOutPoint] {
					return waddrmgr.ErrRecoveryState
				}
				spentOutputs[input.PreviousOutPoint] = true
				ownedInputs++
			}
		}
		if len(details.Debits) != ownedInputs {
			return waddrmgr.ErrRecoveryState
		}
		seenDebits := make(map[uint32]bool)
		for _, debit := range details.Debits {
			if uint64(debit.Index) >= uint64(len(details.MsgTx.TxIn)) || seenDebits[debit.Index] {
				return waddrmgr.ErrRecoveryState
			}
			seenDebits[debit.Index] = true
			op := details.MsgTx.TxIn[debit.Index].PreviousOutPoint
			if b.NestedReadBucket(recoveryOutputs).Get(recoveryOutpointKey(op)) == nil {
				return waddrmgr.ErrRecoveryState
			}
			debitAmounts[op] = int64(debit.Amount)
		}
		for _, credit := range details.Credits {
			ledgerCredits++
			if ledgerCredits > MaxRecoveryOwnedOutputs || uint64(credit.Index) >= uint64(len(details.MsgTx.TxOut)) {
				return waddrmgr.ErrRecoveryState
			}
			output := details.MsgTx.TxOut[credit.Index]
			scriptHash := sha256.Sum256(output.PkScript)
			indexed := b.NestedReadBucket(recoveryOutputs).Get(recoveryOutpointKey(wire.OutPoint{Hash: hash, Index: credit.Index}))
			if !bytes.Equal(indexed, scriptHash[:]) || int64(credit.Amount) != output.Value {
				return waddrmgr.ErrRecoveryState
			}
			row, err := decodeRecoveryScriptLimit(b.NestedReadBucket(recoveryScripts).Get(scriptHash[:]), s.manager.RecoveryIndexLimit())
			if err != nil || !bytes.Equal(row.Script, output.PkScript) || credit.Change != (row.Branch == 1) {
				return waddrmgr.ErrRecoveryState
			}
			op := wire.OutPoint{Hash: hash, Index: credit.Index}
			if _, duplicate := ownedCredits[op]; duplicate {
				return waddrmgr.ErrRecoveryState
			}
			ownedCredits[op] = observedCredit{output.Value, details.Block.Block, credit.Spent}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if outputs != d.Outputs || ledgerCredits != outputs || transactions != d.Transactions || total != d.TransactionBytes || ledgerSummary.Transactions != transactions || ledgerSummary.Credits != outputs || ledgerSummary.TransactionBytes != total || ledgerSummary.Debits != uint32(len(debitAmounts)) {
		return waddrmgr.ErrRecoveryState
	}
	// Pending sessions contain no local spends, output locks or mempool state.
	// Recompute their expected unspent set from the immutable transaction
	// bodies instead of trusting a second, independently corruptible index.
	expectedUnspent := make(map[wire.OutPoint]wtxmgr.Block)
	var expectedBalance int64
	for op, credit := range ownedCredits {
		if credit.spent != spentOutputs[op] || credit.amount < 0 || credit.amount > btcutil.MaxSatoshi {
			return waddrmgr.ErrRecoveryState
		}
		if credit.spent {
			if amount, ok := debitAmounts[op]; !ok || amount != credit.amount {
				return waddrmgr.ErrRecoveryState
			}
			continue
		}
		expectedUnspent[op] = credit.block
		if credit.amount > btcutil.MaxSatoshi-expectedBalance {
			return waddrmgr.ErrRecoveryState
		}
		expectedBalance += credit.amount
	}
	watch, err := s.txStore.UnspentOutpointsBounded(tx.ReadBucket(wtxmgrNamespaceKey), MaxRecoveryOwnedOutputs)
	if err != nil || len(watch) != len(expectedUnspent) {
		return waddrmgr.ErrRecoveryState
	}
	for op, block := range watch {
		expected, ok := expectedUnspent[op]
		if !ok || expected != block {
			return waddrmgr.ErrRecoveryState
		}
		delete(expectedUnspent, op)
	}
	if len(expectedUnspent) != 0 {
		return waddrmgr.ErrRecoveryState
	}
	balance, err := s.txStore.MinedBalance(tx.ReadBucket(wtxmgrNamespaceKey))
	if err != nil || int64(balance) != expectedBalance {
		return waddrmgr.ErrRecoveryState
	}
	return nil
}

// resetPendingRecovery discards only the bounded, private reconstruction view.
// Monotonic issued/used address facts and the public script index survive.
func resetPendingRecovery(tx walletdb.ReadWriteTx, d *recoveryScanState) error {
	return resetPendingRecoveryBucket(tx, d, recoveryScanBucket)
}
func resetPendingRecoveryBucket(tx walletdb.ReadWriteTx, d *recoveryScanState, bucket []byte) error {
	if d.Phase == "complete" {
		return waddrmgr.ErrRecoveryState
	}
	if err := tx.DeleteTopLevelBucket(wtxmgrNamespaceKey); err != nil {
		return err
	}
	ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
	if err != nil {
		return err
	}
	if err = wtxmgr.Create(ns); err != nil {
		return err
	}
	b := tx.ReadWriteBucket(bucket)
	for _, name := range [][]byte{recoveryOutputs, recoveryTransactions} {
		if err = b.DeleteNestedBucket(name); err != nil {
			return err
		}
		if _, err = b.CreateBucket(name); err != nil {
			return err
		}
	}
	d.Height = -1
	d.Hash = ""
	d.Time = 0
	d.Transactions = 0
	d.Outputs = 0
	d.TransactionBytes = 0
	return putRecoveryScan(b, *d)
}

func recoveryOutpointKey(op wire.OutPoint) []byte {
	k := make([]byte, 36)
	copy(k, op.Hash[:])
	binary.LittleEndian.PutUint32(k[32:], op.Index)
	return k
}

func recoveryBucketFor(mgr *waddrmgr.Manager) []byte {
	if mgr.RecoveryVersion() == 1 {
		return phaseARecoveryScanBucket
	}
	return recoveryScanBucket
}

func recoveryBucketExclusive(tx walletdb.ReadTx, mgr *waddrmgr.Manager) error {
	foreign := phaseARecoveryScanBucket
	if mgr.RecoveryVersion() == 1 {
		foreign = recoveryScanBucket
	}
	if tx.ReadBucket(foreign) != nil {
		return waddrmgr.ErrRecoveryState
	}
	return nil
}

func (s *RecoverySession) auditRecoveryScripts(ctx context.Context, tx walletdb.ReadTx, b walletdb.ReadBucket) (uint32, error) {
	ns := tx.ReadBucket(waddrmgrNamespaceKey)
	m, err := s.manager.CandidateRecoveryState(ns)
	if err != nil {
		return 0, err
	}
	keys := make([]*hdkeychain.ExtendedKey, 8)
	defer func() {
		for _, k := range keys {
			if k != nil {
				k.Zero()
			}
		}
	}()
	for i, x := range m.Branches {
		scope, err := s.manager.FetchScopedKeyManager(x.Scope)
		if err != nil {
			return 0, err
		}
		props, err := scope.AccountProperties(ns, 0)
		if err != nil {
			return 0, err
		}
		keys[i], err = props.AccountPubKey.Derive(x.Branch)
		if err != nil {
			return 0, waddrmgr.ErrRecoveryState
		}
	}
	var seen [8][4096]bool
	var tail [8]uint32
	var scripts uint32
	err = b.NestedReadBucket(recoveryScripts).ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		scripts++
		if scripts > s.manager.RecoveryInventoryLimit() || len(k) != 32 || v == nil {
			return waddrmgr.ErrRecoveryState
		}
		row, err := decodeRecoveryScriptLimit(v, s.manager.RecoveryIndexLimit())
		if err != nil {
			return err
		}
		idx := recoveryBranchIndex(row.Purpose, row.Branch)
		if idx < 0 || row.Index >= m.Branches[idx].DerivedNext {
			return waddrmgr.ErrRecoveryState
		}
		if s.manager.RecoveryVersion() == 1 {
			if seen[idx][row.Index] {
				return waddrmgr.ErrRecoveryState
			}
			seen[idx][row.Index] = true
			if row.Index+1 > tail[idx] {
				tail[idx] = row.Index + 1
			}
		}
		h := sha256.Sum256(row.Script)
		if !bytes.Equal(h[:], k) {
			return waddrmgr.ErrRecoveryState
		}
		child, err := keys[idx].Derive(row.Index)
		if err != nil {
			return waddrmgr.ErrRecoveryState
		}
		purpose := row.Purpose
		if s.manager.RecoveryVersion() == 1 && purpose == 49 && row.Branch == 1 {
			purpose = 84
		}
		expected, err := recoveryScriptForKey(child, purpose, s.params)
		child.Zero()
		if err != nil || !bytes.Equal(expected, row.Script) {
			return waddrmgr.ErrRecoveryState
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	if m.Ready && s.manager.RecoveryVersion() == 1 {
		// Immutable canonical outputs give a minimum discovered issuance. A pending
		// reorg may have removed an orphan output while retaining its larger public
		// address inventory, so this is deliberately a minimum, never exact equality.
		var discovered [8]uint32
		var observedOutputs uint32
		e := b.NestedReadBucket(recoveryOutputs).ForEach(func(k, v []byte) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			observedOutputs++
			if observedOutputs > MaxRecoveryOwnedOutputs {
				return waddrmgr.ErrRecoveryState
			}
			if len(k) != 36 || len(v) != 32 {
				return waddrmgr.ErrRecoveryState
			}
			row, e := decodeRecoveryScriptLimit(b.NestedReadBucket(recoveryScripts).Get(v), s.manager.RecoveryIndexLimit())
			if e != nil {
				return e
			}
			i := recoveryBranchIndex(row.Purpose, row.Branch)
			if i < 0 {
				return waddrmgr.ErrRecoveryState
			}
			if row.Index+1 > discovered[i] {
				discovered[i] = row.Index + 1
			}
			return nil
		})
		if e != nil {
			return 0, e
		}
		for i, branch := range m.Branches {
			if discovered[i] > branch.IssuedNext {
				return 0, waddrmgr.ErrRecoveryState
			}
			issued := branch.ImportedNext
			if discovered[i] > issued {
				issued = discovered[i]
			}
			minimum := issued + waddrmgr.RecoveryLookahead
			if minimum > 4096 {
				minimum = 4096
			}
			if tail[i] < minimum {
				tail[i] = minimum
			}
			for index := uint32(0); index < tail[i]; index++ {
				if seen[i][index] {
					continue
				}
				if err := ctx.Err(); err != nil {
					return 0, err
				}
				child, e := keys[i].Derive(index)
				if e == hdkeychain.ErrInvalidChild {
					continue
				}
				if child != nil {
					child.Zero()
				}
				return 0, waddrmgr.ErrRecoveryState
			}
		}
	}
	return scripts, nil
}

// The completed scanner is an immutable reconstruction checkpoint. Its row
// grammar/counts and derivations are audited without treating later live-wallet
// credits, spends, reorgs, or newly issued addresses as checkpoint corruption.
func (s *RecoverySession) auditPhaseAComplete(ctx context.Context, tx walletdb.ReadTx, b walletdb.ReadBucket) error {
	if _, e := s.auditRecoveryScripts(ctx, tx, b); e != nil {
		return e
	}
	d, e := readRecoveryScan(b)
	if e != nil {
		return e
	}
	var outputs, transactions uint32
	var total uint64
	e = b.NestedReadBucket(recoveryOutputs).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		outputs++
		if outputs > MaxRecoveryOwnedOutputs || len(k) != 36 || len(v) != 32 || b.NestedReadBucket(recoveryScripts).Get(v) == nil || b.NestedReadBucket(recoveryTransactions).Get(k[:32]) == nil {
			return waddrmgr.ErrRecoveryState
		}
		return nil
	})
	if e != nil {
		return e
	}
	e = b.NestedReadBucket(recoveryTransactions).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		transactions++
		if transactions > MaxRecoveryTransactions || len(k) != 32 || len(v) != 8 {
			return waddrmgr.ErrRecoveryState
		}
		n := binary.LittleEndian.Uint64(v)
		if n == 0 || n > wire.MaxBlockPayload {
			return waddrmgr.ErrRecoveryState
		}
		total += n
		if total > MaxRecoveryTransactionBytes {
			return waddrmgr.ErrRecoveryState
		}
		return nil
	})
	if e != nil {
		return e
	}
	if outputs != d.Outputs || transactions != d.Transactions || total != d.TransactionBytes {
		return waddrmgr.ErrRecoveryState
	}
	return nil
}
