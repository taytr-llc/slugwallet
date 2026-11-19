package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/psbt/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func withdrawalEligible(t *testing.T, w *Wallet) (int, error) {
	t.Helper()
	n := 0
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		tip := w.Manager.SyncedTo()
		items, e := w.findEligibleOutputs(tx, &waddrmgr.KeyScopeBIP0084, 0, 1, &tip, nil)
		n = len(items)
		return e
	})
	return n, e
}
func TestCandidateWithdrawalReservationAndCorruption(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	if n, e := withdrawalEligible(t, w); e != nil || n != 1 {
		t.Fatal("initial eligible coin", n, e)
	}
	if _, e := s.Prepare(context.Background(), v.Request); e != nil {
		t.Fatal(e)
	}
	op, _ := withdrawalOutpoint(v.Draft.Inputs[0])
	inputs := []*wire.TxIn{wire.NewTxIn(&op, nil, nil)}
	if n, e := withdrawalEligible(t, w); e != nil || n != 0 {
		t.Fatal("prepared coin selected", n, e)
	}
	if e := w.candidateWithdrawalCheckInputs(inputs); !errors.Is(e, ErrWithdrawalConflict) {
		t.Fatal("explicit prepared input bypass", e)
	}
	if e := s.Abandon(context.Background(), v.Request.OperationID, v.DraftDigest); e != nil {
		t.Fatal(e)
	}
	if n, e := withdrawalEligible(t, w); e != nil || n != 1 {
		t.Fatal("known unsigned abandon did not release", n, e)
	}
	request := v.Request
	request.OperationID = strings.Repeat("c", 64)
	d, e := s.Prepare(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := CandidateWithdrawalDraftDigest(d)
	tx, e := validateWithdrawalDraft(d)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Retain(context.Background(), request.OperationID, digest, tx.TxHash().String()); e != nil {
		t.Fatal(e)
	}
	if n, e := withdrawalEligible(t, w); e != nil || n != 0 {
		t.Fatal("retained coin selected", n, e)
	}
	if e := w.candidateWithdrawalCheckInputs(inputs); !errors.Is(e, ErrWithdrawalConflict) {
		t.Fatal("explicit retained input bypass", e)
	}
	// Removing a retained exclusion cannot silently make the corresponding coin
	// selectable: the immutable operation and exact index must agree.
	if e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(withdrawalNamespace).NestedReadWriteBucket(withdrawalRetained).Delete(withdrawalKey(op))
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), request.OperationID); !errors.Is(e, ErrWithdrawalCorrupt) {
		t.Fatal("missing retained index accepted", e)
	}
	if _, e := withdrawalEligible(t, w); !errors.Is(e, ErrWithdrawalCorrupt) {
		t.Fatal("corrupt reservation made coin free", e)
	}
	if empty, e := s.Empty(context.Background()); !errors.Is(e, ErrWithdrawalCorrupt) || empty {
		t.Fatal("corrupt store treated empty", e)
	}
	s.Close()
	if _, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID); !errors.Is(e, ErrWithdrawalCorrupt) {
		t.Fatal("corrupt reopen", e)
	}
}
func TestCandidateWithdrawalSetupAndOperationCapacity(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	if empty, e := s.Empty(context.Background()); e != nil || !empty {
		t.Fatal("fresh namespace not empty", e)
	}
	if _, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID); !errors.Is(e, ErrWithdrawalBusy) {
		t.Fatal("second handle admitted", e)
	}
	s.Close()
	if e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error { return tx.DeleteTopLevelBucket(withdrawalNamespace) }); e != nil {
		t.Fatal(e)
	}
	if _, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID); !errors.Is(e, ErrWithdrawalNotFound) {
		t.Fatal("absent namespace distinction", e)
	}
	s, e := w.CreateCandidateWithdrawals(context.Background(), v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for i := 0; i < 128; i++ {
		request := v.Request
		sum := sha256.Sum256([]byte(fmt.Sprintf("public capacity property %d", i)))
		request.OperationID = hex.EncodeToString(sum[:])
		d, e := s.Prepare(context.Background(), request)
		if e != nil {
			t.Fatalf("prepare %d: %v", i, e)
		}
		digest, e := CandidateWithdrawalDraftDigest(d)
		if e != nil {
			t.Fatal(e)
		}
		if d.Change.Index != uint32(i) {
			t.Fatal("cursor did not advance once", d.Change.Index, i)
		}
		if e := s.Abandon(context.Background(), request.OperationID, digest); e != nil {
			t.Fatal(e)
		}
	}
	if empty, e := s.Empty(context.Background()); e != nil || empty {
		t.Fatal("abandoned history was treated empty", e)
	}
	before := withdrawalCursorIndex(t, w)
	if _, e := s.Prepare(context.Background(), v.Request); !errors.Is(e, ErrWithdrawalCapacity) {
		t.Fatal("129th operation admitted", e)
	}
	if after := withdrawalCursorIndex(t, w); after != before || after != 128 {
		t.Fatal("capacity consumed an address", before, after)
	}
	s.Close()
	if _, e := w.OpenCandidateWithdrawals(context.Background(), strings.Repeat("d", 64)); !errors.Is(e, ErrWithdrawalCorrupt) {
		t.Fatal("binding replaced", e)
	}
	reopened, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if _, e := reopened.Prepare(context.Background(), v.Request); !errors.Is(e, ErrWithdrawalCapacity) {
		t.Fatal("reopen reset operation cap", e)
	}
}
func TestCandidateWithdrawalSigningRechecksOwnedLedger(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	if _, e := s.Prepare(context.Background(), v.Request); e != nil {
		t.Fatal(e)
	}
	retainedUnlock(t, w, retainedPrivPass)
	w.SetChainSynced(false)
	if got, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest); !errors.Is(e, ErrWithdrawalUnavailable) || got.RawHex != "" {
		t.Fatal("unsynced signing", e)
	}
	w.SetChainSynced(true)
	op, _ := withdrawalOutpoint(v.Draft.Inputs[0])
	w.LockOutpoint(op)
	if got, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest); !errors.Is(e, ErrWithdrawalUnavailable) || got.RawHex != "" {
		t.Fatal("locked input signing", e)
	}
	w.UnlockOutpoint(op)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := s.Sign(ctx, v.Request.OperationID, v.DraftDigest); !errors.Is(e, context.Canceled) || got.RawHex != "" {
		t.Fatal("cancelled signing", e)
	}
	// Public transaction-store change: losing the known unspent record makes the
	// saved draft unavailable; it never causes reselection or replacement signing.
	if e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(wtxmgrNamespaceKey).NestedReadWriteBucket([]byte("u"))
		var key []byte
		if e := b.ForEach(func(k, v []byte) error { key = append([]byte{}, k...); return nil }); e != nil {
			return e
		}
		return b.Delete(key)
	}); e != nil {
		t.Fatal(e)
	}
	if got, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest); !errors.Is(e, ErrWithdrawalUnavailable) || got.RawHex != "" {
		t.Fatal("missing unspent signed", e)
	}
	if record, e := s.Lookup(context.Background(), v.Request.OperationID); e != nil || record.State != "prepared" || record.DraftDigest != v.DraftDigest {
		t.Fatal("signing altered draft", e)
	}
}

func TestCandidateWithdrawalDeterministicSixteenInputPrefix(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	script, _ := hex.DecodeString(v.Draft.Inputs[0].Script)
	msg := wire.NewMsgTx(1)
	msg.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, nil, nil))
	for i := 0; i < 17; i++ {
		msg.AddTxOut(wire.NewTxOut(1000000, script))
	}
	rec, e := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	if e != nil {
		t.Fatal(e)
	}
	blockHash, _ := chainhash.NewHashFromStr(v.Draft.Inputs[0].BlockHash)
	block := wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: *blockHash, Height: 109}, Time: time.Unix(1, 0)}
	if e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		b := ns.NestedReadWriteBucket([]byte("u"))
		var old []byte
		if e := b.ForEach(func(k, v []byte) error { old = append([]byte{}, k...); return nil }); e != nil {
			return e
		}
		if e := b.Delete(old); e != nil {
			return e
		}
		if e := w.TxStore.InsertTx(ns, rec, &block); e != nil {
			return e
		}
		for i := uint32(0); i < 17; i++ {
			if e := w.TxStore.AddCredit(ns, rec, &block, i, false); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	request := v.Request
	request.AmountAtoms = 16998000
	if _, e := s.Prepare(context.Background(), request); !errors.Is(e, ErrWithdrawalUnavailable) {
		t.Fatal("selected seventeenth input", e)
	}
	if withdrawalCursorIndex(t, w) != 0 {
		t.Fatal("insufficient funding consumed change")
	}
	request.AmountAtoms = 15998000
	d, e := s.Prepare(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Inputs) != 16 || d.TotalInputAtoms != 16000000 {
		t.Fatal("wrong deterministic prefix", len(d.Inputs), d.TotalInputAtoms)
	}
	for i, in := range d.Inputs {
		if in.TxID != rec.Hash.String() || in.OutputIndex != uint32(i) {
			t.Fatal("equal-value numeric vout order differs", i, in.OutputIndex)
		}
	}
	// Allocation, fee and dust are also checked by the independent pure corpus;
	// this property specifically proves bounded live ledger selection/tie order.
}

func TestCandidateWithdrawalGenericSignersRespectReservations(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	if _, e := s.Prepare(context.Background(), v.Request); e != nil {
		t.Fatal(e)
	}
	check := func() {
		t.Helper()
		tx, e := validateWithdrawalDraft(v.Draft)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := w.SignTransaction(tx, txscript.SigHashAll, nil, nil, nil); !errors.Is(e, ErrWithdrawalConflict) {
			t.Fatal("generic raw signer bypass", e)
		}
		packet, e := psbt.NewFromUnsignedTx(tx)
		if e != nil {
			t.Fatal(e)
		}
		script, _ := hex.DecodeString(v.Draft.Inputs[0].Script)
		packet.Inputs[0].WitnessUtxo = wire.NewTxOut(v.Draft.Inputs[0].Atoms, script)
		if e := w.FinalizePsbt(&waddrmgr.KeyScopeBIP0084, 0, packet); !errors.Is(e, ErrWithdrawalConflict) {
			t.Fatal("generic PSBT signer bypass", e)
		}
		if _, e := w.FundPsbt(packet, &waddrmgr.KeyScopeBIP0084, 1, 0, 1000, CoinSelectionLargest); !errors.Is(e, ErrWithdrawalConflict) {
			t.Fatal("generic PSBT funding bypass", e)
		}
		if len(tx.TxIn[0].Witness) != 0 || len(tx.TxIn[0].SignatureScript) != 0 || len(packet.Inputs[0].FinalScriptWitness) != 0 {
			t.Fatal("generic refusal left signature material")
		}
	}
	check()
	if e := s.Retain(context.Background(), v.Request.OperationID, v.DraftDigest, v.ExpectedSigned.TxID); e != nil {
		t.Fatal(e)
	}
	check()
}
func TestCandidateWithdrawalWalletStopBeforeCommit(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	s.checkpoint = func(stage string) error {
		if stage == "before_commit" {
			w.Stop()
		}
		return nil
	}
	if d, e := s.Prepare(context.Background(), v.Request); !errors.Is(e, ErrWithdrawalClosed) || d.OperationID != "" {
		t.Fatal("wallet stopped before commit", e)
	}
	if withdrawalCursorIndex(t, w) != 0 {
		t.Fatal("stopped wallet consumed change")
	}
	if e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		var meta withdrawalMeta
		if e := withdrawalDecode(tx.ReadBucket(withdrawalNamespace).Get(withdrawalMetaKey), 2048, &meta); e != nil {
			return e
		}
		if meta.RecordCount != 0 || meta.ActiveOperationID != "" {
			t.Fatal("stopped wallet retained draft")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if ids, e := s.OperationIDs(context.Background()); !errors.Is(e, ErrWithdrawalClosed) || ids != nil {
		t.Fatal("stopped wallet disclosed inventory", e)
	}
}
func TestCandidateWithdrawalOwnedInventory(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, _, s := withdrawalFixture(t, v)
	if ids, e := s.OperationIDs(context.Background()); e != nil || ids == nil || len(ids) != 0 {
		t.Fatal("empty inventory", e)
	}
	a := v.Request
	a.OperationID = strings.Repeat("b", 64)
	d, e := s.Prepare(context.Background(), a)
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := CandidateWithdrawalDraftDigest(d)
	if e := s.Abandon(context.Background(), a.OperationID, digest); e != nil {
		t.Fatal(e)
	}
	b := v.Request
	b.OperationID = strings.Repeat("a", 64)
	if _, e := s.Prepare(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	ids, e := s.OperationIDs(context.Background())
	if e != nil || len(ids) != 2 || ids[0] != b.OperationID || ids[1] != a.OperationID {
		t.Fatal("inventory omitted/reordered state", ids, e)
	}
	ids[0] = strings.Repeat("c", 64)
	again, e := s.OperationIDs(context.Background())
	if e != nil || again[0] != b.OperationID {
		t.Fatal("caller changed owned inventory", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ids, e := s.OperationIDs(ctx); !errors.Is(e, context.Canceled) || ids != nil {
		t.Fatal("cancelled inventory disclosure", e)
	}
}
