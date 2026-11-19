package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

type withdrawalReferenceCase struct {
	Name           string                     `json:"name"`
	Fixture        string                     `json:"fixture"`
	Request        CandidateWithdrawalRequest `json:"request"`
	Draft          CandidateWithdrawalDraft   `json:"draft"`
	CanonicalDraft string                     `json:"canonical_draft"`
	DraftDigest    string                     `json:"draft_digest"`
	ExpectedSigned CandidateWithdrawalSigned  `json:"expected_signed"`
}
type withdrawalReference struct {
	Cases          []withdrawalReferenceCase `json:"cases"`
	NegativeDrafts []struct {
		Name  string                   `json:"name"`
		Draft CandidateWithdrawalDraft `json:"draft"`
	} `json:"negative_drafts"`
	NegativeSigned []struct {
		Name   string `json:"name"`
		Case   string `json:"case"`
		RawHex string `json:"raw_hex"`
	} `json:"negative_signed"`
}

func withdrawalVectors(t *testing.T) withdrawalReference {
	t.Helper()
	raw, e := os.ReadFile("testdata/candidate-withdrawals/reference-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "d7c7b1e4c94e02f734a162b5974749853c91828ea1a0a4c4446c379bddc841c3" {
		t.Fatal("independent corpus changed")
	}
	var r withdrawalReference
	if json.Unmarshal(raw, &r) != nil || len(r.Cases) != 24 || len(r.NegativeDrafts) != 13 || len(r.NegativeSigned) != 5 {
		t.Fatal("independent corpus shape")
	}
	return r
}
func TestCandidateWithdrawalIndependentShapesAndSignatures(t *testing.T) {
	r := withdrawalVectors(t)
	cases := map[string]withdrawalReferenceCase{}
	for _, v := range r.Cases {
		t.Run(v.Name, func(t *testing.T) {
			cases[v.Name] = v
			raw, e := json.Marshal(v.Draft)
			if e != nil || string(raw) != v.CanonicalDraft {
				t.Fatal("canonical draft differs from independent bytes", e)
			}
			digest, e := CandidateWithdrawalDraftDigest(v.Draft)
			if e != nil || digest != v.DraftDigest {
				t.Fatal("draft digest differs from independent reference", e)
			}
			signed, e := hex.DecodeString(v.ExpectedSigned.RawHex)
			if e != nil || validateWithdrawalSigned(v.Draft, signed) != nil {
				t.Fatal("independent signed transaction rejected")
			}
			var parsed CandidateWithdrawalDraft
			if withdrawalDecode(raw, 16384, &parsed) != nil || !reflect.DeepEqual(parsed, v.Draft) {
				t.Fatal("roundtrip changed independent value")
			}
		})
	}
	for _, n := range r.NegativeDrafts {
		t.Run(n.Name, func(t *testing.T) {
			if _, e := CandidateWithdrawalDraftDigest(n.Draft); e == nil {
				t.Fatal("independent negative accepted")
			}
		})
	}
	for _, n := range r.NegativeSigned {
		t.Run(n.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(n.RawHex)
			if validateWithdrawalSigned(cases[n.Case].Draft, raw) == nil {
				t.Fatal("independent signed negative accepted")
			}
		})
	}
}

// Deposits the original retained public payout into a real wallet ledger. This
// tests authoring/ownership against independent bytes; no chain validity is
// inferred from the synthetic synchronization setup. Actual-node acceptance is
// a separate normal-PoW gate.
func withdrawalFixture(t *testing.T, v withdrawalReferenceCase) (*Loader, *Wallet, *CandidateWithdrawals) {
	t.Helper()
	l := retainedLoader(t)
	w := retainedCreate(t, l, retainedRecoveryFixture(t, v.Fixture))
	_ = retainedAddress(t, w, waddrmgr.KeyScopeBIP0084, false)
	raw, e := os.ReadFile("testdata/candidate-withdrawals/reference-inputs/public/original-set61-payout.json")
	if e != nil {
		t.Fatal(e)
	}
	var original struct {
		Batches []struct {
			Raw string `json:"raw"`
		} `json:"batches"`
	}
	if json.Unmarshal(raw, &original) != nil || len(original.Batches) != 1 {
		t.Fatal("original payout shape")
	}
	txraw, e := hex.DecodeString(original.Batches[0].Raw)
	if e != nil {
		t.Fatal(e)
	}
	var funding wire.MsgTx
	if e := funding.Deserialize(bytes.NewReader(txraw)); e != nil {
		t.Fatal(e)
	}
	rec, e := wtxmgr.NewTxRecordFromMsgTx(&funding, time.Unix(1700000000, 0))
	if e != nil {
		t.Fatal(e)
	}
	blockHash, _ := chainhash.NewHashFromStr(v.Draft.Inputs[0].BlockHash)
	tipHash, _ := chainhash.NewHashFromStr(v.Draft.TipHash)
	e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		block := &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: *blockHash, Height: v.Draft.Inputs[0].BlockHeight}, Time: time.Unix(1700000000, 0)}
		if e := w.TxStore.InsertTx(ns, rec, block); e != nil {
			return e
		}
		if e := w.TxStore.AddCredit(ns, rec, block, v.Draft.Inputs[0].OutputIndex, false); e != nil {
			return e
		}
		return w.Manager.SetSyncedTo(tx.ReadWriteBucket(waddrmgrNamespaceKey), &waddrmgr.BlockStamp{Hash: *tipHash, Height: v.Draft.TipHeight, Timestamp: time.Unix(1700000000, 0)})
	})
	if e != nil {
		t.Fatal(e)
	}
	w.SetChainSynced(true)
	s, e := w.CreateCandidateWithdrawals(context.Background(), v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return l, w, s
}
func withdrawalCursorIndex(t *testing.T, w *Wallet) uint32 {
	t.Helper()
	m, e := w.recoveryPublicManifest()
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range m.Accounts {
		if a.Purpose == 84 {
			return a.NextInternal
		}
	}
	t.Fatal("native scope missing")
	return 0
}
func TestCandidateWithdrawalActualWalletIndependentOriginals(t *testing.T) {
	r := withdrawalVectors(t)
	for _, v := range r.Cases {
		if !strings.Contains(v.Name, "-original-to-") {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			l, w, s := withdrawalFixture(t, v)
			d, e := s.Prepare(context.Background(), v.Request)
			if e != nil || !reflect.DeepEqual(d, v.Draft) {
				t.Fatalf("prepared draft differs: %v\ngot=%+v", e, d)
			}
			if withdrawalCursorIndex(t, w) != 1 {
				t.Fatal("change cursor did not commit exactly once")
			}
			again, e := s.Prepare(context.Background(), v.Request)
			if e != nil || !reflect.DeepEqual(again, d) || withdrawalCursorIndex(t, w) != 1 {
				t.Fatal("retry reallocated draft", e)
			}
			if got, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest); e == nil || got.RawHex != "" {
				t.Fatal("locked wallet signed")
			}
			retainedUnlock(t, w, retainedPrivPass)
			signed, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest)
			if e != nil || signed != v.ExpectedSigned {
				t.Fatalf("signature differs from independent bytes: %v", e)
			}
			record, e := s.Lookup(context.Background(), v.Request.OperationID)
			if e != nil || record.State != "prepared" || record.RetainedTxID != "" {
				t.Fatal("scratch signing mutated durable state", e)
			}
			e = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				rows, e := w.TxStore.UnminedTxs(tx.ReadBucket(wtxmgrNamespaceKey))
				if len(rows) != 0 {
					t.Fatal("signing queued an unmined transaction")
				}
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			other := v.Request
			other.OperationID = strings.Repeat("a", 64)
			if _, e := s.Prepare(context.Background(), other); !errors.Is(e, ErrWithdrawalBusy) {
				t.Fatal("active draft did not reserve input", e)
			}
			if e := s.Retain(context.Background(), v.Request.OperationID, v.DraftDigest, signed.TxID); e != nil {
				t.Fatal(e)
			}
			if e := s.Abandon(context.Background(), v.Request.OperationID, v.DraftDigest); !errors.Is(e, ErrWithdrawalConflict) {
				t.Fatal("retained input was released", e)
			}
			if _, e := s.Prepare(context.Background(), other); !errors.Is(e, ErrWithdrawalUnavailable) {
				t.Fatal("retained input reselected", e)
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			if e := l.UnloadWallet(); e != nil {
				t.Fatal(e)
			}
			w.Manager.Close()
			w, e = l.OpenExistingWallet(retainedPubPass, false)
			if e != nil {
				t.Fatal(e)
			}
			w.SetChainSynced(true)
			reopened, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			got, e := reopened.Lookup(context.Background(), v.Request.OperationID)
			if e != nil || got.State != "retained" || got.RetainedTxID != signed.TxID || got.DraftDigest != v.DraftDigest {
				t.Fatal("reopen changed exact retained record", e)
			}
			if _, e := reopened.Prepare(context.Background(), other); !errors.Is(e, ErrWithdrawalUnavailable) {
				t.Fatal("reopen/time released permanent exclusion", e)
			}
		})
	}
}
func TestCandidateWithdrawalRollbackUncertaintyAndReopen(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	fault := errors.New("test commit fault")
	s.checkpoint = func(stage string) error {
		if stage == "before_commit" {
			return fault
		}
		return nil
	}
	if _, e := s.Prepare(context.Background(), v.Request); !errors.Is(e, fault) {
		t.Fatal(e)
	}
	if withdrawalCursorIndex(t, w) != 0 {
		t.Fatal("rollback consumed change")
	}
	if _, e := s.Lookup(context.Background(), v.Request.OperationID); !errors.Is(e, ErrWithdrawalNotFound) {
		t.Fatal("rollback retained draft", e)
	}
	s.checkpoint = func(stage string) error {
		if stage == "after_commit" {
			return fault
		}
		return nil
	}
	if got, e := s.Prepare(context.Background(), v.Request); !errors.Is(e, ErrWithdrawalOutcomeUnknown) || got.OperationID != "" {
		t.Fatal("uncertain write disclosed draft", e)
	}
	if _, e := s.Lookup(context.Background(), v.Request.OperationID); !errors.Is(e, ErrWithdrawalOutcomeUnknown) {
		t.Fatal("poisoned owner recovered without reopen", e)
	}
	s.Close()
	s, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Lookup(context.Background(), v.Request.OperationID)
	if e != nil || !reflect.DeepEqual(got.Draft, v.Draft) || withdrawalCursorIndex(t, w) != 1 {
		t.Fatal("exact uncertain draft not recovered", e)
	}
	if e := s.Abandon(context.Background(), v.Request.OperationID, v.DraftDigest); e != nil {
		t.Fatal(e)
	}
	if withdrawalCursorIndex(t, w) != 1 {
		t.Fatal("abandon rolled change cursor backwards")
	}
	if _, e := s.Prepare(context.Background(), v.Request); !errors.Is(e, ErrWithdrawalConflict) {
		t.Fatal("abandoned operation revived", e)
	}
}
func TestCandidateWithdrawalCancelJoinAndNoSignature(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	if _, e := s.Prepare(context.Background(), v.Request); e != nil {
		t.Fatal(e)
	}
	retainedUnlock(t, w, retainedPrivPass)
	entered, release := make(chan struct{}), make(chan struct{})
	s.checkpoint = func(stage string) error {
		if stage == "before_sign" {
			close(entered)
			<-release
		}
		return nil
	}
	type answer struct {
		v CandidateWithdrawalSigned
		e error
	}
	result := make(chan answer, 1)
	go func() {
		v, e := s.Sign(context.Background(), v.Request.OperationID, v.DraftDigest)
		result <- answer{v, e}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("sign did not enter")
	}
	if _, e := s.Lookup(context.Background(), v.Request.OperationID); !errors.Is(e, ErrWithdrawalBusy) {
		t.Fatal("concurrent owner did not fail fast", e)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close did not join signing")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case a := <-result:
		if !errors.Is(a.e, context.Canceled) || a.v.RawHex != "" {
			t.Fatal("cancelled signing published", a.e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sign did not join")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not finish")
	}
	fresh, e := w.OpenCandidateWithdrawals(context.Background(), v.Draft.BindingID)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	got, e := fresh.Lookup(context.Background(), v.Request.OperationID)
	if e != nil || got.State != "prepared" {
		t.Fatal("cancel released/changed reservation", e)
	}
}
func TestCandidateWithdrawalCanonicalAndContainerBounds(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	for _, raw := range [][]byte{[]byte(v.CanonicalDraft + "\n"), bytes.Replace([]byte(v.CanonicalDraft), []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace([]byte(v.CanonicalDraft), []byte(`"inputs":[`), []byte(`"inputs":null,"unexpected":[`), 1)} {
		var got CandidateWithdrawalDraft
		if withdrawalDecode(raw, 16384, &got) == nil {
			t.Fatal("noncanonical input accepted")
		}
	}
	raw, _ := hex.DecodeString(v.Draft.UnsignedTxHex)
	hostile := append(append([]byte{}, raw[:4]...), 0xfe, 0xff, 0xff, 0xff, 0x7f)
	if withdrawalFrame(hostile, false) {
		t.Fatal("hostile count passed preflight")
	}
}
func TestCandidateWithdrawalCheapRefusal(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("tagged profile check")
	}
	w := new(Wallet)
	if _, e := w.CreateCandidateWithdrawals(context.Background(), strings.Repeat("1", 64)); !errors.Is(e, ErrWithdrawalProfile) {
		t.Fatal(e)
	}
	if _, e := w.OpenCandidateWithdrawals(context.Background(), strings.Repeat("1", 64)); !errors.Is(e, ErrWithdrawalProfile) {
		t.Fatal(e)
	}
}

func TestCandidateWithdrawalInitialLedger(t *testing.T) {
	v := withdrawalVectors(t).Cases[0]
	_, w, s := withdrawalFixture(t, v)
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		if _, e := s.audit(context.Background(), tx); e != nil {
			t.Fatalf("initial namespace audit: %v", e)
		}
		r, e := w.TxStore.NewCandidateCreditReader(tx.ReadBucket(wtxmgrNamespaceKey))
		if e != nil {
			return e
		}
		n := 0
		e = r.Visit(context.Background(), func(c wtxmgr.Credit) error {
			n++
			branch, index, e := s.path(tx, c.PkScript)
			if e != nil {
				t.Fatalf("owned path: %v", e)
			}
			if branch != 0 || index != 0 {
				t.Fatal("unexpected funding path")
			}
			return nil
		})
		if e != nil {
			t.Fatalf("bounded previous credit read: %v", e)
		}
		if n != 1 {
			t.Fatal("unexpected credit count", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
