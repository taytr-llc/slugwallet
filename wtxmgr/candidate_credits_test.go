package wtxmgr

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestCandidateCreditsOriginalPayoutParser(t *testing.T) {
	data, e := os.ReadFile("../wallet/testdata/candidate-withdrawals/reference-inputs/public/original-set61-payout.json")
	if e != nil {
		t.Fatal(e)
	}
	var saved struct {
		Batches []struct {
			Raw  string `json:"raw"`
			TxID string `json:"txid"`
		} `json:"batches"`
	}
	if json.Unmarshal(data, &saved) != nil || len(saved.Batches) != 1 {
		t.Fatal("public original shape")
	}
	raw, _ := hex.DecodeString(saved.Batches[0].Raw)
	hash, _ := chainhash.NewHashFromStr(saved.Batches[0].TxID)
	for i, want := range []int64{4950000000, 2970000000, 79999000} {
		atoms, script, coinbase, e := candidatePreviousOutput(context.Background(), raw, *hash, uint32(i))
		if e != nil || atoms != want || len(script) != 22 || coinbase {
			t.Fatalf("original output %d: atoms=%d len=%d coinbase=%t err=%v", i, atoms, len(script), coinbase, e)
		}
	}
}

// The visited-row bound counts skipped (already spent by an unmined input)
// rows too; it is not a bound on only the useful result set.
func TestCandidateCreditsVisitedBoundBeforeSkips(t *testing.T) {
	s, db, e := testStore(t)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	put := func(first, last int) {
		t.Helper()
		if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(namespaceKey)
			for i := first; i < last; i++ {
				var h chainhash.Hash
				binary.LittleEndian.PutUint32(h[:4], uint32(i+1))
				k := canonicalOutPoint(&h, 0)
				if e := ns.NestedReadWriteBucket(bucketUnspent).Put(k, make([]byte, 36)); e != nil {
					return e
				}
				if e := ns.NestedReadWriteBucket(bucketUnminedInputs).Put(k, []byte{1}); e != nil {
					return e
				}
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	read := func(ctx context.Context) error {
		return walletdb.View(db, func(tx walletdb.ReadTx) error {
			r, e := s.NewCandidateCreditReader(tx.ReadBucket(namespaceKey))
			if e != nil {
				return e
			}
			return r.Visit(ctx, func(Credit) error { t.Fatal("skipped row escaped"); return nil })
		})
	}
	put(0, 4096)
	if e := read(context.Background()); e != nil {
		t.Fatal("4096 skipped rows", e)
	}
	put(4096, 4097)
	if e := read(context.Background()); !errors.Is(e, ErrCandidateCreditCapacity) {
		t.Fatal("4097 rows did not fail capacity", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := read(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled scan", e)
	}
}

// A large but structurally valid previous transaction exercises byte budgets
// without using a claimant count to allocate an input/output object array.
func TestCandidateCreditsPreviousTransactionBudgets(t *testing.T) {
	s, db, e := testStore(t)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	msg := wire.NewMsgTx(1)
	prev := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	msg.AddTxIn(wire.NewTxIn(&prev, nil, nil))
	msg.AddTxOut(wire.NewTxOut(123456, append([]byte{0, 20}, make([]byte, 20)...)))
	// With a five-byte CompactSize, the fixed remainder is 86 bytes.
	msg.TxIn[0].SignatureScript = make([]byte, CandidateCreditMaxTransactionBytes-86)
	rec, e := NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	if e != nil {
		t.Fatal(e)
	}
	if len(rec.SerializedTx) != CandidateCreditMaxTransactionBytes {
		t.Fatal("model transaction size", len(rec.SerializedTx))
	}
	block := BlockMeta{Block: Block{Hash: chainhash.Hash{2}, Height: 1}, Time: time.Unix(1, 0)}
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		if e := s.InsertTx(ns, rec, &block); e != nil {
			return e
		}
		return s.AddCredit(ns, rec, &block, 0, false)
	}); e != nil {
		t.Fatal(e)
	}
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		r, e := s.NewCandidateCreditReader(tx.ReadBucket(namespaceKey))
		if e != nil {
			return e
		}
		for i := 0; i < 4; i++ {
			c, ok, e := r.Lookup(context.Background(), wire.OutPoint{Hash: rec.Hash})
			if e != nil || !ok || c.Amount != 123456 || len(c.PkScript) != 22 {
				t.Fatalf("bounded lookup %d: %v", i, e)
			}
		}
		if _, _, e := r.Lookup(context.Background(), wire.OutPoint{Hash: rec.Hash}); !errors.Is(e, ErrCandidateCreditCapacity) {
			t.Fatal("aggregate byte bound", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// A corrupt oversized stored previous record is rejected before parsing it.
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		k, v := existsTxRecord(ns, &rec.Hash, &block.Block)
		return ns.NestedReadWriteBucket(bucketTxRecords).Put(k, append(append([]byte{}, v...), 0))
	}); e != nil {
		t.Fatal(e)
	}
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		r, e := s.NewCandidateCreditReader(tx.ReadBucket(namespaceKey))
		if e != nil {
			return e
		}
		_, _, e = r.Lookup(context.Background(), wire.OutPoint{Hash: rec.Hash})
		return e
	}); !errors.Is(e, ErrCandidateCreditCapacity) {
		t.Fatal("individual byte bound", e)
	}
}

func TestCandidateCreditsPreviousFraming(t *testing.T) {
	msg := wire.NewMsgTx(1)
	msg.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, nil, nil))
	msg.AddTxOut(wire.NewTxOut(99, append([]byte{0, 20}, make([]byte, 20)...)))
	var b bytes.Buffer
	if e := msg.Serialize(&b); e != nil {
		t.Fatal(e)
	}
	raw := b.Bytes()
	hash := msg.TxHash()
	cases := [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 0), append(append([]byte{}, raw[:4]...), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f), append(append([]byte{}, raw[:4]...), append([]byte{0xfd, 1, 0}, raw[5:]...)...)}
	for i, v := range cases {
		if _, _, _, e := candidatePreviousOutput(context.Background(), v, hash, 0); !errors.Is(e, ErrCandidateCreditCorrupt) {
			t.Fatalf("framing %d: %v", i, e)
		}
	}
	if _, _, _, e := candidatePreviousOutput(context.Background(), raw, chainhash.Hash{4}, 0); !errors.Is(e, ErrCandidateCreditCorrupt) {
		t.Fatal("wrong hash", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, e := candidatePreviousOutput(ctx, raw, hash, 0); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled parser", e)
	}
}
