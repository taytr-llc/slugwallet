package wallet

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func activityAddUnmined(t *testing.T, w *Wallet, n byte) chainhash.Hash {
	t.Helper()
	msg := wire.NewMsgTx(1)
	op := wire.OutPoint{Hash: chainhash.Hash{n}, Index: 0}
	msg.AddTxIn(wire.NewTxIn(&op, nil, nil))
	msg.AddTxOut(wire.NewTxOut(int64(n), []byte{0x6a}))
	rec, e := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(int64(n), 0))
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if e := w.TxStore.InsertTx(ns, rec, nil); e != nil {
			return e
		}
		return w.TxStore.AddCredit(ns, rec, nil, 0, false)
	})
	if e != nil {
		t.Fatal(e)
	}
	return rec.Hash
}

type activityBarrierDB struct {
	walletdb.DB
	entered, release chan struct{}
	calls            atomic.Int32
}

func (d *activityBarrierDB) View(fn func(walletdb.ReadTx) error, reset func()) error {
	d.calls.Add(1)
	return d.DB.View(func(tx walletdb.ReadTx) error { close(d.entered); <-d.release; return fn(tx) }, reset)
}
func TestOwnActivityWalletAtomicAndCancellation(t *testing.T) {
	l := retainedLoader(t)
	w := retainedCreate(t, l, retainedRecoveryFixture(t, "zero256"))
	if !w.Locked() {
		t.Fatal("read-only test wallet should be locked")
	}
	first := activityAddUnmined(t, w, 1)
	initial, e := w.CaptureOwnActivity(context.Background())
	if e != nil || len(initial.Records) != 1 || initial.Records[0].TxID != first {
		t.Fatal("initial", e)
	}
	// Reserve DB map space before holding a read transaction so an unrelated
	// writer can commit a same-tip mutation without needing an mmap resize.
	if e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		b, e := tx.CreateTopLevelBucket([]byte("activity-test-padding"))
		if e != nil {
			return e
		}
		return b.Put([]byte("padding"), make([]byte, 1<<20))
	}); e != nil {
		t.Fatal(e)
	}
	base := w.db
	barrier := &activityBarrierDB{DB: base, entered: make(chan struct{}), release: make(chan struct{})}
	w.db = barrier
	type result struct {
		snapshot OwnActivitySnapshot
		err      error
	}
	done := make(chan result, 1)
	go func() { v, e := w.CaptureOwnActivity(context.Background()); done <- result{v, e} }()
	select {
	case <-barrier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not enter atomic read")
	}
	// Keep writer on the retained concrete DB, not the capture-only wrapper.
	writer := make(chan error, 1)
	msg := wire.NewMsgTx(1)
	op := wire.OutPoint{Hash: chainhash.Hash{2}}
	msg.AddTxIn(wire.NewTxIn(&op, nil, nil))
	msg.AddTxOut(wire.NewTxOut(2, []byte{0x6a}))
	rec, e := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(2, 0))
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		writer <- walletdb.Update(base, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
			if e := w.TxStore.InsertTx(ns, rec, nil); e != nil {
				return e
			}
			return w.TxStore.AddCredit(ns, rec, nil, 0, false)
		})
	}()
	select {
	case e = <-writer:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		close(barrier.release)
		<-done
		t.Fatal("same-tip write did not finish with snapshot retained")
	}
	close(barrier.release)
	got := <-done
	w.db = base
	if got.err != nil || !reflect.DeepEqual(got.snapshot, initial) || barrier.calls.Load() != 1 {
		t.Fatal("capture mixed database generations", got.err)
	}
	fresh, e := w.CaptureOwnActivity(context.Background())
	if e != nil || len(fresh.Records) != 2 || fresh.Records[0].TxID != rec.Hash || fresh.SyncedHash != initial.SyncedHash {
		t.Fatal("explicit fresh snapshot", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	barrier = &activityBarrierDB{DB: base, entered: make(chan struct{}), release: make(chan struct{})}
	w.db = barrier
	go func() { v, e := w.CaptureOwnActivity(ctx); done <- result{v, e} }()
	<-barrier.entered
	cancel()
	select {
	case <-done:
		t.Fatal("cancelled database read returned before joined read completed")
	default:
	}
	close(barrier.release)
	got = <-done
	w.db = base
	if !errors.Is(got.err, context.Canceled) || got.snapshot.Records != nil || got.snapshot.Version != 0 {
		t.Fatal("cancelled partial capture", got.err)
	}

	if _, e = w.CaptureOwnActivity(nil); !errors.Is(e, ErrOwnActivityInvalid) {
		t.Fatal(e)
	}
	if e = l.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
	if _, e = w.CaptureOwnActivity(context.Background()); !errors.Is(e, ErrOwnActivityUnavailable) {
		t.Fatal(e)
	}
}
func TestOwnActivityCheapProfileBeforeDatabase(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("tagged profile refusal")
	}
	w := &Wallet{}
	if _, e := w.CaptureOwnActivity(context.Background()); !errors.Is(e, ErrOwnActivityProfile) {
		t.Fatal("cheap profile reached owner/database", e)
	}
}
