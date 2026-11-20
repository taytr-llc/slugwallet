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
	"testing"
	"time"

	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func currentExpected(t *testing.T) map[string]recovery.Manifest {
	t.Helper()
	raw, e := os.ReadFile("testdata/hosted-current-recovery/public.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "e5b71e541b8fd41328dc46ccfd4c14fb9f3de724eea34e9d2fec3d54b349ed3c" {
		t.Fatal("independent public reference changed")
	}
	var v struct {
		Actual map[string]recovery.Manifest `json:"inherited_actual_manifests"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v.Actual
}

func TestCurrentRecoveryCaptureOwnedFixtureInventory(t *testing.T) {
	expected := currentExpected(t)
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			l := retainedLoader(t)
			w := retainedCreate(t, l, retainedRecoveryFixture(t, fixture))
			if !w.Locked() {
				t.Fatal("must remain locked")
			}
			retainedAddress(t, w, waddrmgr.KeyScopeBIP0084, false)
			retainedAddress(t, w, waddrmgr.KeyScopeBIP0084, true)
			before := time.Now().UnixMilli()
			c, e := w.CaptureCurrentRecovery(context.Background())
			after := time.Now().UnixMilli()
			if e != nil || c == nil {
				t.Fatal(e)
			}
			if c.owner != w || c.manager != w.Manager || !reflect.DeepEqual(c.Manifest(), expected[fixture]) || c.CapturedAtMS() < before || c.CapturedAtMS() > after {
				t.Fatal("independent inventory/owner/time mismatch")
			}
			id, e := hex.DecodeString(c.CaptureID())
			if e != nil || len(id) != 32 || bytes.Equal(id, make([]byte, 32)) {
				t.Fatal("capture identity")
			}
			changed := c.Manifest()
			changed.Accounts[2].NextInternal = 4096
			if !reflect.DeepEqual(c.Manifest(), expected[fixture]) {
				t.Fatal("caller mutated retained capture")
			}
			fresh, e := w.CaptureCurrentRecovery(context.Background())
			if e != nil || fresh == c || fresh.CaptureID() == c.CaptureID() || fresh.owner != w {
				t.Fatal("new capture identity", e)
			}
			if !w.Locked() || w.ChainClient() != nil {
				t.Fatal("public capture unlocked or attached backend")
			}
			// JSON cannot initialize any live authority, even from a public manifest.
			var fake CurrentRecoveryCapture
			if e = json.Unmarshal([]byte(`{"manifest":{},"id":"claimant"}`), &fake); e != nil {
				t.Fatal(e)
			}
			if fake.owner != nil || fake.manager != nil || fake.CaptureID() != "" || fake.CapturedAtMS() != 0 || !reflect.DeepEqual(fake.Manifest(), recovery.Manifest{}) {
				t.Fatal("JSON acquired capture fields")
			}
		})
	}
}

func TestCurrentRecoveryOneViewAndConcurrentCursorCommit(t *testing.T) {
	l := retainedLoader(t)
	w := retainedCreate(t, l, retainedRecoveryFixture(t, "zero256"))
	initial, e := w.CaptureCurrentRecovery(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	// Pre-reserve map space so writer can commit while an old read is retained.
	if e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		b, e := tx.CreateTopLevelBucket([]byte("current-test-padding"))
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
		c *CurrentRecoveryCapture
		e error
	}
	done := make(chan result, 1)
	go func() { c, e := w.CaptureCurrentRecovery(context.Background()); done <- result{c, e} }()
	select {
	case <-barrier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not enter View")
	}
	mgr, e := w.Manager.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	if e != nil {
		close(barrier.release)
		<-done
		t.Fatal(e)
	}
	write := make(chan error, 1)
	go func() {
		write <- walletdb.Update(base, func(tx walletdb.ReadWriteTx) error {
			_, e := mgr.NextInternalAddresses(tx.ReadWriteBucket(waddrmgrNamespaceKey), 0, 1)
			return e
		})
	}()
	select {
	case e = <-write:
		if e != nil {
			close(barrier.release)
			<-done
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		close(barrier.release)
		<-done
		<-write
		t.Fatal("cursor writer did not commit")
	}
	close(barrier.release)
	r := <-done
	w.db = base
	if r.e != nil || r.c == nil || !reflect.DeepEqual(r.c.Manifest(), initial.Manifest()) || barrier.calls.Load() != 1 {
		t.Fatal("mixed database snapshot", r.e)
	}
	fresh, e := w.CaptureCurrentRecovery(context.Background())
	if e != nil || fresh.Manifest().Accounts[2].NextInternal != 1 {
		t.Fatal("fresh cursor missing", e)
	}
}

func TestCurrentRecoveryCancellationAndUnloadJoin(t *testing.T) {
	l := retainedLoader(t)
	w := retainedCreate(t, l, retainedRecoveryFixture(t, "zero256"))
	base := w.db
	type result struct {
		c *CurrentRecoveryCapture
		e error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	barrier := &activityBarrierDB{DB: base, entered: make(chan struct{}), release: make(chan struct{})}
	w.db = barrier
	go func() { c, e := w.CaptureCurrentRecovery(ctx); done <- result{c, e} }()
	<-barrier.entered
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation abandoned active View")
	default:
	}
	close(barrier.release)
	r := <-done
	w.db = base
	if !errors.Is(r.e, context.Canceled) || r.c != nil {
		t.Fatal("cancelled capture disclosed result", r.e)
	}
	if _, e := w.CaptureCurrentRecovery(nil); !errors.Is(e, ErrCurrentRecoveryInvalid) {
		t.Fatal(e)
	}
	barrier = &activityBarrierDB{DB: base, entered: make(chan struct{}), release: make(chan struct{})}
	w.db = barrier
	go func() { c, e := w.CaptureCurrentRecovery(context.Background()); done <- result{c, e} }()
	<-barrier.entered
	unloaded := make(chan error, 1)
	go func() { unloaded <- l.UnloadWallet() }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !w.ShuttingDown() {
		select {
		case <-tick.C:
		case <-deadline.C:
			close(barrier.release)
			<-done
			<-unloaded
			t.Fatal("unload did not stop wallet")
		}
	}
	select {
	case <-unloaded:
		t.Fatal("unload abandoned active database read")
	default:
	}
	close(barrier.release)
	r = <-done
	if e := <-unloaded; e != nil {
		t.Fatal(e)
	}
	w.db = base
	if r.c != nil || !errors.Is(r.e, ErrCurrentRecoveryUnavailable) {
		t.Fatal("stopped wallet disclosed capture", r.e)
	}
	if _, e := w.CaptureCurrentRecovery(context.Background()); !errors.Is(e, ErrCurrentRecoveryUnavailable) {
		t.Fatal(e)
	}
}

func TestCurrentRecoveryCheapProfileBeforeDatabase(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("tagged refusal")
	}
	w := &Wallet{}
	if c, e := w.CaptureCurrentRecovery(context.Background()); c != nil || !errors.Is(e, ErrCurrentRecoveryProfile) {
		t.Fatal("cheap profile reached wallet", e)
	}
}
