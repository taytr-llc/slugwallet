//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type hostedLoaderReference struct {
	Name     string `json:"name"`
	Snapshot struct {
		Guard  waddrmgr.HostedAllocationGuard    `json:"guard"`
		Links  []waddrmgr.HostedAllocationRecord `json:"local_links"`
		Marker struct {
			Binding struct {
				Initial recovery.Manifest `json:"initial_manifest"`
			} `json:"binding"`
		} `json:"marker"`
	} `json:"snapshot"`
}

func hostedLoaderRef(t *testing.T, name string) hostedLoaderReference {
	t.Helper()
	raw, e := os.ReadFile("testdata/hosted-allocation/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "221fc42f6848fed27912a43454a1fa9ebe2d4e16b383aad9e294c31316424e6b" {
		t.Fatal("independent corpus changed")
	}
	var v struct {
		States []hostedLoaderReference `json:"states"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, s := range v.States {
		if s.Name == name {
			return s
		}
	}
	t.Fatal("missing independent state", name)
	return hostedLoaderReference{}
}
func hostedLoaderFixture(t *testing.T, fixture string) (*Loader, *Wallet, waddrmgr.HostedAllocationGuard) {
	t.Helper()
	ref := hostedLoaderRef(t, fixture+"/empty-bound")
	g := ref.Snapshot.Guard
	g.State = "locked"
	g.BindingID = ""
	var entropy [32]byte
	if fixture == "incrementing256" {
		for i := range entropy {
			entropy[i] = byte(i)
		}
	}
	l := NewLoader(&chaincfg.MainNetParams, filepath.Join(t.TempDir(), "wallet"), true, time.Second, 0)
	w, e := l.CreateHostedAllocationWallet(context.Background(), retainedPubPass, retainedPrivPass, entropy, time.Unix(0, 0), g)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, ok := l.LoadedWallet(); ok {
			if e := l.UnloadWallet(); e != nil {
				t.Error(e)
			}
		}
	})
	return l, w, g
}
func hostedLoaderBind(t *testing.T, w *Wallet, g waddrmgr.HostedAllocationGuard, fixture string) {
	t.Helper()
	id := hostedLoaderRef(t, fixture+"/empty-bound").Snapshot.Guard.BindingID
	if e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		return w.Manager.BindHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedAllocationNamespace), g, id)
	}); e != nil {
		t.Fatal(e)
	}
}
func hostedLoaderApply(t *testing.T, w *Wallet, r waddrmgr.HostedAllocationRecord) {
	t.Helper()
	var p *waddrmgr.HostedAllocationPlan
	var actual waddrmgr.HostedAllocationRange
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		var e error
		p, actual, e = w.Manager.PlanHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace), r.Purpose, r.Branch)
		return e
	})
	if e != nil || actual.Address != r.Address || actual.Script != r.Script || actual.SelectedIndex != r.SelectedIndex {
		t.Fatal("independent plan", e)
	}
	e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		if r.Outcome == "burned" {
			return w.Manager.BurnHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedAllocationNamespace), p, r)
		}
		return w.Manager.ConsumeHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(hostedAllocationNamespace), p, r)
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestHostedAllocationLoaderExactReopenAndOldAPIs(t *testing.T) {
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			l, w, locked := hostedLoaderFixture(t, fixture)
			ctx := context.Background()
			ref := hostedLoaderRef(t, fixture+"/empty-bound")
			bound := ref.Snapshot.Guard
			identity, e := w.HostedAllocationIdentity(ctx, locked)
			if e != nil || identity.PublicKey != ref.Snapshot.Marker.Binding.Initial.GymPublicKey {
				t.Fatal("locked identity", e)
			}
			if !w.Locked() || w.ChainClient() != nil || w.recoveryWindow != 0 {
				t.Fatal("unexpected unlock/backend/window")
			}
			if _, e = w.CaptureCurrentRecovery(ctx); e == nil {
				t.Fatal("old schema9 capture broadened")
			}
			if _, e = w.CaptureOwnActivity(ctx); e == nil {
				t.Fatal("old schema9 activity broadened")
			}
			if _, e = w.ExportRecovery(ctx); !errors.Is(e, waddrmgr.ErrHostedAllocationProfile) {
				t.Fatal("generic recovery export", e)
			}
			if e = l.UnloadWallet(); e != nil {
				t.Fatal(e)
			}
			if _, e = l.OpenExistingWallet(retainedPubPass, false); !errors.Is(e, waddrmgr.ErrHostedAllocationProfile) {
				t.Fatal("ordinary open adopted13", e)
			}
			// A preselected bound/locked pair may be tried only after a definite,
			// successfully closed guard mismatch; no stored guard is adopted.
			if _, e = l.OpenHostedAllocationWallet(ctx, retainedPubPass, bound); !errors.Is(e, waddrmgr.ErrHostedAllocationConflict) {
				t.Fatal("bound pre-READY mismatch", e)
			}
			var cleanup *HostedAllocationCleanupError
			if errors.As(e, &cleanup) {
				t.Fatal("mismatch cleanup uncertain")
			}
			w, e = l.OpenHostedAllocationWallet(ctx, retainedPubPass, locked)
			if e != nil {
				t.Fatal("locked pre-READY resume", e)
			}
			hostedLoaderBind(t, w, locked, fixture)
			if _, e = w.HostedAllocationIdentity(ctx, locked); !errors.Is(e, waddrmgr.ErrHostedAllocationConflict) {
				t.Fatal("locked expectation adopted bound", e)
			}
			for _, r := range hostedLoaderRef(t, fixture+"/burned-receive").Snapshot.Links {
				hostedLoaderApply(t, w, r)
			}
			before, e := w.hostedAllocationPublic(ctx)
			if e != nil || before.Accounts[2].NextExternal != 3 {
				t.Fatal("current guarded public inventory", e)
			}
			if _, e = w.hostedAllocationActivity(ctx); e != nil {
				t.Fatal("explicit public activity", e)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, e = w.hostedAllocationPublic(cancelled); !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if e = l.UnloadWallet(); e != nil {
				t.Fatal(e)
			}
			if _, e = w.hostedAllocationPublic(ctx); e == nil {
				t.Fatal("closed wallet reader")
			}
			if _, e = l.OpenHostedAllocationWallet(ctx, retainedPubPass, locked); !errors.Is(e, waddrmgr.ErrHostedAllocationConflict) {
				t.Fatal(e)
			}
			w, e = l.OpenHostedAllocationWallet(ctx, retainedPubPass, bound)
			if e != nil {
				t.Fatal(e)
			}
			after, e := w.hostedAllocationPublic(ctx)
			if e != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("reopen changed cursor/identity", e)
			}
		})
	}
}
func TestHostedAllocationLoaderRefusesBeforeFilesystem(t *testing.T) {
	ref := hostedLoaderRef(t, "zero256/empty-bound")
	g := ref.Snapshot.Guard
	g.State = "locked"
	g.BindingID = ""
	for _, mode := range []string{"unknown-fixture", "window", "identity", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "absent")
			window := uint32(0)
			if mode == "window" {
				window = 20
			}
			l := NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, window)
			entropy := [32]byte{}
			expected := g
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "unknown-fixture":
				entropy[31] = 1
			case "identity":
				expected.InitialManifestSHA256 = string(bytes.Repeat([]byte{'9'}, 64))
			case "cancelled":
				cancel()
			}
			if _, e := l.CreateHostedAllocationWallet(ctx, retainedPubPass, retainedPrivPass, entropy, time.Time{}, expected); e == nil {
				t.Fatal("refused precondition accepted")
			}
			if _, e := os.Stat(dir); !os.IsNotExist(e) {
				t.Fatal("refusal created filesystem", e)
			}
		})
	}
}
func TestHostedAllocationWalletGenericBypassRefusal(t *testing.T) {
	_, w, g := hostedLoaderFixture(t, "zero256")
	hostedLoaderBind(t, w, g, "zero256")
	scope := waddrmgr.KeyScopeBIP0084
	checks := map[string]func() error{
		"new-receive": func() error { _, e := w.NewAddress(0, scope); return e }, "new-change": func() error { _, e := w.NewChangeAddress(0, scope); return e }, "current": func() error { _, e := w.CurrentAddress(0, scope); return e },
		"dry-run": func() error { _, e := w.CreateSimpleTx(&scope, 0, nil, 1, 1000, nil, true); return e }, "fund-psbt": func() error { _, e := w.FundPsbt(nil, &scope, 1, 0, 1000, nil); return e }, "finalize-psbt": func() error { return w.FinalizePsbt(&scope, 0, nil) },
		"sign": func() error { _, e := w.SignTransaction(nil, txscript.SigHashAll, nil, nil, nil); return e }, "import-dry-run": func() error { _, _, _, e := w.ImportAccountDryRun("other", nil, 0, nil, 1); return e },
		"derive-private": func() error { _, e := w.DeriveFromKeyPath(scope, waddrmgr.DerivationPath{}); return e }, "derive-add-account": func() error { _, e := w.DeriveFromKeyPathAddAccount(scope, waddrmgr.DerivationPath{}); return e },
		"dump-private": func() error { _, e := w.DumpPrivKeys(); return e }, "dump-wif": func() error { _, e := w.DumpWIFPrivateKey(nil); return e }, "private-key": func() error { _, e := w.PrivKeyForAddress(nil); return e },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if e := check(); !errors.Is(e, waddrmgr.ErrHostedAllocationProfile) {
				t.Fatal("generic path reached work", e)
			}
		})
	}
	if !w.Locked() {
		t.Fatal("bypass unlocked")
	}
}
func TestHostedAllocationLoaderStickyCleanup(t *testing.T) {
	for _, mode := range []string{"failed-open", "unload"} {
		t.Run(mode, func(t *testing.T) {
			l, w, g := hostedLoaderFixture(t, "zero256")
			marker := errors.New("injected first DB close failure")
			var d *phaseAFailedCloseDB
			var e error
			if mode == "failed-open" {
				if e = l.UnloadWallet(); e != nil {
					t.Fatal(e)
				}
				var db walletdb.DB
				db, e = walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), true, time.Second, false)
				if e != nil {
					t.Fatal(e)
				}
				d = &phaseAFailedCloseDB{DB: db, err: marker}
				l.mu.Lock()
				l.db = d
				l.hostedAllocation = true
				_, e = l.finishHostedAllocationOpen(context.Background(), []byte("wrong public pass"), g)
				l.mu.Unlock()
			} else {
				d = &phaseAFailedCloseDB{DB: l.db, err: marker}
				l.db = d
				e = l.UnloadWallet()
				if !w.ShuttingDown() {
					t.Fatal("unload did not join wallet")
				}
			}
			var owner *HostedAllocationCleanupError
			if !errors.As(e, &owner) || !errors.Is(e, marker) {
				t.Fatal("cleanup ownership lost", e)
			}
			if owner.Close() != e || l.UnloadWallet() != e || d.calls != 1 {
				t.Fatal("first failure laundered")
			}
			if _, ok := l.LoadedWallet(); ok {
				t.Fatal("stopped failed owner published")
			}
			if _, again := l.OpenHostedAllocationWallet(context.Background(), retainedPubPass, g); again != e {
				t.Fatal("failed reservation reused", again)
			}
		})
	}
}
func TestHostedAllocationWalletDeclaredWatchFrontier(t *testing.T) {
	_, owned, g := hostedLoaderFixture(t, "zero256")
	hostedLoaderBind(t, owned, g, "zero256")
	ref := hostedLoaderRef(t, "zero256/burned-receive")
	for _, r := range ref.Snapshot.Links {
		hostedLoaderApply(t, owned, r)
	}
	var items []address.Address
	e := walletdb.Update(owned.db, func(tx walletdb.ReadWriteTx) error { var e error; items, _, e = owned.activeData(tx); return e })
	if e != nil || len(items) != 3 {
		t.Fatal("startup omitted committed/burned address", e, len(items))
	}
	have := map[string]bool{}
	for _, a := range items {
		have[a.EncodeAddress()] = true
	}
	for _, r := range ref.Snapshot.Links {
		if !have[r.Address] {
			t.Fatal("missing declared address")
		}
	}
	for _, mode := range []string{"known", "foreign", "over-cap", "failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			w := &Wallet{Manager: owned.Manager, db: owned.db, quit: make(chan struct{})}
			w.SetChainSynced(true)
			batch := &rescanBatch{addrs: append([]address.Address{}, items...), outpoints: make(map[wire.OutPoint]address.Address)}
			backend := &recoveryWatchBackend{}
			marker := errors.New("owned node watch failed")
			switch mode {
			case "foreign":
				a, _ := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.MainNetParams)
				batch.addrs = append(batch.addrs, a)
			case "over-cap":
				batch.addrs = make([]address.Address, 32769)
			case "failure":
				backend.fail = marker
			case "cancel":
				close(w.quit)
			}
			e := w.rescanHostedAllocation(backend, batch)
			if w.ChainSynced() {
				t.Fatal("watch dispatch asserted sync")
			}
			switch mode {
			case "known":
				if e != nil || backend.rescans != 1 || !reflect.DeepEqual(backend.batches, []int{3}) {
					t.Fatal("known watch", e)
				}
			case "failure":
				if !errors.Is(e, marker) || backend.rescans != 0 {
					t.Fatal(e)
				}
			default:
				if e == nil || len(backend.batches) != 0 || backend.rescans != 0 {
					t.Fatal("refused watch reached network", e)
				}
			}
		})
	}
}
