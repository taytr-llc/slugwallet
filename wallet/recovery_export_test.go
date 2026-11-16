package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type retainedRecoveryVector struct {
	Name      string          `json:"name"`
	Entropy   string          `json:"entropy"`
	Export    recovery.Export `json:"export"`
	Addresses []struct {
		Path    string `json:"path"`
		Address string `json:"address"`
	} `json:"addresses"`
}

func retainedRecoveryFixture(t *testing.T, name string) retainedRecoveryVector {
	t.Helper()
	data, err := os.ReadFile("../recovery/testdata/recovery_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FixtureOnly bool                     `json:"fixture_only"`
		Cases       []retainedRecoveryVector `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || !fixture.FixtureOnly {
		t.Fatal("invalid public fixture", err)
	}
	for _, f := range fixture.Cases {
		if f.Name == name {
			return f
		}
	}
	t.Fatal("missing public fixture")
	return retainedRecoveryVector{}
}
func retainedEntropy(t *testing.T, f retainedRecoveryVector) [32]byte {
	t.Helper()
	data, err := hex.DecodeString(f.Entropy)
	if err != nil || len(data) != 32 {
		t.Fatal("invalid fixture entropy")
	}
	var result [32]byte
	copy(result[:], data)
	return result
}

var retainedPubPass = []byte("public fixture only")
var retainedPrivPass = []byte("private fixture password, never a real wallet")

func retainedLoader(t *testing.T) *Loader {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal-chain recovery profile")
	}
	l := NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 20)
	t.Cleanup(func() {
		if _, ok := l.LoadedWallet(); ok {
			if err := l.UnloadWallet(); err != nil {
				t.Error(err)
			}
		}
	})
	return l
}
func retainedCreate(t *testing.T, l *Loader, f retainedRecoveryVector) *Wallet {
	t.Helper()
	w, err := l.CreateNewRecoveryWallet(retainedPubPass, retainedPrivPass, retainedEntropy(t, f), time.Unix(0, 0))
	if err != nil {
		t.Fatal("create recovery", err)
	}
	return w
}
func retainedUnlock(t *testing.T, w *Wallet, pass []byte) {
	t.Helper()
	if err := w.Unlock(pass, nil); err != nil {
		t.Fatal("unlock fixture", err)
	}
}
func retainedAddress(t *testing.T, w *Wallet, scope waddrmgr.KeyScope, internal bool) string {
	t.Helper()
	mgr, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		t.Fatal(err)
	}
	var out []waddrmgr.ManagedAddress
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		var err error
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if internal {
			out, err = mgr.NextInternalAddresses(ns, 0, 1)
		} else {
			out, err = mgr.NextExternalAddresses(ns, 0, 1)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out[0].Address().EncodeAddress()
}
func TestRecoveryRetainedReopenRotateRestore(t *testing.T) {
	f := retainedRecoveryFixture(t, "official-leading-zero-account")
	l := retainedLoader(t)
	w := retainedCreate(t, l, f)
	if w.Manager.DerivationMode() != waddrmgr.DerivationStandard {
		t.Fatal("standard derivation not selected")
	}
	if got, err := w.ExportRecovery(context.Background()); err == nil || got.Mnemonic != "" {
		t.Fatal("locked export returned material")
	}
	if err := w.Unlock([]byte("incorrect fixture password"), nil); err == nil {
		t.Fatal("wrong password accepted")
	}
	retainedUnlock(t, w, retainedPrivPass)
	want := f.Export
	want.Manifest.Accounts = recovery.DefaultAccounts()
	got, err := w.ExportRecovery(context.Background())
	if err != nil {
		t.Fatal("first export", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("export differs from independent fixture")
	}
	// This official fixture contains a leading-zero hardened account ancestor.
	gotAddress := retainedAddress(t, w, waddrmgr.KeyScopeBIP0086, false)
	expected := ""
	for _, a := range f.Addresses {
		if a.Path == "m/86'/0'/0'/0/0" {
			expected = a.Address
		}
	}
	if expected == "" || gotAddress != expected {
		t.Fatalf("standard address mismatch: %s", gotAddress)
	}
	want.Manifest.Accounts[3].NextExternal = 1
	newPass := []byte("rotated public fixture password")
	if err := w.ChangePrivatePassphrase(retainedPrivPass, newPass); err != nil {
		t.Fatal(err)
	}
	if err := l.UnloadWallet(); err != nil {
		t.Fatal(err)
	}
	w, err = l.OpenExistingWallet(retainedPubPass, false)
	if err != nil {
		t.Fatal("reopen", err)
	}
	if err := w.Unlock(retainedPrivPass, nil); err == nil {
		t.Fatal("old private password still accepted")
	}
	retainedUnlock(t, w, newPass)
	got, err = w.ExportRecovery(context.Background())
	if err != nil {
		t.Fatal("later export", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("reopened rotated export mismatch")
	}
	restoredLoader := retainedLoader(t)
	restored, err := restoredLoader.RestoreRecoveryWallet(retainedPubPass, retainedPrivPass, got)
	if err != nil {
		t.Fatal("restore", err)
	}
	retainedUnlock(t, restored, retainedPrivPass)
	again, err := restored.ExportRecovery(context.Background())
	if err != nil || !reflect.DeepEqual(again, got) {
		t.Fatal("restored retained material mismatch", err)
	}
	if retainedAddress(t, restored, waddrmgr.KeyScopeBIP0086, false) != retainedAddress(t, w, waddrmgr.KeyScopeBIP0086, false) {
		t.Fatal("restored cursor not preserved")
	}
}
func TestRecoveryAtomicCreation(t *testing.T) {
	f := retainedRecoveryFixture(t, "zero256")
	l := retainedLoader(t)
	sentinel := errors.New("fixture injected creation failure")
	l.OnWalletCreated(func(tx walletdb.ReadWriteTx) error { return sentinel })
	if _, err := l.CreateNewRecoveryWallet(retainedPubPass, retainedPrivPass, retainedEntropy(t, f), time.Unix(0, 0)); !errors.Is(err, sentinel) {
		t.Fatal("callback failure not propagated", err)
	}
	if _, ok := l.LoadedWallet(); ok {
		t.Fatal("failed wallet published")
	}
	db, err := walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), true, time.Second, false)
	if err != nil {
		t.Fatal("failed creation left DB locked", err)
	}
	defer db.Close()
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		if tx.ReadBucket(waddrmgrNamespaceKey) != nil || tx.ReadBucket(wtxmgrNamespaceKey) != nil {
			t.Fatal("partial creation committed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestRecoveryLegacyRemainsUnavailable(t *testing.T) {
	l := retainedLoader(t)
	f := retainedRecoveryFixture(t, "official-leading-zero-account")
	seed := recovery.SeedFromEntropy(retainedEntropy(t, f))
	w, err := l.CreateNewWallet(retainedPubPass, retainedPrivPass, seed[:], time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	retainedUnlock(t, w, retainedPrivPass)
	if w.Manager.DerivationMode() != waddrmgr.DerivationLegacy {
		t.Fatal("legacy mode changed")
	}
	if result, err := w.ExportRecovery(context.Background()); !errors.Is(err, waddrmgr.ErrRecoveryUnavailable) || result.Mnemonic != "" {
		t.Fatal("legacy material invented", err)
	}
	address := retainedAddress(t, w, waddrmgr.KeyScopeBIP0086, false)
	for _, a := range f.Addresses {
		if a.Path == "m/86'/0'/0'/0/0" && address == a.Address {
			t.Fatal("legacy derivation silently changed")
		}
	}
	if err := l.UnloadWallet(); err != nil {
		t.Fatal(err)
	}
	w, err = l.OpenExistingWallet(retainedPubPass, false)
	if err != nil {
		t.Fatal(err)
	}
	if w.Manager.DerivationMode() != waddrmgr.DerivationLegacy {
		t.Fatal("legacy reopened mode changed")
	}
}

func TestRecoveryCorruptionAndUnsupportedInventory(t *testing.T) {
	f := retainedRecoveryFixture(t, "zero256")
	l := retainedLoader(t)
	w := retainedCreate(t, l, f)
	retainedUnlock(t, w, retainedPrivPass)
	for _, name := range []string{"slug-recovery-public", "slug-recovery-private"} {
		t.Run(name, func(t *testing.T) {
			var original []byte
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				b := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket([]byte("main"))
				original = append([]byte(nil), b.Get([]byte(name))...)
				damaged := append([]byte(nil), original...)
				damaged[len(damaged)-1] ^= 1
				return b.Put([]byte(name), damaged)
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := w.ExportRecovery(context.Background())
			if err == nil || got.Mnemonic != "" {
				t.Fatal("corrupt retained export returned material")
			}
			if err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				return tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket([]byte("main")).Put([]byte(name), original)
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A caller may use the inherited account APIs, but the bounded recovery
	// profile must refuse a partial export instead of silently omitting them.
	if _, err := w.NextAccount(waddrmgr.KeyScopeBIP0084, "extra fixture account"); err != nil {
		t.Fatal(err)
	}
	if got, err := w.ExportRecovery(context.Background()); !errors.Is(err, waddrmgr.ErrRecoveryInventory) || got.Mnemonic != "" {
		t.Fatal("extra account omitted from export", err)
	}
}
func TestRecoveryMissingRetentionFailsWalletReopen(t *testing.T) {
	f := retainedRecoveryFixture(t, "zero256")
	l := retainedLoader(t)
	w := retainedCreate(t, l, f)
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket([]byte("main"))
		for _, name := range []string{"slug-derivation-mode", "slug-recovery-version", "slug-recovery-public", "slug-recovery-private"} {
			if err := b.Delete([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.UnloadWallet(); err != nil {
		t.Fatal(err)
	}
	if w, err := l.OpenExistingWallet(retainedPubPass, false); err == nil || w != nil {
		t.Fatal("damaged recovery silently reopened as legacy")
	}
}
func TestRecoveryRejectsForeignOrCheapProfile(t *testing.T) {
	for _, params := range []*chaincfg.Params{&chaincfg.RegressionNetParams, &chaincfg.TestNet3Params} {
		dir := filepath.Join(t.TempDir(), "never-created")
		l := NewLoader(params, dir, true, time.Second, 20)
		if w, err := l.CreateNewRecoveryWallet(retainedPubPass, retainedPrivPass, [32]byte{}, time.Unix(0, 0)); err == nil || w != nil {
			t.Fatal("foreign profile created")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("invalid profile performed wallet I/O")
		}
	}
	if wire.TestPoW {
		dir := filepath.Join(t.TempDir(), "never-created")
		l := NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, 20)
		if _, err := l.CreateNewRecoveryWallet(retainedPubPass, retainedPrivPass, [32]byte{}, time.Unix(0, 0)); err == nil {
			t.Fatal("cheap profile created")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("cheap profile performed wallet I/O")
		}
	}
}

func TestRecoveryWatchOnlyAndCancellation(t *testing.T) {
	l := retainedLoader(t)
	w, err := l.CreateNewWatchingOnlyWallet(retainedPubPass, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := w.ExportRecovery(context.Background()); err == nil || result.Mnemonic != "" {
		t.Fatal("watch-only export returned material")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := w.ExportRecovery(ctx); !errors.Is(err, context.Canceled) || result.Mnemonic != "" {
		t.Fatal("canceled export returned material", err)
	}
}
