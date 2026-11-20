// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/poolround"
	"github.com/taytr-llc/slug/poolservice"
	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolsettlenode"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/prospectwork"
	"github.com/taytr-llc/slug/registry"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var poolTestPublic = []byte("published pool wallet public passphrase")
var poolTestPrivate = []byte("published pool wallet private passphrase")

func poolTestBinding(t *testing.T) PoolWalletBinding {
	t.Helper()
	raw, e := os.ReadFile("../../slug/poolsettle/testdata/operator-wallet/reference-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "c1f2d725fcdbc3af7ba1b0a30f4dd4dfc6983352ffb0b4f72d83f7c09ac7b087" {
		t.Fatal("independent corpus")
	}
	var v struct {
		Guards []struct {
			Fixture    string
			Guard      waddrmgr.PoolSettlementGuard
			Source     poolshare.Config
			Settlement poolsettle.Config
		}
	}
	if json.Unmarshal(raw, &v) != nil || len(v.Guards) != 3 || v.Guards[0].Fixture != "zero256" {
		t.Fatal("fixture")
	}
	g := v.Guards[0]
	return PoolWalletBinding{1, g.Guard.WalletOwnerID, g.Guard.OperatorProfileID, g.Source, g.Settlement, g.Guard}
}
func poolTestRoot(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	seed := recovery.SeedFromEntropy([32]byte{})
	root, e := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	clear(seed[:])
	if e != nil {
		t.Fatal(e)
	}
	return root
}
func poolTestDirectory(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func poolTestOwner(t *testing.T, b PoolWalletBinding) (*PoolWalletOwner, string) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile")
	}
	root := poolTestRoot(t)
	defer root.Zero()
	path := filepath.Join(poolTestDirectory(t), "owner")
	o, e := CreatePoolSettlementWallet(context.Background(), path, b, poolTestPublic, poolTestPrivate, root, time.Unix(1795000000, 0))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := o.Close(); e != nil {
			t.Error(e)
		}
	})
	return o, path
}
func TestPoolWalletOwnerLifecycle(t *testing.T) {
	b := poolTestBinding(t)
	o, path := poolTestOwner(t, b)
	ctx := context.Background()
	if !o.wallet.Manager.IsLocked() {
		t.Fatal("owner not initially locked")
	}
	copy := o.Binding()
	copy.Settlement.Destinations[0].Script = "changed"
	if o.Binding().Settlement.Destinations[0].Script == "changed" {
		t.Fatal("binding aliases caller")
	}
	if e := o.Unlock(ctx, poolTestPrivate, PoolWalletMaxUnlockLifetime+time.Nanosecond); !errors.Is(e, ErrPoolWalletInvalid) {
		t.Fatal("unbounded lifetime", e)
	}
	if e := o.Unlock(ctx, poolTestPrivate, 20*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !o.wallet.Manager.IsLocked() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !o.wallet.Manager.IsLocked() {
		t.Fatal("explicit unlock failed to expire")
	}
	if e := o.Unlock(ctx, poolTestPrivate, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := o.Unlock(ctx, []byte("wrong public fixture pass"), time.Minute); !waddrmgr.IsError(e, waddrmgr.ErrWrongPassphrase) || !o.wallet.Manager.IsLocked() {
		t.Fatal("wrong pass kept wallet unlocked", e)
	}
	if e := o.Unlock(ctx, poolTestPrivate, time.Minute); e != nil {
		t.Fatal(e)
	}
	op, e := o.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case <-op.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("close failed to cancel admitted work")
	}
	select {
	case <-closed:
		t.Fatal("close did not join original operation")
	default:
	}
	op.end()
	select {
	case e = <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close join timeout")
	}
	if e = o.Unlock(ctx, poolTestPrivate, time.Minute); !errors.Is(e, ErrPoolWalletClosed) {
		t.Fatal("closed owner revived", e)
	}
	next, e := OpenPoolSettlementWallet(ctx, path, b, poolTestPublic)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if !next.wallet.Manager.IsLocked() {
		t.Fatal("reopen retained unlock")
	}
	if e = o.Lock(ctx); !errors.Is(e, ErrPoolWalletClosed) {
		t.Fatal("replacement revived original", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = next.Unlock(canceled, poolTestPrivate, time.Minute); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestPoolWalletOwnerGenericRefusal(t *testing.T) {
	o, _ := poolTestOwner(t, poolTestBinding(t))
	if e := o.Unlock(context.Background(), poolTestPrivate, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := o.wallet.PublishTransaction(wire.NewMsgTx(2), "public fixture"); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("generic publish", e)
	}
	if _, e := o.wallet.CreateSimpleTx(nil, 0, nil, 1, 1, nil, false); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("generic transaction", e)
	}
	if _, e := o.wallet.DeriveFromKeyPath(waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("generic key", e)
	}
	if e := o.Lock(context.Background()); e != nil {
		t.Fatal(e)
	}
}

type poolFailCloseDB struct {
	walletdb.DB
	calls int
}

func (db *poolFailCloseDB) Close() error { db.calls++; return errors.New("synthetic close failure") }
func TestPoolWalletOwnerStickyCleanup(t *testing.T) {
	b := poolTestBinding(t)
	if wire.TestPoW {
		t.Skip("normal profile")
	}
	root := poolTestRoot(t)
	defer root.Zero()
	o, e := CreatePoolSettlementWallet(context.Background(), filepath.Join(poolTestDirectory(t), "owner"), b, poolTestPublic, poolTestPrivate, root, time.Unix(1795000000, 0))
	if e != nil {
		t.Fatal(e)
	}
	original := o.loader.db
	defer original.Close()
	failure := &poolFailCloseDB{DB: original}
	o.loader.db = failure
	first := o.Close()
	if !errors.Is(first, ErrPoolWalletStorage) || o.Close() != first || failure.calls != 1 || o.loader.db != failure || o.wallet == nil {
		t.Fatal("cleanup failure lost original handles", first, failure.calls)
	}
}
func TestPoolWalletOwnerDirectoryCleanupRetained(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal profile")
	}
	b := poolTestBinding(t)
	root := poolTestRoot(t)
	defer root.Zero()
	path := filepath.Join(poolTestDirectory(t), "owner")
	o, e := CreatePoolSettlementWallet(context.Background(), path, b, poolTestPublic, poolTestPrivate, root, time.Unix(1795000000, 0))
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		_ = o.Close()
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		_ = o.Close()
		t.Fatal(e)
	}
	// A real already-closed directory exercises the failure leaf without a
	// production test hook or a fabricated successful filesystem operation.
	if e = o.syncPoolDirectoryFile(f); !errors.Is(e, ErrPoolWalletStorage) {
		_ = o.Close()
		t.Fatal("missing close failure", e)
	}
	retained, e := poolOwnerFailure(o, ErrPoolWalletStorage)
	if retained != o || !errors.Is(e, ErrPoolWalletStorage) || len(o.failedDirectories) != 1 || o.failedDirectories[0] != f || !errors.Is(o.Close(), ErrPoolWalletStorage) {
		t.Fatal("failed original directory owner dropped", e)
	}
}
func TestPoolWalletOwnerStorageIdentity(t *testing.T) {
	b := poolTestBinding(t)
	o, path := poolTestOwner(t, b)
	wrong := b
	wrong.Guard.WalletOwnerID = wrong.Guard.OperatorProfileID
	wrong.WalletOwnerID = wrong.Guard.WalletOwnerID
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	if foreign, e := OpenPoolSettlementWallet(context.Background(), path, wrong, poolTestPublic); e == nil {
		foreign.Close()
		t.Fatal("different expected owner adopted")
	}
	file := filepath.Join(path, WalletDBName)
	if e := os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if foreign, e := OpenPoolSettlementWallet(context.Background(), path, b, poolTestPublic); e == nil {
		foreign.Close()
		t.Fatal("broad file mode admitted")
	}
	if e := os.Chmod(file, 0600); e != nil {
		t.Fatal(e)
	}
	original := file + ".original"
	if e := os.Rename(file, original); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(original, file); e != nil {
		t.Fatal(e)
	}
	if foreign, e := OpenPoolSettlementWallet(context.Background(), path, b, poolTestPublic); e == nil {
		foreign.Close()
		t.Fatal("symlink admitted")
	}
	if e := os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(original, file); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPoolSettlementWallet(context.Background(), path, b, poolTestPublic)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if e = os.Rename(path, path+".moved"); e != nil {
		t.Fatal(e)
	}
	defer os.Rename(path+".moved", path)
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	if e = reopened.Unlock(context.Background(), poolTestPrivate, time.Minute); !errors.Is(e, ErrPoolWalletStorage) {
		t.Fatal("replacement path revived open owner", e)
	}
}

// Empty source fixtures authenticate constructor associations only; every work,
// chain submission and session call refuses. No mining/source award is claimed.
type poolEmptySource struct{}

func (poolEmptySource) ResolveTemplate(context.Context, prospectnode.Policy) (prospectwork.Template, error) {
	return prospectwork.Template{}, errors.New("unused fixture")
}
func (poolEmptySource) Proposal(context.Context, prospect.Context, string) error {
	return errors.New("unused fixture")
}
func (poolEmptySource) RecheckContext(context.Context, prospect.Context) error {
	return errors.New("unused fixture")
}
func (poolEmptySource) SubmitBlock(context.Context, prospect.Context, string) error {
	return errors.New("unused fixture")
}
func (poolEmptySource) CanonicalBlock(context.Context, prospect.Context, prospect.Proof, string) error {
	return errors.New("unused fixture")
}
func (poolEmptySource) ObservePoolBlock(context.Context, prospect.Context, prospect.Proof, string) (prospectnode.PoolBlockObservation, error) {
	return prospectnode.PoolBlockObservation{}, errors.New("unused fixture")
}
func (poolEmptySource) WithSession(context.Context, string, func(string, func() error) error) error {
	return errors.New("unused fixture")
}
func poolTestRoundSource(t *testing.T, b *PoolWalletBinding) *poolround.Store {
	t.Helper()
	pin := b.Source.AuthorityPin
	issuer, e := registry.CreateManifestAuthority(filepath.Join(t.TempDir(), "issuer"), pin.Network, pin.Genesis, pin.DescriptorID)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := issuer.Close(); e != nil {
			t.Error(e)
		}
	})
	info, e := issuer.Info()
	if e != nil {
		t.Fatal(e)
	}
	b.Source.AuthorityPin = info.Pin
	b.Guard.SourceBindingID, e = poolservice.BindingID(b.Source)
	if e != nil {
		t.Fatal(e)
	}
	pool, e := poolshare.Create(filepath.Join(t.TempDir(), "pool"), b.Source, issuer, poolEmptySource{}, poolEmptySource{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := pool.Close(); e != nil {
			t.Error(e)
		}
	})
	rounds, e := poolround.Create(filepath.Join(t.TempDir(), "rounds"), poolround.Limits{Version: 1, MaxRounds: 4, MaxBytes: 8 << 20}, pool, poolEmptySource{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := rounds.Close(); e != nil {
			t.Error(e)
		}
	})
	return rounds
}
func poolTestNode(t *testing.T, b PoolWalletBinding) (*poolsettlenode.Client, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var q struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		if json.Unmarshal(raw, &q) != nil {
			http.Error(w, "bad", 400)
			return
		}
		genesis := chaincfg.MainNetParams.GenesisHash.String()
		var result any
		switch q.Method {
		case "getcurrentnet":
			result = uint32(chaincfg.MainNetParams.Net)
		case "getblockhash":
			result = genesis
		case "getbestblock":
			result = map[string]any{"hash": genesis, "height": 0}
		case "getblockchaininfo":
			deploy := map[string]any{}
			for _, name := range []string{"csv", "segwit", "taproot"} {
				status := "defined"
				if uint32(1) >= chaincfg.PhaseAActivationHeight {
					status = "active"
				}
				deploy[name] = map[string]any{"status": status, "always_active_height": chaincfg.PhaseAActivationHeight}
			}
			result = map[string]any{"chain": "mainnet", "blocks": 0, "bestblockhash": genesis, "bip9_softforks": deploy}
		default:
			http.Error(w, "unexpected request", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "1.0", "id": q.ID, "result": result, "error": nil})
	}))
	t.Cleanup(server.Close)
	config := poolsettlenode.Config{Version: 1, Network: b.Guard.Network, Genesis: b.Guard.Genesis, PoolPublicKey: b.Guard.FundingPublicKey, PoolScript: b.Guard.FundingScript, Fee: poolsettlenode.FeePolicy{Mode: "fixed", AtomsPerKVB: 1000, MaxAtomsPerKVB: 10000, MaxFeeAtoms: 100000}}
	node, e := poolsettlenode.New(context.Background(), config, prospectnode.RPCConfig{Version: 1, URL: server.URL, Username: "public", Password: "published-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := node.Close(); e != nil {
			t.Error(e)
		}
	})
	return node, calls
}
func TestPoolWalletBackendOriginalBinding(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal profile")
	}
	b := poolTestBinding(t)
	rounds := poolTestRoundSource(t, &b)
	o, _ := poolTestOwner(t, b)
	node, calls := poolTestNode(t, b)
	backend, e := NewPoolSettlementBackend(context.Background(), o, node, b)
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Close()
	if _, e = NewPoolSettlementBackend(context.Background(), o, node, b); !errors.Is(e, ErrPoolWalletBinding) {
		t.Fatal("equal backend replacement accepted", e)
	}
	if _, e = backend.Sign(context.Background(), nil, nil); !errors.Is(e, ErrPoolWalletBinding) {
		t.Fatal("unbound signer accepted", e)
	}
	store, e := poolsettle.Create(filepath.Join(t.TempDir(), "settlement"), b.Settlement, rounds, backend)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if e = backend.BindSettlement(context.Background(), store); e != nil {
		t.Fatal(e)
	}
	if e = backend.BindSettlement(context.Background(), store); !errors.Is(e, ErrPoolWalletBinding) {
		t.Fatal("rebind accepted", e)
	}
	count := calls.Load()
	if _, e = backend.Sign(context.Background(), []poolsettle.Coin{{TxID: b.WalletOwnerID, Atoms: 1000000, Script: b.Guard.FundingScript}}, []byte{1}); e == nil {
		t.Fatal("caller DTO authorized signing")
	}
	if calls.Load() != count {
		t.Fatal("refused sign reached node")
	}
	if e = backend.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = backend.Sign(context.Background(), nil, nil); !errors.Is(e, ErrPoolWalletClosed) {
		t.Fatal("closed backend revived", e)
	}
}
func TestPoolWalletProfileRefusal(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("cheap refusal")
	}
	b := poolTestBinding(t)
	root := poolTestRoot(t)
	defer root.Zero()
	path := filepath.Join(poolTestDirectory(t), "absent")
	if o, e := CreatePoolSettlementWallet(context.Background(), path, b, poolTestPublic, poolTestPrivate, root, time.Unix(1795000000, 0)); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) || o != nil {
		t.Fatal("cheap owner admitted", e)
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("cheap constructor touched storage")
	}
}
