//go:build !slugtestpow

package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func phaseABundle(t *testing.T, incrementing bool) recovery.Export {
	t.Helper()
	var e [32]byte
	if incrementing {
		for i := range e {
			e[i] = byte(i)
		}
	}
	b, err := recovery.NewExport(e, recovery.DefaultAccounts())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func phaseABegin(t *testing.T, b recovery.Export) (*Loader, *RecoverySession) {
	t.Helper()
	l := NewLoader(&chaincfg.MainNetParams, filepath.Join(t.TempDir(), "restore"), true, time.Second, 0)
	s, e := l.BeginPhaseARecovery(context.Background(), retainedPubPass, retainedPrivPass, b)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return l, s
}
func TestPhaseARecoveryResumeOriginalManifestAndMixed49(t *testing.T) {
	ctx := context.Background()
	b := phaseABundle(t, false)
	l, s := phaseABegin(t, b)
	if _, loaded := l.LoadedWallet(); loaded {
		t.Fatal("pending published wallet")
	}
	if _, e := l.OpenExistingWallet(retainedPubPass, false); !errors.Is(e, ErrLoaded) {
		t.Fatal(e)
	}
	before, _ := s.Status(ctx)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := s.Step(cancelled, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	after, _ := s.Status(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("cancelled Step committed progress")
	}
	p, e := s.Step(ctx, nil)
	if e != nil || p.Derived != 128 || p.Target != 160 || p.Issued != 0 {
		t.Fatalf("first greedy unit %+v %v", p, e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = l.OpenExistingWallet(retainedPubPass, false); !errors.Is(e, ErrRecoveryInProgress) {
		t.Fatal("pending ordinary open", e)
	}
	changed := b.Manifest
	changed.Accounts = append([]recovery.Account(nil), changed.Accounts...)
	changed.Accounts[0].NextExternal = 1
	if _, e = l.OpenPhaseARecovery(ctx, retainedPubPass, changed); e == nil {
		t.Fatal("accepted different original manifest")
	}
	s, e = l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.Status(ctx)
	if e != nil || !reflect.DeepEqual(p, again) {
		t.Fatal("resume rewrote progress", e)
	}
	p, e = s.Step(ctx, nil)
	if e != nil || p.Derived != 160 || p.Issued != 0 || p.Phase != "scanning" {
		t.Fatalf("second unit %+v %v", p, e)
	}
	// Reopen audits actual schema49 internal native scripts, not candidate49 nesting.
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal("mixed49 audit", e)
	}
	defer s.Close()
	if _, e = l.OpenCandidateRecovery(ctx, retainedPubPass); !errors.Is(e, ErrLoaded) {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = l.OpenCandidateRecovery(ctx, retainedPubPass); e == nil {
		t.Fatal("schema11 API adopted12")
	}
}
func TestPhaseARecoveryFrozenAddressScripts(t *testing.T) {
	raw, e := os.ReadFile("testdata/phase-a-recovery/addresses-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	if h := sha256.Sum256(raw); hex.EncodeToString(h[:]) != "1558bf4a134ab01acfe84fdbb2edc3e8af842b602cb5150feaa9ce2df26b9cf7" {
		t.Fatal("reference changed")
	}
	var corpus struct {
		Cases []struct {
			Name     string
			Branches []struct {
				Purpose, Branch uint32
				Public          string `json:"branch_public_key"`
				Addresses       []struct {
					Index  uint32
					Script string `json:"script_pub_key"`
				}
			}
		}
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range corpus.Cases {
		for _, b := range c.Branches {
			key, e := hdkeychain.NewKeyFromString(b.Public)
			if e != nil {
				t.Fatal(e)
			}
			for _, a := range b.Addresses {
				child, e := key.Derive(a.Index)
				if e != nil {
					t.Fatal(e)
				}
				purpose := b.Purpose
				if purpose == 49 && b.Branch == 1 {
					purpose = 84
				}
				script, e := recoveryScriptForKey(child, purpose, &chaincfg.MainNetParams)
				child.Zero()
				if e != nil || hex.EncodeToString(script) != a.Script {
					t.Fatalf("%s %d/%d/%d frozen script", c.Name, b.Purpose, b.Branch, a.Index)
				}
				count++
			}
			key.Zero()
		}
	}
	if count != 160 {
		t.Fatal(count)
	}
}
func TestPhaseARecoveryReadyRemainsV1AndCannotWithdraw(t *testing.T) {
	ctx := context.Background()
	b := phaseABundle(t, true)
	l, s := phaseABegin(t, b)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	p := reviewFinishRecovery(t, s, source)
	if !p.Ready {
		t.Fatal("not ready")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	p2, e := s.Status(ctx)
	if e != nil || !reflect.DeepEqual(p, p2) {
		t.Fatal("ready session restarted", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	w, e := l.OpenExistingWallet(retainedPubPass, false)
	if e != nil {
		t.Fatal(e)
	}
	defer l.UnloadWallet()
	if w.Manager.RecoveryVersion() != 1 || !w.Manager.ResumableRecovery() || w.Manager.RecoveryIndexLimit() != 4096 {
		t.Fatal("profile changed")
	}
	if e = w.Unlock(retainedPrivPass, nil); e != nil {
		t.Fatal(e)
	}
	exported, e := w.ExportRecovery(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(exported.Manifest, b.Manifest) {
		t.Fatal("export changed v1 manifest")
	}
	e = walletdb.View(w.db, func(tx walletdb.ReadTx) error { _, e := withdrawalProfile(tx, w); return e })
	if !errors.Is(e, ErrWithdrawalProfile) {
		t.Fatal("verification wallet acquired withdrawal authority", e)
	}
}
func TestPhaseARecoveryRefusesPartialDirectoryAndCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := phaseABundle(t, false)
	dir := filepath.Join(t.TempDir(), "scratch")
	l := NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, 0)
	if _, e := l.BeginPhaseARecovery(ctx, retainedPubPass, retainedPrivPass, b); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Stat(dir); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cancellation created directory", e)
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "unowned"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := l.BeginPhaseARecovery(context.Background(), retainedPubPass, retainedPrivPass, b); !errors.Is(e, ErrExists) {
		t.Fatal(e)
	}
}

type phaseAFailedCloseDB struct {
	walletdb.DB
	calls int
	err   error
}

func (d *phaseAFailedCloseDB) Close() error {
	d.calls++
	if d.calls == 1 {
		return errors.Join(d.DB.Close(), d.err)
	}
	return nil
}
func TestPhaseARecoveryStickySessionClose(t *testing.T) {
	b := phaseABundle(t, false)
	l, s := phaseABegin(t, b)
	marker := errors.New("injected close failure")
	d := &phaseAFailedCloseDB{DB: s.db, err: marker}
	s.db = d
	// The callback retains the concrete owner originally registered by the Loader;
	// this seam changes only the one attempted filesystem close.
	e := s.Close()
	var cleanup *PhaseARecoveryCleanupError
	if !errors.As(e, &cleanup) || !errors.Is(e, marker) {
		t.Fatal(e)
	}
	if s.Close() != e || cleanup.Close() != e || d.calls != 1 {
		t.Fatal("cleanup failure laundered")
	}
	if _, e2 := l.OpenPhaseARecovery(context.Background(), retainedPubPass, b.Manifest); e2 != e {
		t.Fatal("failed owner reused", e2)
	}
	if _, ok := l.LoadedWallet(); ok {
		t.Fatal("failed owner published")
	}
	if l.UnloadWallet() != e {
		t.Fatal("unload lost sticky failure")
	}
}

func TestPhaseARecoveryCleanupFailedOpenAndUnload(t *testing.T) {
	for _, mode := range []string{"failed-open", "unload"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			b := phaseABundle(t, false)
			l, s := phaseABegin(t, b)
			source := &reviewRecoverySource{}
			source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
			reviewFinishRecovery(t, s, source)
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			marker := errors.New("first DB close failed")
			if mode == "failed-open" {
				db, e := walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), true, time.Second, false)
				if e != nil {
					t.Fatal(e)
				}
				d := &phaseAFailedCloseDB{DB: db, err: marker}
				l.mu.Lock()
				_, e = l.phaseASessionFromDB(ctx, d, []byte("wrong public pass"), nil)
				l.mu.Unlock()
				var owner *PhaseARecoveryCleanupError
				if !errors.As(e, &owner) || !errors.Is(e, marker) {
					t.Fatal(e)
				}
				if owner.Close() != e || l.UnloadWallet() != e || d.calls != 1 {
					t.Fatal("first close failure laundered")
				}
			} else {
				w, e := l.OpenExistingWallet(retainedPubPass, false)
				if e != nil {
					t.Fatal(e)
				}
				d := &phaseAFailedCloseDB{DB: l.db, err: marker}
				l.db = d
				e = l.UnloadWallet()
				var owner *PhaseARecoveryCleanupError
				if !errors.As(e, &owner) || !errors.Is(e, marker) {
					t.Fatal(e)
				}
				if !w.ShuttingDown() {
					t.Fatal("unload failed to join wallet")
				}
				if _, ok := l.LoadedWallet(); ok {
					t.Fatal("stopped failed owner published")
				}
				if l.UnloadWallet() != e || owner.Close() != e || d.calls != 1 {
					t.Fatal("unload close retried")
				}
			}
		})
	}
}
func TestPhaseARecoveryCompletedAuditAndLaterAllocation(t *testing.T) {
	ctx := context.Background()
	b := phaseABundle(t, false)
	l, s := phaseABegin(t, b)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	reviewFinishRecovery(t, s, source)
	for _, kind := range []string{"script", "output", "transaction"} {
		t.Run(kind, func(t *testing.T) {
			e := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
				scan := tx.ReadWriteBucket(phaseARecoveryScanBucket)
				var bucket walletdb.ReadWriteBucket
				switch kind {
				case "script":
					bucket = scan.NestedReadWriteBucket(recoveryScripts)
				case "output":
					bucket = scan.NestedReadWriteBucket(recoveryOutputs)
				case "transaction":
					bucket = scan.NestedReadWriteBucket(recoveryTransactions)
				}
				if e := bucket.Put([]byte("bad"), []byte("malformed")); e != nil {
					return e
				}
				if e := s.audit(ctx, tx); e == nil {
					t.Fatal("completed session ignored corrupt " + kind)
				}
				if e := candidateRecoveryComplete(tx, s.manager); e == nil {
					t.Fatal("ordinary open ignored corrupt " + kind)
				}
				return bucket.Delete([]byte("bad"))
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	w, e := l.OpenExistingWallet(retainedPubPass, false)
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		scope, e := w.Manager.FetchScopedKeyManager(waddrmgr.KeyScope{Purpose: 84, Coin: 0})
		if e != nil {
			return e
		}
		_, e = scope.NextInternalAddresses(tx.ReadWriteBucket(waddrmgrNamespaceKey), 0, 25)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = l.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
	s, e = l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal("later allocation damaged frozen scanner", e)
	}
	defer s.Close()
	p, e := s.Status(ctx)
	if e != nil || !p.Ready || p.Issued != 25 || p.Derived != 165 {
		t.Fatalf("later live allocation %+v %v", p, e)
	}
}

type phaseACommitFailDB struct {
	walletdb.DB
	failure error
	called  bool
}

func (d *phaseACommitFailDB) Update(f func(walletdb.ReadWriteTx) error, reset func()) error {
	e := d.DB.Update(f, reset)
	if e != nil {
		return e
	}
	d.called = true
	return d.failure
}
func TestPhaseARecoveryOrdinaryOpenCommitFailure(t *testing.T) {
	b := phaseABundle(t, false)
	l, s := phaseABegin(t, b)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	reviewFinishRecovery(t, s, source)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	fail := errors.New("commit result unavailable")
	d := &phaseACommitFailDB{DB: db, failure: fail}
	w, e := OpenWithRetry(d, retainedPubPass, nil, &chaincfg.MainNetParams, 0, time.Second)
	if w != nil || !errors.Is(e, fail) || !d.called {
		t.Fatal("outer commit failure published wallet", e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	w, e = l.OpenExistingWallet(retainedPubPass, false)
	if e != nil {
		t.Fatal("committed exact state could not reopen", e)
	}
	if w.Manager.RecoveryVersion() != 1 {
		t.Fatal("profile changed")
	}
	if e = l.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
}

func phaseAFrozenPayment19(t *testing.T) productionprofile.PaymentPublic {
	t.Helper()
	raw, e := os.ReadFile("testdata/phase-a-recovery/addresses-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Cases []struct {
			Name     string
			Branches []struct {
				Purpose, Branch uint32
				Addresses       []struct {
					Index  uint32
					Script string `json:"script_pub_key"`
				}
			}
		}
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	for _, c := range corpus.Cases {
		if c.Name != "zero256" {
			continue
		}
		for _, b := range c.Branches {
			if b.Purpose != 84 || b.Branch != 0 {
				continue
			}
			for _, a := range b.Addresses {
				if a.Index == 19 {
					return productionprofile.PaymentPublic{ScriptPubKey: a.Script}
				}
			}
		}
	}
	t.Fatal("frozen payment absent")
	return productionprofile.PaymentPublic{}
}
func TestPhaseARecoveryImmutableDiscoveryMinimumAndOrphanTail(t *testing.T) {
	for _, mode := range []string{"canonical", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			bundle := phaseABundle(t, false)
			l, s := phaseABegin(t, bundle)
			genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
			funded := reviewFundingBlock(t, genesis, 1, 19, phaseAFrozenPayment19(t))
			source := &reviewRecoverySource{}
			source.set(genesis, funded)
			var p RecoveryProgress
			for n := 0; n < 30; n++ {
				var e error
				p, e = s.Step(ctx, source)
				if e != nil {
					t.Fatal(e)
				}
				if p.ScannedHeight == 1 && p.Phase == "scanning" && p.Derived == 180 {
					break
				}
				if n == 29 {
					t.Fatal("did not reach discovered pending checkpoint", p)
				}
			}
			if p.Issued != 20 {
				t.Fatal("canonical output did not expand issuance", p)
			}
			if mode == "orphan" {
				source.set(genesis, reviewFundingBlock(t, genesis, 1, 31))
			}
			p = reviewFinishRecovery(t, s, source)
			if p.Issued != 20 || p.Derived != 180 {
				t.Fatal("orphan rolled back address facts", p)
			}
			if mode == "canonical" {
				e := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
					rows := tx.ReadWriteBucket(phaseARecoveryScanBucket).NestedReadWriteBucket(recoveryScripts)
					var key, raw []byte
					if e := rows.ForEach(func(k, v []byte) error {
						row, e := decodeRecoveryScriptLimit(v, 4096)
						if e != nil {
							return e
						}
						if row.Purpose == 84 && row.Branch == 0 && row.Index == 39 {
							key = append([]byte(nil), k...)
							raw = append([]byte(nil), v...)
						}
						return nil
					}); e != nil {
						return e
					}
					if key == nil {
						t.Fatal("discovered tail absent")
					}
					if e := rows.Delete(key); e != nil {
						return e
					}
					if e := s.audit(ctx, tx); e == nil {
						t.Fatal("canonical discovery tail deletion accepted")
					}
					if e := candidateRecoveryComplete(tx, s.manager); e == nil {
						t.Fatal("ordinary open accepted missing discovery tail")
					}

					if e := rows.Put(key, raw); e != nil {
						return e
					}
					// Coherently lower both the stored account cursor and manager progress.
					// Counts/derivation remain valid; immutable paid-output evidence must
					// independently prevent issuance from falling below this historical use.
					ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
					main := ns.NestedReadWriteBucket([]byte("main"))
					progressKey := []byte("slug-phase-a-progress-v1")
					original := append([]byte(nil), main.Get(progressKey)...)
					if len(original) != 236 {
						t.Fatal("progress fixture length")
					}
					lowered := append([]byte(nil), original...)
					binary.LittleEndian.PutUint32(lowered[12+4*28+16:], 0)
					var scopeKey [8]byte
					binary.LittleEndian.PutUint32(scopeKey[:], 84)
					accounts := ns.NestedReadWriteBucket([]byte("scope")).NestedReadWriteBucket(scopeKey[:]).NestedReadWriteBucket([]byte("acct"))
					accountKey := make([]byte, 4)
					accountOriginal := append([]byte(nil), accounts.Get(accountKey)...)
					accountLowered := append([]byte(nil), accountOriginal...)
					offset := 5
					for n := 0; n < 2; n++ {
						if len(accountLowered)-offset < 4 {
							t.Fatal("account fixture framing")
						}
						size := int(binary.LittleEndian.Uint32(accountLowered[offset:]))
						offset += 4
						if size > len(accountLowered)-offset {
							t.Fatal("account fixture field")
						}
						offset += size
					}
					if len(accountLowered)-offset < 8 || binary.LittleEndian.Uint32(accountLowered[offset:]) != 20 {
						t.Fatal("account fixture cursor")
					}
					binary.LittleEndian.PutUint32(accountLowered[offset:], 0)
					if e := main.Put(progressKey, lowered); e != nil {
						return e
					}
					if e := accounts.Put(accountKey, accountLowered); e != nil {
						return e
					}
					if _, e := waddrmgr.RecoveryAccounts(ns); e != nil {
						t.Fatal("lowered cursor fixture was not internally coherent", e)
					}
					if e := s.audit(ctx, tx); e == nil {
						t.Fatal("immutable output allowed a lower issued cursor")
					}
					if e := candidateRecoveryComplete(tx, s.manager); e == nil {
						t.Fatal("ordinary completion ignored lowered issuance")
					}
					if e := main.Put(progressKey, original); e != nil {
						return e
					}
					return accounts.Put(accountKey, accountOriginal)
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			s, e := l.OpenPhaseARecovery(ctx, retainedPubPass, bundle.Manifest)
			if e != nil {
				t.Fatal("legitimate immutable tail refused", e)
			}
			defer s.Close()
			again, e := s.Status(ctx)
			if e != nil || !reflect.DeepEqual(p, again) {
				t.Fatal("ready resume changed historical progress", e)
			}
		})
	}
}
