//go:build !slugtestpow

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

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type carrierReferenceCase struct {
	Name, Kind string
	Value      json.RawMessage
	Context    struct {
		Pin       fightercarrier.Pin
		JournalID string            `json:"journal_id"`
		BindingID string            `json:"binding_id"`
		Original  recovery.Manifest `json:"original_manifest"`
		Carrier   struct {
			FundingTransactions []string `json:"funding_transactions"`
		} `json:"carrier"`
	}
}

func carrierReference(t *testing.T) map[string]carrierReferenceCase {
	t.Helper()
	raw, e := os.ReadFile("../../slug/fightercarrier/testdata/reference/wallet-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "8648ac23d5e077df1a4dd1e3b8f07157922e650e92e9eea99c233a6993283495" {
		t.Fatal("independent corpus changed")
	}
	var v struct{ Positives []carrierReferenceCase }
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	out := make(map[string]carrierReferenceCase)
	for _, c := range v.Positives {
		out[c.Name] = c
	}
	return out
}
func restoredCarrierFixture(t *testing.T, c carrierReferenceCase, incrementing bool) (*Loader, *Wallet, *fightercarrier.Journal, *FighterCarrierOwner, waddrmgr.RestoredCarrierGuard) {
	t.Helper()
	ctx := context.Background()
	var entropy [32]byte
	if incrementing {
		for n := range entropy {
			entropy[n] = byte(n)
		}
	}
	b, e := recovery.NewExport(entropy, c.Context.Original.Accounts)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(b.Manifest, c.Context.Original) {
		t.Fatal("reference import mismatch")
	}
	l, s := phaseABegin(t, b)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	if p := reviewFinishRecovery(t, s, source); !p.Ready {
		t.Fatal("not ready")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	j, e := fightercarrier.Create(ctx, filepath.Join(t.TempDir(), "carrier"), fightercarrier.Identity{JournalID: c.Context.JournalID, Pin: c.Context.Pin})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	w, g, e := l.ActivateRestoredCarrierWallet(ctx, retainedPubPass, b.Manifest, j)
	if e != nil {
		t.Fatal("activation", e)
	}
	t.Cleanup(func() { _ = l.UnloadWallet() })
	if g.ManagerSchema != 15 || w.Manager.CarrierSchema() != 15 || !reflect.DeepEqual(g.OriginalManifest, b.Manifest) {
		t.Fatal("wrong activated identity")
	}
	o, e := w.OpenRestoredFighterCarrier(ctx, j, g)
	if e != nil {
		t.Fatal("owner", e)
	}
	t.Cleanup(func() { _ = o.Close() })
	return l, w, j, o, g
}

func TestFighterCarrierRestoredActivationAndIndependentRecoverySignatures(t *testing.T) {
	refs := carrierReference(t)
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			ctx := context.Background()
			prefix := fixture + "/restored/recover_reveal/recovery"
			c := refs[prefix+"/preparation"]
			l, w, j, o, g := restoredCarrierFixture(t, c, fixture == "incrementing256")
			original, _ := recovery.MarshalManifest(c.Context.Original)
			if e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				raw, e := w.Manager.RecoveryData(tx.ReadBucket(waddrmgrNamespaceKey), false)
				if e != nil {
					return e
				}
				if !bytes.Equal(raw, original) {
					t.Fatal("activation changed original import")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := w.CaptureCurrentRecovery(ctx); e == nil {
				t.Fatal("generic schema9 capture accepted15")
			}
			if _, e := w.ExportRecovery(ctx); e == nil {
				t.Fatal("generic export accepted15")
			}
			if e := w.Unlock(retainedPrivPass, nil); e != nil {
				t.Fatal(e)
			}
			// This tests private cryptographic leaves against independent bytes. It
			// does not fabricate a public ownership capability or claim chain truth.
			kinds := []string{"recover_reveal"}
			if fixture == "zero256" {
				kinds = append(kinds, "recover_refund")
			}
			for _, kind := range kinds {
				name := fixture + "/restored/" + kind + "/recovery"
				var p fightercarrier.Preparation
				var want fightercarrier.SignedPackage
				if e := json.Unmarshal(refs[name+"/preparation"].Value, &p); e != nil {
					t.Fatal(e)
				}
				if e := json.Unmarshal(refs[name+"/package"].Value, &want); e != nil {
					t.Fatal(e)
				}
				e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
					if e := o.validateRecoveryPaths(ctx, tx, p); e != nil {
						return e
					}
					i, e := carrierIntent(p)
					if e != nil {
						return e
					}
					env, e := o.restoredEnvelope(ctx, tx, i)
					if e != nil {
						return e
					}
					if hex.EncodeToString(env.Signature[:]) != p.RecoveryFunding.GymAuthorization {
						t.Fatal("independent deterministic gym signature differs")
					}
					got, e := o.signRecovery(tx, &PreparedFighterTransfer{owner: o, preparation: p}, env)
					if e != nil {
						return e
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatal("independent exact signed package differs")
					}
					var key [33]byte
					raw, _ := hex.DecodeString(p.RecoveryFunding.FundingPublicKey)
					copy(key[:], raw)
					var returned [22]byte
					raw, _ = hex.DecodeString(p.RecoveryFunding.ReturnPath.Script)
					copy(returned[:], raw)
					m, e := w.Manager.MatchRestoredCarrierKeys(ctx, tx.ReadBucket(waddrmgrNamespaceKey), 0, key, returned)
					if e != nil {
						return e
					}
					if m.Next != 3 || m.Total != 3 || !m.FundingFound || !m.ReturnFound || m.FundingBranch != 0 || m.FundingIndex != 0 || m.ReturnBranch != 1 || m.ReturnIndex != 0 {
						t.Fatal("wrong original public lookup", m)
					}
					if e = w.Manager.CheckRestoredCarrierPath(ctx, tx.ReadBucket(waddrmgrNamespaceKey), 1, 1, nil, returned[:]); !errors.Is(e, waddrmgr.ErrHostedAllocationFrontier) {
						t.Fatal("lookahead rescued missing original return", e)
					}
					bad := cloneCarrierPreparation(p)
					bad.RecoveryFunding.FundingBranch = 1
					if e = o.validateRecoveryPaths(ctx, tx, bad); e == nil {
						t.Fatal("swapped path accepted")
					}
					return nil
				})
				if e != nil {
					t.Fatal(kind, e)
				}
			}
			if e := o.Close(); e != nil {
				t.Fatal(e)
			}
			if e := l.UnloadWallet(); e != nil {
				t.Fatal(e)
			}
			if _, e := l.OpenExistingWallet(retainedPubPass, false); e == nil {
				t.Fatal("ordinary loader reopened15")
			}
			bad := g
			bad.WalletOwnerID = string(bytes.Repeat([]byte{'1'}, 64))
			if _, e := l.OpenRestoredCarrierWallet(ctx, retainedPubPass, bad, j); e == nil {
				t.Fatal("wrong original guard adopted")
			}
			w, e := l.OpenRestoredCarrierWallet(ctx, retainedPubPass, g, j)
			if e != nil {
				t.Fatal("exact reopen", e)
			}
			o, e = w.OpenRestoredFighterCarrier(ctx, j, g)
			if e != nil {
				t.Fatal("exact owner reopen", e)
			}
			if e = o.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestFighterCarrierRestoredAtomicAllocationRollback(t *testing.T) {
	ctx := context.Background()
	refs := carrierReference(t)
	c := refs["zero256/restored/transfer/one/preparation"]
	_, w, _, o, _ := restoredCarrierFixture(t, c, false)
	var p fightercarrier.Preparation
	if e := json.Unmarshal(c.Value, &p); e != nil {
		t.Fatal(e)
	}
	var plan *waddrmgr.RestoredCarrierPlan
	var r waddrmgr.HostedAllocationRange
	var before [8]uint32
	if e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		var e error
		plan, r, before, e = w.Manager.PlanRestoredCarrier(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if r.Address != p.NewFunding.ReturnPath.Address || r.Script != p.NewFunding.ReturnPath.Script || r.SelectedIndex != p.NewFunding.ReturnPath.Index {
		t.Fatal("independent allocation path differs")
	}
	injected := errors.New("injected rollback")
	e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		if e := w.Manager.ConsumeRestoredCarrier(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), plan); e != nil {
			return e
		}
		if e := o.auditExclusions(ctx, tx); !errors.Is(e, fightercarrier.ErrCorrupt) {
			t.Fatal("manager issuance without its preparation was accepted", e)
		}
		if e := o.commitPreparation(ctx, tx, p); e != nil {
			return e
		}
		if e := o.auditExclusions(ctx, tx); e != nil {
			return e
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	if e = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		_, again, cursors, e := w.Manager.PlanRestoredCarrier(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
		if e != nil {
			return e
		}
		if cursors != before || !reflect.DeepEqual(again, r) {
			t.Fatal("rollback leaked issuance/cache")
		}
		state, e := readCarrierWalletState(ctx, tx, o.journal.Identity().JournalID, &o.pin)
		if e != nil {
			return e
		}
		if len(state.records) != 0 || state.meta.ActiveRequestID != "" {
			t.Fatal("rollback retained preparation")
		}
		return o.auditExclusions(ctx, tx)
	}); e != nil {
		t.Fatal(e)
	}
}

func TestFighterCarrierRestoredBoundedLookupAndIssuedWatch(t *testing.T) {
	ctx := context.Background()
	refs := carrierReference(t)
	c := refs["zero256/restored/recover_reveal/recovery/preparation"]
	// A property-test input, not a new cryptographic expected vector: increase
	// the imported public bounds while retaining independently known keys0/0.
	c.Context.Original.Accounts = append([]recovery.Account(nil), c.Context.Original.Accounts...)
	for n := range c.Context.Original.Accounts {
		c.Context.Original.Accounts[n].NextExternal = 1
		c.Context.Original.Accounts[n].NextInternal = 1
	}
	c.Context.Original.Accounts[2].NextExternal = 256
	raw, e := recovery.MarshalManifest(c.Context.Original)
	if e != nil {
		t.Fatal(e)
	}
	c.Context.Pin.OriginalManifestSHA256 = carrierSHA(raw)
	_, w, _, o, _ := restoredCarrierFixture(t, c, false)
	var p fightercarrier.Preparation
	if e = json.Unmarshal(c.Value, &p); e != nil {
		t.Fatal(e)
	}
	var key [33]byte
	raw, _ = hex.DecodeString(p.RecoveryFunding.FundingPublicKey)
	copy(key[:], raw)
	var returned [22]byte
	raw, _ = hex.DecodeString(p.RecoveryFunding.ReturnPath.Script)
	copy(returned[:], raw)
	for n, want := range []uint32{128, 256, 257} {
		start := uint32(n * 128)
		e = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			m, e := w.Manager.MatchRestoredCarrierKeys(ctx, tx.ReadBucket(waddrmgrNamespaceKey), start, key, returned)
			if e != nil {
				return e
			}
			if m.Total != 257 || m.Next != want || m.FundingFound != (n == 0) || m.ReturnFound != (n == 2) {
				t.Fatal("lookup step exceeded/changed bound", m)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		_, e := w.Manager.MatchRestoredCarrierKeys(cancelled, tx.ReadBucket(waddrmgrNamespaceKey), 0, key, returned)
		return e
	}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	e = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addresses, credits, e := w.activeData(tx)
		if e != nil {
			return e
		}
		if len(addresses) != 263 || len(credits) != 0 {
			t.Fatal("watch includes lookahead or omits issued scope", len(addresses), len(credits))
		}
		classes := map[txscript.ScriptClass]int{}
		for _, a := range addresses {
			script, e := txscript.PayToAddrScript(a)
			if e != nil {
				return e
			}
			classes[txscript.GetScriptClass(script)]++
		}
		if classes[txscript.PubKeyHashTy] != 2 || classes[txscript.ScriptHashTy] != 1 || classes[txscript.WitnessV0PubKeyHashTy] != 258 || classes[txscript.WitnessV1TaprootTy] != 2 {
			t.Fatal("issued scope watch differs", classes)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.PlanFunding(ctx, p.Request); e == nil {
		t.Fatal("recovery request accepted as new funding")
	}
}
