//go:build !slugtestpow

package wallet

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// Exercise the final live rescan validator, not merely activeData's enumeration.
// The backend records bounded dispatch; actual synchronization belongs to the
// separately source-bound normal-node acceptance scenario.
func carrierWatchDispatch(t *testing.T, owned *Wallet, want int) {
	t.Helper()
	var items []address.Address
	err := walletdb.Update(owned.db, func(tx walletdb.ReadWriteTx) error {
		var e error
		items, _, e = owned.activeData(tx)
		return e
	})
	if err != nil || len(items) != want {
		t.Fatal("issued frontier", len(items), err)
	}
	for _, mode := range []string{"known", "foreign", "duplicate", "over-cap", "failure", "cancel"} {
		if len(items) == 0 && (mode == "duplicate" || mode == "failure") {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			w := &Wallet{Manager: owned.Manager, db: owned.db, quit: make(chan struct{})}
			w.SetChainSynced(true)
			batch := &rescanBatch{addrs: append([]address.Address{}, items...), outpoints: make(map[wire.OutPoint]address.Address)}
			backend := &recoveryWatchBackend{}
			marker := errors.New("carrier watch failure")
			switch mode {
			case "foreign":
				a, _ := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.MainNetParams)
				batch.addrs = append(batch.addrs, a)
			case "duplicate":
				batch.addrs = append(batch.addrs, items[0])
			case "over-cap":
				batch.addrs = make([]address.Address, 32769)
			case "failure":
				backend.fail = marker
			case "cancel":
				close(w.quit)
			}
			err := w.rescanHostedAllocation(backend, batch)
			if w.ChainSynced() {
				t.Fatal("dispatch claimed completed sync")
			}
			switch mode {
			case "known":
				var sizes []int
				if want > 0 {
					sizes = []int{want}
				}
				if err != nil || backend.rescans != 1 || !reflect.DeepEqual(backend.batches, sizes) {
					t.Fatal("known declared watch refused", err, backend.batches, backend.rescans)
				}
			case "failure":
				if !errors.Is(err, marker) || backend.rescans != 0 {
					t.Fatal("watch failure hidden", err)
				}
			default:
				if err == nil || len(backend.batches) != 0 || backend.rescans != 0 {
					t.Fatal("refused frontier reached backend", err)
				}
			}
		})
	}
}

func TestFighterCarrierHostedDeclaredWatchDispatch(t *testing.T) {
	h := newAllocatorFixture2(t, "zero256")
	t.Run("fresh-bound-empty", func(t *testing.T) { carrierWatchDispatch(t, h.wallet, 0) })
	allocatorPool2(t, h)
	ctx := context.Background()
	p, err := h.allocator.PlanReceive(ctx, allocationTestID(731))
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.allocator.Reserve(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := h.allocator.Burn(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.allocator.Acknowledge(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	t.Run("consumed-and-burned", func(t *testing.T) { carrierWatchDispatch(t, h.wallet, 2) })
}

func TestFighterCarrierRestoredDeclaredWatchDispatch(t *testing.T) {
	c := carrierReference(t)["zero256/restored/recover_reveal/recovery/preparation"]
	c.Context.Original.Accounts = append([]recovery.Account(nil), c.Context.Original.Accounts...)
	for i := range c.Context.Original.Accounts {
		c.Context.Original.Accounts[i].NextExternal = 1
		c.Context.Original.Accounts[i].NextInternal = 1
	}
	raw, err := recovery.MarshalManifest(c.Context.Original)
	if err != nil {
		t.Fatal(err)
	}
	c.Context.Pin.OriginalManifestSHA256 = carrierSHA(raw)
	_, w, _, _, _ := restoredCarrierFixture(t, c, false)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		items, _, e := w.activeData(tx)
		if e != nil {
			return e
		}
		classes := map[txscript.ScriptClass]int{}
		for _, a := range items {
			s, e := txscript.PayToAddrScript(a)
			if e != nil {
				return e
			}
			classes[txscript.GetScriptClass(s)]++
		}
		if !reflect.DeepEqual(classes, map[txscript.ScriptClass]int{txscript.PubKeyHashTy: 2, txscript.ScriptHashTy: 1, txscript.WitnessV0PubKeyHashTy: 3, txscript.WitnessV1TaprootTy: 2}) {
			t.Fatal("restored issued scope coverage", classes)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	carrierWatchDispatch(t, w, 8)
}
