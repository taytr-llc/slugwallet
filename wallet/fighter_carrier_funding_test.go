//go:build !slugtestpow

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func carrierPublicFunding(t *testing.T, w *Wallet, c carrierReferenceCase, p fightercarrier.Preparation) {
	t.Helper()
	if len(c.Context.Carrier.FundingTransactions) == 0 {
		t.Fatal("independent parent transactions absent")
	}
	e := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		for _, raw := range c.Context.Carrier.FundingTransactions {
			encoded, e := hex.DecodeString(raw)
			if e != nil {
				return e
			}
			var msg wire.MsgTx
			if e = msg.Deserialize(bytes.NewReader(encoded)); e != nil {
				return e
			}
			record, e := wtxmgr.NewTxRecordFromMsgTx(&msg, time.Unix(1700000000, 0))
			if e != nil {
				return e
			}
			for _, in := range p.NewFunding.Inputs {
				if in.TxID != record.Hash.String() {
					continue
				}
				h, e := chainhash.NewHashFromStr(in.BlockHash)
				if e != nil {
					return e
				}
				b := &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: *h, Height: in.BlockHeight}, Time: time.Unix(1700000000, 0)}
				if e = w.TxStore.InsertTx(ns, record, b); e != nil {
					return e
				}
				if e = w.TxStore.AddCredit(ns, record, b, in.OutputIndex, false); e != nil {
					return e
				}
			}
		}
		h, e := chainhash.NewHashFromStr(p.TipHash)
		if e != nil {
			return e
		}
		return w.Manager.SetSyncedTo(tx.ReadWriteBucket(waddrmgrNamespaceKey), &waddrmgr.BlockStamp{Hash: *h, Height: p.TipHeight, Timestamp: time.Unix(1700000000, 0)})
	})
	if e != nil {
		t.Fatal(e)
	}
	w.SetChainSynced(true)
}

func TestFighterCarrierFundingSelectionAndIndependentSignatures(t *testing.T) {
	refs := carrierReference(t)
	for _, tc := range []struct {
		fixture, kind string
		count         int
		total         int64
	}{{"zero256", "sixteen-small", 16, 512000}, {"incrementing256", "one", 1, 600000}} {
		t.Run(tc.fixture+"/"+tc.kind, func(t *testing.T) {
			ctx := context.Background()
			h := newAllocatorFixture2(t, tc.fixture)
			allocatorPool2(t, h)
			name := tc.fixture + "/hosted/transfer/" + tc.kind
			c := refs[name+"/preparation"]
			var p fightercarrier.Preparation
			var expected fightercarrier.SignedPackage
			if e := json.Unmarshal(c.Value, &p); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(refs[name+"/package"].Value, &expected); e != nil {
				t.Fatal(e)
			}
			// Issue only exact public paths needed by the frozen parent transactions.
			// No watch/network success is claimed by these local authoring fixtures.
			for n := 1; n < tc.count; n++ {
				plan, e := h.allocator.PlanReceive(ctx, allocationTestID(uint64(100+n)))
				if e != nil {
					t.Fatal(e)
				}
				r, e := h.allocator.Reserve(ctx, plan)
				if e != nil {
					t.Fatal(e)
				}
				receipt, e := h.allocator.Consume(ctx, r)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = h.allocator.Acknowledge(ctx, receipt); e != nil {
					t.Fatal(e)
				}
			}
			pin, e := allocationCarrierPin2(h.binding)
			if e != nil {
				t.Fatal(e)
			}
			j, e := fightercarrier.Create(ctx, filepath.Join(t.TempDir(), "carrier"), fightercarrier.Identity{JournalID: h.binding.CarrierJournalID, Pin: pin})
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			o, e := h.allocator.CreateFighterCarrier(ctx, j)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			carrierPublicFunding(t, h.wallet, c, p)
			if _, e = o.PlanFunding(ctx, p.Request); !errors.Is(e, fightercarrier.ErrNotFound) {
				t.Fatal("selection preceded durable intent", e)
			}
			app, e := j.TryAcquire(ctx)
			if e != nil {
				t.Fatal(e)
			}
			staged, e := app.StageIntent(p.Request)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = staged.Publish(func(fn func(func() error) error) error { return fn(func() error { return nil }) }); e != nil {
				t.Fatal(e)
			}
			staged.Close()
			app.Close()
			plan, e := o.PlanFunding(ctx, p.Request)
			if e != nil {
				t.Fatal(e)
			}
			if len(plan.funding.inputs) != tc.count || plan.funding.total != tc.total || !reflect.DeepEqual(plan.funding.inputs, p.NewFunding.Inputs) {
				t.Fatal("concrete selection differs from independent inputs")
			}
			if tc.count == 16 {
				op, e := carrierOutpoint(p.NewFunding.Inputs[0].TxID, p.NewFunding.Inputs[0].OutputIndex)
				if e != nil {
					t.Fatal(e)
				}
				h.wallet.LockOutpoint(op)
				if _, e = o.PlanFunding(ctx, p.Request); !errors.Is(e, fightercarrier.ErrCapacity) {
					t.Fatal("15 small inputs unexpectedly sufficient", e)
				}
				h.wallet.UnlockOutpoint(op)
			}
			if allocatorLocal2(t, h).Meta.Cursors[5] != 0 || withdrawalExclusions2(t, h) != 0 {
				t.Fatal("read-only selection allocated or reserved")
			}
			// Only account/journal metadata is adapted to the freshly owned fixture.
			// The independent signature and transaction bytes remain unchanged.
			p.BindingID = o.binding
			p.Review.BindingID = o.binding
			p.ReviewDigest, e = fightercarrier.ReviewDigest(p.Review)
			if e != nil {
				t.Fatal(e)
			}
			i, e := carrierIntent(p)
			if e != nil {
				t.Fatal(e)
			}
			env := fightertransfer.Envelope{Intent: i}
			raw, _ := hex.DecodeString(expected.GymAuthorization)
			copy(env.Signature[:], raw)
			retainedUnlock(t, h.wallet, retainedPrivPass)
			lease, e := h.wallet.holdUnlockContext(ctx)
			if e != nil {
				t.Fatal(e)
			}
			e = walletdb.View(h.wallet.db, func(tx walletdb.ReadTx) error {
				got, e := o.signNewFunding(ctx, tx, p, env, lease)
				if e != nil {
					return e
				}
				if got.Commit != expected.Commit || got.Spend != expected.Spend || got.GymAuthorization != expected.GymAuthorization || got.TransferID != expected.TransferID {
					t.Fatal("independent exact signed transaction bytes differ")
				}
				return nil
			})
			lease.release()
			if e != nil {
				t.Fatal(e)
			}
			h.revoked.Store(true)
			if _, e = o.PlanFunding(ctx, p.Request); e == nil {
				t.Fatal("revoked original session selected funds")
			}
		})
	}
}
