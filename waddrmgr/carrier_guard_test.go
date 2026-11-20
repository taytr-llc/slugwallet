// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type carrierManagerCase struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Value     json.RawMessage `json:"value"`
	Canonical string          `json:"canonical_utf8"`
	Digest    string          `json:"digest"`
}

func TestCarrierManagerIndependentForgedValidChildRefusal(t *testing.T) {
	if wire.TestPoW {
		t.Skip("concrete child validity requires the normal manager profile")
	}
	positive, negative := carrierManagerCases(t)
	checked := 0
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			db, m, locked, base := carrierManagerFixture(t, fixture)
			ctx := context.Background()
			local := []byte(HostedAllocationNamespace2)
			if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return m.BindHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), locked, base.BindingID)
			}); e != nil {
				t.Fatal(e)
			}
			old := hostedManagerReference(t, fixture+"/receive-complete")
			for n, raw := range old.Snapshot.Links {
				v := hostedManagerRecord(t, raw)
				kind := "receive"
				if n == 0 {
					kind = "pool_recipient"
				}
				r := HostedAllocationRecord2{Version: 2, InventoryID: locked.InventoryID, BindingID: base.BindingID, Sequence: v.Sequence, AllocationID: v.AllocationID, ReservationDigest: v.ReservationDigest, RequestDigest: v.RequestDigest, Outcome: v.Outcome, Purpose: v.Purpose, Branch: v.Branch, StartIndex: v.StartIndex, EndIndex: v.EndIndex, SelectedIndex: v.SelectedIndex, InvalidIndices: v.InvalidIndices, Address: v.Address, Script: v.Script, CursorsBefore: v.CursorsBefore, CursorsAfter: v.CursorsAfter, ConsumerKind: kind, ConsumerID: v.AllocationID}
				if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
					p, _, e := m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(local), 84, 0)
					if e != nil {
						return e
					}
					return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), p, r)
				}); e != nil {
					t.Fatal(e)
				}
			}
			for _, bad := range negative {
				if !strings.HasPrefix(bad.Name, fixture+"/forged-valid-child-") {
					continue
				}
				var forged HostedAllocationRecord2
				if e := json.Unmarshal(bad.Value, &forged); e != nil {
					t.Fatal(e)
				}
				var link HostedAllocationRecord2
				for _, c := range positive {
					if c.Kind == "link2" && strings.HasPrefix(c.Name, fixture+"/range-") && strings.HasSuffix(c.Name, "-consumed") {
						var r HostedAllocationRecord2
						_ = json.Unmarshal(c.Value, &r)
						if r.SelectedIndex == forged.SelectedIndex {
							link = r
						}
					}
				}
				if link.Version != 2 || !rangeMatches(rangeRecord2(link), HostedAllocationRange{Purpose: forged.Purpose, Branch: forged.Branch, StartIndex: forged.StartIndex, EndIndex: forged.EndIndex, SelectedIndex: forged.SelectedIndex, InvalidIndices: forged.InvalidIndices, Address: forged.Address, Script: forged.Script}) {
					t.Fatal("independent case projection mismatch")
				}
				checked++
				e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
					p, actual, e := m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(local), 84, 1)
					if e != nil {
						return e
					}
					if actual.SelectedIndex != 0 || len(actual.InvalidIndices) != 0 {
						t.Fatal("published fixture child0 unexpectedly invalid")
					}
					return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(local), p, link)
				})
				if !errors.Is(e, ErrHostedAllocationInvalid) {
					t.Fatal("forged skipped valid child accepted", bad.Name, e)
				}
			}
			if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
				s, e := m.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(local))
				if e == nil && (s.Meta.CompletedSequence != 2 || s.Meta.Cursors[5] != 0) {
					t.Fatal("refusal advanced inventory")
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
	if checked != 4 {
		t.Fatal("forged independent case count", checked)
	}
}

func carrierManagerCases(t *testing.T) ([]carrierManagerCase, []carrierManagerCase) {
	t.Helper()
	raw, e := os.ReadFile("../../slug/fightercarrier/testdata/reference/wallet-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "8648ac23d5e077df1a4dd1e3b8f07157922e650e92e9eea99c233a6993283495" {
		t.Fatal("independent corpus changed")
	}
	var v struct{ Positives, Negatives []carrierManagerCase }
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v.Positives, v.Negatives
}
func TestCarrierManagerIndependentGuardsAndLinks(t *testing.T) {
	positive, negative := carrierManagerCases(t)
	count := 0
	for _, c := range positive {
		switch c.Kind {
		case "guard14", "guard15", "link2":
		default:
			continue
		}
		count++
		t.Run(c.Name, func(t *testing.T) {
			raw := []byte(c.Canonical)
			var again []byte
			var digest string
			var e error
			switch c.Kind {
			case "guard14":
				var g HostedAllocationGuard2
				g, e = ParseHostedAllocationGuard2(raw)
				if e == nil {
					again, e = MarshalHostedAllocationGuard2(g)
				}
				digest, _ = HostedAllocationGuardDigest2(g)
			case "guard15":
				var g RestoredCarrierGuard
				g, e = ParseRestoredCarrierGuard(raw)
				if e == nil {
					again, e = MarshalRestoredCarrierGuard(g)
				}
				digest, _ = RestoredCarrierGuardDigest(g)
			case "link2":
				var r HostedAllocationRecord2
				r, e = ParseHostedAllocationRecord2(raw)
				if e == nil {
					again, e = MarshalHostedAllocationRecord2(r)
				}
				digest, _ = HostedAllocationRecordDigest2(r)
			}
			if e != nil || !bytes.Equal(again, raw) || digest != c.Digest {
				t.Fatalf("canonical/digest mismatch: %v", e)
			}
		})
	}
	if count == 0 {
		t.Fatal("no manager reference cases")
	}
	// The independent negative set includes external binding/state-context cases
	// that are not promises of these standalone shape parsers. Keep their tests
	// at the concrete manager/inventory boundary instead of counting them here.
	_ = negative
}
func carrierManagerFixture(t *testing.T, names ...string) (walletdb.DB, *Manager, HostedAllocationGuard2, HostedAllocationRecord2) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile required")
	}
	fixture := "zero256"
	if len(names) == 1 {
		fixture = names[0]
	}
	var entropy [32]byte
	if fixture == "incrementing256" {
		for n := range entropy {
			entropy[n] = byte(n)
		}
	}
	cases, _ := carrierManagerCases(t)
	var locked HostedAllocationGuard2
	var record HostedAllocationRecord2
	for _, c := range cases {
		if c.Name == fixture+"/guard-locked" {
			if e := json.Unmarshal(c.Value, &locked); e != nil {
				t.Fatal(e)
			}
		}
		if c.Name == fixture+"/range-0-consumed" {
			if e := json.Unmarshal(c.Value, &record); e != nil {
				t.Fatal(e)
			}
		}
	}
	manifest, e := recovery.ManifestFor(entropy, recovery.DefaultAccounts())
	if e != nil {
		t.Fatal(e)
	}
	public, e := recovery.MarshalManifest(manifest)
	if e != nil {
		t.Fatal(e)
	}
	seed := recovery.SeedFromEntropy(entropy)
	root, e := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	clear(seed[:])
	if e != nil {
		t.Fatal(e)
	}
	defer root.Zero()
	private := make([]byte, 68)
	binary.LittleEndian.PutUint32(private, 1)
	copy(private[4:36], entropy[:])
	h := sha256.Sum256(public)
	copy(private[36:], h[:])
	defer clear(private)
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "carrier.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		local, e := tx.CreateTopLevelBucket([]byte(HostedAllocationNamespace2))
		if e != nil {
			return e
		}
		return CreateWithHostedAllocation2(context.Background(), ns, local, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, public, private, locked)
	})
	if e != nil {
		t.Fatal(e)
	}
	var m *Manager
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		var e error
		m, e = OpenHostedAllocation2(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace2)), pubPassphrase, &chaincfg.MainNetParams, locked)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return db, m, locked, record
}
func TestCarrierManagerAtomicConsumeAndDowngradeRefusal(t *testing.T) {
	db, m, locked, r := carrierManagerFixture(t)
	ctx := context.Background()
	localKey := []byte(HostedAllocationNamespace2)
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if _, e := Open(ns, pubPassphrase, &chaincfg.MainNetParams); e == nil {
			t.Fatal("ordinary open adopted14")
		}
		if _, _, e := m.PlanHostedAllocation2(ctx, ns, tx.ReadBucket(localKey), 84, 0); !errors.Is(e, ErrHostedAllocationConflict) {
			t.Fatal("locked plan", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return m.BindHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(localKey), locked, r.BindingID)
	})
	if e != nil {
		t.Fatal(e)
	}
	// Establish the two preceding external paths from the older independent
	// address corpus. These synthetic local-link identities are test plumbing,
	// not new independently generated reservation/digest expectations.
	old := hostedManagerReference(t, "zero256/receive-complete")
	for i, raw := range old.Snapshot.Links {
		v := hostedManagerRecord(t, raw)
		kind := "receive"
		if i == 0 {
			kind = "pool_recipient"
		}
		link := HostedAllocationRecord2{Version: 2, InventoryID: locked.InventoryID, BindingID: r.BindingID, Sequence: v.Sequence, AllocationID: v.AllocationID, ReservationDigest: v.ReservationDigest, RequestDigest: v.RequestDigest, Outcome: v.Outcome, Purpose: v.Purpose, Branch: v.Branch, StartIndex: v.StartIndex, EndIndex: v.EndIndex, SelectedIndex: v.SelectedIndex, InvalidIndices: v.InvalidIndices, Address: v.Address, Script: v.Script, CursorsBefore: v.CursorsBefore, CursorsAfter: v.CursorsAfter, ConsumerKind: kind, ConsumerID: v.AllocationID}
		var p *HostedAllocationPlan2
		e = walletdb.View(db, func(tx walletdb.ReadTx) error {
			var e error
			p, _, e = m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(localKey), 84, 0)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(localKey), p, link)
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	var plan *HostedAllocationPlan2
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		var got HostedAllocationRange
		var e error
		plan, got, e = m.PlanHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(localKey), r.Purpose, r.Branch)
		if e == nil && (got.Address != r.Address || got.Script != r.Script || got.SelectedIndex != r.SelectedIndex) {
			t.Fatal("independent path mismatch")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	abort := errors.New("rollback after consume")
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		if e := m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(localKey), plan, r); e != nil {
			return e
		}
		return abort
	})
	if !errors.Is(e, abort) {
		t.Fatal(e)
	}
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		s, e := m.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(localKey))
		if e == nil && (s.Meta.CompletedSequence != 2 || s.Meta.Cursors[5] != 0) {
			t.Fatal("rollback disclosed cursor")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return m.ConsumeHostedAllocation2(ctx, tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket(localKey), plan, r)
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		s, e := m.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(localKey))
		if e == nil && (len(s.Records) != 3 || s.Meta.Cursors[5] != 1) {
			t.Fatal("consumption missing")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		sm, _ := m.FetchScopedKeyManager(KeyScopeBIP0084)
		if _, e := sm.NextExternalAddresses(tx.ReadWriteBucket(waddrmgrNamespaceKey), 0, 1); e == nil {
			t.Fatal("generic allocator bypass")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// A valid local record under the wrong binary AllocationID key is corrupt.
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(localKey).NestedReadWriteBucket(hostedAllocationRecordsKey)
		key, _ := hex.DecodeString(r.AllocationID)
		raw := append([]byte(nil), b.Get(key)...)
		if e := b.Delete(key); e != nil {
			return e
		}
		key[0] ^= 1
		return b.Put(key, raw)
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := m.AuditHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(localKey))
		return e
	})
	if !errors.Is(e, ErrHostedAllocationCorrupt) {
		t.Fatal("wrong-key local record accepted", e)
	}
}
