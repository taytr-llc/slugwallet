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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type hostedManagerRef struct {
	Name       string `json:"name"`
	LocalBytes uint64 `json:"local_bytes"`
	Snapshot   struct {
		Marker struct {
			Binding struct {
				Initial recovery.Manifest `json:"initial_manifest"`
			} `json:"binding"`
		} `json:"marker"`
		Guard HostedAllocationGuard `json:"guard"`
		Meta  HostedAllocationMeta  `json:"local_meta"`
		Links []json.RawMessage     `json:"local_links"`
		Rows  []struct {
			ID string `json:"wallet_record_digest"`
		} `json:"rows"`
	} `json:"snapshot"`
}

func hostedManagerReferences(t *testing.T) []hostedManagerRef {
	t.Helper()
	raw, e := os.ReadFile("../wallet/testdata/hosted-allocation/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "221fc42f6848fed27912a43454a1fa9ebe2d4e16b383aad9e294c31316424e6b" {
		t.Fatal("independent corpus changed")
	}
	var out struct {
		States []hostedManagerRef `json:"states"`
	}
	if e = json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}

	// The archived outer document is pretty printed. Preserve the independent
	// nested field order/values while selecting its contract's compact encoding.
	for i := range out.States {
		for j, raw := range out.States[i].Snapshot.Links {
			var compact bytes.Buffer
			if e := json.Compact(&compact, raw); e != nil {
				t.Fatal(e)
			}
			out.States[i].Snapshot.Links[j] = append([]byte(nil), compact.Bytes()...)
		}
	}
	return out.States
}
func hostedManagerReference(t *testing.T, name string) hostedManagerRef {
	t.Helper()
	for _, s := range hostedManagerReferences(t) {
		if s.Name == name {
			return s
		}
	}
	t.Fatal("missing independent state", name)
	return hostedManagerRef{}
}
func hostedManagerRecord(t *testing.T, raw []byte) HostedAllocationRecord {
	t.Helper()
	r, e := ParseHostedAllocationRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestHostedAllocationManagerIndependentCodecs(t *testing.T) {
	for _, s := range hostedManagerReferences(t) {
		t.Run(s.Name, func(t *testing.T) {
			g, e := MarshalHostedAllocationGuard(s.Snapshot.Guard)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ParseHostedAllocationGuard(g); e != nil {
				t.Fatal(e)
			}
			id, e := HostedAllocationGuardDigest(s.Snapshot.Guard)
			if e != nil || id != s.Snapshot.Meta.GuardSHA256 {
				t.Fatal("guard preimage", e)
			}
			for i, raw := range s.Snapshot.Links {
				r := hostedManagerRecord(t, raw)
				again, e := MarshalHostedAllocationRecord(r)
				if e != nil || !bytes.Equal(raw, again) {
					t.Fatal("record bytes", e)
				}
				id, e := HostedAllocationRecordDigest(r)
				if e != nil {
					t.Fatal(e)
				}
				if i < len(s.Snapshot.Rows) && s.Snapshot.Rows[i].ID != "" && id != s.Snapshot.Rows[i].ID {
					t.Fatal("record preimage")
				}
			}
		})
	}
	r := hostedManagerReference(t, "zero256/pool-complete").Snapshot.Links[0]
	for _, raw := range [][]byte{append(append([]byte{}, r...), '\n'), bytes.Replace(r, []byte(`"invalid_indices":[]`), []byte(`"invalid_indices":null`), 1), bytes.Replace(r, []byte(`"sequence":1`), []byte(`"sequence":true`), 1), bytes.Replace(r, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1), bytes.Repeat([]byte(" "), 4097)} {
		if _, e := ParseHostedAllocationRecord(raw); e == nil {
			t.Fatal("noncanonical local record accepted")
		}
	}
}
func hostedManager(t *testing.T, fixture string) (walletdb.DB, *Manager, HostedAllocationGuard) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile only")
	}
	ref := hostedManagerReference(t, fixture+"/empty-bound")
	locked := ref.Snapshot.Guard
	locked.State = "locked"
	locked.BindingID = ""
	entropy := [32]byte{}
	if fixture == "incrementing256" {
		for i := range entropy {
			entropy[i] = byte(i)
		}
	}
	manifest := ref.Snapshot.Marker.Binding.Initial
	pub, e := recovery.MarshalManifest(manifest)
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
	priv := make([]byte, 68)
	binary.LittleEndian.PutUint32(priv, 1)
	copy(priv[4:36], entropy[:])
	sum := sha256.Sum256(pub)
	copy(priv[36:], sum[:])
	defer clear(priv)
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "hosted.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		local, e := tx.CreateTopLevelBucket([]byte(HostedAllocationNamespace))
		if e != nil {
			return e
		}
		return CreateWithHostedAllocation(context.Background(), ns, local, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, pub, priv, locked)
	})
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	var m *Manager
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		var e error
		m, e = OpenHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)), pubPassphrase, &chaincfg.MainNetParams, locked)
		return e
	})
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		m.Close()
		if e := db.Close(); e != nil {
			t.Error(e)
		}
	})
	return db, m, locked
}
func hostedAudit(t *testing.T, db walletdb.DB, m *Manager) HostedAllocationState {
	t.Helper()
	var s HostedAllocationState
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		var e error
		s, e = m.AuditHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func hostedBind(t *testing.T, db walletdb.DB, m *Manager, g HostedAllocationGuard, fixture string) {
	t.Helper()
	id := hostedManagerReference(t, fixture+"/empty-bound").Snapshot.Guard.BindingID
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return m.BindHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace)), g, id)
	}); e != nil {
		t.Fatal(e)
	}
}
func hostedPlan(t *testing.T, db walletdb.DB, m *Manager, branch uint32) (*HostedAllocationPlan, HostedAllocationRange) {
	t.Helper()
	var p *HostedAllocationPlan
	var r HostedAllocationRange
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		var e error
		p, r, e = m.PlanHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)), 84, branch)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return p, r
}
func hostedApply(t *testing.T, db walletdb.DB, m *Manager, r HostedAllocationRecord) {
	t.Helper()
	p, actual := hostedPlan(t, db, m, r.Branch)
	if !rangeMatches(r, actual) {
		t.Fatal("independent address mismatch")
	}
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, local := tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace))
		if r.Outcome == "burned" {
			return m.BurnHostedAllocation(context.Background(), ns, local, p, r)
		}
		return m.ConsumeHostedAllocation(context.Background(), ns, local, p, r)
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestHostedAllocationManagerAtomicGuardAndReopen(t *testing.T) {
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			db, m, locked := hostedManager(t, fixture)
			if s := hostedAudit(t, db, m); s.Guard.State != "locked" || len(s.Records) != 0 {
				t.Fatal("creation not locked/empty")
			}
			e := walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, _, e := m.PlanHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)), 84, 0)
				return e
			})
			if !errors.Is(e, ErrHostedAllocationConflict) {
				t.Fatal("locked plan", e)
			}
			hostedBind(t, db, m, locked, fixture)
			hostedBind(t, db, m, locked, fixture)
			ref := hostedManagerReference(t, fixture+"/burned-receive")
			first := hostedManagerRecord(t, ref.Snapshot.Links[0])
			p, r := hostedPlan(t, db, m, 0)
			if !rangeMatches(first, r) {
				t.Fatal("independent first address")
			}
			before := hostedAudit(t, db, m)
			rollback := errors.New("rollback after address and link writes")
			e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				if e := m.ConsumeHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace)), p, first); e != nil {
					return e
				}
				return rollback
			})
			if !errors.Is(e, rollback) {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, hostedAudit(t, db, m)) {
				t.Fatal("aborted write changed inventory")
			}
			// A rolled-back address must not have escaped into the ordinary address cache.
			sm, _ := m.FetchScopedKeyManager(KeyScopeBIP0084)
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, e := sm.DeriveFromKeyPath(tx.ReadBucket(waddrmgrNamespaceKey), DerivationPath{InternalAccount: 0, Account: hdkeychain.HardenedKeyStart, Branch: 0, Index: 0})
				return e
			})
			if !errors.Is(e, ErrHostedAllocationFrontier) {
				t.Fatal("rollback disclosed path", e)
			}
			for _, raw := range ref.Snapshot.Links {
				hostedApply(t, db, m, hostedManagerRecord(t, raw))
			}
			s := hostedAudit(t, db, m)
			if s.Meta != ref.Snapshot.Meta || s.LogicalBytes != ref.LocalBytes {
				t.Fatalf("independent local metadata/bytes got %+v bytes%d want%+v bytes%d", s.Meta, s.LogicalBytes, ref.Snapshot.Meta, ref.LocalBytes)
			}
			e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return m.ConsumeHostedAllocation(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace)), p, first)
			})
			if !errors.Is(e, ErrHostedAllocationConflict) {
				t.Fatal("stale plan reused", e)
			}
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, e := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
				return e
			})
			if e == nil {
				t.Fatal("generic manager opened13")
			}
			m.Close()
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				next, e := OpenHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)), pubPassphrase, &chaincfg.MainNetParams, ref.Snapshot.Guard)
				if e != nil {
					return e
				}
				defer next.Close()
				got, e := next.AuditHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket([]byte(HostedAllocationNamespace)))
				if e == nil && !reflect.DeepEqual(s, got) {
					t.Fatal("reopen changed state")
				}
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestHostedAllocationManagerBypassAndDamagedIndices(t *testing.T) {
	db, m, locked := hostedManager(t, "zero256")
	hostedBind(t, db, m, locked, "zero256")
	sm, _ := m.FetchScopedKeyManager(KeyScopeBIP0084)
	for name, fn := range map[string]func(walletdb.ReadWriteBucket) error{
		"external":        func(ns walletdb.ReadWriteBucket) error { _, e := sm.NextExternalAddresses(ns, 0, 1); return e },
		"internal":        func(ns walletdb.ReadWriteBucket) error { _, e := sm.NextInternalAddresses(ns, 0, 1); return e },
		"extend-external": func(ns walletdb.ReadWriteBucket) error { return sm.ExtendExternalAddresses(ns, 0, 3) },
		"extend-internal": func(ns walletdb.ReadWriteBucket) error { return sm.ExtendInternalAddresses(ns, 0, 3) },
		"new-account":     func(ns walletdb.ReadWriteBucket) error { _, e := sm.NewAccount(ns, "other"); return e },
	} {
		t.Run(name, func(t *testing.T) {
			e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return fn(tx.ReadWriteBucket(waddrmgrNamespaceKey)) })
			if !errors.Is(e, ErrHostedAllocationProfile) {
				t.Fatal("bypass", e)
			}
		})
	}
	ref := hostedManagerReference(t, "zero256/pool-complete")
	r := hostedManagerRecord(t, ref.Snapshot.Links[0])
	hostedApply(t, db, m, r)
	// Each malformed mutation is rolled back after the same production audit.
	cases := map[string]func(walletdb.ReadWriteBucket, walletdb.ReadWriteBucket) error{
		"extra-key": func(ns, local walletdb.ReadWriteBucket) error { return local.Put([]byte("extra"), []byte{1}) },
		"dangling-forward": func(ns, local walletdb.ReadWriteBucket) error {
			scope := KeyScopeBIP0084
			b, _ := fetchWriteScopeBucket(ns, &scope)
			return b.NestedReadWriteBucket(addrAcctIdxBucketName).Put(bytes.Repeat([]byte{9}, 32), uint32ToBytes(0))
		},
		"dangling-reverse": func(ns, local walletdb.ReadWriteBucket) error {
			scope := KeyScopeBIP0084
			b, _ := fetchWriteScopeBucket(ns, &scope)
			return b.NestedReadWriteBucket(addrAcctIdxBucketName).NestedReadWriteBucket(uint32ToBytes(0)).Put(bytes.Repeat([]byte{9}, 32), []byte{0})
		},
		"wrong-cursor": func(ns, local walletdb.ReadWriteBucket) error {
			scope := KeyScopeBIP0084
			b, _ := fetchWriteScopeBucket(ns, &scope)
			a := b.NestedReadWriteBucket(acctBucketName)
			raw := append([]byte{}, a.Get(uint32ToBytes(0))...)
			pn := int(binary.LittleEndian.Uint32(raw[5:9]))
			off := 9 + pn
			sn := int(binary.LittleEndian.Uint32(raw[off : off+4]))
			off += 4 + sn
			binary.LittleEndian.PutUint32(raw[off:off+4], 2)
			return a.Put(uint32ToBytes(0), raw)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rollback := errors.New("rollback")
			e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns, local := tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace))
				if e := mutate(ns, local); e != nil {
					return e
				}
				if _, e := m.AuditHostedAllocation(context.Background(), ns, local); e == nil {
					t.Error("damaged state accepted")
				}
				return rollback
			})
			if !errors.Is(e, rollback) {
				t.Fatal(e)
			}
			hostedAudit(t, db, m)
		})
	}
	forged := hostedManagerReference(t, "zero256/injected-invalid-prefix")
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, local := tx.ReadWriteBucket(waddrmgrNamespaceKey), tx.ReadWriteBucket([]byte(HostedAllocationNamespace))
		r := hostedManagerRecord(t, forged.Snapshot.Links[1])
		script, _ := hex.DecodeString(r.Script)
		if e := putChainedAddress(ns, &KeyScopeBIP0084, script[2:], 0, ssFull, r.Branch, r.SelectedIndex, adtChain); e != nil {
			return e
		}
		if e := local.NestedReadWriteBucket(hostedAllocationRecordsKey).Put([]byte{0, 0, 0, 2}, forged.Snapshot.Links[1]); e != nil {
			return e
		}
		raw, _ := json.Marshal(forged.Snapshot.Meta)
		if e := local.Put(hostedAllocationMetaKey, raw); e != nil {
			return e
		}
		_, e := m.AuditHostedAllocation(context.Background(), ns, local)
		if e == nil {
			t.Error("valid child labeled invalid")
		}
		return errors.New("rollback forged")
	})
	if e == nil || !strings.Contains(e.Error(), "rollback forged") {
		t.Fatal(e)
	}
}

func TestHostedAllocationManagerRecognizedFrontier(t *testing.T) {
	db, m, g := hostedManager(t, "zero256")
	hostedBind(t, db, m, g, "zero256")
	ref := hostedManagerReference(t, "zero256/pool-complete")
	r := hostedManagerRecord(t, ref.Snapshot.Links[0])
	hostedApply(t, db, m, r)
	addr, e := address.DecodeAddress(r.Address, &chaincfg.MainNetParams)
	if e != nil {
		t.Fatal(e)
	}
	// Warm the inherited cache, then coherently roll back only the underlying
	// issued cursor in an aborted transaction. Even cached recognized addresses
	// must fail the live frontier check instead of becoming 'foreign'.
	if e = walletdb.View(db, func(tx walletdb.ReadTx) error { _, e := m.Address(tx.ReadBucket(waddrmgrNamespaceKey), addr); return e }); e != nil {
		t.Fatal(e)
	}
	rollback := errors.New("restore exact cursor")
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scope := KeyScopeBIP0084
		sb, _ := fetchWriteScopeBucket(ns, &scope)
		b := sb.NestedReadWriteBucket(acctBucketName)
		raw := append([]byte{}, b.Get(uint32ToBytes(0))...)
		off := 9 + int(binary.LittleEndian.Uint32(raw[5:9]))
		off += 4 + int(binary.LittleEndian.Uint32(raw[off:off+4]))
		binary.LittleEndian.PutUint32(raw[off:off+4], 0)
		if e := b.Put(uint32ToBytes(0), raw); e != nil {
			return e
		}
		if _, e := m.Address(ns, addr); !errors.Is(e, ErrHostedAllocationFrontier) {
			t.Error("recognized row treated as foreign", e)
		}
		if e := m.MarkUsed(ns, addr); !errors.Is(e, ErrHostedAllocationFrontier) {
			t.Error("recognized use advanced", e)
		}
		if _, _, e := m.AddrAccount(ns, addr); !errors.Is(e, ErrHostedAllocationFrontier) {
			t.Error("recognized account substituted", e)
		}
		return rollback
	})
	if !errors.Is(e, rollback) {
		t.Fatal(e)
	}
	hostedAudit(t, db, m)
	foreign, _ := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.MainNetParams)
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := m.Address(tx.ReadBucket(waddrmgrNamespaceKey), foreign)
		return e
	})
	if !IsError(e, ErrAddressNotFound) {
		t.Fatal("foreign address misclassified", e)
	}
}
