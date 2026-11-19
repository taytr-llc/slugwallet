package waddrmgr

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type phaseAReference struct {
	Plans []struct {
		Name     string
		Imported []uint32
		Initial  struct {
			Hex string `json:"progress_hex"`
		}
		Selected []struct {
			Step int
			Hex  string `json:"progress_hex"`
		} `json:"selected_steps"`
	}
}

func phaseAReferenceRead(t *testing.T) phaseAReference {
	t.Helper()
	b, e := os.ReadFile("../wallet/testdata/phase-a-recovery/progress-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != "fb0c9a5b1d59711ecb6d855534358f09175df5eb547c1bf88d0474b4b3515801" {
		t.Fatal("progress reference changed")
	}
	var r phaseAReference
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestPhaseARecoveryFrozenPlans(t *testing.T) {
	r := phaseAReferenceRead(t)
	if len(r.Plans) != 7 {
		t.Fatal(len(r.Plans))
	}
	for _, p := range r.Plans {
		t.Run(p.Name, func(t *testing.T) {
			accounts := recovery.DefaultAccounts()
			for i := range accounts {
				accounts[i].NextExternal = p.Imported[2*i]
				accounts[i].NextInternal = p.Imported[2*i+1]
			}
			m, e := recovery.ManifestFor([32]byte{}, accounts)
			if e != nil {
				t.Fatal(e)
			}
			s, e := PhaseARecoveryPlan(context.Background(), m)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := encodeRecoveryProgressFor(s, phaseARecoveryPolicy())
			if e != nil || hex.EncodeToString(raw) != p.Initial.Hex {
				t.Fatal("independent plan byte mismatch", e)
			}
		})
	}
}
func phaseAManager(t *testing.T, accounts []recovery.Account) (walletdb.DB, *Manager) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal-only creation")
	}
	m, e := recovery.ManifestFor([32]byte{}, accounts)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := recovery.MarshalManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	seed := recovery.SeedFromEntropy([32]byte{})
	root, e := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	clear(seed[:])
	if e != nil {
		t.Fatal(e)
	}
	defer root.Zero()
	priv := make([]byte, 68)
	binary.LittleEndian.PutUint32(priv, 1)
	h := sha256.Sum256(pub)
	copy(priv[36:], h[:])
	defer clear(priv)
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "phase-a.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	var mgr *Manager
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = CreateWithPhaseARecovery(context.Background(), ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, pub, priv); e != nil {
			return e
		}
		mgr, e = OpenPhaseARecovery(ns, pubPassphrase, &chaincfg.MainNetParams)
		return e
	})
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { mgr.Close(); db.Close() })
	return db, mgr
}
func TestPhaseARecoveryFrozenGreedyChunks(t *testing.T) {
	r := phaseAReferenceRead(t)
	for _, p := range r.Plans {
		if p.Name != "uniform_0" {
			continue
		}
		db, m := phaseAManager(t, recovery.DefaultAccounts())
		step := 0
		for _, want := range p.Selected {
			for step < want.Step {
				if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
					_, e := m.DeriveRecoveryChunk(context.Background(), tx.ReadWriteBucket(waddrmgrNamespaceKey))
					return e
				}); e != nil {
					t.Fatal(e)
				}
				step++
			}
			state := progressState(t, db, m)
			raw, e := encodeRecoveryProgressFor(state, phaseARecoveryPolicy())
			if e != nil || hex.EncodeToString(raw) != want.Hex {
				t.Fatalf("step%d frozen bytes differ %v", step, e)
			}
		}
		if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
			_, e := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPhaseARecoveryClippedReadyAllocationAndDiscovery(t *testing.T) {
	a := recovery.DefaultAccounts()
	a[3].NextInternal = 4077
	db, m := phaseAManager(t, a)
	deriveAllRecovery(t, db, m)
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		grew, e := m.ObserveRecoveryAddress(ns, KeyScope{86, 0}, 1, 4095)
		if e != nil {
			return e
		}
		if grew {
			t.Fatal("clipped target expanded")
		}
		s, e := m.CandidateRecoveryState(ns)
		if e != nil {
			return e
		}
		if b := s.Branches[7]; b.IssuedNext != 4096 || b.TargetNext != 4096 || b.DerivedNext != 4096 {
			t.Fatal("clipped discovery", b)
		}
		if e = m.SetCandidateRecoveryReady(ns); e != nil {
			return e
		}
		limit, e := m.recoveryAllocationLimit(ns, KeyScope{86, 0}, 1)
		if e != nil {
			return e
		}
		if limit != 4096 {
			t.Fatal(limit)
		}
		if e = m.recordRecoveryAllocation(ns, KeyScope{86, 0}, 1, 4097, 1); e == nil {
			t.Fatal("ready allocation escaped profile")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestPhaseARecoveryPendingTargetAndNamespaceCorruption(t *testing.T) {
	db, m := phaseAManager(t, recovery.DefaultAccounts())
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		main := ns.NestedReadWriteBucket(mainBucketName)
		original := append([]byte(nil), main.Get(phaseAProgressName)...)
		bad := append([]byte(nil), original...)
		binary.LittleEndian.PutUint32(bad[12+24:], 19)
		if e := main.Put(phaseAProgressName, bad); e != nil {
			return e
		}
		if _, e := m.CandidateRecoveryState(ns); e == nil {
			t.Fatal("shortened lookahead accepted")
		}
		if e := main.Put(phaseAProgressName, original); e != nil {
			return e
		}
		if _, e := main.CreateBucket(recoveryProgressName); e != nil {
			return e
		}
		if _, e := OpenPhaseARecovery(ns, pubPassphrase, &chaincfg.MainNetParams); e == nil {
			t.Fatal("foreign nested namespace accepted")
		}
		return main.DeleteNestedBucket(recoveryProgressName)
	})
	if e != nil {
		t.Fatal(e)
	}
}
