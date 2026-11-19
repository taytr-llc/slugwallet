package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

func ownActivityManager(t *testing.T) (walletdb.DB, *Manager, recovery.Manifest) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile public fixture")
	}
	raw, e := os.ReadFile("../wallet/testdata/own-activity/inputs/public/zero256.manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "f027cb1dfc522b59a6f863ad9921b499d42ea7102fa3d7a17a8153b650be9ed5" {
		t.Fatal("independent public manifest changed")
	}
	manifest, e := recovery.ParseManifest(raw)
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
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "activity.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	var mgr *Manager
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = CreateWithRecovery(ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Unix(0, 0), raw, []byte("published fixture setup only")); e != nil {
			return e
		}
		mgr, e = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		return e
	})
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { mgr.Close(); db.Close() })
	return db, mgr, manifest
}

type ownPublicBucket struct {
	walletdb.ReadBucket
	t *testing.T
}

func (b ownPublicBucket) Get(k []byte) []byte {
	for _, private := range [][]byte{recoveryPrivateName, masterHDPrivName, masterPrivKeyName, cryptoPrivKeyName, cryptoScriptKeyName} {
		if bytes.Equal(k, private) {
			b.t.Fatal("private field accessed", string(k))
		}
	}
	return b.ReadBucket.Get(k)
}
func (b ownPublicBucket) NestedReadBucket(k []byte) walletdb.ReadBucket {
	if !bytes.Equal(k, mainBucketName) && !bytes.Equal(k, syncBucketName) {
		b.t.Fatal("address inventory accessed", string(k))
	}
	v := b.ReadBucket.NestedReadBucket(k)
	if v == nil {
		return nil
	}
	return ownPublicBucket{ReadBucket: v, t: b.t}
}
func (b ownPublicBucket) ForEach(func([]byte, []byte) error) error {
	b.t.Fatal("public identity enumerated storage")
	return nil
}
func (b ownPublicBucket) ReadCursor() walletdb.ReadCursor {
	b.t.Fatal("public identity opened cursor")
	return nil
}
func TestOwnActivityPublicIdentityAtomicAndPrivateFree(t *testing.T) {
	db, mgr, manifest := ownActivityManager(t)
	if !mgr.IsLocked() {
		t.Fatal("fixture must remain locked")
	}
	// Direct persisted write deliberately leaves the manager's in-memory stamp at
	// genesis, proving this method returns the atomic database stamp instead.
	var stamp [36]byte
	binary.LittleEndian.PutUint32(stamp[:4], 37)
	stamp[4] = 9
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(syncBucketName).Put(syncedToName, stamp[:])
	})
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		got, e := mgr.ReadOwnActivityState(context.Background(), ownPublicBucket{ReadBucket: tx.ReadBucket(waddrmgrNamespaceKey), t: t})
		if e == nil && (got.RootPublicKey != manifest.RootPublicKey || got.GymPublicKey != manifest.GymPublicKey || got.GymID != manifest.GymID || got.SyncedHeight != 37 || !bytes.Equal(got.SyncedHash[:], stamp[4:])) {
			t.Fatal("public identity/stamp mismatch")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if mgr.SyncedTo().Height == 37 || !mgr.IsLocked() {
		t.Fatal("read mutated loaded state")
	}
}
func TestOwnActivityPublicIdentityBoundsAndProfiles(t *testing.T) {
	db, mgr, _ := ownActivityManager(t)
	for _, tc := range []struct {
		name        string
		bucket, key []byte
		value       []byte
		want        error
	}{
		{"manifest-cipher-bound", mainBucketName, recoveryPublicName, make([]byte, 65577), ErrOwnActivityCorrupt},
		{"root-cipher-bound", mainBucketName, masterHDPubName, make([]byte, 169), ErrOwnActivityCorrupt},
		{"sync37", syncBucketName, syncedToName, make([]byte, 37), ErrOwnActivityCorrupt},
		{"sync-zero-hash", syncBucketName, syncedToName, make([]byte, 36), ErrOwnActivityCorrupt},
		{"mode", mainBucketName, derivationModeName, []byte{0, 0, 0, 0}, ErrOwnActivityCorrupt},
		{"schema8", mainBucketName, mgrVersionName, []byte{8, 0, 0, 0}, ErrOwnActivityProfile},
		{"schema10", mainBucketName, mgrVersionName, []byte{10, 0, 0, 0}, ErrOwnActivityProfile},
		{"schema11", mainBucketName, mgrVersionName, []byte{11, 0, 0, 0}, ErrOwnActivityProfile},
		{"schema12", mainBucketName, mgrVersionName, []byte{12, 0, 0, 0}, ErrOwnActivityProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var old []byte
			if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				b := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(tc.bucket)
				old = append([]byte(nil), b.Get(tc.key)...)
				return b.Put(tc.key, tc.value)
			}); e != nil {
				t.Fatal(e)
			}
			e := walletdb.View(db, func(tx walletdb.ReadTx) error {
				v, e := mgr.ReadOwnActivityState(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey))
				if v != (OwnActivityState{}) {
					t.Fatal("partial identity")
				}
				return e
			})
			if !errors.Is(e, tc.want) {
				t.Fatal("refusal", e)
			}
			if e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(tc.bucket).Put(tc.key, old)
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := mgr.ReadOwnActivityState(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	mgr.Close()
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := mgr.ReadOwnActivityState(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	}); !errors.Is(e, ErrOwnActivityUnavailable) {
		t.Fatal(e)
	}
}
