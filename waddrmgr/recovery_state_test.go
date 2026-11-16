package waddrmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/walletdb/migration"
)

func retainedManager(t *testing.T) (walletdb.DB, *Manager) {
	t.Helper()
	db, err := walletdb.Create("bdb", filepath.Join(t.TempDir(), "fixture.db"), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	var mgr *Manager
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := CreateWithRecovery(ns, rootKey, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, []byte("public fixture metadata"), []byte("published fixture secret payload")); err != nil {
			return err
		}
		mgr, err = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		return err
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close(); db.Close() })
	return db, mgr
}

// The previous implementation advertises only the legacy migrations. Its
// existing upgrade gate must refuse the newly opt-in recovery schema.
type preRecoveryMigration struct{ *MigrationManager }

func (m preRecoveryMigration) Versions() []migration.Version { return versions }
func TestRecoverySchemaAndOldBinaryRefusal(t *testing.T) {
	db, mgr := retainedManager(t)
	if mgr.DerivationMode() != DerivationStandard || !mgr.RecoveryEnabled() {
		t.Fatal("mode missing")
	}
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if v, err := fetchManagerVersion(ns); err != nil || v != RecoveryManagerVersion {
			t.Fatal("mandatory recovery schema missing", err)
		}
		return migration.Upgrade(preRecoveryMigration{NewMigrationManager(ns)})
	})
	if !errors.Is(err, migration.ErrReversion) {
		t.Fatal("old binary version gate accepted recovery schema", err)
	}
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return migration.Upgrade(NewMigrationManager(tx.ReadWriteBucket(waddrmgrNamespaceKey)))
	})
	if err != nil {
		t.Fatal("new version gate rejected recovery", err)
	}
}
func TestRecoveryStateMissingAndCorrupt(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(walletdb.ReadWriteBucket) error
	}{
		{"all-retention-removed", func(b walletdb.ReadWriteBucket) error {
			for _, key := range [][]byte{derivationModeName, recoveryVersionName, recoveryPublicName, recoveryPrivateName} {
				if err := b.Delete(key); err != nil {
					return err
				}
			}
			return nil
		}},
		{"mode-missing", func(b walletdb.ReadWriteBucket) error { return b.Delete(derivationModeName) }},
		{"private-missing", func(b walletdb.ReadWriteBucket) error { return b.Delete(recoveryPrivateName) }},
		{"unknown-mode", func(b walletdb.ReadWriteBucket) error { return b.Put(derivationModeName, uint32ToBytes(99)) }},
		{"downgraded-schema", func(b walletdb.ReadWriteBucket) error { return b.Put(mgrVersionName, uint32ToBytes(latestMgrVersion)) }},
		{"truncated-schema", func(b walletdb.ReadWriteBucket) error { return b.Put(mgrVersionName, []byte{9}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _ := retainedManager(t)
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return test.mutate(tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(mainBucketName))
			}); err != nil {
				t.Fatal(err)
			}
			err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				m, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
				if m != nil {
					m.Close()
				}
				return err
			})
			if err == nil {
				t.Fatal("damaged recovery state reopened")
			}
		})
	}
}
func TestRecoveryEncryptedPayloadAndErasureGuards(t *testing.T) {
	db, mgr := retainedManager(t)
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		main := ns.NestedReadBucket(mainBucketName)
		if bytes.Contains(main.Get(recoveryPrivateName), []byte("published fixture secret payload")) {
			t.Fatal("private plaintext retained")
		}
		if plain, err := mgr.RecoveryData(ns, true); err == nil || len(plain) != 0 {
			t.Fatal("locked recovery decrypted")
		}
		return mgr.Unlock(ns, privPassphrase)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		plain, err := mgr.RecoveryData(tx.ReadBucket(waddrmgrNamespaceKey), true)
		if err != nil {
			return err
		}
		if string(plain) != "published fixture secret payload" {
			t.Fatal("private payload mismatch")
		}
		clear(plain)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func(walletdb.ReadWriteBucket) error{mgr.NeuterRootKey, mgr.ConvertToWatchingOnly} {
		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return operation(tx.ReadWriteBucket(waddrmgrNamespaceKey)) })
		if !errors.Is(err, ErrRecoveryProtected) {
			t.Fatal("destructive operation accepted", err)
		}
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(mainBucketName)
		data := append([]byte(nil), b.Get(recoveryPrivateName)...)
		data[len(data)-1] ^= 1
		return b.Put(recoveryPrivateName, data)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		plain, err := mgr.RecoveryData(tx.ReadBucket(waddrmgrNamespaceKey), true)
		if len(plain) != 0 {
			t.Fatal("corrupt secret returned")
		}
		return err
	}); !errors.Is(err, ErrRecoveryState) {
		t.Fatal("ciphertext corruption accepted", err)
	}
}
func TestRecoveryBranchCapacity(t *testing.T) {
	db, mgr := retainedManager(t)
	scope, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	if err != nil {
		t.Fatal(err)
	}
	// Fixture cursor is advanced directly to the boundary; this is a capacity
	// test, not a derivation golden or a claim that preceding addresses were used.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		row, err := fetchAccountInfo(ns, &KeyScopeBIP0084, 0)
		if err != nil {
			return err
		}
		a := row.(*dbDefaultAccountRow)
		return putDefaultAccountInfo(ns, &KeyScopeBIP0084, 0, a.pubKeyEncrypted, a.privKeyEncrypted, maxRecoveryBranchIndex-1, maxRecoveryBranchIndex-1, a.name)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, internal := range []bool{false, true} {
		err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			if internal {
				_, err = scope.NextInternalAddresses(ns, 0, 1)
			} else {
				_, err = scope.NextExternalAddresses(ns, 0, 1)
			}
			return err
		})
		if err != nil {
			t.Fatal("last supported address rejected", err)
		}
	}
	for _, op := range []func(walletdb.ReadWriteBucket) error{
		func(ns walletdb.ReadWriteBucket) error { _, err := scope.NextExternalAddresses(ns, 0, 1); return err },
		func(ns walletdb.ReadWriteBucket) error { _, err := scope.NextInternalAddresses(ns, 0, 1); return err },
		func(ns walletdb.ReadWriteBucket) error {
			return scope.ExtendExternalAddresses(ns, 0, maxRecoveryBranchIndex)
		},
		func(ns walletdb.ReadWriteBucket) error {
			return scope.ExtendInternalAddresses(ns, 0, maxRecoveryBranchIndex)
		},
	} {
		err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return op(tx.ReadWriteBucket(waddrmgrNamespaceKey)) })
		if !IsError(err, ErrTooManyAddresses) {
			t.Fatal("unsupported cursor issued", err)
		}
	}
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		accounts, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if a.Scope == KeyScopeBIP0084 && (a.NextExternal != maxRecoveryBranchIndex || a.NextInternal != maxRecoveryBranchIndex) {
				t.Fatal("cursor changed after rejected issuance")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("full supported inventory no longer exportable", err)
	}
}
func TestRecoveryInventoryMalformedAndUnsupported(t *testing.T) {
	for _, mutation := range []struct {
		name string
		edit func(walletdb.ReadWriteBucket) error
	}{
		{"short-account-key", func(ns walletdb.ReadWriteBucket) error {
			b, err := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
			if err != nil {
				return err
			}
			return b.NestedReadWriteBucket(acctBucketName).Put([]byte{1}, []byte{1})
		}},
		{"extra-account", func(ns walletdb.ReadWriteBucket) error {
			row, err := fetchAccountInfo(ns, &KeyScopeBIP0084, 0)
			if err != nil {
				return err
			}
			a := row.(*dbDefaultAccountRow)
			return putDefaultAccountInfo(ns, &KeyScopeBIP0084, 1, a.pubKeyEncrypted, a.privKeyEncrypted, 0, 0, "extra")
		}},
		{"oversized-cursor", func(ns walletdb.ReadWriteBucket) error {
			row, err := fetchAccountInfo(ns, &KeyScopeBIP0084, 0)
			if err != nil {
				return err
			}
			a := row.(*dbDefaultAccountRow)
			return putDefaultAccountInfo(ns, &KeyScopeBIP0084, 0, a.pubKeyEncrypted, a.privKeyEncrypted, maxRecoveryBranchIndex+1, 0, a.name)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			db, _ := retainedManager(t)
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return mutation.edit(tx.ReadWriteBucket(waddrmgrNamespaceKey)) }); err != nil {
				t.Fatal(err)
			}
			err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
				return err
			})
			if !errors.Is(err, ErrRecoveryInventory) {
				t.Fatal("unsupported inventory accepted", err)
			}
		})
	}
}

func TestRecoveryInventoryRejectsImportedScript(t *testing.T) {
	db, mgr := retainedManager(t)
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if err := mgr.Unlock(ns, privPassphrase); err != nil {
			return err
		}
		scope, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
		if err != nil {
			return err
		}
		_, err = scope.ImportScript(ns, []byte{0x51}, &BlockStamp{Hash: *chaincfg.MainNetParams.GenesisHash})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
		return err
	})
	if !errors.Is(err, ErrRecoveryInventory) {
		t.Fatal("imported script omitted from recovery contract", err)
	}
}
func TestRecoveryCorruptAccountLengths(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset int
	}{{"outer", 1}, {"public", 5}, {"private", -1}, {"name", -2}} {
		t.Run(test.name, func(t *testing.T) {
			db, _ := retainedManager(t)
			err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				scoped, err := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
				if err != nil {
					return err
				}
				b := scoped.NestedReadWriteBucket(acctBucketName)
				data := append([]byte(nil), b.Get(uint32ToBytes(0))...)
				offset := test.offset
				if offset < 0 {
					offset = 9 + int(binary.LittleEndian.Uint32(data[5:9]))
					if test.offset == -2 {
						offset += 4 + int(binary.LittleEndian.Uint32(data[offset:offset+4])) + 8
					}
				}
				binary.LittleEndian.PutUint32(data[offset:offset+4], ^uint32(0))
				return b.Put(uint32ToBytes(0), data)
			})
			if err != nil {
				t.Fatal(err)
			}
			err = walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
				return err
			})
			if err == nil {
				t.Fatal("corrupt length accepted")
			}
		})
	}
}

func TestRecoveryCorruptWatchOnlyLengths(t *testing.T) {
	for _, offset := range []int{0, 16} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			db, _ := retainedManager(t)
			err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				data := make([]byte, 21)
				binary.LittleEndian.PutUint32(data[offset:offset+4], ^uint32(0))
				return putAccountRow(ns, &KeyScopeBIP0084, 0, &dbAccountRow{acctType: accountWatchOnly, rawData: data})
			})
			if err != nil {
				t.Fatal(err)
			}
			err = walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
				return err
			})
			if !errors.Is(err, ErrRecoveryInventory) {
				t.Fatal("malformed watch-only account accepted", err)
			}
		})
	}
}

func TestRecoveryMalformedScopeAndAddresses(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(walletdb.ReadWriteBucket) error
	}{
		{"schema-one-byte", func(ns walletdb.ReadWriteBucket) error {
			key := scopeToBytes(&KeyScopeBIP0084)
			return ns.NestedReadWriteBucket(scopeSchemaBucketName).Put(key[:], []byte{0})
		}},
		{"schema-extra-byte", func(ns walletdb.ReadWriteBucket) error {
			key := scopeToBytes(&KeyScopeBIP0084)
			return ns.NestedReadWriteBucket(scopeSchemaBucketName).Put(key[:], []byte{0, 0, 0})
		}},
		{"missing-address-bucket", func(ns walletdb.ReadWriteBucket) error {
			scope, err := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
			if err != nil {
				return err
			}
			return scope.DeleteNestedBucket(addrBucketName)
		}},
		{"address-length9", func(ns walletdb.ReadWriteBucket) error { return putDamagedRecoveryAddress(ns, adtChain, 9) }},
		{"address-huge-length", func(ns walletdb.ReadWriteBucket) error { return putDamagedRecoveryAddress(ns, adtChain, ^uint32(0)) }},
		{"import-huge-length", func(ns walletdb.ReadWriteBucket) error { return putDamagedRecoveryAddress(ns, adtImport, ^uint32(0)) }},
		{"script-huge-length", func(ns walletdb.ReadWriteBucket) error { return putDamagedRecoveryAddress(ns, adtScript, ^uint32(0)) }},
		{"nested-address-bucket", func(ns walletdb.ReadWriteBucket) error {
			scope, err := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
			if err != nil {
				return err
			}
			_, err = scope.NestedReadWriteBucket(addrBucketName).CreateBucket(make([]byte, 32))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _ := retainedManager(t)
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return test.edit(tx.ReadWriteBucket(waddrmgrNamespaceKey)) }); err != nil {
				t.Fatal(err)
			}
			err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				_, err := RecoveryAccounts(tx.ReadBucket(waddrmgrNamespaceKey))
				return err
			})
			if !errors.Is(err, ErrRecoveryInventory) {
				t.Fatal("malformed inventory accepted", err)
			}
		})
	}
}
func putDamagedRecoveryAddress(ns walletdb.ReadWriteBucket, kind addressType, size uint32) error {
	scope, err := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
	if err != nil {
		return err
	}
	row := make([]byte, 26)
	row[0] = byte(kind)
	binary.LittleEndian.PutUint32(row[14:18], size)
	return scope.NestedReadWriteBucket(addrBucketName).Put(make([]byte, 32), row)
}
func TestRecoveryReachedDecoderBounds(t *testing.T) {
	for _, size := range []uint32{9, ^uint32(0)} {
		row := make([]byte, 26)
		binary.LittleEndian.PutUint32(row[14:18], size)
		if decoded, err := deserializeAddressRow(row); err == nil || decoded != nil {
			t.Fatal("outer address length accepted")
		}
	}
	for _, offset := range []int{0, 16} {
		data := make([]byte, 21)
		binary.LittleEndian.PutUint32(data[offset:offset+4], ^uint32(0))
		if decoded, err := deserializeWatchOnlyAccountRow(uint32ToBytes(0), &dbAccountRow{acctType: accountWatchOnly, rawData: data}); err == nil || decoded != nil {
			t.Fatal("watch-only unbounded length accepted")
		}
	}
}

func TestRecoveryMissingNamespace(t *testing.T) {
	if _, err := RecoveryAccounts(nil); !errors.Is(err, ErrRecoveryState) {
		t.Fatal("missing namespace accepted", err)
	}
	db, mgr := retainedManager(t)
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return tx.DeleteTopLevelBucket(waddrmgrNamespaceKey) }); err != nil {
		t.Fatal(err)
	}
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		plain, err := mgr.RecoveryData(tx.ReadBucket(waddrmgrNamespaceKey), false)
		if len(plain) != 0 {
			t.Fatal("missing namespace returned payload")
		}
		return err
	})
	if !errors.Is(err, ErrRecoveryState) {
		t.Fatal("missing namespace not rejected", err)
	}
}
