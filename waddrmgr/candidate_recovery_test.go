// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/snacl"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/walletdb/migration"
)

func candidateManager(t *testing.T, supplied ...[]productionprofile.Cursor) (walletdb.DB, *Manager) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal-chain candidate runtime")
	}
	cursors := productionprofile.DefaultCursors()
	if len(supplied) != 0 {
		cursors = supplied[0]
	}
	m, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := productionprofile.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	entropy, err := productionprofile.FixtureEntropy(productionprofile.CandidateZero256)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	priv := make([]byte, 68)
	defer clear(priv)
	binary.LittleEndian.PutUint32(priv, 2)
	copy(priv[4:36], entropy[:])
	digest := sha256.Sum256(pub)
	copy(priv[36:], digest[:])
	db, err := walletdb.Create("bdb", filepath.Join(t.TempDir(), "candidate.db"), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	var manager *Manager
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := CreateWithCandidateRecovery(context.Background(), ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, pub, priv); err != nil {
			return err
		}
		manager, err = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		return err
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close(); db.Close() })
	return db, manager
}

func TestCandidateRetainedCursorMinimumFailsOpen(t *testing.T) {
	for _, internal := range []bool{false, true} {
		name := "external"
		if internal {
			name = "internal"
		}
		t.Run(name, func(t *testing.T) {
			cursors := productionprofile.DefaultCursors()
			for i := range cursors {
				cursors[i].NextExternal, cursors[i].NextInternal = 2, 3
			}
			db, manager := candidateManager(t, cursors)
			keyScope := KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType}
			if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				ns := tx.ReadBucket(waddrmgrNamespaceKey)
				states, err := RecoveryAccounts(ns)
				if err != nil {
					return err
				}
				for _, state := range states {
					if state.NextExternal != 2 || state.NextInternal != 3 {
						t.Fatal("creation exposed incomplete retained cursors")
					}
				}
				var relevant int
				if err := manager.ForEachRelevantActiveAddress(ns, func(address.Address) error { relevant++; return nil }); err != nil {
					return err
				}
				if relevant != 20 {
					t.Fatalf("creation did not materialize retained address inventory: %d", relevant)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			manager.Close()
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				row, err := fetchAccountInfo(ns, &keyScope, 0)
				if err != nil {
					return err
				}
				a := row.(*dbDefaultAccountRow)
				if internal {
					a.nextInternalIndex--
				} else {
					a.nextExternalIndex--
				}
				if err := putDefaultAccountInfo(ns, &keyScope, 0, a.pubKeyEncrypted, a.privKeyEncrypted, a.nextExternalIndex, a.nextInternalIndex, a.name); err != nil {
					return err
				}
				// Roll back the corresponding address row as well so the
				// ordinary inventory bounds remain coherent. This isolates
				// the retained-manifest minimum from that older guard.
				scoped, err := fetchWriteScopeBucket(ns, &keyScope)
				if err != nil {
					return err
				}
				addresses := scoped.NestedReadWriteBucket(addrBucketName)
				var remove [][]byte
				if err := addresses.ForEach(func(key, value []byte) error {
					row, err := deserializeAddressRow(value)
					if err != nil {
						return err
					}
					address, err := deserializeChainedAddress(row)
					if err != nil {
						return err
					}
					if (!internal && address.branch == ExternalBranch && address.index >= a.nextExternalIndex) ||
						(internal && address.branch == InternalBranch && address.index >= a.nextInternalIndex) {
						remove = append(remove, append([]byte(nil), key...))
					}
					return nil
				}); err != nil {
					return err
				}
				for _, key := range remove {
					if err := addresses.Delete(key); err != nil {
						return err
					}
				}
				_, err = RecoveryAccounts(ns)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				opened, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
				if opened != nil {
					opened.Close()
				}
				return err
			}); !errors.Is(err, ErrRecoveryState) {
				t.Fatal("public manager Open accepted cursor below retained minimum", err)
			}
		})
	}
}

func TestCandidateInitializationCancellationRollsBack(t *testing.T) {
	cursors := productionprofile.DefaultCursors()
	cursors[2].NextExternal, cursors[2].NextInternal = 2, 3
	source, manager := candidateManager(t, cursors)
	var public, private []byte
	if err := walletdb.View(source, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if err := manager.Unlock(ns, privPassphrase); err != nil {
			return err
		}
		var err error
		public, err = manager.RecoveryData(ns, false)
		if err != nil {
			return err
		}
		private, err = manager.RecoveryData(ns, true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	entropy, _ := productionprofile.FixtureEntropy(productionprofile.CandidateZero256)
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	teardown, db := emptyDB(t)
	defer teardown()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldGenerator := SetSecretKeyGen(func(password *[]byte, options *ScryptOptions) (*snacl.SecretKey, error) {
		// This is after public validation and namespace creation but before
		// completion. A failed creation must not leave a resumable half-wallet.
		cancel()
		return defaultNewSecretKey(password, options)
	})
	defer SetSecretKeyGen(oldGenerator)
	create := func(ctx context.Context) error {
		return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
			if err != nil {
				return err
			}
			return CreateWithCandidateRecovery(ctx, ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, public, private)
		})
	}
	if err := create(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("creation did not honor cancellation after namespace writes", err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		if tx.ReadBucket(waddrmgrNamespaceKey) != nil {
			t.Fatal("canceled initialization left a partial manager")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	SetSecretKeyGen(oldGenerator)
	if err := create(context.Background()); err != nil {
		t.Fatal("fresh initialization after rollback failed", err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if opened != nil {
			opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal("retried candidate did not durably materialize cursor minima", err)
	}
}

func TestCandidateManagerBoundaryAndReopen(t *testing.T) {
	db, manager := candidateManager(t)
	keyScope := KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType}
	scope, err := manager.FetchScopedKeyManager(keyScope)
	if err != nil {
		t.Fatal(err)
	}
	// Advance only the cursor to isolate the boundary from thousands of
	// derivations; independent high-index cryptographic vectors live elsewhere.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		row, err := fetchAccountInfo(ns, &keyScope, 0)
		if err != nil {
			return err
		}
		a := row.(*dbDefaultAccountRow)
		return putDefaultAccountInfo(ns, &keyScope, 0, a.pubKeyEncrypted, a.privKeyEncrypted, maxRecoveryBranchIndex-1, maxRecoveryBranchIndex-1, a.name)
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
			t.Fatal(err)
		}
	}
	operations := []func(walletdb.ReadWriteBucket) error{
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.NextExternalAddresses(ns, 0, 1); return e },
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.NextInternalAddresses(ns, 0, 2); return e },
		func(ns walletdb.ReadWriteBucket) error {
			return scope.ExtendExternalAddresses(ns, 0, maxRecoveryBranchIndex)
		},
		func(ns walletdb.ReadWriteBucket) error {
			return scope.ExtendInternalAddresses(ns, 0, maxRecoveryBranchIndex)
		},
	}
	for _, operation := range operations {
		if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return operation(tx.ReadWriteBucket(waddrmgrNamespaceKey)) }); !errors.Is(err, ErrRecoveryScanRequired) {
			t.Fatal("candidate boundary mutation accepted", err)
		}
	}
	manager.Close()
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		reopened, e := Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if e != nil {
			return e
		}
		defer reopened.Close()
		states, e := RecoveryAccounts(ns)
		if e != nil {
			return e
		}
		for _, a := range states {
			if a.Scope == keyScope && (a.NextExternal != maxRecoveryBranchIndex || a.NextInternal != maxRecoveryBranchIndex) {
				t.Fatal("rejected allocation changed cursor")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("full bounded candidate no longer opens", err)
	}
}

func TestCandidateUnsupportedMutationPreservesReopen(t *testing.T) {
	db, manager := candidateManager(t)
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		return manager.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase)
	}); err != nil {
		t.Fatal(err)
	}
	scope, err := manager.FetchScopedKeyManager(KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType})
	if err != nil {
		t.Fatal(err)
	}
	operations := []func(walletdb.ReadWriteBucket) error{
		func(ns walletdb.ReadWriteBucket) error {
			_, e := manager.NewScopedKeyManager(ns, KeyScope{Purpose: 99, Coin: 0}, ScopeAddrSchema{ExternalAddrType: PubKeyHash, InternalAddrType: PubKeyHash})
			return e
		},
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.NewAccount(ns, "extra"); return e },
		func(ns walletdb.ReadWriteBucket) error { return scope.NewRawAccount(ns, 1) },
		func(ns walletdb.ReadWriteBucket) error { return scope.NewRawAccountWatchingOnly(ns, 1, nil, 0, nil) },
		func(ns walletdb.ReadWriteBucket) error { return scope.RenameAccount(ns, 0, "renamed") },
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.ImportPrivateKey(ns, nil, nil); return e },
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.ImportPublicKey(ns, nil, nil); return e },
		func(ns walletdb.ReadWriteBucket) error { _, e := scope.ImportScript(ns, []byte{0x51}, nil); return e },
		func(ns walletdb.ReadWriteBucket) error {
			_, e := scope.ImportWitnessScript(ns, []byte{0x51}, nil, 0, false)
			return e
		},
		func(ns walletdb.ReadWriteBucket) error {
			_, e := scope.ImportTaprootScript(ns, nil, nil, 1, false)
			return e
		},
	}
	for _, operation := range operations {
		if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return operation(tx.ReadWriteBucket(waddrmgrNamespaceKey)) }); !errors.Is(err, ErrRecoveryInventory) {
			t.Fatal("unsupported mutation was not rejected", err)
		}
	}
	manager.Close()
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		m, e := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if e == nil {
			m.Close()
		}
		return e
	}); err != nil {
		t.Fatal("rejected operation damaged reopen", err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return migration.Upgrade(preRecoveryMigration{NewMigrationManager(tx.ReadWriteBucket(waddrmgrNamespaceKey))})
	}); !errors.Is(err, migration.ErrReversion) {
		t.Fatal("old binary version gate accepted candidate", err)
	}
}

func candidateEditManifest(ns walletdb.ReadWriteBucket, manager *Manager, edit func(*productionprofile.Manifest)) error {
	raw, err := manager.RecoveryData(ns, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	manifest, err := productionprofile.ParseManifest(raw)
	if err != nil {
		return err
	}
	edit(&manifest)
	raw, err = json.Marshal(manifest)
	if err != nil {
		return err
	}
	encrypted, err := manager.cryptoKeyPub.Encrypt(raw)
	if err != nil {
		return err
	}
	return ns.NestedReadWriteBucket(mainBucketName).Put(recoveryPublicName, encrypted)
}

func TestCandidateMandatoryStateCorruptionFailsOpen(t *testing.T) {
	scope := KeyScope{Purpose: 49, Coin: productionprofile.CandidateCoinType}
	tests := []struct {
		name string
		edit func(walletdb.ReadWriteBucket, *Manager) error
	}{
		{"all-retention-removed", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			b := ns.NestedReadWriteBucket(mainBucketName)
			for _, key := range [][]byte{derivationModeName, recoveryVersionName, recoveryPublicName, recoveryPrivateName, candidateFixtureName} {
				if err := b.Delete(key); err != nil {
					return err
				}
			}
			return nil
		}},
		{"fixture-missing", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Delete(candidateFixtureName)
		}},
		{"old-fixture-name", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Put(candidateFixtureName, []byte("zero256"))
		}},
		{"wrong-fixture", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Put(candidateFixtureName, []byte(productionprofile.CandidateIncrementing256))
		}},
		{"public-missing", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Delete(recoveryPublicName)
		}},
		{"private-missing", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Delete(recoveryPrivateName)
		}},
		{"private-truncated", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Put(recoveryPrivateName, make([]byte, 40))
		}},
		{"retained-version1", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Put(recoveryVersionName, uint32ToBytes(1))
		}},
		{"derivation-legacy", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return ns.NestedReadWriteBucket(mainBucketName).Put(derivationModeName, uint32ToBytes(uint32(DerivationLegacy)))
		}},
		{"schema9", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			return putManagerVersion(ns, RecoveryManagerVersion)
		}},
		{"schema8", func(ns walletdb.ReadWriteBucket, _ *Manager) error { return putManagerVersion(ns, LatestMgrVersion) }},
		{"future-schema", func(ns walletdb.ReadWriteBucket, _ *Manager) error { return putManagerVersion(ns, 11) }},
		{"descriptor-coin0", func(ns walletdb.ReadWriteBucket, m *Manager) error {
			return candidateEditManifest(ns, m, func(manifest *productionprofile.Manifest) { manifest.Descriptor.CoinType = 0 })
		}},
		{"descriptor-hash", func(ns walletdb.ReadWriteBucket, m *Manager) error {
			return candidateEditManifest(ns, m, func(manifest *productionprofile.Manifest) { manifest.DescriptorHash = strings.Repeat("f", 64) })
		}},
		{"scope49-mixed", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			key := scopeToBytes(&scope)
			schema := ScopeAddrSchema{ExternalAddrType: NestedWitnessPubKey, InternalAddrType: WitnessPubKey}
			return ns.NestedReadWriteBucket(scopeSchemaBucketName).Put(key[:], scopeSchemaToBytes(&schema))
		}},
		{"scope-schema-missing", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			key := scopeToBytes(&scope)
			return ns.NestedReadWriteBucket(scopeSchemaBucketName).Delete(key[:])
		}},
		{"scope-missing", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			key := scopeToBytes(&scope)
			return ns.NestedReadWriteBucket(scopeBucketName).DeleteNestedBucket(key[:])
		}},
		{"cursor4097", func(ns walletdb.ReadWriteBucket, _ *Manager) error {
			row, err := fetchAccountInfo(ns, &scope, 0)
			if err != nil {
				return err
			}
			a := row.(*dbDefaultAccountRow)
			return putDefaultAccountInfo(ns, &scope, 0, a.pubKeyEncrypted, a.privKeyEncrypted, maxRecoveryBranchIndex+1, 0, a.name)
		}},
		{"coherent-other-public-tuple", func(ns walletdb.ReadWriteBucket, m *Manager) error {
			other, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateIncrementing256, productionprofile.DefaultCursors())
			if err != nil {
				return err
			}
			raw, err := productionprofile.MarshalManifest(other)
			if err != nil {
				return err
			}
			encrypted, err := m.cryptoKeyPub.Encrypt(raw)
			if err != nil {
				return err
			}
			b := ns.NestedReadWriteBucket(mainBucketName)
			if err := b.Put(recoveryPublicName, encrypted); err != nil {
				return err
			}
			return b.Put(candidateFixtureName, []byte(productionprofile.CandidateIncrementing256))
		}},
		{"account-xpub-substitution", func(ns walletdb.ReadWriteBucket, m *Manager) error {
			other, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateIncrementing256, productionprofile.DefaultCursors())
			if err != nil {
				return err
			}
			encrypted, err := m.cryptoKeyPub.Encrypt([]byte(other.Accounts[1].AccountPublicKey))
			if err != nil {
				return err
			}
			row, err := fetchAccountInfo(ns, &scope, 0)
			if err != nil {
				return err
			}
			a := row.(*dbDefaultAccountRow)
			return putDefaultAccountInfo(ns, &scope, 0, encrypted, a.privKeyEncrypted, 0, 0, a.name)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, manager := candidateManager(t)
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error { return tt.edit(tx.ReadWriteBucket(waddrmgrNamespaceKey), manager) }); err != nil {
				t.Fatal("fixture mutation", err)
			}
			manager.Close()
			err := walletdb.View(db, func(tx walletdb.ReadTx) error {
				opened, err := Open(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
				if opened != nil {
					opened.Close()
				}
				return err
			})
			if err == nil {
				t.Fatal("corrupted candidate silently reopened")
			}
		})
	}
}

// An old binary that already knows schema9 must still reject the opt-in10.
type preCandidateMigration struct{ *MigrationManager }

func (m preCandidateMigration) Versions() []migration.Version {
	return append(append([]migration.Version(nil), versions...), migration.Version{Number: RecoveryManagerVersion})
}
func TestCandidateSchemaNeverMigratesPriorWallets(t *testing.T) {
	db, manager := candidateManager(t)
	if manager.RecoveryVersion() != 2 || manager.DerivationMode() != DerivationStandard || !manager.RecoveryEnabled() {
		t.Fatal("candidate state missing")
	}
	if LatestMgrVersion != 8 || getLatestVersion() != 8 {
		t.Fatal("legacy migration target changed")
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return migration.Upgrade(preCandidateMigration{NewMigrationManager(tx.ReadWriteBucket(waddrmgrNamespaceKey))})
	}); !errors.Is(err, migration.ErrReversion) {
		t.Fatal("schema9 binary accepted10", err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return migration.Upgrade(NewMigrationManager(tx.ReadWriteBucket(waddrmgrNamespaceKey)))
	}); err != nil {
		t.Fatal("current binary rejected10", err)
	}
	oldDB, oldManager := retainedManager(t)
	if err := walletdb.Update(oldDB, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if err := migration.Upgrade(NewMigrationManager(ns)); err != nil {
			return err
		}
		version, err := fetchManagerVersion(ns)
		if err != nil {
			return err
		}
		if version != 9 {
			t.Fatal("v1 recovery silently migrated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if oldManager.RecoveryVersion() != 1 {
		t.Fatal("v1 runtime relabeled")
	}
	teardown, legacyDB := emptyDB(t)
	defer teardown()
	if err := walletdb.Update(legacyDB, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := Create(ns, rootKey, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}); err != nil {
			return err
		}
		if err := migration.Upgrade(NewMigrationManager(ns)); err != nil {
			return err
		}
		version, err := fetchManagerVersion(ns)
		if err != nil {
			return err
		}
		if version != 8 {
			t.Fatal("legacy wallet silently migrated")
		}
		opened, err := Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if err != nil {
			return err
		}
		defer opened.Close()
		if opened.RecoveryEnabled() || opened.DerivationMode() != DerivationLegacy || opened.RecoveryVersion() != 0 {
			t.Fatal("legacy derivation mode changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateCreationOwnsValidatedPayloads(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal-chain candidate runtime")
	}
	manifest, err := productionprofile.FixtureManifest(context.Background(), productionprofile.CandidateZero256, productionprofile.DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	public, err := productionprofile.MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entropy, _ := productionprofile.FixtureEntropy(productionprofile.CandidateZero256)
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	private := make([]byte, 68)
	defer clear(private)
	binary.LittleEndian.PutUint32(private, 2)
	copy(private[4:36], entropy[:])
	hash := sha256.Sum256(public)
	copy(private[36:], hash[:])
	tearDown, db := emptyDB(t)
	defer tearDown()
	accepted, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	original := SetSecretKeyGen(func(password *[]byte, options *ScryptOptions) (*snacl.SecretKey, error) {
		once.Do(func() { close(accepted); <-release })
		return defaultNewSecretKey(password, options)
	})
	defer SetSecretKeyGen(original)
	done := make(chan error, 1)
	go func() {
		done <- walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
			if err != nil {
				return err
			}
			return CreateWithCandidateRecovery(context.Background(), ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Time{}, public, private)
		})
	}()
	select {
	case <-accepted:
	case err := <-done:
		close(release)
		t.Fatal("creation failed before controlled KDF", err)
	case <-time.After(5 * time.Second):
		close(release)
		<-done
		t.Fatal("creation never reached controlled KDF")
	}
	// Validation and ownership transfer have happened. A caller reusing its
	// byte buffers while the slow KDF runs must not corrupt retained state.
	clear(public)
	clear(private)
	close(release)
	if err := <-done; err != nil {
		t.Fatal("caller buffer mutation reached creation", err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		manager, err := Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if err != nil {
			return err
		}
		defer manager.Close()
		if err := manager.Unlock(ns, privPassphrase); err != nil {
			return err
		}
		stored, err := manager.RecoveryData(ns, true)
		defer clear(stored)
		if err == nil && (len(stored) != 68 || binary.LittleEndian.Uint32(stored) != 2 || !bytes.Equal(stored[36:], hash[:])) {
			t.Fatal("owned private retention changed")
		}
		return err
	}); err != nil {
		t.Fatal("created candidate cannot reopen", err)
	}
}
