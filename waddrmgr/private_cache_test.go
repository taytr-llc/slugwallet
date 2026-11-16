// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// privateCacheFixture uses the published fixture root already used throughout
// this package. No key material from outside the test database is accessed.
func privateCacheFixture(t *testing.T) (*Manager, *ScopedKeyManager,
	walletdb.DB, DerivationPath, *cachedKey) {

	t.Helper()
	teardown, db := emptyDB(t)
	t.Cleanup(teardown)
	var manager *Manager
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := Create(ns, rootKey, pubPassphrase, privPassphrase,
			&chaincfg.MainNetParams, fastScrypt, time.Time{}); err != nil {
			return err
		}
		manager, err = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if err != nil {
			return err
		}
		return manager.Unlock(ns, privPassphrase)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	scope, err := manager.FetchScopedKeyManager(KeyScopeBIP0044)
	if err != nil {
		t.Fatal(err)
	}
	path := DerivationPath{InternalAccount: 0,
		Account: hdkeychain.HardenedKeyStart, Branch: 10, Index: 1}
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, err := scope.DeriveFromKeyPath(
			tx.ReadBucket(waddrmgrNamespaceKey), path,
		)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := scope.DeriveFromKeyPathCache(path)
	if err != nil {
		t.Fatal(err)
	}
	key.Zero()
	cached, err := scope.privKeyCache.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	return manager, scope, db, path, cached
}

func TestPrivateCacheLockUnlockCopies(t *testing.T) {
	manager, scope, db, path, retained := privateCacheFixture(t)
	copyKey, err := scope.DeriveFromKeyPathCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer copyKey.Zero()
	publicKey := copyKey.PubKey().SerializeCompressed()
	if err := manager.Lock(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copyKey.PubKey().SerializeCompressed(), publicKey) {
		t.Fatal("locking invalidated a caller-owned key copy")
	}
	if !bytes.Equal(retained.key.Serialize(), make([]byte, 32)) {
		t.Fatal("locking retained the cached secret")
	}
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		return manager.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase)
	})
	if err != nil {
		t.Fatal(err)
	}
	refilled, err := scope.DeriveFromKeyPathCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer refilled.Zero()
	if !bytes.Equal(refilled.PubKey().SerializeCompressed(), publicKey) {
		t.Fatal("unlock did not restore the same derivation")
	}
}

func TestPrivateCacheConcurrentLock(t *testing.T) {
	manager, scope, db, path, _ := privateCacheFixture(t)
	var workers sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 1)
	for range 4 {
		workers.Go(func() {
			<-start
			for range 100 {
				key, err := scope.DeriveFromKeyPathCache(path)
				if key != nil {
					key.Zero()
				}
				if err != nil && !IsError(err, ErrLocked) {
					select {
					case failures <- err:
					default:
					}
				}
			}
		})
	}
	close(start)
	for range 20 {
		if err := manager.Lock(); err != nil {
			t.Fatal(err)
		}
		err := walletdb.View(db, func(tx walletdb.ReadTx) error {
			return manager.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	if err := manager.Lock(); err != nil {
		t.Fatal(err)
	}
	if key, err := scope.DeriveFromKeyPathCache(path); key != nil || !IsError(err, ErrLocked) {
		t.Fatal("cache was usable after the final lock")
	}
}

func TestPrivateCacheEvictionClearsSecret(t *testing.T) {
	_, scope, _, path, retained := privateCacheFixture(t)
	source := retained.key
	defer source.Zero()
	for i := uint32(0); i < defaultPrivKeyCacheSize; i++ {
		otherPath := path
		otherPath.Index = i + 2
		if _, err := scope.privKeyCache.Put(otherPath, &cachedKey{key: source}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(retained.key.Serialize(), make([]byte, 32)) {
		t.Fatal("LRU eviction did not zero the removed secret")
	}
}

// Imports hold the scope mutex while briefly taking the root mutex. Locking
// the root must therefore never wait for the scope mutex to clear this cache.
func TestPrivateCacheLockDoesNotInvertScopeOrder(t *testing.T) {
	manager, scope, _, _, _ := privateCacheFixture(t)
	scope.mtx.Lock()
	done := make(chan error, 1)
	go func() { done <- manager.Lock() }()
	select {
	case err := <-done:
		scope.mtx.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		scope.mtx.Unlock()
		<-done
		t.Fatal("root lock waited for scope mutex and could deadlock an import")
	}
}

func TestPrivateCacheWatchingOnlyAccount(t *testing.T) {
	_, scope, db, _, _ := privateCacheFixture(t)
	accountKey := deriveTestAccountKey(t)
	defer accountKey.Zero()
	publicKey, err := accountKey.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	defer publicKey.Zero()
	const account = 1000
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if err := scope.NewRawAccountWatchingOnly(ns, account, publicKey, 0, nil); err != nil {
			return err
		}
		_, err := scope.NextExternalAddresses(ns, account, 1)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := scope.DeriveFromKeyPathCache(DerivationPath{
		InternalAccount: account, Account: account + hdkeychain.HardenedKeyStart,
		Branch: ExternalBranch, Index: 0,
	})
	if key != nil {
		key.Zero()
		t.Fatal("private key returned for a watching-only account")
	}
	if !IsError(err, ErrWatchingOnly) {
		t.Fatalf("want watching-only error, got %v", err)
	}
}

func TestPrivateCacheStateTransitions(t *testing.T) {
	for _, transition := range []string{"lock", "watch-only", "close", "scope-close"} {
		t.Run(transition, func(t *testing.T) {
			manager, scope, db, path, retained := privateCacheFixture(t)
			switch transition {
			case "lock":
				if err := manager.Lock(); err != nil {
					t.Fatal(err)
				}
			case "watch-only":
				err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
					return manager.ConvertToWatchingOnly(
						tx.ReadWriteBucket(waddrmgrNamespaceKey),
					)
				})
				if err != nil {
					t.Fatal(err)
				}
			case "close":
				manager.Close()
			case "scope-close":
				scope.Close()
			}
			key, err := scope.DeriveFromKeyPathCache(path)
			if key != nil {
				key.Zero()
				t.Errorf("private key returned after %s", transition)
			}
			if err == nil {
				t.Errorf("cache access succeeded after %s", transition)
			}
			if scope.privKeyCache.Len() != 0 {
				t.Error("private key cache was not cleared")
			}
			if !bytes.Equal(retained.key.Serialize(), make([]byte, 32)) {
				t.Error("removed cache key was not zeroed")
			}
		})
	}
}
