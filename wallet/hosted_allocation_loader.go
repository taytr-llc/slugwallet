// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

var hostedAllocationNamespace = []byte(waddrmgr.HostedAllocationNamespace)

// A failed first close cannot be cleared by a later no-op successful DB Close.
type HostedAllocationCleanupError struct {
	cause   error
	loader  *Loader
	db      walletdb.DB
	manager *waddrmgr.Manager
}

func (e *HostedAllocationCleanupError) Error() string {
	return "hosted allocation wallet cleanup failed"
}
func (e *HostedAllocationCleanupError) Unwrap() error { return e.cause }
func (e *HostedAllocationCleanupError) Close() error  { return e }
func (l *Loader) retainHostedAllocationCleanup(m *waddrmgr.Manager, cause, closeErr error) error {
	if l.hostedCleanup != nil {
		return l.hostedCleanup
	}
	e := &HostedAllocationCleanupError{errors.Join(cause, closeErr), l, l.db, m}
	l.hostedCleanup = e
	l.recoverySession = true
	l.hostedAllocation = true
	return e
}
func (l *Loader) closeHostedAllocationFailure(m *waddrmgr.Manager, cause error) error {
	if m != nil {
		m.Close()
	}
	if l.db != nil && l.localDB {
		if e := l.db.Close(); e != nil {
			return l.retainHostedAllocationCleanup(m, cause, e)
		}
	}
	l.db = nil
	l.hostedAllocation = false
	return cause
}
func hostedSchema(db walletdb.DB) bool {
	found := false
	if db == nil {
		return false
	}
	_ = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return nil
		}
		main := ns.NestedReadBucket([]byte("main"))
		if main == nil {
			return nil
		}
		v := main.Get([]byte("mgrver"))
		found = len(v) == 4 && binary.LittleEndian.Uint32(v) == 13
		return nil
	})
	return found
}
func (l *Loader) CreateHostedAllocationWallet(ctx context.Context, pubPass, privPass []byte, entropy [32]byte, birthday time.Time, expected waddrmgr.HostedAllocationGuard) (*Wallet, error) {
	defer clear(entropy[:])
	if ctx == nil {
		return nil, waddrmgr.ErrHostedAllocationInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, waddrmgr.ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if _, e := waddrmgr.HostedAllocationGuardDigest(expected); e != nil || expected.State != "locked" {
		return nil, waddrmgr.ErrHostedAllocationInvalid
	}
	manifest, e := recovery.ManifestFor(entropy, recovery.DefaultAccounts())
	if e != nil {
		return nil, e
	}
	if gymaccount.ValidateFixtureIdentity(manifest.RootPublicKey, manifest.GymPublicKey, manifest.GymID) != nil {
		return nil, waddrmgr.ErrHostedAllocationProfile
	}
	public, e := recovery.MarshalManifest(manifest)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(public)
	if hex.EncodeToString(digest[:]) != expected.InitialManifestSHA256 {
		return nil, waddrmgr.ErrHostedAllocationConflict
	}
	data, root, e := prepareRecovery(entropy, manifest, l.chainParams)
	if e != nil {
		return nil, e
	}
	defer root.Zero()
	defer clear(data.private)
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	privPass = append([]byte(nil), privPass...)
	defer clear(privPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hostedCleanup != nil {
		return nil, l.hostedCleanup
	}
	if l.phaseACleanup != nil {
		return nil, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	exists, e := l.WalletExists()
	if e != nil {
		return nil, e
	}
	if exists {
		return nil, ErrExists
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = os.MkdirAll(l.dbDirPath, 0700); e != nil {
		return nil, e
	}
	l.db, e = walletdb.Create("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return nil, e
	}
	l.hostedAllocation = true
	e = walletdb.Update(l.db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		local, e := tx.CreateTopLevelBucket(hostedAllocationNamespace)
		if e != nil {
			return e
		}
		tm, e := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = waddrmgr.CreateWithHostedAllocation(ctx, ns, local, root, pubPass, privPass, l.chainParams, nil, birthday, data.public, data.private, expected); e != nil {
			return e
		}
		if e = wtxmgr.Create(tm); e != nil {
			return e
		}
		return ctx.Err()
	})
	if e != nil {
		return nil, l.closeHostedAllocationFailure(nil, e)
	}
	return l.finishHostedAllocationOpen(ctx, pubPass, expected)
}
func (l *Loader) OpenHostedAllocationWallet(ctx context.Context, pubPass []byte, expected waddrmgr.HostedAllocationGuard) (*Wallet, error) {
	if ctx == nil {
		return nil, waddrmgr.ErrHostedAllocationInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, waddrmgr.ErrHostedAllocationProfile
	}
	if _, e := waddrmgr.HostedAllocationGuardDigest(expected); e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hostedCleanup != nil {
		return nil, l.hostedCleanup
	}
	if l.phaseACleanup != nil {
		return nil, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	exists, e := l.WalletExists()
	if e != nil {
		return nil, e
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	l.db, e = walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return nil, e
	}
	l.hostedAllocation = true
	return l.finishHostedAllocationOpen(ctx, pubPass, expected)
}
func (l *Loader) finishHostedAllocationOpen(ctx context.Context, pubPass []byte, expected waddrmgr.HostedAllocationGuard) (*Wallet, error) {
	var manager *waddrmgr.Manager
	var store *wtxmgr.Store
	e := walletdb.View(l.db, func(tx walletdb.ReadTx) error {
		var e error
		manager, e = waddrmgr.OpenHostedAllocation(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace), pubPass, l.chainParams, expected)
		if e != nil {
			return e
		}
		tm := tx.ReadBucket(wtxmgrNamespaceKey)
		if tm == nil {
			return waddrmgr.ErrHostedAllocationCorrupt
		}
		store, e = wtxmgr.Open(tm, l.chainParams)
		if e != nil {
			return e
		}
		return ctx.Err()
	})
	if e != nil {
		return nil, l.closeHostedAllocationFailure(manager, e)
	}
	if e = ctx.Err(); e != nil {
		return nil, l.closeHostedAllocationFailure(manager, e)
	}
	w := walletFromManagers(l.db, append([]byte(nil), pubPass...), l.chainParams, 0, l.cfg.walletSyncRetryInterval, manager, store)
	w.Start()
	l.onLoaded(w)
	return w, nil
}
