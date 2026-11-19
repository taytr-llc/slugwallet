// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// PhaseARecoveryCleanupError retains an uncertain schema12 database owner.
// Close reports the first joined failure; it never retries an underlying Close
// whose later nil result could conceal an earlier filesystem cleanup failure.
type PhaseARecoveryCleanupError struct {
	cause   error
	db      walletdb.DB
	manager *waddrmgr.Manager
	loader  *Loader
}

func (e *PhaseARecoveryCleanupError) Error() string { return "phase A recovery storage cleanup failed" }
func (e *PhaseARecoveryCleanupError) Unwrap() error { return e.cause }
func (e *PhaseARecoveryCleanupError) Close() error  { return e }

// Called with l.mu held, after exactly one attempted database Close.
func (l *Loader) retainPhaseACleanup(db walletdb.DB, mgr *waddrmgr.Manager, cause, closeErr error) error {
	if l.phaseACleanup != nil {
		return l.phaseACleanup
	}
	e := &PhaseARecoveryCleanupError{cause: errors.Join(cause, closeErr), db: db, manager: mgr, loader: l}
	l.phaseACleanup = e
	l.phaseARecovery = true
	l.recoverySession = true
	l.db = db
	return e
}
func (l *Loader) closePhaseAFailure(db walletdb.DB, mgr *waddrmgr.Manager, cause error) error {
	if mgr != nil {
		mgr.Close()
	}
	if e := db.Close(); e != nil {
		return l.retainPhaseACleanup(db, mgr, cause, e)
	}
	l.db = nil
	return cause
}
func ownPhaseAManifest(ctx context.Context, m recovery.Manifest) (recovery.Manifest, []byte, error) {
	if ctx == nil {
		return recovery.Manifest{}, nil, ErrRecoveryProfile
	}
	if e := ctx.Err(); e != nil {
		return recovery.Manifest{}, nil, e
	}
	if len(m.Accounts) != 4 {
		return recovery.Manifest{}, nil, ErrRecoveryProfile
	}
	m.Accounts = append([]recovery.Account(nil), m.Accounts...)
	if _, e := waddrmgr.PhaseARecoveryPlan(ctx, m); e != nil {
		return recovery.Manifest{}, nil, e
	}
	raw, e := recovery.MarshalManifest(m)
	return m, raw, e
}

// BeginPhaseARecovery creates an exclusive, bounded schema12 scratch restore of
// an unchanged v1 export. It never adopts an existing or partial database.
func (l *Loader) BeginPhaseARecovery(ctx context.Context, pubPass, privPass []byte, bundle recovery.Export) (*RecoverySession, error) {
	if !l.localDB || recoveryChain(l.chainParams) != nil {
		return nil, ErrRecoveryProfile
	}
	m, _, e := ownPhaseAManifest(ctx, bundle.Manifest)
	if e != nil {
		return nil, e
	}
	bundle.Manifest = m
	if recovery.ValidateExport(bundle) != nil {
		return nil, ErrRecoveryProfile
	}
	entropy, e := recovery.Entropy(bundle.Mnemonic)
	if e != nil {
		return nil, ErrRecoveryProfile
	}
	defer clear(entropy[:])
	data, root, e := prepareRecovery(entropy, m, l.chainParams)
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
	if l.phaseACleanup != nil {
		return nil, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	entries, e := os.ReadDir(l.dbDirPath)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if len(entries) != 0 {
		return nil, ErrExists
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = os.MkdirAll(l.dbDirPath, 0700); e != nil {
		return nil, e
	}
	db, e := walletdb.Create("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return nil, e
	}
	l.phaseARecovery = true
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addr, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		txs, e := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = waddrmgr.CreateWithPhaseARecovery(ctx, addr, root, pubPass, privPass, l.chainParams, nil, l.chainParams.GenesisBlock.Header.Timestamp, data.public, data.private); e != nil {
			return e
		}
		if e = wtxmgr.Create(txs); e != nil {
			return e
		}
		if e = initializeRecovery(tx, phaseARecoveryScanBucket); e != nil {
			return e
		}
		if l.walletCreated != nil {
			if e = l.walletCreated(tx); e != nil {
				return e
			}
		}
		return ctx.Err()
	})
	if e != nil {
		return nil, l.closePhaseAFailure(db, nil, e)
	}
	if l.recoveryCheckpoint != nil {
		l.recoveryCheckpoint("initialized")
	}
	return l.phaseASessionFromDB(ctx, db, pubPass, data.public)
}

// OpenPhaseARecovery resumes only the same retained ORIGINAL manifest. Mutable
// issued cursors cannot substitute for this independent expected identity.
func (l *Loader) OpenPhaseARecovery(ctx context.Context, pubPass []byte, expected recovery.Manifest) (*RecoverySession, error) {
	if !l.localDB || recoveryChain(l.chainParams) != nil {
		return nil, ErrRecoveryProfile
	}
	_, raw, e := ownPhaseAManifest(ctx, expected)
	if e != nil {
		return nil, e
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.phaseACleanup != nil {
		return nil, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	db, e := walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return nil, e
	}
	// This explicit entry point owns cleanup even when the supplied DB is malformed.
	l.phaseARecovery = true
	return l.phaseASessionFromDB(ctx, db, pubPass, raw)
}
func (l *Loader) phaseASessionFromDB(ctx context.Context, db walletdb.DB, pubPass, expected []byte) (*RecoverySession, error) {
	var mgr *waddrmgr.Manager
	var txs *wtxmgr.Store
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		var e error
		mgr, e = waddrmgr.OpenPhaseARecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPass, l.chainParams)
		if e != nil {
			return e
		}
		_, original, e := readRecoveryBase(tx.ReadBucket(waddrmgrNamespaceKey), mgr, l.chainParams)
		if e != nil {
			return e
		}
		if !bytes.Equal(original, expected) {
			return ErrRecoveryProfile
		}
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return waddrmgr.ErrRecoveryState
		}
		txs, e = wtxmgr.Open(ns, l.chainParams)
		return e
	})
	if e != nil {
		return nil, l.closePhaseAFailure(db, mgr, e)
	}
	s, e := newRecoverySession(ctx, db, mgr, txs, l.chainParams, func() { l.mu.Lock(); l.recoverySession = false; l.db = nil; l.mu.Unlock() })
	if e != nil {
		return nil, l.closePhaseAFailure(db, mgr, e)
	}
	s.onCloseFailure = func(closeErr error) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.retainPhaseACleanup(db, mgr, nil, closeErr)
	}
	l.db = db
	l.recoverySession = true
	l.phaseARecovery = true
	return s, nil
}

// Identifies schema12 before generic open/key loading. A Loader that already
// owned this scratch DB refuses replacement by a different or malformed schema.
func (l *Loader) checkPhaseASchema(db walletdb.DB) error {
	var version uint32
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return waddrmgr.ErrRecoveryState
		}
		var e error
		version, e = new(waddrmgr.MigrationManager).CurrentVersion(ns)
		return e
	})
	if e == nil && version == waddrmgr.PhaseAManagerVersion {
		l.phaseARecovery = true
		return nil
	}
	if l.phaseARecovery {
		return waddrmgr.ErrRecoveryState
	}
	return nil // Existing schemas retain their existing migration/open behavior.
}
