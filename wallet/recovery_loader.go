// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// BeginCandidateFixture uses a named public fixture with zero issued cursors.
func (l *Loader) BeginCandidateFixture(ctx context.Context, pubPass, privPass []byte, fixture string) (*RecoverySession, error) {
	if ctx == nil {
		return nil, ErrRecoveryProfile
	}
	bundle, err := productionprofile.FixtureExport(ctx, fixture, productionprofile.DefaultCursors())
	if err != nil {
		return nil, err
	}
	return l.BeginCandidateRecovery(ctx, pubPass, privPass, bundle)
}

// BeginCandidateRecovery starts an explicitly bounded schema11 restoration of
// one of the two compiled public fixtures. All profile/quota checks precede
// filesystem changes. The session exclusively owns this Loader until Close.
func (l *Loader) BeginCandidateRecovery(ctx context.Context, pubPass, privPass []byte, bundle productionprofile.Export) (*RecoverySession, error) {
	if ctx == nil {
		return nil, ErrRecoveryProfile
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !l.localDB || l.chainParams == nil || l.chainParams.GenesisBlock == nil {
		return nil, ErrRecoveryProfile
	}
	if err := recoveryChain(l.chainParams); err != nil {
		return nil, err
	}
	m, err := ownCandidateManifest(bundle.Manifest)
	if err != nil {
		return nil, err
	}
	bundle.Manifest = m
	fixture, err := productionprofile.ValidateFixtureExport(ctx, bundle)
	if err != nil {
		return nil, err
	}
	if _, err := waddrmgr.CandidateRecoveryPlan(ctx, m); err != nil {
		return nil, err
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	privPass = append([]byte(nil), privPass...)
	defer clear(privPass)
	public, err := productionprofile.MarshalManifest(m)
	if err != nil {
		return nil, err
	}
	entropy, err := productionprofile.FixtureEntropy(fixture)
	if err != nil {
		return nil, err
	}
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], l.chainParams)
	if err != nil {
		return nil, err
	}
	defer root.Zero()
	private := make([]byte, 68)
	defer clear(private)
	binary.LittleEndian.PutUint32(private, productionprofile.Version2)
	copy(private[4:36], entropy[:])
	digest := sha256.Sum256(public)
	copy(private[36:], digest[:])
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	exists, err := l.WalletExists()
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrExists
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(l.dbDirPath, 0700); err != nil {
		return nil, err
	}
	db, err := walletdb.Create("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if err != nil {
		return nil, err
	}
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addr, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		txs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}
		if err := waddrmgr.CreateWithResumableCandidateRecovery(ctx, addr, root, pubPass, privPass, l.chainParams, nil, l.chainParams.GenesisBlock.Header.Timestamp, public, private); err != nil {
			return err
		}
		if err := wtxmgr.Create(txs); err != nil {
			return err
		}
		if err := initializeCandidateRecovery(tx); err != nil {
			return err
		}
		if l.walletCreated != nil {
			if err := l.walletCreated(tx); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if l.recoveryCheckpoint != nil {
		l.recoveryCheckpoint("initialized")
	}
	return l.recoverySessionFromDB(ctx, db, pubPass)
}

// OpenCandidateRecovery resumes only an existing schema11 database. It does
// not recreate a missing progress record or initialize a replacement wallet.
func (l *Loader) OpenCandidateRecovery(ctx context.Context, pubPass []byte) (*RecoverySession, error) {
	if ctx == nil {
		return nil, ErrRecoveryProfile
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !l.localDB {
		return nil, ErrRecoveryProfile
	}
	if err := recoveryChain(l.chainParams); err != nil {
		return nil, err
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wallet != nil || l.recoverySession {
		return nil, ErrLoaded
	}
	db, err := walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if err != nil {
		return nil, err
	}
	return l.recoverySessionFromDB(ctx, db, pubPass)
}

// The caller holds l.mu. newRecoverySession does not invoke onClose until a
// successfully returned session is explicitly closed by its owner.
func (l *Loader) recoverySessionFromDB(ctx context.Context, db walletdb.DB, pubPass []byte) (*RecoverySession, error) {
	var mgr *waddrmgr.Manager
	var txs *wtxmgr.Store
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		mgr, err = waddrmgr.OpenCandidateRecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPass, l.chainParams)
		if err != nil {
			return err
		}
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return waddrmgr.ErrRecoveryState
		}
		txs, err = wtxmgr.Open(ns, l.chainParams)
		return err
	})
	if err != nil {
		if mgr != nil {
			mgr.Close()
		}
		return nil, errors.Join(err, db.Close())
	}
	s, err := newRecoverySession(ctx, db, mgr, txs, l.chainParams, func() { l.mu.Lock(); l.recoverySession = false; l.db = nil; l.mu.Unlock() })
	if err != nil {
		mgr.Close()
		return nil, errors.Join(err, db.Close())
	}
	l.db = db
	l.recoverySession = true
	return s, nil
}
