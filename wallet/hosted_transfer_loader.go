// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

var hostedAllocationNamespace2 = []byte(waddrmgr.HostedAllocationNamespace2)

func (l *Loader) CreateHostedTransferWallet(ctx context.Context, pubPass, privPass []byte, entropy [32]byte, birthday time.Time, expected waddrmgr.HostedAllocationGuard2) (*Wallet, error) {
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
	if _, e := waddrmgr.HostedAllocationGuardDigest2(expected); e != nil || expected.State != "locked" {
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
		local, e := tx.CreateTopLevelBucket(hostedAllocationNamespace2)
		if e != nil {
			return e
		}
		tm, e := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = waddrmgr.CreateWithHostedAllocation2(ctx, ns, local, root, pubPass, privPass, l.chainParams, nil, birthday, data.public, data.private, expected); e != nil {
			return e
		}
		if e = createCarrierWalletNamespaces(tx, 14, expected.CarrierJournalID, expected.WithdrawalJournalID, nil); e != nil {
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
	return l.finishHostedTransferOpen(ctx, pubPass, expected)
}
func (l *Loader) OpenHostedTransferWallet(ctx context.Context, pubPass []byte, expected waddrmgr.HostedAllocationGuard2) (*Wallet, error) {
	if ctx == nil {
		return nil, waddrmgr.ErrHostedAllocationInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, waddrmgr.ErrHostedAllocationProfile
	}
	if _, e := waddrmgr.HostedAllocationGuardDigest2(expected); e != nil {
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
	return l.finishHostedTransferOpen(ctx, pubPass, expected)
}
func (l *Loader) finishHostedTransferOpen(ctx context.Context, pubPass []byte, expected waddrmgr.HostedAllocationGuard2) (*Wallet, error) {
	var manager *waddrmgr.Manager
	var store *wtxmgr.Store
	e := walletdb.View(l.db, func(tx walletdb.ReadTx) error {
		var e error
		manager, e = waddrmgr.OpenHostedAllocation2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2), pubPass, l.chainParams, expected)
		if e != nil {
			return e
		}
		manifest, e := manager.ReadHostedAllocationManifest2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2))
		if e != nil {
			return e
		}
		pin := fightercarrier.Pin{Version: 1, OwnerMode: "hosted", ManagerSchema: 14, Network: manifest.Network, Genesis: manifest.Genesis, WalletProfile: manifest.Profile, RootPublicKey: manifest.RootPublicKey, GymPublicKey: manifest.GymPublicKey, GymID: manifest.GymID, WalletOwnerID: expected.WalletOwnerID, OwnershipPinID: expected.OwnershipPinID, AccountAuthorityID: expected.AuthorityID, AccountID: expected.AccountID, AllocationBindingID: expected.BindingID}
		if e = auditPurposeExclusions(ctx, tx, pin, expected.CarrierJournalID, expected.WithdrawalJournalID); e != nil {
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
