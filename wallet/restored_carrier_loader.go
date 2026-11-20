// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func restoredCarrierPinMatches(pin fightercarrier.Pin, g waddrmgr.RestoredCarrierGuard) bool {
	m := g.OriginalManifest
	return fightercarrier.ValidatePin(pin) == nil && pin.OwnerMode == "restored" && pin.ManagerSchema == 15 && pin.WalletOwnerID == g.WalletOwnerID && pin.OwnershipPinID == g.OwnershipPinID && pin.OriginalManifestSHA256 == g.OriginalManifestSHA256 && pin.Network == m.Network && pin.Genesis == m.Genesis && pin.WalletProfile == m.Profile && pin.RootPublicKey == m.RootPublicKey && pin.GymPublicKey == m.GymPublicKey && pin.GymID == m.GymID
}

// ActivateRestoredCarrierWallet is separate from backup verification. It only
// accepts an unloaded completed schema12 and the exact concrete empty journal.
// A nonzero returned guard is the observed pre-mutation snapshot, including on
// an uncertain commit; it never authorizes signing without audited reopen.
func (l *Loader) ActivateRestoredCarrierWallet(ctx context.Context, pubPass []byte, original recovery.Manifest, journal *fightercarrier.Journal) (*Wallet, waddrmgr.RestoredCarrierGuard, error) {
	var guard waddrmgr.RestoredCarrierGuard
	if ctx == nil || journal == nil {
		return nil, guard, fightercarrier.ErrInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, guard, fightercarrier.ErrProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, guard, e
	}
	identity := journal.Identity()
	if fightercarrier.ValidatePin(identity.Pin) != nil || identity.Pin.OwnerMode != "restored" {
		return nil, guard, fightercarrier.ErrProfile
	}
	raw, e := recovery.MarshalManifest(original)
	if e != nil || carrierSHA(raw) != identity.Pin.OriginalManifestSHA256 {
		return nil, guard, fightercarrier.ErrConflict
	}
	owner, e := journal.TryAcquire(ctx)
	if e != nil {
		return nil, guard, e
	}
	defer owner.Close()
	snap, e := owner.Snapshot()
	if e != nil || snap.Count != 0 || snap.ActiveRequestID != "" {
		return nil, guard, fightercarrier.ErrConflict
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hostedCleanup != nil {
		return nil, guard, l.hostedCleanup
	}
	if l.phaseACleanup != nil {
		return nil, guard, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return nil, guard, ErrLoaded
	}
	exists, e := l.WalletExists()
	if e != nil {
		return nil, guard, e
	}
	if !exists {
		return nil, guard, os.ErrNotExist
	}
	l.db, e = walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return nil, guard, e
	}
	l.hostedAllocation = true
	var manager *waddrmgr.Manager
	e = walletdb.Update(l.db, func(tx walletdb.ReadWriteTx) error {
		var e error
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		manager, e = waddrmgr.OpenPhaseARecovery(ns, pubPass, l.chainParams)
		if e != nil {
			return e
		}
		if e = candidateRecoveryComplete(tx, manager); e != nil {
			return e
		}
		guard, e = manager.RestoredCarrierActivationSnapshot(ctx, ns, original, identity.Pin.WalletOwnerID, identity.JournalID, identity.Pin.OwnershipPinID)
		if e != nil {
			return e
		}
		if !restoredCarrierPinMatches(identity.Pin, guard) {
			return fightercarrier.ErrConflict
		}
		if e = createCarrierWalletNamespaces(tx, 15, identity.JournalID, "", &identity.Pin); e != nil {
			return e
		}
		if e = manager.ActivateRestoredCarrier(ctx, ns, guard); e != nil {
			return e
		}
		return ctx.Err()
	})
	if manager != nil {
		manager.Close()
		manager = nil
	}
	if e != nil {
		return nil, guard, l.closeHostedAllocationFailure(nil, errors.Join(fightercarrier.ErrOutcomeUnknown, e))
	}
	w, e := l.finishRestoredCarrierOpen(ctx, pubPass, guard, identity)
	return w, guard, e
}

func (l *Loader) OpenRestoredCarrierWallet(ctx context.Context, pubPass []byte, expected waddrmgr.RestoredCarrierGuard, journal *fightercarrier.Journal) (*Wallet, error) {
	if ctx == nil || journal == nil {
		return nil, fightercarrier.ErrInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, fightercarrier.ErrProfile
	}
	identity := journal.Identity()
	if identity.JournalID != expected.CarrierJournalID || !restoredCarrierPinMatches(identity.Pin, expected) {
		return nil, fightercarrier.ErrConflict
	}
	owner, e := journal.TryAcquire(ctx)
	if e != nil {
		return nil, e
	}
	defer owner.Close()
	if _, e = owner.Snapshot(); e != nil {
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
	if e = ctx.Err(); e != nil {
		return nil, e
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
	return l.finishRestoredCarrierOpen(ctx, pubPass, expected, identity)
}

func (l *Loader) finishRestoredCarrierOpen(ctx context.Context, pubPass []byte, expected waddrmgr.RestoredCarrierGuard, identity fightercarrier.Identity) (*Wallet, error) {
	var manager *waddrmgr.Manager
	var store *wtxmgr.Store
	e := walletdb.View(l.db, func(tx walletdb.ReadTx) error {
		var e error
		manager, e = waddrmgr.OpenRestoredCarrier(ctx, tx.ReadBucket(waddrmgrNamespaceKey), pubPass, l.chainParams, expected)
		if e != nil {
			return e
		}
		if e = candidateRecoveryComplete(tx, manager); e != nil {
			return e
		}
		if _, e = readCarrierWalletState(ctx, tx, identity.JournalID, &identity.Pin); e != nil {
			return e
		}
		if e = auditRestoredCarrierRows(ctx, tx, manager, l.chainParams, identity.Pin, identity.JournalID); e != nil {
			return e
		}
		if e = auditPurposeExclusions(ctx, tx, identity.Pin, identity.JournalID, ""); e != nil {
			return e
		}
		tm := tx.ReadBucket(wtxmgrNamespaceKey)
		if tm == nil {
			return fightercarrier.ErrCorrupt
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
