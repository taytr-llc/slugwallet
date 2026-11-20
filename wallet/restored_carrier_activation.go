// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"os"
	"path/filepath"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// InspectRestoredCarrierActivation returns the owned public guard of an
// unloaded, fully audited ready12. The caller must durably retain this exact
// guard before calling ActivateRestoredCarrierWalletExpected. No database or
// manager owner is left open on success. A failed close is sticky on Loader.
func (l *Loader) InspectRestoredCarrierActivation(ctx context.Context, pubPass []byte, original recovery.Manifest, journal *fightercarrier.Journal) (waddrmgr.RestoredCarrierGuard, error) {
	var none waddrmgr.RestoredCarrierGuard
	if ctx == nil || journal == nil {
		return none, fightercarrier.ErrInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return none, fightercarrier.ErrProfile
	}
	original, raw, e := ownPhaseAManifest(ctx, original)
	if e != nil {
		return none, e
	}
	identity := journal.Identity()
	if fightercarrier.ValidatePin(identity.Pin) != nil || identity.Pin.OwnerMode != "restored" || carrierSHA(raw) != identity.Pin.OriginalManifestSHA256 {
		return none, fightercarrier.ErrConflict
	}
	owner, e := journal.TryAcquire(ctx)
	if e != nil {
		return none, e
	}
	defer owner.Close()
	snapshot, e := owner.Snapshot()
	if e != nil {
		return none, e
	}
	if snapshot.Count != 0 || snapshot.ActiveRequestID != "" {
		return none, fightercarrier.ErrConflict
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hostedCleanup != nil {
		return none, l.hostedCleanup
	}
	if l.phaseACleanup != nil {
		return none, l.phaseACleanup
	}
	if l.wallet != nil || l.recoverySession {
		return none, ErrLoaded
	}
	if e = ctx.Err(); e != nil {
		return none, e
	}
	exists, e := l.WalletExists()
	if e != nil {
		return none, e
	}
	if !exists {
		return none, os.ErrNotExist
	}
	l.db, e = walletdb.Open("bdb", filepath.Join(l.dbDirPath, WalletDBName), l.noFreelistSync, l.timeout, false)
	if e != nil {
		return none, e
	}
	var manager *waddrmgr.Manager
	var guard waddrmgr.RestoredCarrierGuard
	e = walletdb.View(l.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		var e error
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
		return ctx.Err()
	})
	if e = l.closeHostedAllocationFailure(manager, e); e != nil {
		return none, e
	}
	if e = ctx.Err(); e != nil {
		return none, e
	}
	return guard, nil
}

// ActivateRestoredCarrierWalletExpected atomically compares the precommitted
// guard to the current ready12 snapshot before any namespace/schema write.
// It never adopts a stored schema15 guard after an interrupted activation.
func (l *Loader) ActivateRestoredCarrierWalletExpected(ctx context.Context, pubPass []byte, expected waddrmgr.RestoredCarrierGuard, journal *fightercarrier.Journal) (*Wallet, error) {
	if ctx == nil || journal == nil {
		return nil, fightercarrier.ErrInvalid
	}
	if wire.TestPoW || l.recoveryWindow != 0 || !l.localDB {
		return nil, fightercarrier.ErrProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	raw, e := waddrmgr.MarshalRestoredCarrierGuard(expected)
	if e != nil {
		return nil, e
	}
	owned, e := waddrmgr.ParseRestoredCarrierGuard(raw)
	if e != nil {
		return nil, e
	}
	identity := journal.Identity()
	if identity.JournalID != owned.CarrierJournalID || !restoredCarrierPinMatches(identity.Pin, owned) {
		return nil, fightercarrier.ErrConflict
	}
	w, _, e := l.activateRestoredCarrierWallet(ctx, pubPass, owned.OriginalManifest, journal, &owned)
	return w, e
}
