// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (w *Wallet) hostedAllocationPublic2(ctx context.Context) (recovery.Manifest, error) {
	var out recovery.Manifest
	if ctx == nil {
		return out, waddrmgr.ErrHostedAllocationInvalid
	}
	if wire.TestPoW || !w.currentRecoveryAlive() || !w.Manager.HostedAllocation2() {
		return out, waddrmgr.ErrHostedAllocationProfile
	}
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		var e error
		out, e = w.Manager.ReadHostedAllocationManifest2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2))
		return e
	})
	if e != nil {
		return recovery.Manifest{}, e
	}
	if e = ctx.Err(); e != nil {
		return recovery.Manifest{}, e
	}
	if !w.currentRecoveryAlive() {
		return recovery.Manifest{}, ErrWalletShuttingDown
	}
	return out, nil
}
func (w *Wallet) HostedAllocationIdentity2(ctx context.Context, expected waddrmgr.HostedAllocationGuard2) (GymIdentity, error) {
	if ctx == nil || !w.currentRecoveryAlive() || !w.Manager.HostedAllocation2() {
		return GymIdentity{}, waddrmgr.ErrHostedAllocationProfile
	}
	var m recovery.Manifest
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns, local := tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2)
		state, e := w.Manager.AuditHostedAllocation2(ctx, ns, local)
		if e != nil {
			return e
		}
		if state.Guard != expected {
			return waddrmgr.ErrHostedAllocationConflict
		}
		m, e = w.Manager.ReadHostedAllocationManifest2(ctx, ns, local)
		return e
	})
	if e != nil {
		return GymIdentity{}, e
	}
	if e = ctx.Err(); e != nil {
		return GymIdentity{}, e
	}
	if !w.currentRecoveryAlive() {
		return GymIdentity{}, ErrWalletShuttingDown
	}
	return hostedGymIdentity(m), nil
}
func (w *Wallet) hostedAllocationGymIdentity2(ctx context.Context) (GymIdentity, error) {
	m, e := w.hostedAllocationPublic2(ctx)
	if e != nil {
		return GymIdentity{}, e
	}
	return hostedGymIdentity(m), nil
}
func (w *Wallet) hostedAllocationActivity2(ctx context.Context) (OwnActivitySnapshot, error) {
	var out OwnActivitySnapshot
	if ctx == nil {
		return out, waddrmgr.ErrHostedAllocationInvalid
	}
	if wire.TestPoW || !w.ownActivityAlive() || !w.Manager.HostedAllocation2() {
		return out, waddrmgr.ErrHostedAllocationProfile
	}
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		s, e := w.Manager.ReadHostedAllocationActivityState2(ctx, tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2))
		if e != nil {
			return e
		}
		if gymaccount.ValidateFixtureIdentity(s.RootPublicKey, s.GymPublicKey, s.GymID) != nil {
			return waddrmgr.ErrHostedAllocationProfile
		}
		rows, older, e := w.TxStore.CaptureOwnActivity(ctx, tx.ReadBucket(wtxmgrNamespaceKey), s.SyncedHeight)
		if e != nil {
			return e
		}
		out = OwnActivitySnapshot{Version: 1, RootPublicKey: s.RootPublicKey, GymPublicKey: s.GymPublicKey, GymID: s.GymID, SyncedHeight: s.SyncedHeight, SyncedHash: s.SyncedHash, HasOlder: older, Records: rows}
		return ctx.Err()
	})
	if e != nil {
		return OwnActivitySnapshot{}, e
	}
	if !w.ownActivityAlive() {
		return OwnActivitySnapshot{}, ErrWalletShuttingDown
	}
	return out, ctx.Err()
}

// Caller owns the short unlock lease. Never exported and never used by generic
// ExportRecovery: inventory-backed export remains a separate vault operation.
func (w *Wallet) hostedAllocationMaterial2(ctx context.Context) (entropy [32]byte, manifest recovery.Manifest, err error) {
	defer func() {
		if err != nil {
			clear(entropy[:])
			manifest = recovery.Manifest{}
		}
	}()
	if !w.Manager.HostedAllocation2() {
		return entropy, manifest, waddrmgr.ErrHostedAllocationProfile
	}
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns, local := tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace2)
		state, e := w.Manager.AuditHostedAllocation2(ctx, ns, local)
		if e != nil {
			return e
		}
		if state.Guard.State != "bound" {
			return waddrmgr.ErrHostedAllocationConflict
		}
		base, public, e := readRecoveryBase(ns, w.Manager, w.chainParams)
		if e != nil {
			return e
		}
		private, e := w.Manager.RecoveryData(ns, true)
		if e != nil {
			return e
		}
		defer clear(private)
		digest := sha256.Sum256(public)
		if len(private) != 68 || binary.LittleEndian.Uint32(private) != 1 || !bytes.Equal(private[36:], digest[:]) {
			return waddrmgr.ErrHostedAllocationCorrupt
		}
		copy(entropy[:], private[4:36])
		if recovery.ValidateEntropyManifest(entropy, base) != nil {
			return waddrmgr.ErrHostedAllocationCorrupt
		}
		manifest, e = w.Manager.ReadHostedAllocationManifest2(ctx, ns, local)
		if e != nil {
			return e
		}
		return w.validateRecoveryAccountKeys(ns, entropy, manifest)
	})
	return
}
