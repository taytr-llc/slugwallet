// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"errors"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

var (
	ErrOwnActivityInvalid     = errors.New("invalid own activity request")
	ErrOwnActivityProfile     = errors.New("unsupported own activity profile")
	ErrOwnActivityUnavailable = errors.New("own activity unavailable")
	ErrOwnActivityCapacity    = errors.New("own activity capacity")
	ErrOwnActivityCorrupt     = errors.New("invalid own activity storage")
)

type OwnActivityRecord = wtxmgr.OwnActivityRecord
type OwnActivityBlock = wtxmgr.OwnActivityBlock
type OwnActivityCredit = wtxmgr.OwnActivityCredit
type OwnActivityDebit = wtxmgr.OwnActivityDebit

type OwnActivitySnapshot struct {
	Version       uint32
	RootPublicKey string
	GymPublicKey  string
	GymID         string
	SyncedHeight  uint32
	SyncedHash    chainhash.Hash
	HasOlder      bool
	Records       []OwnActivityRecord
}

func (w *Wallet) ownActivityAlive() bool {
	if w == nil || w.db == nil || w.Manager == nil || w.TxStore == nil {
		return false
	}
	w.quitMu.Lock()
	started, quit := w.started, w.quit
	w.quitMu.Unlock()
	if !started || quit == nil {
		return false
	}
	select {
	case <-quit:
		return false
	default:
		return true
	}
}
func ownActivityError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	case errors.Is(e, waddrmgr.ErrOwnActivityProfile):
		return ErrOwnActivityProfile
	case errors.Is(e, waddrmgr.ErrOwnActivityUnavailable), errors.Is(e, walletdb.ErrDbNotOpen):
		return ErrOwnActivityUnavailable
	case errors.Is(e, wtxmgr.ErrOwnActivityCapacity):
		return ErrOwnActivityCapacity
	case errors.Is(e, wtxmgr.ErrOwnActivityCorrupt), errors.Is(e, waddrmgr.ErrOwnActivityCorrupt):
		return ErrOwnActivityCorrupt
	default:
		return ErrOwnActivityUnavailable
	}
}

// CaptureOwnActivity returns owned bounded records from one atomic local read.
// It neither contacts a backend nor unlocks, signs or changes wallet state. The
// caller must keep its concrete wallet owner alive until this synchronous call
// has returned; a context cannot preempt a database lock or rollback.
func (w *Wallet) CaptureOwnActivity(ctx context.Context) (OwnActivitySnapshot, error) {
	var none OwnActivitySnapshot
	if ctx == nil {
		return none, ErrOwnActivityInvalid
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	if wire.TestPoW {
		return none, ErrOwnActivityProfile
	}
	if !w.ownActivityAlive() {
		return none, ErrOwnActivityUnavailable
	}
	if w.chainParams == nil || w.chainParams.GenesisHash == nil || uint32(w.chainParams.Net) != recovery.Network || w.chainParams.GenesisHash.String() != recovery.Genesis {
		return none, ErrOwnActivityProfile
	}
	var result OwnActivitySnapshot
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		identity, e := w.Manager.ReadOwnActivityState(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
		if e != nil {
			return e
		}
		if gymaccount.ValidateFixtureIdentity(identity.RootPublicKey, identity.GymPublicKey, identity.GymID) != nil {
			return waddrmgr.ErrOwnActivityProfile
		}
		records, older, e := w.TxStore.CaptureOwnActivity(ctx, tx.ReadBucket(wtxmgrNamespaceKey), identity.SyncedHeight)
		if e != nil {
			return e
		}
		result = OwnActivitySnapshot{Version: 1, RootPublicKey: identity.RootPublicKey, GymPublicKey: identity.GymPublicKey, GymID: identity.GymID, SyncedHeight: identity.SyncedHeight, SyncedHash: identity.SyncedHash, HasOlder: older, Records: records}
		return ctx.Err()
	})
	if e != nil {
		return none, ownActivityError(e)
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	if !w.ownActivityAlive() {
		return none, ErrOwnActivityUnavailable
	}
	return result, nil
}
