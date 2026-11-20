// Copyright (c) 2026 The SLUG developers. ISC license.

package wallet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var (
	ErrCurrentRecoveryInvalid     = errors.New("invalid current recovery request")
	ErrCurrentRecoveryProfile     = errors.New("unsupported current recovery profile")
	ErrCurrentRecoveryUnavailable = errors.New("current recovery unavailable")
	ErrCurrentRecoveryCorrupt     = errors.New("invalid current recovery storage")
)

// CurrentRecoveryCapture is an immutable public inventory minted by the exact
// retained Wallet. It cannot be constructed from JSON or a supplied manifest.
// Owners must still keep that wallet open until their work joins: the private
// pointer identifies the owner, and is not an additional database lifetime lease.
type CurrentRecoveryCapture struct {
	owner        *Wallet
	manager      *waddrmgr.Manager
	manifest     recovery.Manifest
	id           string
	capturedAtMS int64
}

// Manifest returns an owned public value, with no signing or export authority.
func (c *CurrentRecoveryCapture) Manifest() recovery.Manifest {
	if c == nil {
		return recovery.Manifest{}
	}
	result := c.manifest
	result.Accounts = append([]recovery.Account(nil), result.Accounts...)
	return result
}

func (c *CurrentRecoveryCapture) CaptureID() string {
	if c == nil {
		return ""
	}
	return c.id
}

func (c *CurrentRecoveryCapture) CapturedAtMS() int64 {
	if c == nil {
		return 0
	}
	return c.capturedAtMS
}

func (w *Wallet) currentRecoveryAlive() bool {
	if w == nil || w.db == nil || w.Manager == nil {
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

func currentRecoveryError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	case errors.Is(e, waddrmgr.ErrCurrentRecoveryProfile):
		return ErrCurrentRecoveryProfile
	case errors.Is(e, waddrmgr.ErrCurrentRecoveryCorrupt):
		return ErrCurrentRecoveryCorrupt
	default:
		return ErrCurrentRecoveryUnavailable
	}
}

// CaptureCurrentRecovery is one synchronous, bounded public-only database View.
// It does not unlock, derive, allocate addresses, read private retention or use
// the backend. The caller retains its concrete wallet/lifecycle and waits for
// this method to return before unloading; cancellation never abandons a View.
func (w *Wallet) CaptureCurrentRecovery(ctx context.Context) (*CurrentRecoveryCapture, error) {
	if ctx == nil {
		return nil, ErrCurrentRecoveryInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if wire.TestPoW {
		return nil, ErrCurrentRecoveryProfile
	}
	if !w.currentRecoveryAlive() {
		return nil, ErrCurrentRecoveryUnavailable
	}
	if w.chainParams == nil || w.chainParams.GenesisHash == nil || uint32(w.chainParams.Net) != recovery.Network || w.chainParams.GenesisHash.String() != recovery.Genesis {
		return nil, ErrCurrentRecoveryProfile
	}
	manager := w.Manager
	var manifest recovery.Manifest
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		value, e := manager.ReadCurrentRecoveryManifest(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
		if e != nil {
			return e
		}
		if gymaccount.ValidateFixtureIdentity(value.RootPublicKey, value.GymPublicKey, value.GymID) != nil {
			return waddrmgr.ErrCurrentRecoveryProfile
		}
		manifest = value
		return ctx.Err()
	})
	if e != nil {
		return nil, currentRecoveryError(e)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if !w.currentRecoveryAlive() {
		return nil, ErrCurrentRecoveryUnavailable
	}
	var id [32]byte
	if _, e = rand.Read(id[:]); e != nil || id == ([32]byte{}) {
		return nil, ErrCurrentRecoveryUnavailable
	}
	when := time.Now().UnixMilli()
	if when <= 0 || when > 253402300799999 {
		return nil, ErrCurrentRecoveryUnavailable
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if !w.currentRecoveryAlive() {
		return nil, ErrCurrentRecoveryUnavailable
	}
	return &CurrentRecoveryCapture{owner: w, manager: manager, manifest: manifest, id: hex.EncodeToString(id[:]), capturedAtMS: when}, nil
}
