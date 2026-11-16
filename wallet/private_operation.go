// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"time"

	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// unlockLease owns one accepted walletLocker hold. Its quit channel belongs to
// that wallet run: post-operation checks must not consult quitMu because a
// concurrent Start can hold it while waiting for this run to finish.
type unlockLease struct {
	hold heldUnlock
	quit <-chan struct{}
}

func (l unlockLease) release() { l.hold.release() }

func (l unlockLease) err(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-l.quit:
		return ErrWalletShuttingDown
	default:
		return nil
	}
}

// holdUnlockContext acquires a short private-operation lease without leaving a
// goroutine or an orphaned unlock hold on cancellation. The wallet must already
// be started. Once the locker accepts a request, its response is joined before
// returning: that handshake performs only an atomic state read and channel
// delivery, with no database, network, key derivation, or user interaction.
// A caller must defer release immediately, then check lease.err after its work
// before returning any private material or signature. No I/O belongs in a lease
// except a bounded local wallet transaction.
func (w *Wallet) holdUnlockContext(ctx context.Context) (unlockLease, error) {
	var none unlockLease
	// Start historically keeps quitMu while joining a prior run. Respect
	// cancellation during that contention without spawning an abandoned lock
	// waiter or changing the legacy lifecycle APIs.
	for {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if w.quitMu.TryLock() {
			break
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return none, ctx.Err()
		case <-timer.C:
		}
	}
	started, quit := w.started, w.quit
	w.quitMu.Unlock()
	if !started {
		return none, ErrWalletShuttingDown
	}

	request := make(chan heldUnlock)
	select {
	case <-ctx.Done():
		return none, ctx.Err()
	case <-quit:
		return none, ErrWalletShuttingDown
	case w.holdUnlockRequests <- request:
	}

	// Sending above transfers the request to walletLocker. Never abandon its
	// response, even when cancellation races with acceptance.
	hold, ok := <-request
	if !ok {
		return none, waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrLocked, Description: "address manager is locked",
		}
	}
	lease := unlockLease{hold: hold, quit: quit}
	if err := lease.err(ctx); err != nil {
		lease.release()
		return none, err
	}
	return lease, nil
}
