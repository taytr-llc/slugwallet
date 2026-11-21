// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type PoolWalletOwner struct {
	daily             bool // immutable constructor-selected binding profile
	mu                sync.Mutex
	closeOnce         sync.Once
	closed            chan struct{}
	closing           bool
	closeErr          error
	failedDirectories []*os.File
	life              context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	gate              chan struct{}
	rootPath          string
	dir, file         os.FileInfo
	binding           PoolWalletBinding
	loader            *Loader // exclusively factory-owned; never exposed or callback-published
	wallet            *Wallet
	timer             *time.Timer
	backend           *PoolSettlementBackend // original selection, never rebound
}

type poolWalletOperation struct {
	owner  *PoolWalletOwner
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
}

func (o *PoolWalletOwner) begin(ctx context.Context) (*poolWalletOperation, error) {
	if o == nil || ctx == nil || o.life == nil {
		return nil, ErrPoolWalletInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closing || o.wallet == nil {
		return nil, ErrPoolWalletClosed
	}
	if e := o.life.Err(); e != nil {
		return nil, e
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return nil, ErrPoolWalletBusy
	}
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(o.life, cancel)
	o.wg.Add(1)
	return &poolWalletOperation{o, work, cancel, stop}, nil
}
func (p *poolWalletOperation) end() { p.stop(); p.cancel(); <-p.owner.gate; p.owner.wg.Done() }
func (o *PoolWalletOwner) Binding() PoolWalletBinding {
	if o == nil {
		return PoolWalletBinding{}
	}
	return ownedPoolBinding(o.binding)
}

// Unlock is an explicit local custody operation, never invoked by Sign. The
// supplied secret is owned only until the original locker request has joined.
func (o *PoolWalletOwner) Unlock(ctx context.Context, privatePass []byte, lifetime time.Duration) error {
	if len(privatePass) == 0 || len(privatePass) > 1024 || lifetime <= 0 || lifetime > PoolWalletMaxUnlockLifetime {
		return ErrPoolWalletInvalid
	}
	op, e := o.begin(ctx)
	if e != nil {
		return e
	}
	defer op.end()
	if e = o.checkPaths(); e != nil {
		return e
	}
	pass := append([]byte(nil), privatePass...)
	defer clear(pass)
	timer := time.NewTimer(lifetime)
	accepted := false
	defer func() {
		if !accepted {
			timer.Stop()
		}
	}()
	response := make(chan error, 1)
	request := unlockRequest{passphrase: pass, lockAfter: timer.C, err: response}
	select {
	case <-op.ctx.Done():
		return op.ctx.Err()
	case o.wallet.unlockRequests <- request:
	}
	// The accepted request must join even if cancellation races its bounded KDF.
	e = <-response
	if e == nil {
		e = op.ctx.Err()
	}
	if e != nil {
		_ = o.wallet.Manager.Lock()
		return e
	}
	if o.timer != nil {
		o.timer.Stop()
	}
	o.timer = timer
	accepted = true
	return nil
}
func (o *PoolWalletOwner) Lock(ctx context.Context) error {
	op, e := o.begin(ctx)
	if e != nil {
		return e
	}
	defer op.end()
	if o.timer != nil {
		o.timer.Stop()
		o.timer = nil
	}
	// No signing lease can coexist: this original owner gate is held.
	e = o.wallet.Manager.Lock()
	if waddrmgr.IsError(e, waddrmgr.ErrLocked) {
		e = nil
	}
	if e != nil {
		return e
	}
	return op.ctx.Err()
}

// Close cancels and joins original admitted operations before clearing keys or
// closing storage. Cleanup failure is sticky; the failed handles remain owned.
func (o *PoolWalletOwner) Close() error {
	if o == nil || o.life == nil {
		return nil
	}
	o.closeOnce.Do(func() {
		o.mu.Lock()
		o.closing = true
		o.cancel()
		o.mu.Unlock()
		o.wg.Wait()
		if o.timer != nil {
			o.timer.Stop()
			o.timer = nil
		}
		if o.wallet != nil {
			o.wallet.Stop()
			o.wallet.WaitForShutdown()
			o.wallet.Manager.Close()
		}
		if o.loader != nil && o.loader.db != nil {
			if e := o.loader.db.Close(); e != nil {
				o.closeErr = ErrPoolWalletStorage
			} else {
				o.loader.db = nil
				o.loader.wallet = nil
				o.wallet = nil
			}
		}
		close(o.closed)
	})
	<-o.closed
	return o.closeErr
}

func CreatePoolSettlementWallet(life context.Context, rootPath string, expected PoolWalletBinding, pubPass, privPass []byte, root *hdkeychain.ExtendedKey, birthday time.Time) (*PoolWalletOwner, error) {
	return openPoolSettlementWallet(life, rootPath, expected, pubPass, privPass, root, birthday, true, false)
}
func OpenPoolSettlementWallet(life context.Context, rootPath string, expected PoolWalletBinding, pubPass []byte) (*PoolWalletOwner, error) {
	return openPoolSettlementWallet(life, rootPath, expected, pubPass, nil, nil, time.Time{}, false, false)
}

// A failed construction returns a retained owner only if its cleanup failed.
func poolOwnerFailure(o *PoolWalletOwner, cause error) (*PoolWalletOwner, error) {
	if e := o.Close(); e != nil {
		return o, errors.Join(cause, e)
	}
	return nil, cause
}

// Assert the private loader shape locally without returning its Wallet or DB.
func poolOwnerInventory(tx walletdb.ReadTx) error {
	count := 0
	e := tx.ForEachBucket(func(key []byte) error {
		count++
		if count > 2 || string(key) != string(waddrmgrNamespaceKey) && string(key) != string(wtxmgrNamespaceKey) {
			return ErrPoolWalletStorage
		}
		return nil
	})
	if e != nil || count != 2 {
		return ErrPoolWalletStorage
	}
	return nil
}

// Daily constructors require a fresh Binding2 or its exact same established root.
// They do not migrate a legacy guard or expose the factory-owned Loader/Wallet.
func CreateDailyPoolSettlementWallet(life context.Context, rootPath string, expected PoolWalletBinding, pubPass, privPass []byte, root *hdkeychain.ExtendedKey, birthday time.Time) (*PoolWalletOwner, error) {
	return openPoolSettlementWallet(life, rootPath, expected, pubPass, privPass, root, birthday, true, true)
}
func OpenDailyPoolSettlementWallet(life context.Context, rootPath string, expected PoolWalletBinding, pubPass []byte) (*PoolWalletOwner, error) {
	return openPoolSettlementWallet(life, rootPath, expected, pubPass, nil, nil, time.Time{}, false, true)
}
