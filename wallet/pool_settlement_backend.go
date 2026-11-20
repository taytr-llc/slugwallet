// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"reflect"
	"sync"

	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolsettlenode"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type PoolSettlementBackend struct {
	mu        sync.Mutex
	closeOnce sync.Once
	life      context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closing   bool
	original  *poolsettle.Store
	bound     bool
	wallet    *PoolWalletOwner
	node      *poolsettlenode.Client
	expected  PoolWalletBinding
}

var _ poolsettle.Backend = (*PoolSettlementBackend)(nil)

func NewPoolSettlementBackend(life context.Context, wallet *PoolWalletOwner, node *poolsettlenode.Client, expected PoolWalletBinding) (*PoolSettlementBackend, error) {
	if wire.TestPoW {
		return nil, waddrmgr.ErrPoolSettlementProfile
	}
	if life == nil || wallet == nil || node == nil || ValidatePoolWalletBinding(expected) != nil {
		return nil, ErrPoolWalletInvalid
	}
	if e := life.Err(); e != nil {
		return nil, e
	}
	op, e := wallet.begin(life)
	if e != nil {
		return nil, e
	}
	defer op.end()
	// All fields apart from the owned payee slice are comparable. Compare IDs
	// plus the full fixed guard/source and each validated immutable payee.
	actual := wallet.binding
	if actual.Version != expected.Version || actual.WalletOwnerID != expected.WalletOwnerID || actual.OperatorProfileID != expected.OperatorProfileID || actual.Guard != expected.Guard || actual.Source != expected.Source || !reflect.DeepEqual(actual.Settlement, expected.Settlement) {
		return nil, ErrPoolWalletBinding
	}
	cfg := node.Config()
	if poolsettlenode.ValidateConfig(cfg) != nil || cfg.Network != expected.Guard.Network || cfg.Genesis != expected.Guard.Genesis || cfg.PoolPublicKey != expected.Guard.FundingPublicKey || cfg.PoolScript != expected.Guard.FundingScript {
		return nil, ErrPoolWalletBinding
	}
	if e = wallet.checkPaths(); e != nil {
		return nil, e
	}
	wallet.mu.Lock()
	defer wallet.mu.Unlock()
	if wallet.closing || wallet.backend != nil {
		return nil, ErrPoolWalletBinding
	}
	if e = op.ctx.Err(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(life)
	b := &PoolSettlementBackend{life: ctx, cancel: cancel, wallet: wallet, node: node, expected: ownedPoolBinding(expected)}
	wallet.backend = b
	return b, nil
}
func (b *PoolSettlementBackend) begin(ctx context.Context) (*poolWalletOperation, func(), error) {
	if b == nil || ctx == nil || b.life == nil {
		return nil, nil, ErrPoolWalletInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return nil, nil, ErrPoolWalletClosed
	}
	if e := b.life.Err(); e != nil {
		b.mu.Unlock()
		return nil, nil, e
	}
	b.wg.Add(1)
	b.mu.Unlock()
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(b.life, cancel)
	op, e := b.wallet.begin(work)
	if e != nil {
		stop()
		cancel()
		b.wg.Done()
		return nil, nil, e
	}
	done := func() { op.end(); stop(); cancel(); b.wg.Done() }
	return op, done, nil
}

// BindSettlement is constructor-phase only, after the original store opens and
// before READY. Even an equal later rebind cannot revive or retarget this owner.
func (b *PoolSettlementBackend) BindSettlement(ctx context.Context, original *poolsettle.Store) error {
	op, done, e := b.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if original == nil {
		return ErrPoolWalletInvalid
	}
	b.mu.Lock()
	if b.bound {
		b.mu.Unlock()
		return ErrPoolWalletBinding
	}
	b.mu.Unlock()
	if e = original.CheckBackendBinding(op.ctx, b, b.expected.Settlement, b.expected.Source); e != nil {
		return e
	}
	if e = op.ctx.Err(); e != nil {
		return e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing || b.bound {
		return ErrPoolWalletBinding
	}
	b.original = original
	b.bound = true
	return nil
}
func (b *PoolSettlementBackend) Close() error {
	if b == nil || b.life == nil {
		return nil
	}
	b.closeOnce.Do(func() { b.mu.Lock(); b.closing = true; b.cancel(); b.mu.Unlock(); b.wg.Wait() })
	return nil
}
func (b *PoolSettlementBackend) boundStore() (*poolsettle.Store, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing || !b.bound || b.original == nil {
		return nil, ErrPoolWalletBinding
	}
	return b.original, nil
}

func (b *PoolSettlementBackend) Inspect(ctx context.Context, coins []poolsettle.Coin) ([]poolsettle.Funding, error) {
	op, done, e := b.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	if _, e = b.boundStore(); e != nil {
		return nil, e
	}
	out, e := b.node.Inspect(op.ctx, coins)
	if e == nil {
		e = op.ctx.Err()
	}
	return out, e
}
func (b *PoolSettlementBackend) EstimateFee(ctx context.Context, coins []poolsettle.Coin, payments []poolsettle.Payment, change string) (int64, error) {
	op, done, e := b.begin(ctx)
	if e != nil {
		return 0, e
	}
	defer done()
	if _, e = b.boundStore(); e != nil {
		return 0, e
	}
	if change != b.expected.Guard.FundingScript {
		return 0, ErrPoolWalletBinding
	}
	out, e := b.node.EstimateFee(op.ctx, coins, payments, change)
	if e == nil {
		e = op.ctx.Err()
	}
	return out, e
}
func (b *PoolSettlementBackend) ObserveTransaction(ctx context.Context, id string) (poolsettle.TransactionObservation, error) {
	op, done, e := b.begin(ctx)
	if e != nil {
		return poolsettle.TransactionObservation{}, e
	}
	defer done()
	if _, e = b.boundStore(); e != nil {
		return poolsettle.TransactionObservation{}, e
	}
	out, e := b.node.ObserveTransaction(op.ctx, id)
	if e == nil {
		e = op.ctx.Err()
	}
	return out, e
}
func (b *PoolSettlementBackend) Broadcast(ctx context.Context, raw []byte) (string, error) {
	op, done, e := b.begin(ctx)
	if e != nil {
		return "", e
	}
	defer done()
	if _, e = b.boundStore(); e != nil {
		return "", e
	}
	out, e := b.node.Broadcast(op.ctx, raw)
	if e == nil {
		e = op.ctx.Err()
	}
	return out, e
}

func (b *PoolSettlementBackend) Sign(ctx context.Context, coins []poolsettle.Coin, unsigned []byte) ([]byte, error) {
	op, done, e := b.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	original, e := b.boundStore()
	if e != nil {
		return nil, e
	}
	check := func() error {
		return poolsettle.CheckSigningRequest(op.ctx, original, b, b.expected.Settlement, b.expected.Source, coins, unsigned)
	}
	if e = check(); e != nil {
		return nil, e
	}
	if e = b.wallet.checkPaths(); e != nil {
		return nil, e
	}
	// Concrete canonical UTXO checks happen before acquiring the short unlock
	// lease. DTO claims cannot substitute for the original ledger capability.
	funding, e := b.node.Inspect(op.ctx, coins)
	if e != nil {
		return nil, e
	}
	if len(funding) != len(coins) {
		return nil, ErrPoolWalletBinding
	}
	for i, f := range funding {
		if f.TxID != coins[i].TxID || f.Index != coins[i].Index || f.State != "ready" {
			return nil, ErrPoolWalletBinding
		}
	}
	if e = check(); e != nil {
		return nil, e
	}
	lease, e := b.wallet.wallet.holdUnlockContext(op.ctx)
	if e != nil {
		return nil, e
	}
	defer lease.release()
	var signed []byte
	e = walletdb.View(b.wallet.loader.db, func(tx walletdb.ReadTx) error {
		if e := poolOwnerInventory(tx); e != nil {
			return e
		}
		var e error
		signed, e = b.wallet.wallet.Manager.SignPoolSettlement(op.ctx, tx.ReadBucket(waddrmgrNamespaceKey), b.expected.Guard, original, b, b.expected.Settlement, b.expected.Source, coins, unsigned)
		return e
	})
	if e != nil {
		return nil, e
	}
	if e = lease.err(op.ctx); e != nil {
		clear(signed)
		return nil, e
	}
	if e = b.wallet.checkPaths(); e != nil {
		clear(signed)
		return nil, e
	}
	if e = check(); e != nil {
		clear(signed)
		return nil, e
	}
	return signed, nil
}
