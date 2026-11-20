// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/wallet"
)

// PreparedInventoryExport owns secret bytes and both concrete publication
// permits. No accessor or callback can extract its private recovery file.
type PreparedInventoryExport struct {
	mu          sync.Mutex
	vault       *HostedVault
	token       string
	epoch       EpochFence
	account     gymaccount.Account
	binding     wallet.AllocationBinding
	record      vaultRecord
	head        *wallet.HostedRecoveryHead
	lease       *wallet.HostedRecoveryHeadLease
	destination *CurrentDestination
	raw         []byte
	used        bool
	closed      bool
	closeErr    error
}

func allocationVaultBinding(b wallet.AllocationBinding, r vaultRecord, vaultID string) bool {
	v := r.Binding
	m := b.InitialManifest
	return b.HostedVaultID == vaultID && r.State == "enrolled" && r.Receipt != nil && b.RetentionID == r.Receipt.RetentionID &&
		b.AuthorityID == v.AuthorityID && b.AccountID == v.AccountID && b.PrincipalID == v.PrincipalID && b.ProvisionID == v.ProvisionID &&
		m.Network == v.Network && m.Genesis == v.Genesis && m.Profile == v.Profile && m.RootPublicKey == v.RootPublicKey && m.GymPublicKey == v.GymPublicKey && m.GymID == v.GymID && reflect.DeepEqual(m, r.Manifest)
}

// PrepareInventoryExport requires the same original token as the opaque head.
// The supplied parent fence is preflighted, and the head's retained original
// fence controls all concrete authority checks and final publication. Passing a
// new parent callback therefore cannot rescue a head whose original View ended.
func (h *HostedVault) PrepareInventoryExport(ctx context.Context, originalToken string, head *wallet.HostedRecoveryHead, destination *CurrentDestination, epoch EpochFence) (result *PreparedInventoryExport, err error) {
	if h == nil || head == nil || destination == nil || epoch == nil || ctx == nil {
		return nil, ErrConfig
	}
	if err = runEpoch(ctx, epoch, ctx.Err, func(check func() error) error { return check() }); err != nil {
		return nil, err
	}
	lease, err := head.Hold(ctx, originalToken)
	if err != nil {
		return nil, err
	}
	ctx, release, err := lease.Acquire(ctx)
	if err != nil {
		_ = lease.Close()
		return nil, err
	}
	defer func() {
		release()
		if result == nil {
			err = errors.Join(err, lease.Close())
		}
	}()
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	h.inventoryMu.Lock()
	closing := h.inventoryClosing
	h.inventoryMu.Unlock()
	if closing {
		return nil, ErrClosed
	}
	originalEpoch := EpochFence(head.WithOriginalEpoch)
	a, r, err := h.snapshot(ctx, originalToken, gymaccount.RecoveryExport, originalEpoch)
	if err != nil {
		return nil, err
	}
	b := head.Binding()
	if _, err = wallet.AllocationBindingID(b); err != nil || !allocationVaultBinding(b, r, h.header.HostedVaultID) || r.Recovery == nil {
		return nil, ErrConflict
	}
	m := head.Manifest()
	if currentManifest(m, b.InitialManifest) != nil {
		return nil, ErrConflict
	}
	if err = destination.claim(); err != nil {
		return nil, err
	}
	raw, err := openEnvelope(ctx, h.core.wrapper, *r.Recovery)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	entropy, err := decodeRecovery(raw, r)
	if err != nil {
		return nil, err
	}
	defer clear(entropy[:])
	bundle, err := recovery.NewExport(entropy, m.Accounts)
	if err != nil {
		return nil, ErrEnvelope
	}
	if !reflect.DeepEqual(bundle.Manifest, m) {
		bundle.Mnemonic = ""
		return nil, ErrConflict
	}
	encoded, err := recovery.MarshalExport(bundle)
	bundle.Mnemonic = ""
	if err != nil {
		return nil, ErrEnvelope
	}
	if len(encoded) > 65536 {
		clear(encoded)
		return nil, ErrCapacity
	}
	p := &PreparedInventoryExport{vault: h, token: originalToken, epoch: originalEpoch, account: a, binding: b, record: r, head: head, lease: lease, destination: destination, raw: encoded}
	if err = p.authorize(ctx, func(check func() error) error { return check() }); err != nil {
		clear(encoded)
		return nil, err
	}
	h.inventoryMu.Lock()
	defer h.inventoryMu.Unlock()
	if h.inventoryClosing {
		clear(encoded)
		return nil, ErrClosed
	}
	if h.inventoryExports == nil {
		h.inventoryExports = make(map[*PreparedInventoryExport]bool)
	}
	if len(h.inventoryExports)+len(h.inventoryExports2) >= 2 {
		clear(encoded)
		return nil, ErrCapacity
	}
	// Exactly one retained prepared export per concrete inventory/account.
	for old := range h.inventoryExports {
		if old.binding.InventoryID == b.InventoryID || old.binding.AccountID == b.AccountID {
			clear(encoded)
			return nil, ErrBusy
		}
	}
	for old := range h.inventoryExports2 {
		if old.binding.InventoryID == b.InventoryID || old.binding.AccountID == b.AccountID {
			clear(encoded)
			return nil, ErrBusy
		}
	}
	h.inventoryExports[p] = true
	return p, nil
}

func (p *PreparedInventoryExport) authorize(ctx context.Context, fn func(func() error) error) error {
	return p.vault.fence(ctx, p.token, gymaccount.RecoveryExport, false, p.epoch, &p.account, func(a gymaccount.Account, _ gymaccount.Identity, check func() error) error {
		r, ok := p.vault.records[a.ID]
		if !ok || r.Revision != p.record.Revision || r.Binding != p.record.Binding || !bindingMatchesAccount(r.Binding, a) {
			return ErrConflict
		}
		guard := func() error {
			if e := p.lease.Check(); e != nil {
				return e
			}
			return check()
		}
		if e := guard(); e != nil {
			return e
		}
		return fn(guard)
	})
}
func (p *PreparedInventoryExport) Publish(ctx context.Context) error {
	if p == nil {
		return ErrConfig
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	defer p.mu.Unlock()
	if p.closed || p.used {
		return ErrClosed
	}
	ctx, release, err := p.lease.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	ctx, done, err := p.vault.acquire(ctx)
	if err != nil {
		return err
	}
	defer done()
	p.used = true
	d := p.destination
	if !d.mu.TryLock() {
		return ErrBusy
	}
	defer d.mu.Unlock()
	if d.closed || d.used || !d.claimed {
		return ErrConflict
	}
	if err = d.parentMatches(); err != nil {
		return err
	}
	attempted := false
	err = p.authorize(ctx, func(check func() error) error { attempted = true; return d.publish(ctx, p.raw, check) })
	clear(p.raw)
	p.raw = nil
	if err != nil && attempted && d.used && (d.mayPublish || errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, wallet.ErrAllocationOutcomeUnknown)) {
		err = errors.Join(ErrExportUncertain, err)
	}
	if errors.Is(err, ErrCleanup) {
		p.closeErr = errors.Join(p.closeErr, err)
	}
	return err
}
func (p *PreparedInventoryExport) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	clear(p.raw)
	p.raw = nil
	p.closeErr = errors.Join(p.closeErr, p.destination.Close(), p.lease.Close())
	p.closed = true
	if p.closeErr == nil {
		p.vault.inventoryMu.Lock()
		delete(p.vault.inventoryExports, p)
		p.vault.inventoryMu.Unlock()
	}
	return p.closeErr
}
