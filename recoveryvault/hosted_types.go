// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/taytr-llc/slug/gymaccount"
)

var (
	ErrBusy            = errors.New("hosted recovery owner busy")
	ErrOutcomeUnknown  = errors.New("hosted recovery outcome unknown")
	ErrExportUncertain = errors.New("current recovery export uncertain")
	ErrCleanup         = errors.New("current recovery cleanup failed")
	ErrUnsupported     = errors.New("current recovery destination unsupported")
)

// EpochFence retains only the original parent View. It must not call account
// APIs. The concrete vault independently retains the original account lease.
type EpochFence func(context.Context, func(check func() error) error) error

type HostedInfo struct {
	Version       uint32                   `json:"version"`
	HostedVaultID string                   `json:"hosted_vault_id"`
	Authority     gymaccount.AuthorityInfo `json:"authority"`
	Config        Config                   `json:"config"`
}

type hostedHeader struct {
	Application   string                   `json:"application"`
	Version       uint32                   `json:"version"`
	HostedVaultID string                   `json:"hosted_vault_id"`
	Authority     gymaccount.AuthorityInfo `json:"authority"`
	Config        Config                   `json:"config"`
}
type hostedMetadata struct {
	Header     hostedHeader       `json:"header"`
	Operations uint32             `json:"operations"`
	Reserved   uint32             `json:"reserved"`
	Accounts   []reservationIndex `json:"accounts"`
}

// HostedVault exposes no legacy Vault. Its private codec reuses only the
// immutable v1 record/cipher validators; all authorization uses hosted fences.
type HostedVault struct {
	core              *Vault
	header            hostedHeader
	records           map[string]vaultRecord // owned by the pre-acquired core gate
	inventoryMu       sync.Mutex
	inventoryClosing  bool
	inventoryExports  map[*PreparedInventoryExport]bool
	inventoryExports2 map[*PreparedInventoryExport2]bool
}

func nonzeroID(s string) bool {
	if !canonicalHex(s, 32) {
		return false
	}
	for _, c := range s {
		if c != '0' {
			return true
		}
	}
	return false
}

func (h *HostedVault) acquire(ctx context.Context) (context.Context, func(), error) {
	if h == nil || h.core == nil {
		return nil, nil, ErrClosed
	}
	ctx, done, err := h.core.begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	select {
	case h.core.gate <- struct{}{}:
	default:
		done()
		return nil, nil, ErrBusy
	}
	if err = ctx.Err(); err == nil {
		if h.core.closed {
			err = ErrClosed
		} else if h.core.poisoned {
			err = ErrPoisoned
		}
	}
	if err != nil {
		h.core.unlock()
		done()
		return nil, nil, err
	}
	return ctx, func() { h.core.unlock(); done() }, nil
}
func (h *HostedVault) Close() error {
	if h == nil || h.core == nil {
		return nil
	}
	h.inventoryMu.Lock()
	h.inventoryClosing = true
	prepared := make([]*PreparedInventoryExport, 0, len(h.inventoryExports))
	for p := range h.inventoryExports {
		prepared = append(prepared, p)
	}
	prepared2 := make([]*PreparedInventoryExport2, 0, len(h.inventoryExports2))
	for p := range h.inventoryExports2 {
		prepared2 = append(prepared2, p)
	}
	h.inventoryMu.Unlock()
	var err error
	for _, p := range prepared {
		err = errors.Join(err, p.Close())
	}
	for _, p := range prepared2 {
		err = errors.Join(err, p.Close())
	}
	return errors.Join(err, h.core.Close())
}
func (h *HostedVault) Info(ctx context.Context) (HostedInfo, error) {
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return HostedInfo{}, err
	}
	defer done()
	c := h.core.config
	c.AllowedRecoveryKeyRefs = append([]string(nil), c.AllowedRecoveryKeyRefs...)
	c.AllowedGymKeyRefs = append([]string(nil), c.AllowedGymKeyRefs...)
	if err = ctx.Err(); err != nil {
		return HostedInfo{}, err
	}
	return HostedInfo{Version1, h.header.HostedVaultID, h.core.authority, c}, nil
}

// A wrapper call is joined; there is deliberately no detached timeout worker.
type hostedWrapper struct{ KeyWrapper }

func (w hostedWrapper) Wrap(ctx context.Context, ref string, key [32]byte, aad []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := w.KeyWrapper.Wrap(ctx, ref, key, aad)
	if ctx.Err() != nil {
		clear(raw)
		return nil, ctx.Err()
	}
	return raw, err
}
func (w hostedWrapper) Unwrap(ctx context.Context, ref string, blob, aad []byte) ([32]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	key, err := w.KeyWrapper.Unwrap(ctx, ref, blob, aad)
	if ctx.Err() != nil {
		clear(key[:])
		return [32]byte{}, ctx.Err()
	}
	return key, err
}

// runEpoch never retains an account recheck. Its small guard joins an invalid
// concurrently-returning fence before the concrete account lease is released.
// Actual parent fences execute synchronously and TryLock their own View mutex.
func runEpoch(ctx context.Context, epoch EpochFence, accountCheck func() error, fn func(func() error) error) error {
	if epoch == nil || accountCheck == nil || fn == nil {
		return ErrConflict
	}
	var mu sync.Mutex
	active, count := true, 0
	entered := false
	var inner error
	err := epoch(ctx, func(parentCheck func() error) error {
		mu.Lock()
		defer mu.Unlock()
		count++
		if !active || count != 1 || parentCheck == nil {
			inner = ErrConflict
			return ErrConflict
		}
		check := func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := accountCheck(); e != nil {
				return e
			}
			if e := parentCheck(); e != nil {
				return e
			}
			return ctx.Err()
		}
		if e := check(); e != nil {
			inner = e
			return e
		}
		entered = true
		inner = fn(check)
		if e := check(); e != nil {
			inner = errors.Join(inner, e)
		}
		return inner
	})
	mu.Lock()
	defer mu.Unlock()
	active = false
	if count != 1 || err != nil || inner != nil || ctx.Err() != nil {
		cause := errors.Join(err, inner, ctx.Err())
		if cause == nil {
			cause = ErrConflict
		}
		if entered && (err != nil && inner == nil || count != 1 || ctx.Err() != nil) {
			return errors.Join(ErrOutcomeUnknown, cause)
		}
		return cause
	}
	return nil
}
