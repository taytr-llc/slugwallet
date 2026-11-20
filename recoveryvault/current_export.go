// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

// PreparedCurrentExport owns only a private bounded encoding and a concrete
// source/destination. It has deliberately no plaintext accessor or callback.
type PreparedCurrentExport struct {
	mu          sync.Mutex
	source      *CurrentSource
	destination *CurrentDestination
	checkpoint  CurrentCheckpoint
	revision    uint64
	raw         []byte
	used        bool
	closed      atomic.Bool
	closeErr    error
}

func (s *CurrentSource) PrepareExport(ctx context.Context, captureID string, destination *CurrentDestination) (*PreparedCurrentExport, error) {
	ctx, done, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if s.exported != nil {
		if !s.exported.closed.Load() {
			return nil, ErrBusy
		}
		if s.exported.closeErr != nil {
			return nil, ErrCleanup
		}
	}
	if s.installed == nil || s.installed.ShuttingDown() {
		return nil, ErrClosed
	}
	c, err := s.liveCheckpoint(captureID)
	if err != nil {
		return nil, err
	}
	if destination == nil {
		return nil, ErrConfig
	}
	if err = s.authorize(ctx, gymaccount.RecoveryExport, func(check func() error) error { return check() }); err != nil {
		return nil, err
	}
	r := s.store.vault.records[s.account.ID]
	if r.Recovery == nil || r.Receipt == nil {
		return nil, ErrConflict
	}
	if err = destination.claim(); err != nil {
		return nil, err
	}
	raw, err := openEnvelope(ctx, s.store.vault.core.wrapper, *r.Recovery)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	entropy, err := decodeRecovery(raw, r)
	if err != nil {
		return nil, err
	}
	defer clear(entropy[:])
	bundle, err := recovery.NewExport(entropy, c.Manifest.Accounts)
	if err != nil {
		return nil, ErrEnvelope
	}
	if !reflect.DeepEqual(bundle.Manifest, c.Manifest) {
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
	if err = s.authorize(ctx, gymaccount.RecoveryExport, func(check func() error) error { return check() }); err != nil {
		clear(encoded)
		return nil, err
	}
	p := &PreparedCurrentExport{source: s, destination: destination, checkpoint: cloneCheckpoint(c), revision: r.Revision, raw: encoded}
	s.exported = p
	return p, nil
}
func (p *PreparedCurrentExport) Publish(ctx context.Context) error {
	if p == nil {
		return ErrConfig
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	defer p.mu.Unlock()
	if p.closed.Load() || p.used {
		return ErrClosed
	}
	ctx, done, err := p.source.acquire(ctx)
	if err != nil {
		return err
	}
	defer done()
	p.used = true
	if p.source.installed == nil || p.source.installed.ShuttingDown() {
		return ErrClosed
	}
	c, err := p.source.liveCheckpoint(p.checkpoint.CaptureID)
	if err != nil || !reflect.DeepEqual(c, p.checkpoint) {
		return ErrConflict
	}
	r := p.source.store.vault.records[p.source.account.ID]
	if r.Revision != p.revision {
		return ErrConflict
	}
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
	err = p.source.authorize(ctx, gymaccount.RecoveryExport, func(check func() error) error { attempted = true; return d.publish(ctx, p.raw, check) })
	clear(p.raw)
	p.raw = nil
	if err != nil && attempted && d.used {
		// Outer fence failure after an apparently successful publication must keep
		// the conservative uncertainty even when the filesystem helper returned nil.
		if d.mayPublish || errors.Is(err, ErrOutcomeUnknown) {
			err = errors.Join(ErrExportUncertain, err)
		}
	}
	if errors.Is(err, ErrCleanup) {
		p.closeErr = errors.Join(p.closeErr, err)
	}
	return err
}
func (p *PreparedCurrentExport) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return p.closeErr
	}
	clear(p.raw)
	p.raw = nil
	p.closeErr = errors.Join(p.closeErr, p.destination.Close())
	p.closed.Store(true)
	return p.closeErr
}
