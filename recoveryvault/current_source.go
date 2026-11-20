// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/wallet"
)

func (s *CurrentStore) AttachSource(ctx context.Context, token string, binding CurrentBinding, installed *wallet.Wallet, epoch EpochFence) (*CurrentSource, error) {
	if s == nil || ctx == nil || installed == nil || epoch == nil {
		return nil, ErrConfig
	}
	ctx, vdone, err := s.vault.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer vdone()
	ctx, done, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	index := -1
	for i, b := range s.marker.Bindings {
		if binding == b {
			index = i
		}
	}
	if index < 0 {
		return nil, ErrConflict
	}
	a, r, err := s.vault.snapshot(ctx, token, gymaccount.View, epoch)
	if err != nil {
		return nil, err
	}
	if r.State != "enrolled" || r.Receipt == nil || r.Binding != binding.VaultBinding || r.Receipt.RetentionID != binding.RetentionID {
		return nil, ErrConflict
	}
	observed, err := installed.CaptureCurrentRecovery(ctx)
	if err != nil {
		return nil, err
	}
	if currentManifest(observed.Manifest(), r.Manifest) != nil {
		return nil, ErrConflict
	}
	if err = s.vault.disclose(ctx, token, gymaccount.View, epoch, a, r); err != nil {
		return nil, err
	}
	src := &CurrentSource{owner: newCurrentLife(), store: s, token: token, binding: binding, account: a, installed: installed, epoch: epoch, index: index, committed: make(map[string]*wallet.CurrentRecoveryCapture)}
	s.sourcesMu.Lock()
	defer s.sourcesMu.Unlock()
	s.owner.mu.Lock()
	closing := s.owner.closing
	s.owner.mu.Unlock()
	if closing {
		src.owner.cancel()
		return nil, ErrClosed
	}
	// Exactly one live attachment per bound installed owner; no same-root wallet
	// substitution can coexist with an already borrowed source.
	for other := range s.sources {
		if other.binding == binding {
			src.owner.cancel()
			return nil, ErrBusy
		}
	}
	s.sources[src] = true
	return src, nil
}
func (s *CurrentSource) acquire(ctx context.Context) (context.Context, func(), error) {
	if s == nil || s.store == nil {
		return nil, nil, ErrClosed
	}
	ctx, ownDone, err := s.owner.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	ctx, vaultDone, err := s.store.vault.acquire(ctx)
	if err != nil {
		ownDone()
		return nil, nil, err
	}
	ctx, storeDone, err := s.store.acquire(ctx)
	if err != nil {
		vaultDone()
		ownDone()
		return nil, nil, err
	}
	return ctx, func() { storeDone(); vaultDone(); ownDone() }, nil
}
func (s *CurrentSource) authorize(ctx context.Context, cap gymaccount.Capability, fn func(func() error) error) error {
	return s.store.vault.fence(ctx, s.token, cap, false, s.epoch, &s.account, func(a gymaccount.Account, _ gymaccount.Identity, check func() error) error {
		r, ok := s.store.vault.records[a.ID]
		if !ok || r.State != "enrolled" || r.Binding != s.binding.VaultBinding || r.Receipt == nil || r.Receipt.RetentionID != s.binding.RetentionID || !bindingMatchesAccount(r.Binding, a) {
			return ErrConflict
		}
		return fn(check)
	})
}
func (s *CurrentSource) Capture(ctx context.Context) (*wallet.CurrentRecoveryCapture, error) {
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
	s.exported = nil
	if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
		return nil, err
	}
	capture, err := s.installed.CaptureCurrentRecovery(ctx)
	if err != nil {
		return nil, err
	}
	if currentManifest(capture.Manifest(), s.store.originals[s.index]) != nil || !nonzeroID(capture.CaptureID()) {
		return nil, ErrConflict
	}
	if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
		return nil, err
	}
	s.capture = capture
	return capture, nil
}
func (s *CurrentSource) Checkpoint(ctx context.Context, expected uint32, capture *wallet.CurrentRecoveryCapture) (CurrentCheckpoint, bool, error) {
	ctx, done, err := s.acquire(ctx)
	if err != nil {
		return CurrentCheckpoint{}, false, err
	}
	defer done()
	if capture == nil || (capture != s.capture && s.committed[capture.CaptureID()] != capture) || (s.exported != nil && !s.exported.closed.Load()) {
		return CurrentCheckpoint{}, false, ErrConflict
	}
	if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
		return CurrentCheckpoint{}, false, err
	}
	req := currentIntent{s.binding, capture.CaptureID(), expected, capture.CapturedAtMS(), capture.Manifest()}
	c, meta, raw, mr, changed, err := s.store.stageCheckpoint(s.index, req, s.store.now().UnixMilli())
	if err != nil {
		return CurrentCheckpoint{}, false, err
	}
	if !changed {
		if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
			return CurrentCheckpoint{}, false, err
		}
		return c, false, nil
	}
	batch := new(leveldb.Batch)
	batch.Put([]byte("action/"+c.CaptureID), raw)
	batch.Put([]byte("meta"), mr)
	oldMeta, _ := json.Marshal(s.store.meta)
	nextBytes := s.store.bytes - len(oldMeta) + len(mr) + 71 + len(raw)
	attempted := false
	err = s.authorize(ctx, gymaccount.View, func(check func() error) error {
		if e := check(); e != nil {
			return e
		}
		attempted = true
		if s.store.writeBatch(batch, &opt.WriteOptions{Sync: true}) != nil {
			return ErrPoisoned
		}
		s.store.actions[c.CaptureID] = c
		s.store.meta = meta
		s.store.bytes = nextBytes
		return check()
	})
	if err != nil {
		if attempted {
			s.store.poisoned = true
			return CurrentCheckpoint{}, false, errors.Join(ErrOutcomeUnknown, err)
		}
		return CurrentCheckpoint{}, false, err
	}
	s.committed[c.CaptureID] = capture
	return cloneCheckpoint(c), true, nil
}
func (s *CurrentSource) LookupCheckpoint(ctx context.Context, captureID string) (CurrentCheckpoint, error) {
	ctx, done, err := s.acquire(ctx)
	if err != nil {
		return CurrentCheckpoint{}, err
	}
	defer done()
	if !nonzeroID(captureID) {
		return CurrentCheckpoint{}, ErrConfig
	}
	c, ok := s.store.actions[captureID]
	if !ok || c.Binding != s.binding {
		return CurrentCheckpoint{}, ErrNotFound
	}
	if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
		return CurrentCheckpoint{}, err
	}
	return cloneCheckpoint(c), nil
}

// CurrentCheckpoint returns only an existing dated head/CAS revision. It never
// resolves an uncertain old CaptureID and is not a substitute for fresh capture.
func (s *CurrentSource) CurrentCheckpoint(ctx context.Context) (CurrentCheckpoint, bool, error) {
	ctx, done, err := s.acquire(ctx)
	if err != nil {
		return CurrentCheckpoint{}, false, err
	}
	defer done()
	p := s.store.meta.Current[s.index]
	c, ok := s.store.actions[p.CaptureID]
	if err = s.authorize(ctx, gymaccount.View, func(check func() error) error { return check() }); err != nil {
		return CurrentCheckpoint{}, false, err
	}
	if !ok {
		return CurrentCheckpoint{}, false, nil
	}
	return cloneCheckpoint(c), true, nil
}
func (s *CurrentSource) liveCheckpoint(captureID string) (CurrentCheckpoint, error) {
	if s.capture == nil || s.capture.CaptureID() != captureID {
		return CurrentCheckpoint{}, ErrConflict
	}
	c, ok := s.store.actions[captureID]
	if !ok || c.Binding != s.binding || c.CapturedAtMS != s.capture.CapturedAtMS() || !reflect.DeepEqual(c.Manifest, s.capture.Manifest()) {
		return CurrentCheckpoint{}, ErrConflict
	}
	return c, nil
}
func (s *CurrentSource) Close() error {
	if s == nil {
		return nil
	}
	first, err := s.owner.startClose()
	if !first {
		return err
	}
	s.owner.active.Wait()
	if s.exported != nil {
		err = errors.Join(err, s.exported.Close())
		if err == nil {
			s.exported = nil
		}
	}
	if err == nil {
		s.capture = nil
		s.committed = nil
		s.installed = nil
		s.token = ""
		s.store.sourcesMu.Lock()
		delete(s.store.sources, s)
		s.store.sourcesMu.Unlock()
	}
	return s.owner.finishClose(err)
}
