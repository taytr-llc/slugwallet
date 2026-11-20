// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

func CreateCurrentStore(ctx context.Context, path string, vault *HostedVault, bindings []CurrentBinding) (*CurrentStore, error) {
	return openCurrentStore(ctx, path, vault, bindings, true)
}
func OpenCurrentStore(ctx context.Context, path string, vault *HostedVault, bindings []CurrentBinding) (*CurrentStore, error) {
	return openCurrentStore(ctx, path, vault, bindings, false)
}
func openCurrentStore(ctx context.Context, path string, vault *HostedVault, bindings []CurrentBinding, create bool) (*CurrentStore, error) {
	if wire.TestPoW || ctx == nil || vault == nil || len(bindings) != 2 {
		return nil, ErrConfig
	}
	ctx, done, err := vault.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	bindings = append([]CurrentBinding(nil), bindings...)
	originals := make([]recovery.Manifest, 2)
	for i, b := range bindings {
		r, e := vault.record(b.VaultBinding.AccountID)
		if e != nil || b.HostedVaultID != vault.header.HostedVaultID || r.Binding != b.VaultBinding || r.Receipt == nil || r.Receipt.RetentionID != b.RetentionID {
			return nil, ErrConflict
		}
		originals[i] = cloneManifest(r.Manifest)
	}
	if err = validateCurrentBindings(bindings, originals); err != nil {
		return nil, err
	}
	path, err = hostedPath(path)
	if err != nil {
		return nil, err
	}
	marker := currentMarker{currentApplication, Version1, bindings}
	markerPath := filepath.Join(path, currentMarkerFile)
	markerExists := false
	if _, e := os.Lstat(markerPath); e == nil {
		markerExists = true
	} else if !os.IsNotExist(e) {
		return nil, ErrCorrupt
	}
	if create {
		if markerExists {
			return nil, ErrConflict
		}
		if os.Mkdir(path, 0700) != nil {
			return nil, ErrCorrupt
		}
	} else {
		if !vaultRegular(path, true) || !vaultRegular(filepath.Join(path, "db"), true) {
			return nil, ErrCorrupt
		}
		if markerExists {
			var got currentMarker
			if readHostedMarker(markerPath, &got) != nil || !reflect.DeepEqual(got, marker) {
				return nil, ErrCorrupt
			}
		}
	}
	db, err := leveldb.OpenFile(filepath.Join(path, "db"), &opt.Options{ErrorIfExist: create, ErrorIfMissing: !create})
	if err != nil {
		return nil, ErrCorrupt
	}
	s := &CurrentStore{owner: newCurrentLife(), vault: vault, path: path, marker: marker, originals: originals, db: db, actions: map[string]CurrentCheckpoint{}, writeBatch: db.Write, now: time.Now, sources: map[*CurrentSource]bool{}}
	fail := func(e error) (*CurrentStore, error) {
		s.owner.cancel()
		ce := db.Close()
		if ce != nil {
			e = errors.Join(e, ErrCleanup)
		}
		return nil, e
	}
	if create {
		hash, _ := jsonSHA(marker)
		s.meta = currentMetadata{Version: Version1, MarkerSHA256: hash, Current: []currentPointer{{AccountID: bindings[0].VaultBinding.AccountID}, {AccountID: bindings[1].VaultBinding.AccountID}}}
		raw, _ := json.Marshal(s.meta)
		batch := new(leveldb.Batch)
		batch.Put([]byte("meta"), raw)
		if db.Write(batch, &opt.WriteOptions{Sync: true}) != nil {
			return fail(ErrPoisoned)
		}
		s.bytes = 4 + len(raw)
	} else {
		if err = s.audit(); err != nil {
			return fail(err)
		}
		if !markerExists && s.meta.Actions != 0 {
			return fail(ErrCorrupt)
		}
	}
	if !markerExists {
		if err = writeHostedMarker(markerPath, marker); err != nil {
			return fail(err)
		}
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *CurrentStore) acquire(ctx context.Context) (context.Context, func(), error) {
	if s == nil {
		return nil, nil, ErrClosed
	}
	ctx, done, err := s.owner.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	if s.poisoned {
		done()
		return nil, nil, ErrPoisoned
	}
	return ctx, done, nil
}
func (s *CurrentStore) Close() error {
	if s == nil {
		return nil
	}
	first, err := s.owner.startClose()
	if !first {
		return err
	}
	s.sourcesMu.Lock()
	sources := make([]*CurrentSource, 0, len(s.sources))
	for src := range s.sources {
		sources = append(sources, src)
	}
	s.sourcesMu.Unlock()
	for _, src := range sources {
		err = errors.Join(err, src.Close())
	}
	s.owner.active.Wait()
	if e := s.db.Close(); e != nil {
		err = errors.Join(err, ErrCleanup)
	}
	if s.poisoned {
		err = errors.Join(err, ErrPoisoned)
	}
	return s.owner.finishClose(err)
}
