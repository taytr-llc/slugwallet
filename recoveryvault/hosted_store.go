// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
)

const hostedApplication = "slug-hosted-fixture-recovery-vault"
const hostedMarkerMax = 32768

func hostedPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 2048 {
		return "", ErrConfig
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", ErrCorrupt
	}
	// Canonical aliases supplied by an owning initializer are normalized once;
	// the actual leaf must never be a symlink.
	path = filepath.Join(parent, filepath.Base(path))
	if st, e := os.Lstat(path); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return "", ErrCorrupt
	} else if e != nil && !os.IsNotExist(e) {
		return "", ErrCorrupt
	}
	return path, nil
}
func strictHosted(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !json.Valid(raw) || json.Unmarshal(raw, out) != nil {
		return ErrCorrupt
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(encoded, raw) {
		return ErrCorrupt
	}
	return nil
}
func readHostedMarker(path string, out any) error {
	if !vaultRegular(path, false) {
		return ErrCorrupt
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrCorrupt
	}
	raw, re := io.ReadAll(io.LimitReader(f, hostedMarkerMax+1))
	ce := f.Close()
	if re != nil || ce != nil || len(raw) < 2 || len(raw) > hostedMarkerMax || raw[len(raw)-1] != '\n' {
		return ErrCorrupt
	}
	return strictHosted(raw[:len(raw)-1], out, hostedMarkerMax-1)
}
func writeHostedMarker(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > hostedMarkerMax {
		return ErrCorrupt
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrCorrupt
	}
	raw = append(raw, '\n')
	n, we := f.Write(raw)
	if errors.Join(we, f.Sync(), f.Close()) != nil || n != len(raw) {
		return ErrPoisoned
	}
	if syncVaultDir(filepath.Dir(path)) != nil || syncVaultDir(filepath.Dir(filepath.Dir(path))) != nil {
		return ErrPoisoned
	}
	return nil
}
func jsonSHA(v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func CreateHosted(ctx context.Context, path string, c Config, accounts *gymaccount.Store, wrapper KeyWrapper, expectedID string) (*HostedVault, error) {
	return openHosted(ctx, path, c, accounts, wrapper, expectedID, true)
}
func OpenHosted(ctx context.Context, path string, c Config, accounts *gymaccount.Store, wrapper KeyWrapper, expectedID string) (*HostedVault, error) {
	return openHosted(ctx, path, c, accounts, wrapper, expectedID, false)
}
func openHosted(ctx context.Context, path string, c Config, accounts *gymaccount.Store, wrapper KeyWrapper, expectedID string, create bool) (*HostedVault, error) {
	c, a, err := vaultSetup(ctx, c, accounts, wrapper)
	if err != nil {
		return nil, err
	}
	if !nonzeroID(expectedID) {
		return nil, ErrConfig
	}
	path, err = hostedPath(path)
	if err != nil {
		return nil, err
	}
	header := hostedHeader{hostedApplication, Version1, expectedID, a, c}
	markerPath := filepath.Join(path, vaultMarker)
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
		if e := os.Mkdir(path, 0700); e != nil {
			return nil, ErrCorrupt
		}
	} else {
		if !vaultRegular(path, true) || !vaultRegular(filepath.Join(path, "db"), true) {
			return nil, ErrCorrupt
		}
		if markerExists {
			var got hostedHeader
			if readHostedMarker(markerPath, &got) != nil || !reflect.DeepEqual(got, header) {
				return nil, ErrCorrupt
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	db, err := leveldb.OpenFile(filepath.Join(path, "db"), &opt.Options{ErrorIfExist: create, ErrorIfMissing: !create})
	if err != nil {
		return nil, ErrCorrupt
	}
	core := newVault(path, c, a, accounts, hostedWrapper{wrapper}, db)
	h := &HostedVault{core: core, header: header, records: map[string]vaultRecord{}}
	fail := func(err error) (*HostedVault, error) {
		core.cancel()
		ce := db.Close()
		if ce != nil {
			return nil, errors.Join(err, ErrCleanup)
		}
		return nil, err
	}
	if create {
		core.meta = vaultMetadata{Header: vaultHeader{hostedApplication, Version1, a, c}, Accounts: []reservationIndex{}}
		batch := new(leveldb.Batch)
		if err = h.putMeta(batch, core.meta); err == nil {
			err = db.Write(batch, &opt.WriteOptions{Sync: true})
		}
		if err != nil {
			return fail(ErrPoisoned)
		}
	} else {
		var meta hostedMetadata
		raw, e := db.Get([]byte("meta"), nil)
		if e != nil || strictVault(raw, &meta) != nil || !reflect.DeepEqual(meta.Header, header) {
			return fail(ErrCorrupt)
		}
		core.meta = vaultMetadata{Header: vaultHeader{hostedApplication, Version1, a, c}, Operations: meta.Operations, Reserved: meta.Reserved, Accounts: meta.Accounts}
		if core.audit() != nil {
			return fail(ErrCorrupt)
		}
		for _, idx := range core.meta.Accounts {
			r, e := core.record(idx.AccountID)
			if e != nil {
				return fail(ErrCorrupt)
			}
			h.records[idx.AccountID] = r
		}
		// Only an exact, fully synced empty initializer may complete its marker.
		// An established marker with missing state never reaches this branch.
		if !markerExists && (core.meta.Operations != 0 || core.meta.Reserved != 0 || len(core.meta.Accounts) != 0) {
			return fail(ErrCorrupt)
		}
	}
	if !markerExists {
		if err = writeHostedMarker(markerPath, header); err != nil {
			return fail(err)
		}
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return h, nil
}
func (h *HostedVault) putMeta(batch *leveldb.Batch, meta vaultMetadata) error {
	return putVault(batch, "meta", hostedMetadata{h.header, meta.Operations, meta.Reserved, meta.Accounts})
}
func (h *HostedVault) record(id string) (vaultRecord, error) {
	r, ok := h.records[id]
	if !ok {
		return vaultRecord{}, ErrNotFound
	}
	return cloneRecord(r), nil
}
func (h *HostedVault) stage(r vaultRecord, meta vaultMetadata) (*leveldb.Batch, error) {
	if h.core.validateRecord(r) != nil {
		return nil, ErrCorrupt
	}
	b := new(leveldb.Batch)
	if putVault(b, "account:"+r.Binding.AccountID, r) != nil || h.putMeta(b, meta) != nil {
		return nil, ErrCorrupt
	}
	return b, nil
}

// commit is called only with the hosted permit already owned. All parsing,
// encoding, hashing, allocation and record validation preceded the lease.
func (h *HostedVault) commit(ctx context.Context, b *leveldb.Batch, r vaultRecord, meta vaultMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.core.writeBatch(b, &opt.WriteOptions{Sync: true}) != nil {
		h.core.poisoned = true
		return ErrPoisoned
	}
	h.core.meta = meta
	h.records[r.Binding.AccountID] = r
	return nil
}
