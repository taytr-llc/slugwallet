// Copyright (c) 2026 The SLUG developers. ISC license.

package waddrmgr

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var (
	ErrCurrentRecoveryProfile     = errors.New("unsupported current recovery profile")
	ErrCurrentRecoveryCorrupt     = errors.New("invalid current recovery inventory")
	ErrCurrentRecoveryUnavailable = errors.New("current recovery manager unavailable")
)

// currentAccountCursors reads fixed public offsets in a bounded mixed row.
// Private ciphertext is necessarily present in the borrowed database value;
// its framed span is skipped without copying, retaining or decrypting it.
// In particular this must not call deserializeDefaultAccountRow, which copies
// both encrypted key spans into an allocated account object.
func currentAccountCursors(raw []byte, account uint32) (uint32, uint32, error) {
	bad := func() (uint32, uint32, error) { return 0, 0, ErrCurrentRecoveryCorrupt }
	if len(raw) < 25 || len(raw) > 65536 || raw[0] != byte(accountDefault) || uint64(binary.LittleEndian.Uint32(raw[1:5])) != uint64(len(raw)-5) || (account != DefaultAccountNum && account != ImportedAddrAccount) {
		return bad()
	}
	pos := 5
	skip := func(reserve int) (uint32, bool) {
		if len(raw)-pos < 4 {
			return 0, false
		}
		n := binary.LittleEndian.Uint32(raw[pos : pos+4])
		pos += 4
		if len(raw)-pos < reserve || uint64(n) > uint64(len(raw)-pos-reserve) {
			return 0, false
		}
		pos += int(n)
		return n, true
	}
	public, ok := skip(16)
	if !ok {
		return bad()
	}
	private, ok := skip(12)
	if !ok {
		return bad()
	}
	external := binary.LittleEndian.Uint32(raw[pos : pos+4])
	internal := binary.LittleEndian.Uint32(raw[pos+4 : pos+8])
	pos += 8
	if _, ok = skip(0); !ok || pos != len(raw) {
		return bad()
	}
	if account == ImportedAddrAccount {
		if public != 0 || private != 0 || external != 0 || internal != 0 {
			return bad()
		}
	} else if public == 0 || private == 0 || external > 4096 || internal > 4096 {
		return bad()
	}
	return external, internal, nil
}

func currentRecoveryPublicError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	case errors.Is(e, ErrOwnActivityProfile):
		return ErrCurrentRecoveryProfile
	case errors.Is(e, ErrOwnActivityUnavailable):
		return ErrCurrentRecoveryUnavailable
	default:
		return ErrCurrentRecoveryCorrupt
	}
}

// ReadCurrentRecoveryManifest reads public retained identity and all eight
// issued cursors in the caller's one read transaction. It performs no private
// retention Get, unlock/KDF, address derivation, address inventory or chain read.
// The returned value is owned public data; it is not a wallet capture capability.
func (m *Manager) ReadCurrentRecoveryManifest(ctx context.Context, ns walletdb.ReadBucket) (recovery.Manifest, error) {
	return m.readCurrentRecoveryManifestSchema(ctx, ns, RecoveryManagerVersion)
}

func (m *Manager) readCurrentRecoveryManifestSchema(ctx context.Context, ns walletdb.ReadBucket, schema uint32) (recovery.Manifest, error) {
	var none recovery.Manifest
	if ctx == nil || ns == nil {
		return none, ErrCurrentRecoveryCorrupt
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	if wire.TestPoW {
		return none, ErrCurrentRecoveryProfile
	}
	if m == nil {
		return none, ErrCurrentRecoveryUnavailable
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.closed {
		return none, ErrCurrentRecoveryUnavailable
	}
	if !m.publicRecoveryProfileLocked() || (schema == HostedAllocationManagerVersion) != m.hostedAllocation {
		return none, ErrCurrentRecoveryProfile
	}
	main := ns.NestedReadBucket(mainBucketName)
	if main == nil {
		return none, ErrCurrentRecoveryCorrupt
	}
	manifest, e := m.publicRecoveryManifestSchemaLocked(ctx, main, 4096, schema)
	if e != nil {
		return none, currentRecoveryPublicError(e)
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	root := ns.NestedReadBucket(scopeBucketName)
	schemas := ns.NestedReadBucket(scopeSchemaBucketName)
	if root == nil || schemas == nil {
		return none, ErrCurrentRecoveryCorrupt
	}
	accounts := recovery.DefaultAccounts()
	expectedSchemas := [...]ScopeAddrSchema{
		{ExternalAddrType: PubKeyHash, InternalAddrType: PubKeyHash},
		{ExternalAddrType: NestedWitnessPubKey, InternalAddrType: WitnessPubKey},
		{ExternalAddrType: WitnessPubKey, InternalAddrType: WitnessPubKey},
		{ExternalAddrType: TaprootPubKey, InternalAddrType: TaprootPubKey},
	}
	cursor := root.ReadCursor()
	if cursor == nil {
		return none, ErrCurrentRecoveryCorrupt
	}
	count := 0
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		if e := ctx.Err(); e != nil {
			return none, e
		}
		if count == len(accounts) || len(key) != 8 || value != nil {
			return none, ErrCurrentRecoveryCorrupt
		}
		a := &accounts[count]
		if binary.LittleEndian.Uint32(key[:4]) != a.Purpose || binary.LittleEndian.Uint32(key[4:]) != 0 {
			return none, ErrCurrentRecoveryCorrupt
		}
		schema := schemas.Get(key)
		if len(schema) != 2 || schema[0] != byte(expectedSchemas[count].InternalAddrType) || schema[1] != byte(expectedSchemas[count].ExternalAddrType) {
			return none, ErrCurrentRecoveryCorrupt
		}
		scoped := root.NestedReadBucket(key)
		if scoped == nil {
			return none, ErrCurrentRecoveryCorrupt
		}
		bucket := scoped.NestedReadBucket(acctBucketName)
		index := scoped.NestedReadBucket(addrAcctIdxBucketName)
		if bucket == nil || index == nil {
			return none, ErrCurrentRecoveryCorrupt
		}
		ac := bucket.ReadCursor()
		if ac == nil {
			return none, ErrCurrentRecoveryCorrupt
		}
		accountCount := 0
		for ak, av := ac.First(); ak != nil; ak, av = ac.Next() {
			if e := ctx.Err(); e != nil {
				return none, e
			}
			if accountCount == 2 || len(ak) != 4 || av == nil {
				return none, ErrCurrentRecoveryCorrupt
			}
			expected := uint32(DefaultAccountNum)
			if accountCount == 1 {
				expected = ImportedAddrAccount
			}
			account := binary.LittleEndian.Uint32(ak)
			if account != expected {
				return none, ErrCurrentRecoveryCorrupt
			}
			external, internal, e := currentAccountCursors(av, account)
			if e != nil {
				return none, e
			}
			if account == DefaultAccountNum {
				a.NextExternal, a.NextInternal = external, internal
			}
			accountCount++
		}
		if accountCount != 2 {
			return none, ErrCurrentRecoveryCorrupt
		}
		if e := ctx.Err(); e != nil {
			return none, e
		}
		importedKey := uint32ToBytes(ImportedAddrAccount)
		if index.Get(importedKey) != nil {
			return none, ErrCurrentRecoveryCorrupt
		}
		if imported := index.NestedReadBucket(importedKey); imported != nil {
			ic := imported.ReadCursor()
			if ic == nil {
				return none, ErrCurrentRecoveryCorrupt
			}
			if k, _ := ic.First(); k != nil {
				return none, ErrCurrentRecoveryCorrupt
			}
		}
		count++
	}
	if count != len(accounts) {
		return none, ErrCurrentRecoveryCorrupt
	}
	manifest.Accounts = accounts
	if e := ctx.Err(); e != nil {
		return none, e
	}
	return manifest, nil
}
