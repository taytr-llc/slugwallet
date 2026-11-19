// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"encoding/binary"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// validateResumableInvalidChildren proves recorded skips instead of trusting
// their counts. It only decrypts account public keys and derives the exact
// recorded nonhardened child; it never substitutes a neighbouring index.
func validateResumableInvalidChildren(ns walletdb.ReadBucket, cryptoKeyPub EncryptorDecryptor) error {
	if ns == nil || cryptoKeyPub == nil {
		return ErrRecoveryState
	}
	version, err := fetchManagerVersion(ns)
	if err != nil || version != ResumableManagerVersion && version != PhaseAManagerVersion {
		return ErrRecoveryState
	}
	state, err := fetchRecoveryProgress(ns)
	if err != nil {
		return ErrRecoveryState
	}
	if err := validateRecoveryInvalid(ns, state); err != nil {
		return ErrRecoveryState
	}
	var branches [8]*hdkeychain.ExtendedKey
	defer func() {
		for _, key := range branches {
			if key != nil {
				key.Zero()
			}
		}
	}()
	policy, err := recoveryPolicyFor(ns)
	if err != nil {
		return err
	}
	markers := ns.NestedReadBucket(mainBucketName).NestedReadBucket(policy.invalid)
	return markers.ForEach(func(key, value []byte) error {
		// The bounded format and coverage check above precedes all slicing
		// and derivation, including for malformed nested buckets.
		scope := KeyScope{Purpose: binary.LittleEndian.Uint32(key), Coin: binary.LittleEndian.Uint32(key[4:])}
		branch, index := binary.LittleEndian.Uint32(key[8:]), binary.LittleEndian.Uint32(key[12:])
		position := -1
		for i, candidate := range state.Branches {
			if candidate.Scope == scope && candidate.Branch == branch {
				position = i
				break
			}
		}
		if position < 0 {
			return ErrRecoveryState
		}
		if branches[position] == nil {
			row, err := fetchAccountInfo(ns, &scope, DefaultAccountNum)
			if err != nil {
				return ErrRecoveryState
			}
			account, ok := row.(*dbDefaultAccountRow)
			if !ok {
				return ErrRecoveryState
			}
			plain, err := cryptoKeyPub.Decrypt(account.pubKeyEncrypted)
			if err != nil {
				clear(plain)
				return ErrRecoveryState
			}
			public, err := hdkeychain.NewKeyFromString(string(plain))
			clear(plain)
			if err != nil {
				return ErrRecoveryState
			}
			if public.IsPrivate() {
				public.Zero()
				return ErrRecoveryState
			}
			branches[position], err = public.Derive(branch)
			public.Zero()
			if err != nil {
				return ErrRecoveryState
			}
		}
		child, err := branches[position].Derive(index)
		if child != nil {
			child.Zero()
		}
		if err != hdkeychain.ErrInvalidChild {
			return ErrRecoveryState
		}
		return nil
	})
}
