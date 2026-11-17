// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"encoding/binary"

	"github.com/taytr-llc/slugwallet/walletdb"
)

// recoveryScryptOptions owns and bounds the parameters before a schema11
// creation or password change can enter scrypt. Older schemas keep their
// existing configurable behavior.
func recoveryScryptOptions(config *ScryptOptions) (ScryptOptions, error) {
	if config == nil {
		config = &DefaultScryptOptions
	}
	owned := *config
	if owned.N <= 1 || owned.N > 1<<18 || owned.N&(owned.N-1) != 0 || owned.R < 1 || owned.R > 8 || owned.P != 1 {
		return ScryptOptions{}, ErrRecoveryState
	}
	return owned, nil
}

// validateRecoveryKeyFields runs before inherited decoders copy encrypted
// fields or derive passphrase keys. No unbounded allocation depends on stored
// schema11 key parameters, and a missing sync bucket cannot reach nil access.
func validateRecoveryKeyFields(ns walletdb.ReadBucket) error {
	main := ns.NestedReadBucket(mainBucketName)
	sync := ns.NestedReadBucket(syncBucketName)
	if main == nil || sync == nil {
		return ErrRecoveryState
	}
	for _, name := range [][]byte{masterPubKeyName, masterPrivKeyName} {
		raw := main.Get(name)
		if len(raw) != 88 {
			return ErrRecoveryState
		}
		n, r, p := binary.LittleEndian.Uint64(raw[64:72]), binary.LittleEndian.Uint64(raw[72:80]), binary.LittleEndian.Uint64(raw[80:88])
		if n <= 1 || n > 1<<18 || n&(n-1) != 0 || r < 1 || r > 8 || p != 1 {
			return ErrRecoveryState
		}
	}
	for _, name := range [][]byte{cryptoPubKeyName, cryptoPrivKeyName, cryptoScriptKeyName} {
		if len(main.Get(name)) != 72 {
			return ErrRecoveryState
		}
	}
	for _, name := range [][]byte{masterHDPubName, masterHDPrivName} {
		if n := len(main.Get(name)); n <= 40 || n > 296 {
			return ErrRecoveryState
		}
	}
	if watch := main.Get(watchingOnlyName); len(watch) != 1 || watch[0] != 0 {
		return ErrRecoveryState
	}
	for _, field := range []struct {
		name []byte
		size int
	}{{syncedToName, 40}, {startBlockName, 36}, {birthdayName, 8}} {
		if len(sync.Get(field.name)) != field.size {
			return ErrRecoveryState
		}
	}
	if birthday := sync.Get(birthdayBlockName); birthday != nil && len(birthday) != 44 {
		return ErrRecoveryState
	}
	if sync.NestedReadBucket(birthdayBlockName) != nil || sync.NestedReadBucket(birthdayBlockVerifiedName) != nil {
		return ErrRecoveryState
	}
	if verified := sync.Get(birthdayBlockVerifiedName); verified != nil && (len(verified) != 2 || binary.BigEndian.Uint16(verified) > 1) {
		return ErrRecoveryState
	}
	return nil
}
