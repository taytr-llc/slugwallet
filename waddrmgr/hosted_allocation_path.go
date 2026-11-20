// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// hostedPath permits only already committed supported paths. Cached private
// derivation without a transaction is refused separately, before cache lookup.
func (s *ScopedKeyManager) hostedPath(ns walletdb.ReadBucket, account, branch, index uint32) error {
	if !s.rootManager.HostedAllocation() {
		return nil
	}
	supported := s.scope.Purpose == 84
	if s.rootManager.carrierSchema == RestoredCarrierManagerVersion {
		supported = s.scope.Purpose == 44 || s.scope.Purpose == 49 || s.scope.Purpose == 84 || s.scope.Purpose == 86
	}
	if ns == nil || account != 0 || !supported || s.scope.Coin != 0 || branch > 1 || index >= 4096 {
		return ErrHostedAllocationFrontier
	}
	scoped, e := fetchReadScopeBucket(ns, &s.scope)
	if e != nil {
		return ErrHostedAllocationFrontier
	}
	accounts := scoped.NestedReadBucket(acctBucketName)
	if accounts == nil {
		return ErrHostedAllocationFrontier
	}
	external, internal, e := currentAccountCursors(accounts.Get(uint32ToBytes(0)), 0)
	if e != nil {
		return ErrHostedAllocationFrontier
	}
	next := external
	if branch == 1 {
		next = internal
	}
	if index >= next {
		return ErrHostedAllocationFrontier
	}
	return nil
}

// Check a recognized row before the ordinary cache can return it. Foreign
// addresses retain the inherited not-found path; recognized unsupported rows
// must not be silently treated as foreign by the root manager.
func (s *ScopedKeyManager) hostedAddress(ns walletdb.ReadBucket, addr address.Address) error {
	if !s.rootManager.HostedAllocation() {
		return nil
	}
	if ns == nil || addr == nil {
		return ErrHostedAllocationFrontier
	}
	scoped, err := fetchReadScopeBucket(ns, &s.scope)
	if err != nil {
		return ErrHostedAllocationFrontier
	}
	bucket := scoped.NestedReadBucket(addrBucketName)
	if bucket == nil {
		return ErrHostedAllocationFrontier
	}
	hash := sha256.Sum256(addr.ScriptAddress())
	raw := bucket.Get(hash[:])
	if raw == nil {
		return nil
	}
	if len(raw) != 26 || raw[0] != byte(adtChain) || binary.LittleEndian.Uint32(raw[14:18]) != 8 {
		return ErrHostedAllocationFrontier
	}
	return s.hostedPath(ns, binary.LittleEndian.Uint32(raw[1:5]), binary.LittleEndian.Uint32(raw[18:22]), binary.LittleEndian.Uint32(raw[22:26]))
}
