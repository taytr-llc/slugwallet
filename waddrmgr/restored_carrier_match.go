// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// RestoredCarrierMatch is public lookup data, not permission to allocate or
// sign. Next counts raw children, including invalid children, in the ORIGINAL
// imported native84 external branch followed by its internal branch.
type RestoredCarrierMatch struct {
	Next, Total                 uint32
	FundingFound, ReturnFound   bool
	FundingBranch, FundingIndex uint32
	ReturnBranch, ReturnIndex   uint32
}

// Only schema15's issued frontier is watched after activation. Retained schema12
// lookahead is audited and kept for recovery provenance but cannot trigger live
// issuance through the ordinary notification path.
func (s *ScopedKeyManager) restoredCarrierIssuedRow(ns walletdb.ReadBucket, row interface{}) (bool, error) {
	r, ok := row.(*dbChainAddressRow)
	if !ok || r.account != 0 || r.branch > 1 || r.index >= 4096 || s.scope.Coin != 0 || s.scope.Purpose != 44 && s.scope.Purpose != 49 && s.scope.Purpose != 84 && s.scope.Purpose != 86 {
		return false, ErrHostedAllocationCorrupt
	}
	scope, e := fetchReadScopeBucket(ns, &s.scope)
	if e != nil {
		return false, e
	}
	accounts := scope.NestedReadBucket(acctBucketName)
	if accounts == nil {
		return false, ErrHostedAllocationCorrupt
	}
	external, internal, e := currentAccountCursors(accounts.Get(uint32ToBytes(0)), 0)
	if e != nil {
		return false, e
	}
	next := external
	if r.branch == 1 {
		next = internal
	}
	return r.index < next, nil
}

func (m *Manager) restoredPublicAccount(ns walletdb.ReadBucket) (*hdkeychain.ExtendedKey, error) {
	scope, e := fetchReadScopeBucket(ns, &KeyScopeBIP0084)
	if e != nil {
		return nil, ErrHostedAllocationCorrupt
	}
	accounts := scope.NestedReadBucket(acctBucketName)
	if accounts == nil {
		return nil, ErrHostedAllocationCorrupt
	}
	raw := accounts.Get(uint32ToBytes(0))
	if _, _, e = currentAccountCursors(raw, 0); e != nil {
		return nil, e
	}
	n := int(binary.LittleEndian.Uint32(raw[5:9]))
	plain, e := m.cryptoKeyPub.Decrypt(raw[9 : 9+n])
	if e != nil {
		return nil, ErrHostedAllocationCorrupt
	}
	defer clear(plain)
	key, e := hdkeychain.NewKeyFromString(string(plain))
	if e != nil {
		return nil, ErrHostedAllocationCorrupt
	}
	if key.IsPrivate() {
		key.Zero()
		return nil, ErrHostedAllocationCorrupt
	}
	return key, nil
}

// MatchRestoredCarrierKeys performs at most128 public child derivations in one
// read transaction, with no unlock, cache publication or issuance mutation.
func (m *Manager) MatchRestoredCarrierKeys(ctx context.Context, ns walletdb.ReadBucket, start uint32, funding [33]byte, returned [22]byte) (RestoredCarrierMatch, error) {
	var out RestoredCarrierMatch
	g, e := m.AuditRestoredCarrier(ctx, ns)
	if e != nil {
		return out, e
	}
	a := g.OriginalManifest.Accounts[2]
	if a.Purpose != 84 {
		return out, ErrHostedAllocationCorrupt
	}
	out.Total = a.NextExternal + a.NextInternal
	if start > out.Total {
		return out, ErrHostedAllocationInvalid
	}
	out.Next = start
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return out, ErrHostedAllocationProfile
	}
	key, e := m.restoredPublicAccount(ns)
	if e != nil {
		return out, e
	}
	defer key.Zero()
	var branches [2]*hdkeychain.ExtendedKey
	defer func() {
		for _, k := range branches {
			if k != nil {
				k.Zero()
			}
		}
	}()
	for out.Next < out.Total && out.Next-start < 128 {
		if e = ctx.Err(); e != nil {
			return RestoredCarrierMatch{}, e
		}
		branch, index := uint32(0), out.Next
		if index >= a.NextExternal {
			branch, index = 1, index-a.NextExternal
		}
		if branches[branch] == nil {
			branches[branch], e = key.Derive(branch)
			if e != nil {
				return RestoredCarrierMatch{}, ErrHostedAllocationCorrupt
			}
		}
		child, e := branches[branch].Derive(index)
		out.Next++
		if e == hdkeychain.ErrInvalidChild {
			continue
		}
		if e != nil {
			return RestoredCarrierMatch{}, ErrHostedAllocationCorrupt
		}
		pub, e := child.ECPubKey()
		child.Zero()
		if e != nil {
			return RestoredCarrierMatch{}, ErrHostedAllocationCorrupt
		}
		serialized := pub.SerializeCompressed()
		if bytes.Equal(serialized, funding[:]) {
			out.FundingFound, out.FundingBranch, out.FundingIndex = true, branch, index
		}
		if returned[0] == 0 && returned[1] == 20 && bytes.Equal(address.Hash160(serialized), returned[2:]) {
			out.ReturnFound, out.ReturnBranch, out.ReturnIndex = true, branch, index
		}
	}
	return out, ctx.Err()
}

// CheckRestoredCarrierPath crosschecks a retained public path against the
// immutable import bounds, not later current issuance or derived lookahead.
func (m *Manager) CheckRestoredCarrierPath(ctx context.Context, ns walletdb.ReadBucket, branch, index uint32, public, script []byte) error {
	g, e := m.AuditRestoredCarrier(ctx, ns)
	if e != nil {
		return e
	}
	if branch > 1 || len(public) != 0 && len(public) != 33 || len(script) != 22 || script[0] != 0 || script[1] != 20 {
		return ErrHostedAllocationInvalid
	}
	a := g.OriginalManifest.Accounts[2]
	limit := a.NextExternal
	if branch == 1 {
		limit = a.NextInternal
	}
	if index >= limit {
		return ErrHostedAllocationFrontier
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return ErrHostedAllocationProfile
	}
	key, e := m.restoredPublicAccount(ns)
	if e != nil {
		return e
	}
	defer key.Zero()
	b, e := key.Derive(branch)
	if e != nil {
		return ErrHostedAllocationCorrupt
	}
	defer b.Zero()
	c, e := b.Derive(index)
	if e != nil {
		return ErrHostedAllocationCorrupt
	}
	defer c.Zero()
	pub, e := c.ECPubKey()
	if e != nil {
		return ErrHostedAllocationCorrupt
	}
	raw := pub.SerializeCompressed()
	if len(public) != 0 && !bytes.Equal(raw, public) || !bytes.Equal(address.Hash160(raw), script[2:]) {
		return ErrHostedAllocationConflict
	}
	return ctx.Err()
}

// CheckRestoredCarrierRange rederives one retained new-allocation range. The
// caller folds its before/after cursors from the immutable activation snapshot;
// this check independently proves each claimed skipped BIP32 child.
func (m *Manager) CheckRestoredCarrierRange(ctx context.Context, ns walletdb.ReadBucket, expected HostedAllocationRange) error {
	if _, e := m.AuditRestoredCarrier(ctx, ns); e != nil {
		return e
	}
	if expected.Purpose != 84 || expected.Branch != 1 {
		return ErrHostedAllocationInvalid
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return ErrHostedAllocationProfile
	}
	actual, e := m.hostedRange(ctx, ns, 84, 1, expected.StartIndex)
	if e != nil {
		return e
	}
	if !rangeMatches(HostedAllocationRecord{Purpose: expected.Purpose, Branch: expected.Branch, StartIndex: expected.StartIndex, EndIndex: expected.EndIndex, SelectedIndex: expected.SelectedIndex, InvalidIndices: expected.InvalidIndices, Address: expected.Address, Script: expected.Script}, actual) {
		return ErrHostedAllocationCorrupt
	}
	return ctx.Err()
}
