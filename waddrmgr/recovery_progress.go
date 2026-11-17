// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/walletdb"
)

const (
	ResumableManagerVersion uint32 = 11
	RecoveryAttemptLimit    uint32 = 65536
	RecoveryChunkSize       uint32 = 128
	RecoveryLookahead       uint32 = 20
)

var (
	ErrRecoveryInProgress = errors.New("candidate recovery is not complete")
	ErrRecoveryQuota      = errors.New("candidate recovery exceeds supported inventory quota")
	recoveryProgressName  = []byte("slug-candidate-progress")
	recoveryInvalidName   = []byte("slug-candidate-invalid-children")
)

// RecoveryBranch separates imported/issued highwaters from unissued lookahead.
// DerivedNext counts raw child indexes, including any invalid BIP32 children.
type RecoveryBranch struct {
	Scope        KeyScope
	Branch       uint32
	ImportedNext uint32
	IssuedNext   uint32
	DerivedNext  uint32
	TargetNext   uint32
}

type RecoveryState struct {
	Version      uint32
	Ready        bool
	AddressCount uint32
	Branches     []RecoveryBranch
}

type RecoveryAddress struct {
	Scope    KeyScope
	Branch   uint32
	Index    uint32
	Address  address.Address
	PkScript []byte
}

func recoveryBranchCharge(b RecoveryBranch) uint64 {
	reserve := uint64(b.IssuedNext) + uint64(RecoveryLookahead)
	if reserve > uint64(productionprofile.MaxNextIndex) {
		reserve = uint64(productionprofile.MaxNextIndex)
	}
	if reserve < uint64(b.TargetNext) {
		reserve = uint64(b.TargetNext)
	}
	return reserve
}

func validRecoveryProgress(s RecoveryState) bool {
	if s.Version != 1 || len(s.Branches) != 8 {
		return false
	}
	var target, derived uint64
	for i, b := range s.Branches {
		if b.Scope != (KeyScope{Purpose: []uint32{44, 49, 84, 86}[i/2], Coin: productionprofile.CandidateCoinType}) || b.Branch != uint32(i%2) || b.ImportedNext > b.IssuedNext || b.IssuedNext > b.TargetNext || b.DerivedNext > b.TargetNext || b.TargetNext > productionprofile.MaxNextIndex || (s.Ready && b.DerivedNext != b.TargetNext) {
			return false
		}
		target += recoveryBranchCharge(b)
		derived += uint64(b.DerivedNext)
	}
	return target <= uint64(RecoveryAttemptLimit) && uint64(s.AddressCount) <= derived
}

func encodeRecoveryProgress(s RecoveryState) ([]byte, error) {
	if !validRecoveryProgress(s) {
		return nil, ErrRecoveryState
	}
	b := make([]byte, 12+8*28)
	binary.LittleEndian.PutUint32(b, s.Version)
	if s.Ready {
		binary.LittleEndian.PutUint32(b[4:], 1)
	}
	binary.LittleEndian.PutUint32(b[8:], s.AddressCount)
	for i, x := range s.Branches {
		p := b[12+i*28:]
		for j, v := range []uint32{x.Scope.Purpose, x.Scope.Coin, x.Branch, x.ImportedNext, x.IssuedNext, x.DerivedNext, x.TargetNext} {
			binary.LittleEndian.PutUint32(p[j*4:], v)
		}
	}
	return b, nil
}

func fetchRecoveryProgress(ns walletdb.ReadBucket) (RecoveryState, error) {
	var s RecoveryState
	if ns == nil || ns.NestedReadBucket(mainBucketName) == nil {
		return s, ErrRecoveryState
	}
	b := ns.NestedReadBucket(mainBucketName).Get(recoveryProgressName)
	if len(b) != 12+8*28 || binary.LittleEndian.Uint32(b[4:]) > 1 {
		return s, ErrRecoveryState
	}
	s.Version = binary.LittleEndian.Uint32(b)
	s.Ready = binary.LittleEndian.Uint32(b[4:]) == 1
	s.AddressCount = binary.LittleEndian.Uint32(b[8:])
	s.Branches = make([]RecoveryBranch, 8)
	for i := range s.Branches {
		p := b[12+i*28:]
		v := make([]uint32, 7)
		for j := range v {
			v[j] = binary.LittleEndian.Uint32(p[j*4:])
		}
		s.Branches[i] = RecoveryBranch{KeyScope{Purpose: v[0], Coin: v[1]}, v[2], v[3], v[4], v[5], v[6]}
	}
	if !validRecoveryProgress(s) {
		return RecoveryState{}, ErrRecoveryState
	}
	return s, nil
}

func putRecoveryProgress(ns walletdb.ReadWriteBucket, s RecoveryState) error {
	b, err := encodeRecoveryProgress(s)
	if err != nil {
		return err
	}
	return ns.NestedReadWriteBucket(mainBucketName).Put(recoveryProgressName, b)
}

// CandidateRecoveryPlan validates the entire supported work quota before a
// caller creates any files. It never truncates a manifest cursor.
func CandidateRecoveryPlan(ctx context.Context, m productionprofile.Manifest) (RecoveryState, error) {
	if _, err := productionprofile.ValidateFixtureManifest(ctx, m); err != nil {
		return RecoveryState{}, err
	}
	s := RecoveryState{Version: 1, Branches: make([]RecoveryBranch, 0, 8)}
	for _, a := range m.Accounts {
		for branch, n := range []uint32{a.NextExternal, a.NextInternal} {
			target := uint64(n) + uint64(RecoveryLookahead)
			if target > uint64(productionprofile.MaxNextIndex) {
				target = uint64(productionprofile.MaxNextIndex)
			}
			s.Branches = append(s.Branches, RecoveryBranch{Scope: KeyScope{Purpose: a.Purpose, Coin: a.Coin}, Branch: uint32(branch), ImportedNext: n, IssuedNext: n, TargetNext: uint32(target)})
		}
	}
	if !validRecoveryProgress(s) {
		return RecoveryState{}, ErrRecoveryQuota
	}
	return s, nil
}

func setRecoveryAccountCursors(ns walletdb.ReadWriteBucket, scope KeyScope, external, internal uint32) error {
	row, err := fetchAccountInfo(ns, &scope, DefaultAccountNum)
	if err != nil {
		return ErrRecoveryState
	}
	a, ok := row.(*dbDefaultAccountRow)
	if !ok {
		return ErrRecoveryState
	}
	return putDefaultAccountInfo(ns, &scope, DefaultAccountNum, a.pubKeyEncrypted, a.privKeyEncrypted, external, internal, a.name)
}

// CreateWithResumableCandidateRecovery creates only a compiled public fixture.
// It retains the unchanged v2 recovery payload and no derived address rows.
func CreateWithResumableCandidateRecovery(ctx context.Context, ns walletdb.ReadWriteBucket, root *hdkeychain.ExtendedKey, pubPass, privPass []byte, params *chaincfg.Params, config *ScryptOptions, birthday time.Time, public, private []byte) error {
	if ns == nil || ctx == nil || ctx.Err() != nil || !candidateChain(params) || root == nil || !root.IsPrivate() || len(private) != 68 || len(public) == 0 || len(public) > productionprofile.MaxManifestSize {
		return ErrRecoveryState
	}
	ownedConfig, err := recoveryScryptOptions(config)
	if err != nil {
		return err
	}
	config = &ownedConfig
	public = append([]byte(nil), public...)
	private = append([]byte(nil), private...)
	defer clear(private)
	m, err := productionprofile.ParseManifest(public)
	if err != nil {
		return ErrRecoveryState
	}
	s, err := CandidateRecoveryPlan(ctx, m)
	if err != nil {
		return err
	}
	fixture, err := productionprofile.ValidateFixtureManifest(ctx, m)
	if err != nil {
		return ErrRecoveryState
	}
	entropy, err := productionprofile.FixtureEntropy(fixture)
	if err != nil {
		return ErrRecoveryState
	}
	defer clear(entropy[:])
	digest := sha256.Sum256(public)
	if binary.LittleEndian.Uint32(private) != 2 || !bytes.Equal(private[4:36], entropy[:]) || !bytes.Equal(private[36:], digest[:]) {
		return ErrRecoveryState
	}
	pub, err := root.Neuter()
	if err != nil || pub.String() != m.RootPublicKey {
		return ErrRecoveryState
	}
	if err := createManager(ns, root, pubPass, privPass, params, config, birthday, DerivationStandard, public, private, fixture); err != nil {
		return err
	}
	for _, a := range m.Accounts {
		if err := setRecoveryAccountCursors(ns, KeyScope{Purpose: a.Purpose, Coin: a.Coin}, a.NextExternal, a.NextInternal); err != nil {
			return err
		}
	}
	if err := putManagerVersion(ns, ResumableManagerVersion); err != nil {
		return err
	}
	if _, err := ns.NestedReadWriteBucket(mainBucketName).CreateBucket(recoveryInvalidName); err != nil {
		return err
	}
	if err := putRecoveryProgress(ns, s); err != nil {
		return err
	}
	return ctx.Err()
}

// OpenCandidateRecovery is the exclusive recovery-session entry point. A
// pending manager cannot be unlocked or used to allocate ordinary addresses.
func OpenCandidateRecovery(ns walletdb.ReadBucket, pubPass []byte, params *chaincfg.Params) (*Manager, error) {
	if ns == nil {
		return nil, ErrRecoveryState
	}
	v, err := fetchManagerVersion(ns)
	if err != nil || v != ResumableManagerVersion {
		return nil, ErrRecoveryState
	}
	return loadManagerInternal(ns, pubPass, params, true)
}

func (m *Manager) ResumableRecovery() bool { return m.resumableRecovery }

func (m *Manager) CandidateRecoveryState(ns walletdb.ReadBucket) (RecoveryState, error) {
	if !m.resumableRecovery {
		return RecoveryState{}, ErrRecoveryUnavailable
	}
	return fetchRecoveryProgress(ns)
}

// DeriveRecoveryChunk writes at most128 raw child attempts. The returned
// scripts must be indexed by the caller in this same database transaction.
// Lookahead does not modify account issued-next cursors or private-key caches.
func (m *Manager) DeriveRecoveryChunk(ctx context.Context, ns walletdb.ReadWriteBucket) ([]RecoveryAddress, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return nil, ErrRecoveryUnavailable
	}
	if ctx == nil {
		return nil, ErrRecoveryState
	}
	s, err := m.CandidateRecoveryState(ns)
	if err != nil {
		return nil, err
	}
	if s.Ready {
		return nil, ErrRecoveryProtected
	}
	var out []RecoveryAddress
	var attempts uint32
	for i := range s.Branches {
		b := &s.Branches[i]
		if b.DerivedNext == b.TargetNext {
			continue
		}
		scoped := m.scopedManagers[b.Scope]
		if scoped == nil {
			return nil, ErrRecoveryState
		}
		row, err := fetchAccountInfo(ns, &b.Scope, 0)
		if err != nil {
			return nil, ErrRecoveryState
		}
		a, ok := row.(*dbDefaultAccountRow)
		if !ok {
			return nil, ErrRecoveryState
		}
		keyBytes, err := m.cryptoKeyPub.Decrypt(a.pubKeyEncrypted)
		if err != nil {
			return nil, ErrRecoveryState
		}
		key, err := hdkeychain.NewKeyFromString(string(keyBytes))
		clear(keyBytes)
		if err != nil {
			return nil, ErrRecoveryState
		}
		branch, err := key.Derive(b.Branch)
		key.Zero()
		if err != nil {
			return nil, ErrRecoveryState
		}
		for b.DerivedNext < b.TargetNext && attempts < RecoveryChunkSize {
			if err := ctx.Err(); err != nil {
				branch.Zero()
				return nil, err
			}
			index := b.DerivedNext
			child, err := branch.Derive(index)
			attempts++
			b.DerivedNext++
			if err == hdkeychain.ErrInvalidChild {
				if err := putRecoveryInvalid(ns, b.Scope, b.Branch, index); err != nil {
					branch.Zero()
					return nil, err
				}
				continue
			}
			if err != nil {
				branch.Zero()
				return nil, ErrRecoveryState
			}
			path := DerivationPath{InternalAccount: 0, Account: hdkeychain.HardenedKeyStart, Branch: b.Branch, Index: index}
			ma, err := newManagedAddressFromExtKey(scoped, path, child, scoped.accountAddrType(&accountInfo{}, b.Branch == 1), nil)
			child.Zero()
			if err != nil {
				branch.Zero()
				return nil, err
			}
			addr := ma.Address()
			script, err := txscript.PayToAddrScript(addr)
			if err != nil {
				branch.Zero()
				return nil, err
			}
			if err := putChainedAddress(ns, &b.Scope, addr.ScriptAddress(), 0, ssFull, b.Branch, index, adtChain); err != nil {
				branch.Zero()
				return nil, err
			}
			s.AddressCount++
			out = append(out, RecoveryAddress{Scope: b.Scope, Branch: b.Branch, Index: index, Address: addr, PkScript: script})
		}
		branch.Zero()
		// putChainedAddress normally advances issuance. Restore the separate
		// committed issuance highwaters after recording this lookahead batch.
		base := i - i%2
		if err := setRecoveryAccountCursors(ns, b.Scope, s.Branches[base].IssuedNext, s.Branches[base+1].IssuedNext); err != nil {
			return nil, err
		}
		if attempts == RecoveryChunkSize {
			break
		}
	}
	if err := putRecoveryProgress(ns, s); err != nil {
		return nil, err
	}
	return out, nil
}

func putRecoveryInvalid(ns walletdb.ReadWriteBucket, scope KeyScope, branch, index uint32) error {
	b := ns.NestedReadWriteBucket(mainBucketName).NestedReadWriteBucket(recoveryInvalidName)
	if b == nil {
		return ErrRecoveryState
	}
	key := make([]byte, 16)
	for i, n := range []uint32{scope.Purpose, scope.Coin, branch, index} {
		binary.LittleEndian.PutUint32(key[i*4:], n)
	}
	return b.Put(key, []byte{1})
}

func validateRecoveryInvalid(ns walletdb.ReadBucket, state RecoveryState) error {
	b := ns.NestedReadBucket(mainBucketName).NestedReadBucket(recoveryInvalidName)
	if b == nil {
		return ErrRecoveryState
	}
	var count, derived uint32
	for _, branch := range state.Branches {
		derived += branch.DerivedNext
	}
	err := b.ForEach(func(k, v []byte) error {
		if len(k) != 16 || len(v) != 1 || v[0] != 1 || count >= RecoveryAttemptLimit {
			return ErrRecoveryState
		}
		scope := KeyScope{Purpose: binary.LittleEndian.Uint32(k), Coin: binary.LittleEndian.Uint32(k[4:])}
		branch, index := binary.LittleEndian.Uint32(k[8:]), binary.LittleEndian.Uint32(k[12:])
		for _, x := range state.Branches {
			if x.Scope == scope && x.Branch == branch && index < x.DerivedNext {
				count++
				return nil
			}
		}
		return ErrRecoveryState
	})
	if err != nil {
		return err
	}
	if count+state.AddressCount != derived {
		return ErrRecoveryState
	}
	return nil
}

// recoveryPublicAddress is used only by address-only iteration. Unlike
// keyToManaged it does not enqueue every watched public key for private
// derivation on the next unlock, nor retain a managed-address cache entry.
// The caller holds the scoped manager lock.
func (s *ScopedKeyManager) recoveryPublicAddress(ns walletdb.ReadBucket, row interface{}) (address.Address, error) {
	a, ok := row.(*dbChainAddressRow)
	if !ok || a.account != 0 || a.branch > 1 {
		return nil, ErrRecoveryInventory
	}
	info, err := s.loadAccountInfo(ns, 0)
	if err != nil {
		return nil, err
	}
	branch, err := info.acctKeyPub.Derive(a.branch)
	if err != nil {
		return nil, err
	}
	defer branch.Zero()
	child, err := branch.Derive(a.index)
	if err != nil {
		return nil, err
	}
	defer child.Zero()
	ma, err := newManagedAddressFromExtKey(s, DerivationPath{InternalAccount: 0, Account: hdkeychain.HardenedKeyStart, Branch: a.branch, Index: a.index}, child, s.accountAddrType(info, a.branch == 1), info)
	if err != nil {
		return nil, err
	}
	return ma.Address(), nil
}

// ObserveRecoveryAddress advances issuance for a used lookahead address. Any
// target expansion requires the scanner to derive then replay prior history.
func (m *Manager) ObserveRecoveryAddress(ns walletdb.ReadWriteBucket, scope KeyScope, branch, index uint32) (bool, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return false, ErrRecoveryUnavailable
	}
	s, err := m.CandidateRecoveryState(ns)
	if err != nil {
		return false, err
	}
	for i := range s.Branches {
		b := &s.Branches[i]
		if b.Scope != scope || b.Branch != branch {
			continue
		}
		if index >= b.DerivedNext {
			return false, ErrRecoveryState
		}
		if index < b.IssuedNext {
			return false, nil
		}
		b.IssuedNext = index + 1
		target := uint64(b.IssuedNext) + uint64(RecoveryLookahead)
		if target > uint64(productionprofile.MaxNextIndex) {
			target = uint64(productionprofile.MaxNextIndex)
		}
		expanded := !s.Ready && target > uint64(b.TargetNext)
		if expanded {
			b.TargetNext = uint32(target)
		}
		if !validRecoveryProgress(s) {
			return false, ErrRecoveryQuota
		}
		base := i - i%2
		if err := setRecoveryAccountCursors(ns, scope, s.Branches[base].IssuedNext, s.Branches[base+1].IssuedNext); err != nil {
			return false, err
		}
		if err := putRecoveryProgress(ns, s); err != nil {
			return false, err
		}
		// No account cache is used during derivation. Clear a previously read
		// public account cache only after the transaction commits.
		ns.Tx().OnCommit(func() {
			if sm := m.scopedManagers[scope]; sm != nil {
				sm.mtx.Lock()
				delete(sm.acctInfo, 0)
				sm.mtx.Unlock()
			}
		})
		return expanded, nil
	}
	return false, ErrRecoveryState
}

// SetCandidateRecoveryReady must share the scanner's final canonical checkpoint
// transaction. It does not make a claim about chain state by itself.
func (m *Manager) SetCandidateRecoveryReady(ns walletdb.ReadWriteBucket) error {
	s, err := m.CandidateRecoveryState(ns)
	if err != nil {
		return err
	}
	for _, b := range s.Branches {
		if b.DerivedNext != b.TargetNext {
			return ErrRecoveryInProgress
		}
	}
	s.Ready = true
	if err := putRecoveryProgress(ns, s); err != nil {
		return err
	}
	ns.Tx().OnCommit(func() { m.recoveryPending.Store(false) })
	return nil
}

// recoveryAllocationLimit bounds an ordinary ready-wallet allocation before
// deriving or writing any address. Existing lookahead already consumes quota.
func (m *Manager) recoveryAllocationLimit(ns walletdb.ReadBucket, scope KeyScope, branch uint32) (uint32, error) {
	s, err := m.CandidateRecoveryState(ns)
	if err != nil {
		return 0, err
	}
	if !s.Ready {
		return 0, ErrRecoveryInProgress
	}
	var total uint64
	for _, b := range s.Branches {
		total += recoveryBranchCharge(b)
	}
	for _, b := range s.Branches {
		if b.Scope == scope && b.Branch == branch {
			// Preserve enough quota that every issued highwater can be
			// restored with the same fixed lookahead policy.
			return uint32(recoveryBranchCharge(b) + (uint64(RecoveryAttemptLimit) - total) - uint64(RecoveryLookahead)), nil
		}
	}
	return 0, ErrRecoveryState
}

func (m *Manager) recordRecoveryAllocation(ns walletdb.ReadWriteBucket, scope KeyScope, branch, next, newRows uint32) error {
	s, err := m.CandidateRecoveryState(ns)
	if err != nil {
		return err
	}
	if !s.Ready {
		return ErrRecoveryInProgress
	}
	for i := range s.Branches {
		b := &s.Branches[i]
		if b.Scope != scope || b.Branch != branch {
			continue
		}
		if next < b.IssuedNext {
			return ErrRecoveryState
		}
		b.IssuedNext = next
		if next > b.TargetNext {
			b.TargetNext = next
			b.DerivedNext = next
		}
		s.AddressCount += newRows
		if !validRecoveryProgress(s) {
			return ErrRecoveryQuota
		}
		return putRecoveryProgress(ns, s)
	}
	return ErrRecoveryState
}
