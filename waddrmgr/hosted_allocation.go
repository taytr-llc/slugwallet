// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

const HostedAllocationNamespace = "slug-hosted-allocation-v1"

func (m *Manager) HostedAllocation() bool { return m != nil && m.hostedAllocation }

func CreateWithHostedAllocation(ctx context.Context, ns, local walletdb.ReadWriteBucket, root *hdkeychain.ExtendedKey, pubPass, privPass []byte, params *chaincfg.Params, config *ScryptOptions, birthday time.Time, public, private []byte, locked HostedAllocationGuard) error {
	if ctx == nil || ns == nil || local == nil || !validHostedGuard(locked) || locked.State != "locked" {
		return ErrHostedAllocationInvalid
	}
	if wire.TestPoW || !candidateChain(params) {
		return ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if k, _ := local.ReadCursor().First(); k != nil {
		return ErrHostedAllocationConflict
	}
	opts, e := recoveryScryptOptions(config)
	if e != nil {
		return e
	}
	manifest, e := recovery.ParseManifest(public)
	if e != nil {
		return ErrHostedAllocationInvalid
	}
	canon, e := recovery.MarshalManifest(manifest)
	if e != nil || !bytes.Equal(canon, public) || hostedHash("", public) != locked.InitialManifestSHA256 {
		return ErrHostedAllocationInvalid
	}
	for _, a := range manifest.Accounts {
		if a.NextExternal != 0 || a.NextInternal != 0 {
			return ErrHostedAllocationInvalid
		}
	}
	entropy, e := phaseAEntropy(manifest)
	defer clear(entropy[:])
	if e != nil {
		return ErrHostedAllocationProfile
	}
	digest := sha256.Sum256(public)
	if root == nil || !root.IsPrivate() || len(private) != 68 || binary.LittleEndian.Uint32(private) != 1 || !bytes.Equal(private[4:36], entropy[:]) || !bytes.Equal(private[36:], digest[:]) {
		return ErrHostedAllocationInvalid
	}
	neuter, e := root.Neuter()
	if e != nil || neuter.String() != manifest.RootPublicKey {
		return ErrHostedAllocationInvalid
	}
	if e = createManager(ns, root, pubPass, privPass, params, &opts, birthday, DerivationStandard, public, private); e != nil {
		return e
	}
	if e = putManagerVersion(ns, HostedAllocationManagerVersion); e != nil {
		return e
	}
	raw, _ := json.Marshal(locked)
	if e = ns.NestedReadWriteBucket(mainBucketName).Put(hostedAllocationGuardKey, raw); e != nil {
		return e
	}
	if _, e = local.CreateBucket(hostedAllocationRecordsKey); e != nil {
		return e
	}
	hash, _ := HostedAllocationGuardDigest(locked)
	raw, _ = json.Marshal(HostedAllocationMeta{Version: 1, GuardSHA256: hash})
	if e = local.Put(hostedAllocationMetaKey, raw); e != nil {
		return e
	}
	return ctx.Err()
}

func OpenHostedAllocation(ctx context.Context, ns, local walletdb.ReadBucket, pubPass []byte, params *chaincfg.Params, expected HostedAllocationGuard) (*Manager, error) {
	if ctx == nil || !validHostedGuard(expected) {
		return nil, ErrHostedAllocationInvalid
	}
	if wire.TestPoW || !candidateChain(params) {
		return nil, ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	state, e := readHostedState(ctx, ns, local)
	if e != nil {
		return nil, e
	}
	if state.Guard != expected {
		return nil, ErrHostedAllocationConflict
	}
	if e = validateRecoveryKeyFields(ns); e != nil {
		return nil, e
	}
	m, e := loadManagerProfile(ns, pubPass, params, false, true)
	if e != nil {
		return nil, e
	}
	if _, e = m.AuditHostedAllocation(ctx, ns, local); e != nil {
		m.Close()
		return nil, e
	}
	return m, nil
}

func readHostedState(ctx context.Context, ns, local walletdb.ReadBucket) (HostedAllocationState, error) {
	var out HostedAllocationState
	if ctx == nil || ns == nil || local == nil {
		return out, ErrHostedAllocationCorrupt
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	v, e := fetchManagerVersion(ns)
	if e != nil || v != HostedAllocationManagerVersion {
		return out, ErrHostedAllocationProfile
	}
	main := ns.NestedReadBucket(mainBucketName)
	if main == nil {
		return out, ErrHostedAllocationCorrupt
	}
	raw := main.Get(hostedAllocationGuardKey)
	if hostedDecode(raw, 2048, &out.Guard) != nil || !validHostedGuard(out.Guard) {
		return out, ErrHostedAllocationCorrupt
	}
	out.LogicalBytes = uint64(len(HostedAllocationNamespace) + len(hostedAllocationGuardKey) + len(raw))
	count := 0
	e = local.ForEach(func(k, v []byte) error {
		count++
		if count > 2 {
			return ErrHostedAllocationCorrupt
		}
		out.LogicalBytes += uint64(len(k) + len(v))
		if string(k) == "meta" && v != nil {
			return nil
		}
		if string(k) == "records" && v == nil {
			return nil
		}
		return ErrHostedAllocationCorrupt
	})
	if e != nil || count != 2 {
		return out, ErrHostedAllocationCorrupt
	}
	if hostedDecode(local.Get(hostedAllocationMetaKey), 2048, &out.Meta) != nil || out.Meta.Version != 1 || out.Meta.CompletedSequence > 1024 {
		return out, ErrHostedAllocationCorrupt
	}
	hash, _ := HostedAllocationGuardDigest(out.Guard)
	if out.Meta.GuardSHA256 != hash {
		return out, ErrHostedAllocationCorrupt
	}
	records := local.NestedReadBucket(hostedAllocationRecordsKey)
	if records == nil {
		return out, ErrHostedAllocationCorrupt
	}
	ids := make(map[string]bool)
	consumers := make(map[string]bool)
	var cursors [8]uint32
	e = records.ForEach(func(k, raw []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if len(out.Records) >= 1024 || len(k) != 4 || raw == nil || len(raw) > 4096 {
			return ErrHostedAllocationCorrupt
		}
		out.LogicalBytes += uint64(len(k) + len(raw))
		if out.LogicalBytes > HostedAllocationMaxBytes {
			return ErrHostedAllocationCapacity
		}
		var r HostedAllocationRecord
		if hostedDecode(raw, 4096, &r) != nil || !validHostedRecord(r) || r.Sequence != uint32(len(out.Records))+1 || binary.BigEndian.Uint32(k) != r.Sequence || r.InventoryID != out.Guard.InventoryID || r.BindingID != out.Guard.BindingID || r.CursorsBefore != cursors || ids[r.AllocationID] {
			return ErrHostedAllocationCorrupt
		}
		ids[r.AllocationID] = true
		if r.WithdrawalOperationID != "" {
			if consumers[r.WithdrawalOperationID] {
				return ErrHostedAllocationCorrupt
			}
			consumers[r.WithdrawalOperationID] = true
		}
		cursors = r.CursorsAfter
		out.Records = append(out.Records, r)
		return nil
	})
	if e != nil {
		return out, e
	}
	if out.LogicalBytes > HostedAllocationMaxBytes || uint32(len(out.Records)) != out.Meta.CompletedSequence || cursors != out.Meta.Cursors || out.Guard.State == "locked" && out.Meta.CompletedSequence != 0 {
		return out, ErrHostedAllocationCorrupt
	}
	return out, nil
}

// publicHostedState checks only public framing/cursors; no private retention or
// account private span is copied, and no key derivation is performed here.
func (m *Manager) publicHostedState(ctx context.Context, ns, local walletdb.ReadBucket) (HostedAllocationState, recovery.Manifest, error) {
	var none recovery.Manifest
	if !m.HostedAllocation() {
		return HostedAllocationState{}, none, ErrHostedAllocationProfile
	}
	state, e := readHostedState(ctx, ns, local)
	if e != nil {
		return state, none, e
	}
	manifest, e := m.readCurrentRecoveryManifestSchema(ctx, ns, HostedAllocationManagerVersion)
	if e != nil {
		return state, none, e
	}
	if gymaccount.ValidateFixtureIdentity(manifest.RootPublicKey, manifest.GymPublicKey, manifest.GymID) != nil {
		return state, none, ErrHostedAllocationProfile
	}
	initial := manifest
	initial.Accounts = append([]recovery.Account(nil), manifest.Accounts...)
	for i := range initial.Accounts {
		if manifest.Accounts[i].NextExternal != state.Meta.Cursors[2*i] || manifest.Accounts[i].NextInternal != state.Meta.Cursors[2*i+1] {
			return state, none, ErrHostedAllocationCorrupt
		}
		initial.Accounts[i].NextExternal = 0
		initial.Accounts[i].NextInternal = 0
	}
	raw, e := recovery.MarshalManifest(initial)
	if e != nil || hostedHash("", raw) != state.Guard.InitialManifestSHA256 {
		return state, none, ErrHostedAllocationCorrupt
	}
	return state, manifest, nil
}
func (m *Manager) ReadHostedAllocationManifest(ctx context.Context, ns, local walletdb.ReadBucket) (recovery.Manifest, error) {
	_, manifest, e := m.publicHostedState(ctx, ns, local)
	return manifest, e
}
func (m *Manager) ReadHostedAllocationActivityState(ctx context.Context, ns, local walletdb.ReadBucket) (OwnActivityState, error) {
	var out OwnActivityState
	_, manifest, e := m.publicHostedState(ctx, ns, local)
	if e != nil {
		return out, e
	}
	sync := ns.NestedReadBucket(syncBucketName)
	if sync == nil {
		return out, ErrHostedAllocationCorrupt
	}
	raw := sync.Get(syncedToName)
	if len(raw) != 36 && len(raw) != 40 {
		return out, ErrHostedAllocationCorrupt
	}
	height := binary.LittleEndian.Uint32(raw[:4])
	var hash chainhash.Hash
	copy(hash[:], raw[4:36])
	if height > 0x7fffffff || hash == (chainhash.Hash{}) {
		return out, ErrHostedAllocationCorrupt
	}
	return OwnActivityState{RootPublicKey: manifest.RootPublicKey, GymPublicKey: manifest.GymPublicKey, GymID: manifest.GymID, SyncedHeight: height, SyncedHash: hash}, ctx.Err()
}

// Caller holds m.mtx; this reads/copies only the account public ciphertext.
func (m *Manager) hostedRange(ctx context.Context, ns walletdb.ReadBucket, purpose, branch, start uint32) (HostedAllocationRange, error) {
	out := HostedAllocationRange{Purpose: purpose, Branch: branch, StartIndex: start, InvalidIndices: []uint32{}}
	if purpose != 84 || branch > 1 || start >= 4096 {
		return out, ErrHostedAllocationCapacity
	}
	scope := KeyScope{Purpose: purpose, Coin: 0}
	scoped, e := fetchReadScopeBucket(ns, &scope)
	if e != nil {
		return out, e
	}
	accounts := scoped.NestedReadBucket(acctBucketName)
	if accounts == nil {
		return out, ErrHostedAllocationCorrupt
	}
	raw := accounts.Get(uint32ToBytes(0))
	if _, _, e = currentAccountCursors(raw, 0); e != nil {
		return out, ErrHostedAllocationCorrupt
	}
	n := int(binary.LittleEndian.Uint32(raw[5:9]))
	plain, e := m.cryptoKeyPub.Decrypt(raw[9 : 9+n])
	if e != nil {
		return out, ErrHostedAllocationCorrupt
	}
	key, e := hdkeychain.NewKeyFromString(string(plain))
	clear(plain)
	if e != nil {
		return out, ErrHostedAllocationCorrupt
	}
	defer key.Zero()
	bk, e := key.Derive(branch)
	if e != nil {
		return out, ErrHostedAllocationCorrupt
	}
	defer bk.Zero()
	for index := start; index < 4096 && index-start < 128; index++ {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		child, e := bk.Derive(index)
		if e == hdkeychain.ErrInvalidChild {
			out.InvalidIndices = append(out.InvalidIndices, index)
			continue
		}
		if e != nil {
			return out, ErrHostedAllocationCorrupt
		}
		sm := m.scopedManagers[scope]
		if sm == nil {
			child.Zero()
			return out, ErrHostedAllocationCorrupt
		}
		ma, e := newManagedAddressFromExtKey(sm, DerivationPath{InternalAccount: 0, Account: hdkeychain.HardenedKeyStart, Branch: branch, Index: index}, child, WitnessPubKey, nil)
		child.Zero()
		if e != nil {
			return out, e
		}
		script, e := txscript.PayToAddrScript(ma.Address())
		if e != nil || len(script) != 22 {
			return out, ErrHostedAllocationCorrupt
		}
		out.SelectedIndex = index
		out.EndIndex = index + 1
		out.Address = ma.Address().EncodeAddress()
		out.Script = hex.EncodeToString(script)
		return out, nil
	}
	return out, ErrHostedAllocationCapacity
}

func rangeMatches(r HostedAllocationRecord, p HostedAllocationRange) bool {
	return r.Purpose == p.Purpose && r.Branch == p.Branch && r.StartIndex == p.StartIndex && r.EndIndex == p.EndIndex && r.SelectedIndex == p.SelectedIndex && r.Address == p.Address && r.Script == p.Script && len(r.InvalidIndices) == len(p.InvalidIndices)
}

func (m *Manager) AuditHostedAllocation(ctx context.Context, ns, local walletdb.ReadBucket) (HostedAllocationState, error) {
	state, _, e := m.publicHostedState(ctx, ns, local)
	if e != nil {
		return state, e
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return state, ErrHostedAllocationProfile
	}
	expected := make(map[string]HostedAllocationRecord, len(state.Records))
	for _, r := range state.Records {
		p, e := m.hostedRange(ctx, ns, r.Purpose, r.Branch, r.StartIndex)
		if e != nil {
			return state, e
		}
		if !rangeMatches(r, p) {
			return state, ErrHostedAllocationCorrupt
		}
		script, _ := hex.DecodeString(r.Script)
		h := sha256.Sum256(script[2:])
		expected[string(h[:])] = r
	}
	var count uint32
	for _, scope := range []KeyScope{{44, 0}, {49, 0}, {84, 0}, {86, 0}} {
		sb, e := fetchReadScopeBucket(ns, &scope)
		if e != nil {
			return state, e
		}
		b := sb.NestedReadBucket(addrBucketName)
		idx := sb.NestedReadBucket(addrAcctIdxBucketName)
		if b == nil || idx == nil {
			return state, ErrHostedAllocationCorrupt
		}
		e = b.ForEach(func(k, v []byte) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			count++
			if count > 1024 || len(k) != 32 || len(v) != 26 || v[0] != byte(adtChain) || binary.LittleEndian.Uint32(v[1:5]) != 0 || binary.LittleEndian.Uint32(v[14:18]) != 8 {
				return ErrHostedAllocationCorrupt
			}
			r, ok := expected[string(k)]
			if !ok || scope.Purpose != r.Purpose || binary.LittleEndian.Uint32(v[18:22]) != r.Branch || binary.LittleEndian.Uint32(v[22:26]) != r.SelectedIndex {
				return ErrHostedAllocationCorrupt
			}
			account := idx.Get(k)
			sub := idx.NestedReadBucket(uint32ToBytes(0))
			if len(account) != 4 || binary.LittleEndian.Uint32(account) != 0 || sub == nil || sub.Get(k) == nil {
				return ErrHostedAllocationCorrupt
			}
			return nil
		})
		if e != nil {
			return state, e
		}
		// Reject dangling, extra, or malformed index entries in either direction.
		var indexed uint32
		e = idx.ForEach(func(k, v []byte) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if len(k) == 4 && v == nil {
				if binary.LittleEndian.Uint32(k) != 0 && binary.LittleEndian.Uint32(k) != ImportedAddrAccount {
					return ErrHostedAllocationCorrupt
				}
				sub := idx.NestedReadBucket(k)
				return sub.ForEach(func(ak, av []byte) error {
					indexed++
					if indexed > 1024 || len(ak) != 32 || av == nil || b.Get(ak) == nil || !bytes.Equal(idx.Get(ak), k) {
						return ErrHostedAllocationCorrupt
					}
					return nil
				})
			}
			if len(k) != 32 || len(v) != 4 || binary.LittleEndian.Uint32(v) != 0 || b.Get(k) == nil {
				return ErrHostedAllocationCorrupt
			}
			return nil
		})
		if e != nil {
			return state, e
		}
	}
	if int(count) != len(expected) {
		return state, ErrHostedAllocationCorrupt
	}
	return state, ctx.Err()
}

func (m *Manager) BindHostedAllocation(ctx context.Context, ns, local walletdb.ReadWriteBucket, locked HostedAllocationGuard, bindingID string) error {
	if !validHostedGuard(locked) || locked.State != "locked" || !hostedHex(bindingID, false) {
		return ErrHostedAllocationInvalid
	}
	state, e := m.AuditHostedAllocation(ctx, ns, local)
	if e != nil {
		return e
	}
	bound := locked
	bound.State = "bound"
	bound.BindingID = bindingID
	if state.Guard == bound {
		return nil
	}
	if state.Guard != locked || state.Meta.CompletedSequence != 0 {
		return ErrHostedAllocationConflict
	}
	raw, _ := json.Marshal(bound)
	if e = ns.NestedReadWriteBucket(mainBucketName).Put(hostedAllocationGuardKey, raw); e != nil {
		return e
	}
	state.Meta.GuardSHA256, _ = HostedAllocationGuardDigest(bound)
	raw, _ = json.Marshal(state.Meta)
	return local.Put(hostedAllocationMetaKey, raw)
}
func (m *Manager) PlanHostedAllocation(ctx context.Context, ns, local walletdb.ReadBucket, purpose, branch uint32) (*HostedAllocationPlan, HostedAllocationRange, error) {
	var none HostedAllocationRange
	state, e := m.AuditHostedAllocation(ctx, ns, local)
	if e != nil {
		return nil, none, e
	}
	if state.Guard.State != "bound" {
		return nil, none, ErrHostedAllocationConflict
	}
	if purpose != 84 || branch > 1 {
		return nil, none, ErrHostedAllocationInvalid
	}
	if state.Meta.CompletedSequence >= 1024 {
		return nil, none, ErrHostedAllocationCapacity
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return nil, none, ErrHostedAllocationProfile
	}
	p, e := m.hostedRange(ctx, ns, purpose, branch, state.Meta.Cursors[4+branch])
	if e != nil {
		return nil, none, e
	}
	plan := &HostedAllocationPlan{manager: m, guard: state.Guard, sequence: state.Meta.CompletedSequence, before: state.Meta.Cursors, candidate: p}
	p.InvalidIndices = append([]uint32{}, p.InvalidIndices...)
	return plan, p, nil
}
func (m *Manager) ConsumeHostedAllocation(ctx context.Context, ns, local walletdb.ReadWriteBucket, p *HostedAllocationPlan, r HostedAllocationRecord) error {
	return m.applyHostedAllocation(ctx, ns, local, p, r, "consumed")
}
func (m *Manager) BurnHostedAllocation(ctx context.Context, ns, local walletdb.ReadWriteBucket, p *HostedAllocationPlan, r HostedAllocationRecord) error {
	return m.applyHostedAllocation(ctx, ns, local, p, r, "burned")
}
func (m *Manager) applyHostedAllocation(ctx context.Context, ns, local walletdb.ReadWriteBucket, p *HostedAllocationPlan, r HostedAllocationRecord, outcome string) error {
	if p == nil || p.manager != m || !validHostedRecord(r) || r.Outcome != outcome || !rangeMatches(r, p.candidate) {
		return ErrHostedAllocationInvalid
	}
	state, e := m.AuditHostedAllocation(ctx, ns, local)
	if e != nil {
		return e
	}
	if state.Guard != p.guard || state.Meta.CompletedSequence != p.sequence || state.Meta.Cursors != p.before || r.Sequence != p.sequence+1 || r.CursorsBefore != p.before || r.InventoryID != p.guard.InventoryID || r.BindingID != p.guard.BindingID {
		return ErrHostedAllocationConflict
	}
	for _, old := range state.Records {
		if old.AllocationID == r.AllocationID || r.WithdrawalOperationID != "" && old.WithdrawalOperationID == r.WithdrawalOperationID {
			return ErrHostedAllocationConflict
		}
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 4096 || state.LogicalBytes+uint64(len(raw))+4+64 > HostedAllocationMaxBytes {
		return ErrHostedAllocationCapacity
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return ErrHostedAllocationProfile
	}
	fresh, e := m.hostedRange(ctx, ns, r.Purpose, r.Branch, r.StartIndex)
	if e != nil {
		return e
	}
	if !rangeMatches(r, fresh) {
		return ErrHostedAllocationConflict
	}
	script, _ := hex.DecodeString(r.Script)
	scope := KeyScope{Purpose: 84, Coin: 0}
	if e = putChainedAddress(ns, &scope, script[2:], 0, ssFull, r.Branch, r.SelectedIndex, adtChain); e != nil {
		return e
	}
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], r.Sequence)
	if e = local.NestedReadWriteBucket(hostedAllocationRecordsKey).Put(key[:], raw); e != nil {
		return e
	}
	state.Meta.CompletedSequence = r.Sequence
	state.Meta.Cursors = r.CursorsAfter
	raw, _ = json.Marshal(state.Meta)
	if e = local.Put(hostedAllocationMetaKey, raw); e != nil {
		return e
	}
	sm := m.scopedManagers[scope]
	ns.Tx().OnCommit(func() { sm.mtx.Lock(); delete(sm.acctInfo, 0); delete(sm.addrs, addrKey(script[2:])); sm.mtx.Unlock() })
	return ctx.Err()
}
