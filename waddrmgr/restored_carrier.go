// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// CarrierSchema is an immutable property of this opened concrete manager.
// It is zero for all earlier modes; it never adopts an on-disk version change.
func (m *Manager) CarrierSchema() uint32 {
	if m == nil {
		return 0
	}
	return m.carrierSchema
}

// HostedAllocation2 distinguishes the explicit fresh schema14 owner from13/15.
func (m *Manager) HostedAllocation2() bool {
	return m != nil && m.carrierSchema == HostedTransferManagerVersion
}

func MarshalRestoredCarrierGuard(g RestoredCarrierGuard) ([]byte, error) {
	if _, e := RestoredCarrierGuardDigest(g); e != nil {
		return nil, e
	}
	return json.Marshal(g)
}
func ParseRestoredCarrierGuard(raw []byte) (RestoredCarrierGuard, error) {
	var g RestoredCarrierGuard
	if carrierGuardDecode(raw, 8192, &g) != nil {
		return g, ErrHostedAllocationCorrupt
	}
	if _, e := RestoredCarrierGuardDigest(g); e != nil {
		return g, ErrHostedAllocationCorrupt
	}
	return g, nil
}
func readRestoredGuard(ns walletdb.ReadBucket) (RestoredCarrierGuard, error) {
	var none RestoredCarrierGuard
	if ns == nil {
		return none, ErrHostedAllocationCorrupt
	}
	v, e := fetchManagerVersion(ns)
	if e != nil || v != RestoredCarrierManagerVersion {
		return none, ErrHostedAllocationProfile
	}
	main := ns.NestedReadBucket(mainBucketName)
	if main == nil || recoveryNamePresent(main, hostedAllocationGuardKey) || recoveryNamePresent(main, hostedAllocationGuardKey2) {
		return none, ErrHostedAllocationCorrupt
	}
	return ParseRestoredCarrierGuard(main.Get(restoredCarrierGuardKey))
}
func sameRestoredGuard(a, b RestoredCarrierGuard) bool {
	x, e := MarshalRestoredCarrierGuard(a)
	if e != nil {
		return false
	}
	y, e := MarshalRestoredCarrierGuard(b)
	return e == nil && bytes.Equal(x, y)
}

// RestoredCarrierActivationSnapshot is read from a fully audited ready12
// manager. The caller must also audit the wallet scanner/ledger in this same
// transaction and close this manager before opening the activated schema15.
func (m *Manager) RestoredCarrierActivationSnapshot(ctx context.Context, ns walletdb.ReadBucket, original recovery.Manifest, owner, journal, pin string) (RestoredCarrierGuard, error) {
	var none RestoredCarrierGuard
	if ctx == nil || ns == nil || m == nil || m.carrierSchema != 0 || m.hostedAllocation || !m.resumableRecovery || m.recoveryVersion != 1 || wire.TestPoW {
		return none, ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	v, e := fetchManagerVersion(ns)
	if e != nil || v != PhaseAManagerVersion {
		return none, ErrHostedAllocationProfile
	}
	main := ns.NestedReadBucket(mainBucketName)
	if main == nil || recoveryNamePresent(main, hostedAllocationGuardKey) || recoveryNamePresent(main, hostedAllocationGuardKey2) || recoveryNamePresent(main, restoredCarrierGuardKey) {
		return none, ErrHostedAllocationCorrupt
	}
	progress, e := m.CandidateRecoveryState(ns)
	if e != nil || !progress.Ready {
		return none, ErrRecoveryInProgress
	}
	public, e := m.RecoveryData(ns, false)
	if e != nil {
		return none, e
	}
	defer clear(public)
	expected, e := recovery.MarshalManifest(original)
	if e != nil || !bytes.Equal(expected, public) {
		return none, ErrHostedAllocationConflict
	}
	entropy, e := phaseAEntropy(original)
	clear(entropy[:])
	if e != nil {
		return none, ErrHostedAllocationProfile
	}
	accounts, e := recoveryAccounts(ns, true)
	if e != nil || len(accounts) != 4 {
		return none, ErrHostedAllocationCorrupt
	}
	if ns.NestedReadBucket(syncBucketName) == nil {
		return none, ErrHostedAllocationCorrupt
	}
	tip, e := fetchSyncedTo(ns)
	if e != nil {
		return none, e
	}
	g := RestoredCarrierGuard{Version: 1, State: "ready", ManagerSchema: 15, WalletOwnerID: owner, CarrierJournalID: journal, OwnershipPinID: pin, OriginalManifestSHA256: hostedHash("", expected), OriginalManifest: original, ActivationTipHash: tip.Hash.String(), ActivationTipHeight: tip.Height}
	for i, a := range accounts {
		g.ActivationCursors[2*i] = a.NextExternal
		g.ActivationCursors[2*i+1] = a.NextInternal
	}
	if _, e = RestoredCarrierGuardDigest(g); e != nil {
		return none, e
	}
	// Return owned public memory, independent of the caller's original slice.
	g.OriginalManifest.Accounts = append([]recovery.Account(nil), original.Accounts...)
	return g, ctx.Err()
}

// ActivateRestoredCarrier changes only the manager version and its new guard.
// The wallet caller atomically establishes the empty purpose/carrier namespaces
// in this transaction; no cached old manager is reused after its commit.
func (m *Manager) ActivateRestoredCarrier(ctx context.Context, ns walletdb.ReadWriteBucket, expected RestoredCarrierGuard) error {
	g, e := m.RestoredCarrierActivationSnapshot(ctx, ns, expected.OriginalManifest, expected.WalletOwnerID, expected.CarrierJournalID, expected.OwnershipPinID)
	if e != nil {
		return e
	}
	if !sameRestoredGuard(g, expected) {
		return ErrHostedAllocationConflict
	}
	raw, e := MarshalRestoredCarrierGuard(g)
	if e != nil {
		return e
	}
	if e = ns.NestedReadWriteBucket(mainBucketName).Put(restoredCarrierGuardKey, raw); e != nil {
		return e
	}
	if e = putManagerVersion(ns, RestoredCarrierManagerVersion); e != nil {
		return e
	}
	return ctx.Err()
}

func OpenRestoredCarrier(ctx context.Context, ns walletdb.ReadBucket, pubPass []byte, params *chaincfg.Params, expected RestoredCarrierGuard) (*Manager, error) {
	if ctx == nil {
		return nil, ErrHostedAllocationInvalid
	}
	if wire.TestPoW || !candidateChain(params) {
		return nil, ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	g, e := readRestoredGuard(ns)
	if e != nil {
		return nil, e
	}
	if !sameRestoredGuard(g, expected) {
		return nil, ErrHostedAllocationConflict
	}
	m, e := loadManagerAllowedProfile(ns, pubPass, params, false, RestoredCarrierManagerVersion)
	if e != nil {
		return nil, e
	}
	if _, e = m.AuditRestoredCarrier(ctx, ns); e != nil {
		m.Close()
		return nil, e
	}
	return m, nil
}

// AuditRestoredCarrier checks immutable import/activation identity and the
// complete current address-manager inventory. The wallet additionally checks
// the retained scanner and the carrier/exclusion bidirectional links.
func (m *Manager) AuditRestoredCarrier(ctx context.Context, ns walletdb.ReadBucket) (RestoredCarrierGuard, error) {
	var none RestoredCarrierGuard
	if ctx == nil || m == nil || m.carrierSchema != 15 || !m.hostedAllocation {
		return none, ErrHostedAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	g, e := readRestoredGuard(ns)
	if e != nil {
		return none, e
	}
	public, e := m.RecoveryData(ns, false)
	if e != nil {
		return none, e
	}
	defer clear(public)
	expected, e := recovery.MarshalManifest(g.OriginalManifest)
	if e != nil || !bytes.Equal(expected, public) {
		return none, ErrHostedAllocationCorrupt
	}
	accounts, e := recoveryAccounts(ns, true)
	if e != nil || len(accounts) != 4 {
		return none, ErrHostedAllocationCorrupt
	}
	for i, a := range accounts {
		if a.NextExternal < g.ActivationCursors[2*i] || a.NextInternal < g.ActivationCursors[2*i+1] {
			return none, ErrHostedAllocationCorrupt
		}
	}
	return g, ctx.Err()
}

type RestoredCarrierPlan struct {
	manager   *Manager
	guard     RestoredCarrierGuard
	before    [8]uint32
	candidate HostedAllocationRange
}

func (m *Manager) PlanRestoredCarrier(ctx context.Context, ns walletdb.ReadBucket) (*RestoredCarrierPlan, HostedAllocationRange, [8]uint32, error) {
	var none HostedAllocationRange
	var cursors [8]uint32
	g, e := m.AuditRestoredCarrier(ctx, ns)
	if e != nil {
		return nil, none, cursors, e
	}
	a, e := recoveryAccounts(ns, true)
	if e != nil {
		return nil, none, cursors, e
	}
	for i, x := range a {
		cursors[2*i] = x.NextExternal
		cursors[2*i+1] = x.NextInternal
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return nil, none, cursors, ErrHostedAllocationProfile
	}
	r, e := m.hostedRange(ctx, ns, 84, 1, cursors[5])
	if e != nil {
		return nil, none, cursors, e
	}
	p := &RestoredCarrierPlan{m, g, cursors, r}
	r.InvalidIndices = append([]uint32{}, r.InvalidIndices...)
	return p, r, cursors, nil
}
func (m *Manager) ConsumeRestoredCarrier(ctx context.Context, ns walletdb.ReadWriteBucket, p *RestoredCarrierPlan) error {
	if p == nil || p.manager != m {
		return ErrHostedAllocationInvalid
	}
	g, e := m.AuditRestoredCarrier(ctx, ns)
	if e != nil {
		return e
	}
	if !sameRestoredGuard(g, p.guard) {
		return ErrHostedAllocationConflict
	}
	a, e := recoveryAccounts(ns, true)
	if e != nil {
		return e
	}
	for i, x := range a {
		if p.before[2*i] != x.NextExternal || p.before[2*i+1] != x.NextInternal {
			return ErrHostedAllocationConflict
		}
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if m.closed {
		return ErrHostedAllocationProfile
	}
	r, e := m.hostedRange(ctx, ns, 84, 1, p.before[5])
	if e != nil {
		return e
	}
	if !rangeMatches(HostedAllocationRecord{Purpose: p.candidate.Purpose, Branch: p.candidate.Branch, StartIndex: p.candidate.StartIndex, EndIndex: p.candidate.EndIndex, SelectedIndex: p.candidate.SelectedIndex, InvalidIndices: p.candidate.InvalidIndices, Address: p.candidate.Address, Script: p.candidate.Script}, r) {
		return ErrHostedAllocationConflict
	}
	s, e := fetchRecoveryProgress(ns)
	if e != nil {
		return e
	}
	b := s.Branches[5]
	// Existing Phase-A lookahead rows remain separate from issuance. Only new
	// indices beyond that already-derived prefix add to its row accounting.
	for _, i := range r.InvalidIndices {
		if i >= b.DerivedNext {
			if e = putRecoveryInvalid(ns, KeyScopeBIP0084, 1, i); e != nil {
				return e
			}
		}
	}
	script, _ := hex.DecodeString(r.Script)
	if e = putChainedAddress(ns, &KeyScopeBIP0084, script[2:], 0, ssFull, 1, r.SelectedIndex, adtChain); e != nil {
		return e
	}
	var rows uint32
	if r.SelectedIndex >= b.DerivedNext {
		rows = 1
	}
	if e = m.recordRecoveryAllocation(ns, KeyScopeBIP0084, 1, r.EndIndex, rows); e != nil {
		return e
	}
	sm := m.scopedManagers[KeyScopeBIP0084]
	ns.Tx().OnCommit(func() { sm.mtx.Lock(); delete(sm.acctInfo, 0); delete(sm.addrs, addrKey(script[2:])); sm.mtx.Unlock() })
	return ctx.Err()
}

func (m *Manager) ReadRestoredCarrierManifest(ctx context.Context, ns walletdb.ReadBucket) (recovery.Manifest, error) {
	if _, e := m.AuditRestoredCarrier(ctx, ns); e != nil {
		return recovery.Manifest{}, e
	}
	return m.readCurrentRecoveryManifestSchema(ctx, ns, RestoredCarrierManagerVersion)
}
