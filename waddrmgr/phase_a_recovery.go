// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

const PhaseAManagerVersion uint32 = 12
const PhaseARecoveryAttemptLimit uint32 = 8 * recovery.MaxBranchIndex

var phaseAProgressName = []byte("slug-phase-a-progress-v1")
var phaseAInvalidName = []byte("slug-phase-a-invalid-children-v1")

type recoveryPolicy struct {
	schema, coin, indexLimit, attemptLimit uint32
	progress, invalid                      []byte
}

func candidateRecoveryPolicy() recoveryPolicy {
	return recoveryPolicy{ResumableManagerVersion, productionprofile.CandidateCoinType, productionprofile.MaxNextIndex, RecoveryAttemptLimit, recoveryProgressName, recoveryInvalidName}
}
func phaseARecoveryPolicy() recoveryPolicy {
	return recoveryPolicy{PhaseAManagerVersion, 0, recovery.MaxBranchIndex, PhaseARecoveryAttemptLimit, phaseAProgressName, phaseAInvalidName}
}
func recoveryPolicyFor(ns walletdb.ReadBucket) (recoveryPolicy, error) {
	v, e := fetchManagerVersion(ns)
	if e != nil {
		return recoveryPolicy{}, e
	}
	switch v {
	case ResumableManagerVersion:
		return candidateRecoveryPolicy(), nil
	case PhaseAManagerVersion:
		return phaseARecoveryPolicy(), nil
	}
	return recoveryPolicy{}, ErrRecoveryState
}
func (m *Manager) recoveryPolicy() recoveryPolicy {
	if m.recoveryVersion == 1 {
		return phaseARecoveryPolicy()
	}
	return candidateRecoveryPolicy()
}

// RecoveryInventoryLimit reports the immutable resumable profile's raw inventory bound.
func (m *Manager) RecoveryInventoryLimit() uint32 {
	if !m.resumableRecovery {
		return 0
	}
	return m.recoveryPolicy().attemptLimit
}

// RecoveryIndexLimit reports the immutable resumable profile's next-index ceiling.
func (m *Manager) RecoveryIndexLimit() uint32 {
	if !m.resumableRecovery {
		return 0
	}
	return m.recoveryPolicy().indexLimit
}

func phaseAEntropy(m recovery.Manifest) ([32]byte, error) {
	var entropy [32]byte
	if recovery.ValidateManifest(m) != nil {
		return entropy, ErrRecoveryState
	}
	if recovery.ValidateEntropyManifest(entropy, m) == nil {
		return entropy, nil
	}
	for i := range entropy {
		entropy[i] = byte(i)
	}
	if recovery.ValidateEntropyManifest(entropy, m) == nil {
		return entropy, nil
	}
	clear(entropy[:])
	return entropy, ErrRecoveryState
}

// PhaseARecoveryPlan accepts only the two published unchanged version-1 fixtures.
func PhaseARecoveryPlan(ctx context.Context, m recovery.Manifest) (RecoveryState, error) {
	if ctx == nil {
		return RecoveryState{}, ErrRecoveryState
	}
	if e := ctx.Err(); e != nil {
		return RecoveryState{}, e
	}
	entropy, e := phaseAEntropy(m)
	clear(entropy[:])
	if e != nil {
		return RecoveryState{}, e
	}
	p := phaseARecoveryPolicy()
	s := RecoveryState{Version: 1, Branches: make([]RecoveryBranch, 0, 8)}
	for _, a := range m.Accounts {
		for branch, n := range []uint32{a.NextExternal, a.NextInternal} {
			target := n + RecoveryLookahead
			if target > p.indexLimit {
				target = p.indexLimit
			}
			s.Branches = append(s.Branches, RecoveryBranch{Scope: KeyScope{Purpose: a.Purpose, Coin: a.Coin}, Branch: uint32(branch), ImportedNext: n, IssuedNext: n, TargetNext: target})
		}
	}
	if !validRecoveryProgressFor(s, p) {
		return RecoveryState{}, ErrRecoveryQuota
	}
	return s, ctx.Err()
}

// CreateWithPhaseARecovery creates a new pending schema12; it never upgrades schema9.
func CreateWithPhaseARecovery(ctx context.Context, ns walletdb.ReadWriteBucket, root *hdkeychain.ExtendedKey, pubPass, privPass []byte, params *chaincfg.Params, config *ScryptOptions, birthday time.Time, public, private []byte) error {
	if ctx == nil || ctx.Err() != nil || ns == nil || !candidateChain(params) || root == nil || !root.IsPrivate() || len(public) == 0 || len(public) > recovery.MaxManifestSize || len(private) != 68 {
		return ErrRecoveryState
	}
	owned, e := recoveryScryptOptions(config)
	if e != nil {
		return e
	}
	m, e := recovery.ParseManifest(public)
	if e != nil {
		return ErrRecoveryState
	}
	canonical, e := recovery.MarshalManifest(m)
	if e != nil || !bytes.Equal(canonical, public) {
		return ErrRecoveryState
	}
	state, e := PhaseARecoveryPlan(ctx, m)
	if e != nil {
		return e
	}
	entropy, e := phaseAEntropy(m)
	defer clear(entropy[:])
	if e != nil {
		return e
	}
	digest := sha256.Sum256(public)
	if binary.LittleEndian.Uint32(private) != 1 || !bytes.Equal(private[4:36], entropy[:]) || !bytes.Equal(private[36:], digest[:]) {
		return ErrRecoveryState
	}
	key, e := root.Neuter()
	if e != nil || key.String() != m.RootPublicKey {
		return ErrRecoveryState
	}
	if e = createManager(ns, root, pubPass, privPass, params, &owned, birthday, DerivationStandard, public, private); e != nil {
		return e
	}
	for _, a := range m.Accounts {
		if e = setRecoveryAccountCursors(ns, KeyScope{Purpose: a.Purpose, Coin: a.Coin}, a.NextExternal, a.NextInternal); e != nil {
			return e
		}
	}
	if e = putManagerVersion(ns, PhaseAManagerVersion); e != nil {
		return e
	}
	if _, e = ns.NestedReadWriteBucket(mainBucketName).CreateBucket(phaseAInvalidName); e != nil {
		return e
	}
	if e = putRecoveryProgress(ns, state); e != nil {
		return e
	}
	return ctx.Err()
}

// OpenPhaseARecovery is the exclusive pending/complete schema12 manager entry point.
func OpenPhaseARecovery(ns walletdb.ReadBucket, pubPass []byte, params *chaincfg.Params) (*Manager, error) {
	if ns == nil {
		return nil, ErrRecoveryState
	}
	v, e := fetchManagerVersion(ns)
	if e != nil || v != PhaseAManagerVersion {
		return nil, ErrRecoveryState
	}
	return loadManagerInternal(ns, pubPass, params, true)
}
func validateStoredPhaseA(ns walletdb.ReadBucket, pubKey EncryptorDecryptor, params *chaincfg.Params) error {
	if !candidateChain(params) {
		return ErrRecoveryState
	}
	b := ns.NestedReadBucket(mainBucketName)
	raw, e := pubKey.Decrypt(b.Get(recoveryPublicName))
	if e != nil {
		return ErrRecoveryState
	}
	defer clear(raw)
	m, e := recovery.ParseManifest(raw)
	if e != nil {
		return ErrRecoveryState
	}
	canonical, e := recovery.MarshalManifest(m)
	if e != nil || !bytes.Equal(canonical, raw) {
		return ErrRecoveryState
	}
	entropy, e := phaseAEntropy(m)
	defer clear(entropy[:])
	if e != nil {
		return e
	}
	_, encrypted := fetchMasterHDKeys(ns)
	retained, e := pubKey.Decrypt(encrypted)
	if e != nil {
		return ErrRecoveryState
	}
	defer clear(retained)
	if string(retained) != m.RootPublicKey {
		return ErrRecoveryState
	}
	if _, e = RecoveryAccounts(ns); e != nil {
		return e
	}
	s, e := fetchRecoveryProgress(ns)
	if e != nil {
		return e
	}
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, e := hdkeychain.NewMaster(seed[:], params)
	if e != nil {
		return ErrRecoveryState
	}
	defer root.Zero()
	for i, a := range m.Accounts {
		if s.Branches[2*i].ImportedNext != a.NextExternal || s.Branches[2*i+1].ImportedNext != a.NextInternal {
			return ErrRecoveryState
		}
		scope := KeyScope{Purpose: a.Purpose, Coin: a.Coin}
		row, e := fetchAccountInfo(ns, &scope, 0)
		if e != nil {
			return e
		}
		account, ok := row.(*dbDefaultAccountRow)
		if !ok {
			return ErrRecoveryState
		}
		child := root
		for _, index := range []uint32{a.Purpose, a.Coin, a.Account} {
			next, e := child.Derive(index + hdkeychain.HardenedKeyStart)
			if child != root {
				child.Zero()
			}
			if e != nil {
				return ErrRecoveryState
			}
			child = next
		}
		expected, e := child.Neuter()
		if e != nil {
			child.Zero()
			return ErrRecoveryState
		}
		want := expected.String()
		child.Zero()
		key, e := pubKey.Decrypt(account.pubKeyEncrypted)
		if e != nil {
			return ErrRecoveryState
		}
		match := string(key) == want
		clear(key)
		if !match {
			return ErrRecoveryState
		}
	}
	return nil
}
