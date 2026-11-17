// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// CandidateManagerVersion is creation-only. It never migrates legacy or v1
// recovery wallets and is refused by binaries that only understand schemas8/9.
const CandidateManagerVersion uint32 = 10

var candidateFixtureName = []byte("slug-candidate-fixture")

func legacyDefaultScopes() map[KeyScope]ScopeAddrSchema {
	result := make(map[KeyScope]ScopeAddrSchema, len(ScopeAddrMap))
	for scope, schema := range ScopeAddrMap {
		result[scope] = schema
	}
	return result
}

func candidateDefaultScopes() map[KeyScope]ScopeAddrSchema {
	coin := productionprofile.CandidateCoinType
	return map[KeyScope]ScopeAddrSchema{
		{Purpose: 44, Coin: coin}: {ExternalAddrType: PubKeyHash, InternalAddrType: PubKeyHash},
		{Purpose: 49, Coin: coin}: {ExternalAddrType: NestedWitnessPubKey, InternalAddrType: NestedWitnessPubKey},
		{Purpose: 84, Coin: coin}: {ExternalAddrType: WitnessPubKey, InternalAddrType: WitnessPubKey},
		{Purpose: 86, Coin: coin}: {ExternalAddrType: TaprootPubKey, InternalAddrType: TaprootPubKey},
	}
}

func creationDefaultScopes(candidate ...string) []KeyScope {
	if len(candidate) == 0 {
		return append([]KeyScope(nil), DefaultKeyScopes...)
	}
	result := make([]KeyScope, 0, 4)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		result = append(result, KeyScope{Purpose: purpose, Coin: productionprofile.CandidateCoinType})
	}
	return result
}

func validCandidateFixture(name string) bool {
	return name == productionprofile.CandidateZero256 || name == productionprofile.CandidateIncrementing256
}

func candidateChain(params *chaincfg.Params) bool {
	want := &chaincfg.MainNetParams
	return !wire.TestPoW && params != nil && params.GenesisBlock != nil && params.GenesisHash != nil &&
		params.Net == want.Net && params.GenesisHash.IsEqual(want.GenesisHash) &&
		params.PubKeyHashAddrID == want.PubKeyHashAddrID && params.ScriptHashAddrID == want.ScriptHashAddrID &&
		params.PrivateKeyID == want.PrivateKeyID && params.Bech32HRPSegwit == want.Bech32HRPSegwit &&
		params.HDPublicKeyID == want.HDPublicKeyID && params.HDPrivateKeyID == want.HDPrivateKeyID
}

// IsDefaultScope reports membership in the wallet's immutable creation profile.
// It preserves legacy default scopes while including candidate payment scopes.
func (m *Manager) IsDefaultScope(scope KeyScope) bool {
	_, ok := m.defaultScopes[scope]
	return ok
}

// PaymentScope resolves a supported purpose within this wallet's immutable
// profile. It does not create a scope or change the legacy exported defaults.
func (m *Manager) PaymentScope(purpose uint32) (KeyScope, error) {
	coin := uint32(0)
	if m.recoveryVersion == productionprofile.Version2 {
		coin = productionprofile.CandidateCoinType
	}
	scope := KeyScope{Purpose: purpose, Coin: coin}
	if _, ok := m.defaultScopes[scope]; !ok {
		return KeyScope{}, ErrRecoveryInventory
	}
	return scope, nil
}

// CreateWithCandidateRecovery is restricted to the two compiled public
// fixtures. Neither arbitrary descriptors nor arbitrary roots can opt into
// schema10. All retention and scope initialization uses the caller's transaction.
func CreateWithCandidateRecovery(ctx context.Context, ns walletdb.ReadWriteBucket,
	root *hdkeychain.ExtendedKey, pubPass, privPass []byte, params *chaincfg.Params,
	config *ScryptOptions, birthday time.Time, public, private []byte) error {

	if ctx == nil || ctx.Err() != nil || !candidateChain(params) || root == nil || !root.IsPrivate() || len(private) != 68 || len(public) == 0 || len(public) > productionprofile.MaxManifestSize {
		return ErrRecoveryState
	}
	public = append([]byte(nil), public...)
	private = append([]byte(nil), private...)
	defer clear(private)
	manifest, err := productionprofile.ParseManifest(public)
	if err != nil {
		return ErrRecoveryState
	}
	fixture, err := productionprofile.ValidateFixtureManifest(ctx, manifest)
	if err != nil {
		return ErrRecoveryState
	}
	entropy, err := productionprofile.FixtureEntropy(fixture)
	if err != nil {
		return ErrRecoveryState
	}
	defer clear(entropy[:])
	digest := sha256.Sum256(public)
	if binary.LittleEndian.Uint32(private) != productionprofile.Version2 || !bytes.Equal(private[4:36], entropy[:]) || !bytes.Equal(private[36:], digest[:]) {
		return ErrRecoveryState
	}
	pub, err := root.Neuter()
	if err != nil {
		return ErrRecoveryState
	}
	// Neuter shares chain code with root; do not zero the borrowed alias.
	if pub.String() != manifest.RootPublicKey {
		return ErrRecoveryState
	}
	for _, a := range manifest.Accounts {
		if a.NextExternal > maxRecoveryBranchIndex || a.NextInternal > maxRecoveryBranchIndex {
			return ErrRecoveryScanRequired
		}
	}
	if err := createManager(ns, root, pubPass, privPass, params, config, birthday,
		DerivationStandard, public, private, fixture); err != nil {
		return err
	}
	// No partially initialized schema10 is returned to a caller. Derive and
	// commit every retained cursor inside this same creation transaction.
	mgr, err := loadManagerInternal(ns, pubPass, params, true)
	if err != nil {
		return err
	}
	defer mgr.Close()
	for _, a := range manifest.Accounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		scope, err := mgr.FetchScopedKeyManager(KeyScope{Purpose: a.Purpose, Coin: a.Coin})
		if err != nil {
			return err
		}
		if a.NextExternal != 0 {
			if err := scope.ExtendExternalAddresses(ns, a.Account, a.NextExternal-1); err != nil {
				return err
			}
		}
		if a.NextInternal != 0 {
			if err := scope.ExtendInternalAddresses(ns, a.Account, a.NextInternal-1); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return validateStoredCandidate(ns, mgr.cryptoKeyPub, params, false)
}

func validateStoredCandidate(ns walletdb.ReadBucket, pubKey EncryptorDecryptor, params *chaincfg.Params, creating bool) error {
	if !candidateChain(params) {
		return ErrRecoveryState
	}
	b := ns.NestedReadBucket(mainBucketName)
	public, err := pubKey.Decrypt(b.Get(recoveryPublicName))
	if err != nil {
		return ErrRecoveryState
	}
	defer clear(public)
	manifest, err := productionprofile.ParseManifest(public)
	if err != nil {
		return ErrRecoveryState
	}
	fixture, err := productionprofile.ValidateFixtureManifest(context.Background(), manifest)
	if err != nil || fixture != string(b.Get(candidateFixtureName)) {
		return ErrRecoveryState
	}
	_, encrypted := fetchMasterHDKeys(ns)
	root, err := pubKey.Decrypt(encrypted)
	if err != nil {
		return ErrRecoveryState
	}
	defer clear(root)
	if string(root) != manifest.RootPublicKey {
		return ErrRecoveryState
	}
	if _, err := RecoveryAccounts(ns); err != nil {
		return err
	}
	var progress *RecoveryState
	if version, _ := fetchManagerVersion(ns); version == ResumableManagerVersion {
		state, err := fetchRecoveryProgress(ns)
		if err != nil {
			return err
		}
		progress = &state
	}
	for accountIndex, account := range manifest.Accounts {
		if progress != nil && (progress.Branches[2*accountIndex].ImportedNext != account.NextExternal || progress.Branches[2*accountIndex+1].ImportedNext != account.NextInternal) {
			return ErrRecoveryState
		}
		scope := KeyScope{Purpose: account.Purpose, Coin: account.Coin}
		row, err := fetchAccountInfo(ns, &scope, account.Account)
		if err != nil {
			return ErrRecoveryState
		}
		data, ok := row.(*dbDefaultAccountRow)
		if !ok {
			return ErrRecoveryState
		}
		if !creating && (data.nextExternalIndex < account.NextExternal || data.nextInternalIndex < account.NextInternal) {
			return ErrRecoveryState
		}
		key, err := pubKey.Decrypt(data.pubKeyEncrypted)
		if err != nil {
			return ErrRecoveryState
		}
		matches := string(key) == account.AccountPublicKey
		clear(key)
		if !matches {
			return ErrRecoveryState
		}
	}
	return nil
}
