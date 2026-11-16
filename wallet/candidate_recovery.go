// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// ErrRecoveryScanRequired distinguishes a valid descriptor from the bounded
// fixture runtime. It does not imply a complete production restoration engine.
var ErrRecoveryScanRequired = waddrmgr.ErrRecoveryScanRequired

func (w *Wallet) defaultChangeScope() waddrmgr.KeyScope {
	if w.Manager.RecoveryVersion() == productionprofile.Version2 {
		return waddrmgr.KeyScope{Purpose: 84, Coin: productionprofile.CandidateCoinType}
	}
	return waddrmgr.KeyScopeBIP0086
}

func ownCandidateManifest(m productionprofile.Manifest) (productionprofile.Manifest, error) {
	if len(m.Accounts) != 4 || len(m.Descriptor.Payments) != 4 || len(m.GymPath) != 5 {
		return productionprofile.Manifest{}, productionprofile.ErrManifest
	}
	m.Accounts = append([]productionprofile.Account(nil), m.Accounts...)
	m.Descriptor.Payments = append([]productionprofile.Payment(nil), m.Descriptor.Payments...)
	m.GymPath = append([]uint32(nil), m.GymPath...)
	return m, nil
}

func candidateRuntimeBounds(m productionprofile.Manifest) error {
	for _, a := range m.Accounts {
		if a.NextExternal > productionprofile.FixtureRuntimeMaxNextIndex || a.NextInternal > productionprofile.FixtureRuntimeMaxNextIndex {
			return ErrRecoveryScanRequired
		}
	}
	return nil
}

func prepareCandidate(fixture string, manifest productionprofile.Manifest, params *chaincfg.Params) (*recoveryCreation, *hdkeychain.ExtendedKey, error) {
	if params == nil || params.GenesisBlock == nil {
		return nil, nil, ErrRecoveryProfile
	}
	if err := recoveryChain(params); err != nil {
		return nil, nil, err
	}
	name, err := productionprofile.ValidateFixtureManifest(context.Background(), manifest)
	if err != nil || name != fixture {
		return nil, nil, productionprofile.ErrFixture
	}
	if err := candidateRuntimeBounds(manifest); err != nil {
		return nil, nil, err
	}
	entropy, err := productionprofile.FixtureEntropy(fixture)
	if err != nil {
		return nil, nil, err
	}
	defer clear(entropy[:])
	public, err := productionprofile.MarshalManifest(manifest)
	if err != nil {
		return nil, nil, err
	}
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], params)
	if err != nil {
		return nil, nil, productionprofile.ErrDerivation
	}
	private := make([]byte, 68)
	binary.LittleEndian.PutUint32(private, productionprofile.Version2)
	copy(private[4:36], entropy[:])
	digest := sha256.Sum256(public)
	copy(private[36:], digest[:])
	return &recoveryCreation{public: public, private: private, candidate: &manifest}, root, nil
}

// CreateCandidateFixtureWallet accepts only a compiled published fixture label.
// There is no entropy, descriptor, finalization flag, or production-key route.
func (l *Loader) CreateCandidateFixtureWallet(pubPass, privPass []byte, fixture string) (*Wallet, error) {
	if l.chainParams == nil || l.chainParams.GenesisBlock == nil {
		return nil, ErrRecoveryProfile
	}
	if err := recoveryChain(l.chainParams); err != nil {
		return nil, err
	}
	manifest, err := productionprofile.FixtureManifest(context.Background(), fixture, productionprofile.DefaultCursors())
	if err != nil {
		return nil, err
	}
	data, root, err := prepareCandidate(fixture, manifest, l.chainParams)
	if err != nil {
		return nil, err
	}
	defer root.Zero()
	defer clear(data.private)
	return l.createNewWallet(pubPass, privPass, root, l.chainParams.GenesisBlock.Header.Timestamp, false, data)
}

// RestoreCandidateFixtureWallet validates the complete file-only export and
// exact published identity before opening storage. Cursors above the operational
// fixture bound are refused, not truncated or presented as fully restored.
func (l *Loader) RestoreCandidateFixtureWallet(pubPass, privPass []byte, bundle productionprofile.Export) (*Wallet, error) {
	if l.chainParams == nil || l.chainParams.GenesisBlock == nil {
		return nil, ErrRecoveryProfile
	}
	if err := recoveryChain(l.chainParams); err != nil {
		return nil, err
	}
	manifest, err := ownCandidateManifest(bundle.Manifest)
	if err != nil {
		return nil, err
	}
	bundle.Manifest = manifest
	fixture, err := productionprofile.ValidateFixtureExport(context.Background(), bundle)
	if err != nil {
		return nil, err
	}
	data, root, err := prepareCandidate(fixture, manifest, l.chainParams)
	if err != nil {
		return nil, err
	}
	defer root.Zero()
	defer clear(data.private)
	return l.createNewWallet(pubPass, privPass, root, l.chainParams.GenesisBlock.Header.Timestamp, false, data)
}

func restoreCandidateCursors(ns walletdb.ReadWriteBucket, pubPass []byte, params *chaincfg.Params, manifest productionprofile.Manifest) error {
	if err := candidateRuntimeBounds(manifest); err != nil {
		return err
	}
	mgr, err := waddrmgr.Open(ns, pubPass, params)
	if err != nil {
		return err
	}
	defer mgr.Close()
	current, _, _, err := readCandidatePublic(context.Background(), ns, mgr, params)
	if err != nil {
		return err
	}
	for i := range current.Accounts {
		if current.Accounts[i] != manifest.Accounts[i] {
			return waddrmgr.ErrRecoveryState
		}
	}
	return nil
}

func readCandidatePublic(ctx context.Context, ns walletdb.ReadBucket, mgr *waddrmgr.Manager, params *chaincfg.Params) (productionprofile.Manifest, []byte, string, error) {
	var none productionprofile.Manifest
	if err := recoveryChain(params); err != nil {
		return none, nil, "", err
	}
	if mgr.RecoveryVersion() != productionprofile.Version2 || mgr.DerivationMode() != waddrmgr.DerivationStandard {
		return none, nil, "", waddrmgr.ErrRecoveryUnavailable
	}
	public, err := mgr.RecoveryData(ns, false)
	if err != nil {
		return none, nil, "", err
	}
	manifest, err := productionprofile.ParseManifest(public)
	if err != nil {
		return none, nil, "", waddrmgr.ErrRecoveryState
	}
	fixture, err := productionprofile.ValidateFixtureManifest(ctx, manifest)
	if err != nil {
		return none, nil, "", waddrmgr.ErrRecoveryState
	}
	root, err := mgr.RecoveryRootPublicKey(ns)
	if err != nil || root != manifest.RootPublicKey {
		return none, nil, "", waddrmgr.ErrRecoveryState
	}
	states, err := waddrmgr.RecoveryAccounts(ns)
	if err != nil {
		return none, nil, "", err
	}
	for i := range manifest.Accounts {
		a := &manifest.Accounts[i]
		found := false
		for _, state := range states {
			if state.Scope.Purpose != a.Purpose || state.Scope.Coin != a.Coin {
				continue
			}
			if state.NextExternal < a.NextExternal || state.NextInternal < a.NextInternal {
				return none, nil, "", waddrmgr.ErrRecoveryState
			}
			a.NextExternal, a.NextInternal = state.NextExternal, state.NextInternal
			found = true
		}
		if !found {
			return none, nil, "", waddrmgr.ErrRecoveryInventory
		}
		scope, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScope{Purpose: a.Purpose, Coin: a.Coin})
		if err != nil {
			return none, nil, "", err
		}
		properties, err := scope.AccountProperties(ns, a.Account)
		if err != nil || properties.AccountPubKey == nil || properties.AccountPubKey.String() != a.AccountPublicKey {
			return none, nil, "", waddrmgr.ErrRecoveryState
		}
	}
	return manifest, public, fixture, nil
}

// ExportCandidateRecovery requires an unlocked lease and validates retained
// material against the exact fixture identity and one committed cursor snapshot.
func (w *Wallet) ExportCandidateRecovery(ctx context.Context) (productionprofile.Export, error) {
	lease, err := w.holdUnlockContext(ctx)
	if err != nil {
		return productionprofile.Export{}, err
	}
	defer lease.release()
	var result productionprofile.Export
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		manifest, public, fixture, err := readCandidatePublic(ctx, ns, w.Manager, w.chainParams)
		if err != nil {
			return err
		}
		private, err := w.Manager.RecoveryData(ns, true)
		if err != nil {
			return err
		}
		defer clear(private)
		entropy, err := productionprofile.FixtureEntropy(fixture)
		if err != nil {
			return err
		}
		defer clear(entropy[:])
		digest := sha256.Sum256(public)
		if len(private) != 68 || binary.LittleEndian.Uint32(private) != productionprofile.Version2 || !bytes.Equal(private[4:36], entropy[:]) || !bytes.Equal(private[36:], digest[:]) {
			return waddrmgr.ErrRecoveryState
		}
		result = productionprofile.Export{Version: productionprofile.Version2, Mnemonic: recovery.Mnemonic(entropy), Manifest: manifest}
		_, err = productionprofile.ValidateFixtureExport(ctx, result)
		return err
	})
	if err != nil {
		return productionprofile.Export{}, err
	}
	if err := lease.err(ctx); err != nil {
		return productionprofile.Export{}, err
	}
	return result, nil
}

// CandidateGymIdentity is public metadata only. It cannot enroll this candidate
// identity with the old fixture authority or invoke an existing wallet signer.
func (w *Wallet) CandidateGymIdentity(ctx context.Context) (GymIdentity, error) {
	if ctx == nil {
		return GymIdentity{}, productionprofile.ErrProfile
	}
	if err := ctx.Err(); err != nil {
		return GymIdentity{}, err
	}
	var result GymIdentity
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		m, _, _, err := readCandidatePublic(ctx, tx.ReadBucket(waddrmgrNamespaceKey), w.Manager, w.chainParams)
		if err != nil {
			return err
		}
		result = GymIdentity{Version: productionprofile.Version2, Profile: m.Descriptor.Profile,
			Network: m.Descriptor.Network, Genesis: m.Descriptor.Genesis, PublicKey: m.GymPublicKey, GymID: m.GymID}
		return nil
	})
	if err != nil {
		return GymIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return GymIdentity{}, err
	}
	return result, nil
}
