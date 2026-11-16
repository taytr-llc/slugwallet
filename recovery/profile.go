// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recovery

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
)

func profileParams() *chaincfg.Params {
	return &chaincfg.Params{HDPublicKeyID: [4]byte{0x53, 0x4c, 0x55, 0x47}, HDPrivateKeyID: [4]byte{0x73, 0x6c, 0x75, 0x67}}
}
func identityContext() prospect.Context {
	return prospect.Context{Version: 1, Network: Network, Genesis: Genesis}
}

// ValidateManifest checks the fixed profile and bounded public identities. It
// does not prove correspondence to a recovery phrase; use ValidateExport for it.
func ValidateManifest(m Manifest) error {
	if m.Version != Version1 || m.Profile != ProfileID || m.Network != Network || m.Genesis != Genesis || m.Derivation != DerivationStandard || m.ScanFromHeight != 0 || m.GymPath != GymPath {
		return errors.New("unsupported recovery profile or chain")
	}
	defaults := DefaultAccounts()
	if len(m.Accounts) != len(defaults) {
		return errors.New("unsupported recovery account inventory")
	}
	for i, a := range m.Accounts {
		if a.NextExternal > MaxBranchIndex || a.NextInternal > MaxBranchIndex {
			return errors.New("recovery branch index exceeds bound")
		}
		a.NextExternal = 0
		a.NextInternal = 0
		if a != defaults[i] {
			return errors.New("unsupported or unordered recovery account")
		}
	}
	if len(m.RootPublicKey) > 128 {
		return errors.New("invalid recovery root identity")
	}
	root, err := hdkeychain.NewKeyFromString(m.RootPublicKey)
	if err != nil {
		return errors.New("invalid recovery root identity")
	}
	defer root.Zero()
	params := profileParams()
	if root.IsPrivate() || root.Depth() != 0 || root.ChildIndex() != 0 || root.ParentFingerprint() != 0 || !bytes.Equal(root.Version(), params.HDPublicKeyID[:]) || root.String() != m.RootPublicKey {
		return errors.New("invalid recovery root identity")
	}
	if len(m.GymPublicKey) != 66 || len(m.GymID) != 64 {
		return errors.New("invalid recovery gym identity")
	}
	public, err := hex.DecodeString(m.GymPublicKey)
	if err != nil || hex.EncodeToString(public) != m.GymPublicKey {
		return errors.New("invalid recovery gym identity")
	}
	id, err := gymauth.GymID(identityContext(), m.GymPublicKey)
	if err != nil || id != m.GymID {
		return errors.New("invalid recovery gym identity")
	}
	return nil
}

// ManifestFor derives public identities from the original entropy and copies
// the caller's account inventory. It accepts no custom derivation path.
func ManifestFor(entropy [32]byte, accounts []Account) (Manifest, error) {
	defer clear(entropy[:])
	defaults := DefaultAccounts()
	if len(accounts) != len(defaults) {
		return Manifest{}, errors.New("unsupported recovery account inventory")
	}
	// Bound before copying, then validate only the owned inventory.
	m := Manifest{Version: Version1, Profile: ProfileID, Network: Network, Genesis: Genesis, Derivation: DerivationStandard, ScanFromHeight: 0, GymPath: GymPath, Accounts: append([]Account(nil), accounts...)}
	for i, a := range m.Accounts {
		if a.NextExternal > MaxBranchIndex || a.NextInternal > MaxBranchIndex {
			return Manifest{}, errors.New("recovery branch index exceeds bound")
		}
		a.NextExternal = 0
		a.NextInternal = 0
		if a != defaults[i] {
			return Manifest{}, errors.New("unsupported recovery account")
		}
	}
	seed := SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], profileParams())
	if err != nil {
		return Manifest{}, errors.New("recovery seed cannot derive root")
	}
	defer root.Zero()
	publicRoot, err := root.Neuter()
	if err != nil {
		return Manifest{}, errors.New("recovery root cannot derive public identity")
	}
	m.RootPublicKey = publicRoot.String()
	// Neuter shares chain-code storage with root; clear only after derivation.
	defer publicRoot.Zero()
	current := root
	for _, index := range GymPathIndices() {
		next, deriveErr := current.Derive(index)
		if current != root {
			current.Zero()
		}
		if deriveErr != nil {
			return Manifest{}, errors.New("recovery seed cannot derive gym identity")
		}
		current = next
	}
	defer current.Zero()
	pub, err := current.ECPubKey()
	if err != nil {
		return Manifest{}, errors.New("recovery gym public identity unavailable")
	}
	m.GymPublicKey = hex.EncodeToString(pub.SerializeCompressed())
	m.GymID, err = gymauth.GymID(identityContext(), m.GymPublicKey)
	if err != nil {
		return Manifest{}, errors.New("recovery gym identity unavailable")
	}
	if err = ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ValidateEntropyManifest proves that the fixed profile identities match the
// supplied entropy. Cursor claims remain metadata, not proof of chain history.
func ValidateEntropyManifest(entropy [32]byte, m Manifest) error {
	defer clear(entropy[:])
	if err := ValidateManifest(m); err != nil {
		return err
	}
	expected, err := ManifestFor(entropy, m.Accounts)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, m) {
		return errors.New("recovery identity does not match phrase")
	}
	return nil
}

// NewExport creates the exact supported recovery export from retained entropy.
func NewExport(entropy [32]byte, accounts []Account) (Export, error) {
	defer clear(entropy[:])
	m, err := ManifestFor(entropy, accounts)
	if err != nil {
		return Export{}, err
	}
	return Export{Version: Version1, Mnemonic: Mnemonic(entropy), Manifest: m}, nil
}

// ValidateExport verifies the complete public metadata against the phrase.
func ValidateExport(e Export) error {
	if e.Version != Version1 {
		return errors.New("unsupported recovery export version")
	}
	entropy, err := Entropy(e.Mnemonic)
	defer clear(entropy[:])
	if err != nil {
		return err
	}
	return ValidateEntropyManifest(entropy, e.Manifest)
}
