// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcec/v2/schnorr"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

func keyOrigin(purpose, coin uint32) string { return fmt.Sprintf("m/%d'/%d'/0'", purpose, coin) }
func validPublicKey(encoded string, depth uint8, child uint32, root bool) bool {
	if len(encoded) == 0 || len(encoded) > 128 {
		return false
	}
	key, err := hdkeychain.NewKeyFromString(encoded)
	if err != nil {
		return false
	}
	defer key.Zero()
	params := profileParams()
	return !key.IsPrivate() && key.Depth() == depth && key.ChildIndex() == child && (!root || key.ParentFingerprint() == 0) && bytes.Equal(key.Version(), params.HDPublicKeyID[:]) && key.String() == encoded
}
func ValidateManifest(m Manifest) error {
	if m.Version != Version2 || len(m.Accounts) != 4 || len(m.GymPath) != 5 || ValidateDescriptor(m.Descriptor) != nil || !canonicalHex(m.DescriptorHash, 32) || !validPublicKey(m.RootPublicKey, 0, 0, true) {
		return ErrManifest
	}
	hash, err := DescriptorHash(m.Descriptor)
	if err != nil || hash != m.DescriptorHash {
		return ErrManifest
	}
	uri, path := gymIdentity(m.Descriptor)
	if m.GymIdentityURI != uri || !reflect.DeepEqual(m.GymPath, path) || !canonicalHex(m.GymPublicKey, 33) || !canonicalHex(m.GymID, 32) {
		return ErrManifest
	}
	id, err := gymauth.GymID(prospect.Context{Version: 1, Network: m.Descriptor.Network, Genesis: m.Descriptor.Genesis}, m.GymPublicKey)
	if err != nil || id != m.GymID {
		return ErrManifest
	}
	for i, a := range m.Accounts {
		p := m.Descriptor.Payments[i]
		if a.Purpose != p.Purpose || a.Coin != m.Descriptor.CoinType || a.Account != 0 || a.ExternalType != p.ExternalType || a.InternalType != p.InternalType || a.KeyOrigin != keyOrigin(a.Purpose, a.Coin) || !validPublicKey(a.AccountPublicKey, 3, MaxNextIndex, false) || a.NextExternal > MaxNextIndex || a.NextInternal > MaxNextIndex {
			return ErrManifest
		}
	}
	return nil
}
func validateCursors(cursors []Cursor) error {
	want := DefaultCursors()
	if len(cursors) != len(want) {
		return ErrManifest
	}
	for i, c := range cursors {
		if c.Purpose != want[i].Purpose || c.NextExternal > MaxNextIndex || c.NextInternal > MaxNextIndex {
			return ErrManifest
		}
	}
	return nil
}
func manifestCursors(m Manifest) []Cursor {
	cursors := make([]Cursor, len(m.Accounts))
	for i, a := range m.Accounts {
		cursors[i] = Cursor{a.Purpose, a.NextExternal, a.NextInternal}
	}
	return cursors
}

// deriveExactPath never changes a semantic index after ErrInvalidChild. Address
// allocators may separately skip invalid address indices and persist that cursor.
func deriveExactPath(ctx context.Context, root *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	return deriveExactPathWith(ctx, root, path, func(key *hdkeychain.ExtendedKey, index uint32) (*hdkeychain.ExtendedKey, error) {
		return key.Derive(index)
	})
}

func deriveExactPathWith(ctx context.Context, root *hdkeychain.ExtendedKey, path []uint32, derive func(*hdkeychain.ExtendedKey, uint32) (*hdkeychain.ExtendedKey, error)) (*hdkeychain.ExtendedKey, error) {
	current := root
	for _, index := range path {
		if err := checkedContext(ctx); err != nil {
			if current != root {
				current.Zero()
			}
			return nil, err
		}
		next, err := derive(current, index)
		if current != root {
			current.Zero()
		}
		if err != nil {
			return nil, err
		}
		current = next
	}
	if err := checkedContext(ctx); err != nil {
		if current != root {
			current.Zero()
		}
		return nil, err
	}
	return current, nil
}
func deriveManifest(ctx context.Context, entropy [32]byte, d Descriptor, cursors []Cursor) (Manifest, error) {
	defer clear(entropy[:])
	if err := checkedContext(ctx); err != nil {
		return Manifest{}, err
	}
	if ValidateDescriptor(d) != nil || validateCursors(cursors) != nil {
		return Manifest{}, ErrManifest
	}
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], profileParams())
	if err != nil {
		return Manifest{}, ErrDerivation
	}
	defer root.Zero()
	rootPublic, err := root.Neuter()
	if err != nil {
		return Manifest{}, ErrDerivation
	}
	// Neuter aliases chain code: clear it only after all payment derivation.
	defer rootPublic.Zero()
	hash, err := DescriptorHash(d)
	if err != nil {
		return Manifest{}, err
	}
	uri, path := gymIdentity(d)
	m := Manifest{Version: Version2, Descriptor: d, DescriptorHash: hash, RootPublicKey: rootPublic.String(), GymIdentityURI: uri, GymPath: path, Accounts: make([]Account, 4)}
	m.Descriptor.Payments = append([]Payment(nil), d.Payments...)
	for i, p := range d.Payments {
		key, err := deriveExactPath(ctx, root, []uint32{p.Purpose | MaxNextIndex, d.CoinType | MaxNextIndex, MaxNextIndex})
		if err != nil {
			return Manifest{}, err
		}
		public, err := key.Neuter()
		if err != nil {
			key.Zero()
			return Manifest{}, ErrDerivation
		}
		encoded := public.String()
		public.Zero()
		key.Zero()
		m.Accounts[i] = Account{Purpose: p.Purpose, Coin: d.CoinType, ExternalType: p.ExternalType, InternalType: p.InternalType, KeyOrigin: keyOrigin(p.Purpose, d.CoinType), AccountPublicKey: encoded, NextExternal: cursors[i].NextExternal, NextInternal: cursors[i].NextInternal}
	}
	gym, err := slip10Path(ctx, seed[:], path)
	if err != nil {
		return Manifest{}, err
	}
	defer gym.zero()
	private, _ := btcec.PrivKeyFromBytes(gym.key[:])
	m.GymPublicKey = hex.EncodeToString(private.PubKey().SerializeCompressed())
	private.Zero()
	m.GymID, err = gymauth.GymID(prospect.Context{Version: 1, Network: d.Network, Genesis: d.Genesis}, m.GymPublicKey)
	if err != nil {
		return Manifest{}, ErrDerivation
	}
	if err = ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	if err = checkedContext(ctx); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func FixtureManifest(ctx context.Context, name string, cursors []Cursor) (Manifest, error) {
	if len(cursors) != 4 {
		return Manifest{}, ErrManifest
	}
	cursors = append([]Cursor(nil), cursors...)
	entropy, err := FixtureEntropy(name)
	if err != nil {
		return Manifest{}, err
	}
	defer clear(entropy[:])
	return deriveManifest(ctx, entropy, CandidateDescriptor(), cursors)
}
func FixtureExport(ctx context.Context, name string, cursors []Cursor) (Export, error) {
	m, err := FixtureManifest(ctx, name, cursors)
	if err != nil {
		return Export{}, err
	}
	entropy, err := FixtureEntropy(name)
	if err != nil {
		return Export{}, err
	}
	defer clear(entropy[:])
	if err = checkedContext(ctx); err != nil {
		return Export{}, err
	}
	return Export{Version: Version2, Mnemonic: recovery.Mnemonic(entropy), Manifest: m}, nil
}

// ValidateFixtureManifest binds every public identity to one published candidate
// tuple. Structural xpub validation alone cannot prove hardened key ancestry.
func ValidateFixtureManifest(ctx context.Context, m Manifest) (string, error) {
	if len(m.Accounts) != 4 || len(m.GymPath) != 5 || len(m.Descriptor.Payments) != 4 {
		return "", ErrManifest
	}
	m = cloneManifest(m)
	if err := ValidateManifest(m); err != nil {
		return "", err
	}
	if !reflect.DeepEqual(m.Descriptor, CandidateDescriptor()) {
		return "", ErrFixture
	}
	for _, name := range []string{CandidateZero256, CandidateIncrementing256} {
		expected, err := FixtureManifest(ctx, name, manifestCursors(m))
		if err != nil {
			return "", err
		}
		if reflect.DeepEqual(expected, m) {
			return name, nil
		}
	}
	return "", ErrFixture
}
func ValidateFixtureExport(ctx context.Context, e Export) (string, error) {
	if err := checkedContext(ctx); err != nil {
		return "", err
	}
	if e.Version != Version2 || len(e.Mnemonic) == 0 || len(e.Mnemonic) > MaxPhraseSize || len(e.Manifest.Accounts) != 4 || len(e.Manifest.GymPath) != 5 || len(e.Manifest.Descriptor.Payments) != 4 {
		return "", ErrManifest
	}
	e.Manifest = cloneManifest(e.Manifest)
	entropy, err := recovery.Entropy(e.Mnemonic)
	if err != nil {
		return "", ErrManifest
	}
	defer clear(entropy[:])
	var name string
	for _, candidate := range []string{CandidateZero256, CandidateIncrementing256} {
		known, _ := FixtureEntropy(candidate)
		same := known == entropy
		clear(known[:])
		if same {
			name = candidate
			break
		}
	}
	if name == "" {
		return "", ErrFixture
	}
	expected, err := FixtureManifest(ctx, name, manifestCursors(e.Manifest))
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(expected, e.Manifest) || recovery.Mnemonic(entropy) != e.Mnemonic {
		return "", ErrManifest
	}
	if err := checkedContext(ctx); err != nil {
		return "", err
	}
	return name, nil
}

// DerivePaymentPublic derives exactly one index from a structurally validated
// public manifest. It does not authenticate the manifest or issue an address.
func DerivePaymentPublic(ctx context.Context, m Manifest, purpose, branch, index uint32) (PaymentPublic, error) {
	var empty PaymentPublic
	if err := checkedContext(ctx); err != nil {
		return empty, err
	}
	if len(m.Accounts) != 4 || len(m.GymPath) != 5 || len(m.Descriptor.Payments) != 4 || branch > 1 || index >= MaxNextIndex {
		return empty, ErrManifest
	}
	m = cloneManifest(m)
	if err := ValidateManifest(m); err != nil {
		return empty, err
	}
	var account *Account
	for i := range m.Accounts {
		if m.Accounts[i].Purpose == purpose {
			account = &m.Accounts[i]
			break
		}
	}
	if account == nil {
		return empty, ErrManifest
	}
	root, err := hdkeychain.NewKeyFromString(account.AccountPublicKey)
	if err != nil {
		return empty, ErrManifest
	}
	defer root.Zero()
	child, err := deriveExactPath(ctx, root, []uint32{branch, index})
	if err != nil {
		return empty, err
	}
	defer child.Zero()
	public, err := child.ECPubKey()
	if err != nil {
		return empty, ErrDerivation
	}
	result := PaymentPublic{Purpose: purpose, Branch: branch, Index: index, Path: fmt.Sprintf("%s/%d/%d", account.KeyOrigin, branch, index), PublicKey: hex.EncodeToString(public.SerializeCompressed())}
	params := profileParams()
	var destination address.Address
	switch purpose {
	case 44:
		destination, err = address.NewAddressPubKeyHash(address.Hash160(public.SerializeCompressed()), params)
	case 49:
		var witness *address.AddressWitnessPubKeyHash
		witness, err = address.NewAddressWitnessPubKeyHash(address.Hash160(public.SerializeCompressed()), params)
		if err == nil {
			var script []byte
			script, err = txscript.PayToAddrScript(witness)
			if err == nil {
				destination, err = address.NewAddressScriptHash(script, params)
			}
		}
	case 84:
		destination, err = address.NewAddressWitnessPubKeyHash(address.Hash160(public.SerializeCompressed()), params)
	case 86:
		output := txscript.ComputeTaprootKeyNoScript(public)
		result.InternalKey = hex.EncodeToString(schnorr.SerializePubKey(public))
		result.OutputKey = hex.EncodeToString(schnorr.SerializePubKey(output))
		destination, err = address.NewAddressTaproot(schnorr.SerializePubKey(output), params)
	default:
		return empty, ErrManifest
	}
	if err != nil {
		return empty, ErrDerivation
	}
	script, err := txscript.PayToAddrScript(destination)
	if err != nil {
		return empty, ErrDerivation
	}
	result.Address = destination.EncodeAddress()
	result.ScriptPubKey = hex.EncodeToString(script)
	if err = checkedContext(ctx); err != nil {
		return empty, err
	}
	return result, nil
}
