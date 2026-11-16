// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"

	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

// These are the two explicitly published BIP39 fixtures, never generated user
// wallet material. Selection follows the account authority's configured tuple.
func fixtureEntropy(identity gymaccount.Identity) ([32]byte, error) {
	var entropy [32]byte
	zero, _ := gymaccount.FixtureIdentity("zero256")
	if identity == zero {
		return entropy, nil
	}
	incrementing, _ := gymaccount.FixtureIdentity("incrementing256")
	if identity == incrementing {
		for i := range entropy {
			entropy[i] = byte(i)
		}
		return entropy, nil
	}
	return entropy, ErrConfig
}
func identityForBinding(b Binding) gymaccount.Identity {
	return gymaccount.Identity{Network: b.Network, Genesis: b.Genesis, Profile: b.Profile, RootPublicKey: b.RootPublicKey, GymPublicKey: b.GymPublicKey, GymID: b.GymID}
}
func deriveGym(entropy [32]byte) (*btcec.PrivateKey, error) {
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	key, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		return nil, ErrEnvelope
	}
	defer func() { key.Zero() }()
	for _, index := range recovery.GymPathIndices() {
		next, err := key.Derive(index)
		if err != nil {
			return nil, ErrEnvelope
		}
		key.Zero()
		key = next
	}
	result, err := key.ECPrivKey()
	if err != nil {
		return nil, ErrEnvelope
	}
	return result, nil
}
func materialPayloads(identity gymaccount.Identity) (recovery.Manifest, []byte, []byte, error) {
	entropy, err := fixtureEntropy(identity)
	defer clear(entropy[:])
	if err != nil {
		return recovery.Manifest{}, nil, nil, err
	}
	manifest, err := recovery.ManifestFor(entropy, recovery.DefaultAccounts())
	if err != nil || manifest.RootPublicKey != identity.RootPublicKey || manifest.GymPublicKey != identity.GymPublicKey || manifest.GymID != identity.GymID {
		return recovery.Manifest{}, nil, nil, ErrEnvelope
	}
	raw, err := recovery.MarshalManifest(manifest)
	if err != nil {
		return recovery.Manifest{}, nil, nil, ErrEnvelope
	}
	recoveryPayload := make([]byte, 40+len(raw))
	binary.LittleEndian.PutUint32(recoveryPayload, 1)
	copy(recoveryPayload[4:36], entropy[:])
	binary.LittleEndian.PutUint32(recoveryPayload[36:40], uint32(len(raw)))
	copy(recoveryPayload[40:], raw)
	key, err := deriveGym(entropy)
	if err != nil {
		clear(recoveryPayload)
		return recovery.Manifest{}, nil, nil, err
	}
	defer key.Zero()
	gymPayload := make([]byte, 36)
	binary.LittleEndian.PutUint32(gymPayload, 1)
	scalar := key.Serialize()
	copy(gymPayload[4:], scalar)
	clear(scalar)
	return manifest, recoveryPayload, gymPayload, nil
}
func decodeRecovery(raw []byte, record vaultRecord) ([32]byte, error) {
	var entropy [32]byte
	if len(raw) < 40 || len(raw) > MaxPayloadSize || binary.LittleEndian.Uint32(raw) != 1 || uint64(binary.LittleEndian.Uint32(raw[36:40])) != uint64(len(raw)-40) {
		return entropy, ErrEnvelope
	}
	manifest, err := recovery.ParseManifest(raw[40:])
	if err != nil || !reflect.DeepEqual(manifest, record.Manifest) {
		return entropy, ErrEnvelope
	}
	canonical, err := recovery.MarshalManifest(manifest)
	if err != nil || !bytes.Equal(canonical, raw[40:]) {
		return entropy, ErrEnvelope
	}
	copy(entropy[:], raw[4:36])
	if recovery.ValidateEntropyManifest(entropy, manifest) != nil {
		clear(entropy[:])
		return entropy, ErrEnvelope
	}
	return entropy, nil
}
func decodeGym(raw []byte, binding Binding) (*btcec.PrivateKey, error) {
	if len(raw) != 36 || binary.LittleEndian.Uint32(raw) != 1 || bytes.Equal(raw[4:], make([]byte, 32)) {
		return nil, ErrEnvelope
	}
	key, _ := btcec.PrivKeyFromBytes(raw[4:])
	scalar := key.Serialize()
	canonical := bytes.Equal(scalar, raw[4:])
	clear(scalar)
	if !canonical || hex.EncodeToString(key.PubKey().SerializeCompressed()) != binding.GymPublicKey {
		key.Zero()
		return nil, ErrEnvelope
	}
	return key, nil
}
