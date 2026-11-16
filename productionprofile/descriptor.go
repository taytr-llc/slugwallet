// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

func CandidateDescriptor() Descriptor {
	return Descriptor{Version: DescriptorVersion1, Profile: ProfileID, Seed: SeedScheme, PaymentDerivation: PaymentDerivation,
		Network: recovery.Network, Genesis: recovery.Genesis, CoinType: CandidateCoinType,
		Encodings:             Encodings{"53", "47", "d3", "slug", "534c5547", "736c7567"},
		Payments:              []Payment{{44, 0, "p2pkh", "p2pkh"}, {49, 0, "p2sh-p2wpkh", "p2sh-p2wpkh"}, {84, 0, "p2wpkh", "p2wpkh"}, {86, 0, "p2tr", "p2tr"}},
		DefaultReceivePurpose: 84, DefaultChangePurpose: 84, GymScheme: GymScheme}
}
func canonicalHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func ValidateDescriptor(d Descriptor) error {
	if len(d.Payments) != 4 || d.Network == 0 || !canonicalHex(d.Genesis, 32) || d.Genesis == string(makeZeroHex()) || d.CoinType < 2 || d.CoinType >= MaxNextIndex {
		return ErrProfile
	}
	want := CandidateDescriptor()
	want.Network, want.Genesis, want.CoinType = d.Network, d.Genesis, d.CoinType
	if !reflect.DeepEqual(d, want) {
		return ErrProfile
	}
	return nil
}
func makeZeroHex() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = '0'
	}
	return b
}
func MarshalDescriptor(d Descriptor) ([]byte, error) {
	if err := ValidateDescriptor(d); err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
	if err != nil || len(b) > MaxDescriptorSize {
		return nil, ErrProfile
	}
	return b, nil
}
func DescriptorHash(d Descriptor) (string, error) {
	b, err := MarshalDescriptor(d)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("SLUG recovery profile\x00v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ResolveProduction is the sole finalized-profile lookup. The reviewed table is
// intentionally empty until permanent genesis, coin allocation and restore gates
// are resolved. Candidate hashes and caller-supplied finalization cannot enable it.
func ResolveProduction(descriptorHash string) (Descriptor, error) {
	return Descriptor{}, ErrProfileUnfinalized
}

func DefaultCursors() []Cursor {
	return []Cursor{{Purpose: 44}, {Purpose: 49}, {Purpose: 84}, {Purpose: 86}}
}

// FixtureEntropy returns only explicitly published test constants, never an
// issued wallet's secret or caller-controlled entropy.
func FixtureEntropy(name string) ([32]byte, error) {
	var entropy [32]byte
	switch name {
	case CandidateZero256:
	case CandidateIncrementing256:
		for i := range entropy {
			entropy[i] = byte(i)
		}
	default:
		return entropy, ErrFixture
	}
	return entropy, nil
}
func gymIdentity(d Descriptor) (string, []uint32) {
	uri := "slug://" + d.Genesis + "/gym/v1"
	raw := make([]byte, 4, len(uri)+4)
	binary.LittleEndian.PutUint32(raw, d.GymIdentityIndex)
	raw = append(raw, uri...)
	hash := sha256.Sum256(raw)
	path := []uint32{0x8000000d}
	for i := 0; i < 4; i++ {
		path = append(path, binary.LittleEndian.Uint32(hash[i*4:i*4+4])|MaxNextIndex)
	}
	return uri, path
}
func profileParams() *chaincfg.Params {
	return &chaincfg.Params{PubKeyHashAddrID: 0x53, ScriptHashAddrID: 0x47, PrivateKeyID: 0xd3, Bech32HRPSegwit: "slug", HDPublicKeyID: [4]byte{0x53, 0x4c, 0x55, 0x47}, HDPrivateKeyID: [4]byte{0x73, 0x6c, 0x75, 0x67}}
}
func cloneManifest(m Manifest) Manifest {
	m.Descriptor.Payments = append([]Payment(nil), m.Descriptor.Payments...)
	m.GymPath = append([]uint32(nil), m.GymPath...)
	m.Accounts = append([]Account(nil), m.Accounts...)
	return m
}
