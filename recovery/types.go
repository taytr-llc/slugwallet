// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recovery

const (
	Version1           uint32 = 1
	ProfileID                 = "slug-phase-a-fixture-bip39-v1"
	DerivationStandard        = "bip32-standard-v1"
	Network            uint32 = 0x534c5547
	Genesis                   = "7893676099cf9985bb198dfb6a347d9422a19f2422cf3326a999a7230ce246cd"
	GymPath                   = "m/1397511495'/1'/0'"
	MaxBranchIndex     uint32 = 4096
	MaxPhraseSize             = 256
	MaxManifestSize           = 65536
	MaxExportSize             = 65536
)

// Account describes the supported deterministic account and its next unused
// branch indexes. The fixture profile contains account zero in all four scopes.
type Account struct {
	Purpose      uint32 `json:"purpose"`
	Coin         uint32 `json:"coin"`
	Account      uint32 `json:"account"`
	ExternalType string `json:"external_type"`
	InternalType string `json:"internal_type"`
	NextExternal uint32 `json:"next_external"`
	NextInternal uint32 `json:"next_internal"`
}

// Manifest is public recovery metadata. Its identities must be bound to the
// retained entropy before export or restore; structural validation alone does
// not authenticate who supplied it.
type Manifest struct {
	Version        uint32    `json:"version"`
	Profile        string    `json:"profile"`
	Network        uint32    `json:"network"`
	Genesis        string    `json:"genesis"`
	Derivation     string    `json:"derivation"`
	ScanFromHeight uint32    `json:"scan_from_height"`
	RootPublicKey  string    `json:"root_public_key"`
	GymPath        string    `json:"gym_path"`
	GymPublicKey   string    `json:"gym_public_key"`
	GymID          string    `json:"gym_id"`
	Accounts       []Account `json:"accounts"`
}

// Export contains secret recovery material. Never log it or expose it through
// public snapshots. Its mnemonic uses the empty BIP39 passphrase exclusively.
type Export struct {
	Version  uint32   `json:"version"`
	Mnemonic string   `json:"mnemonic"`
	Manifest Manifest `json:"manifest"`
}

// GymPathIndices returns an owned copy of the fixed fixture derivation path.
// This local convention is not a registered BIP purpose or production policy.
func GymPathIndices() [3]uint32 { return [3]uint32{0xd34c5547, 0x80000001, 0x80000000} }

// DefaultAccounts returns a fresh ordered account inventory for this profile.
func DefaultAccounts() []Account {
	return []Account{
		{Purpose: 44, ExternalType: "p2pkh", InternalType: "p2pkh"},
		{Purpose: 49, ExternalType: "p2sh-p2wpkh", InternalType: "p2wpkh"},
		{Purpose: 84, ExternalType: "p2wpkh", InternalType: "p2wpkh"},
		{Purpose: 86, ExternalType: "p2tr", InternalType: "p2tr"},
	}
}
