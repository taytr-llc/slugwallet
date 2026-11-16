// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

// Package productionprofile defines the unfinalized D73 recovery contract and
// its two published candidate fixtures. It does not authorize production issuance.
package productionprofile

import "errors"

const (
	DescriptorVersion1         uint32 = 1
	Version2                   uint32 = 2
	ProfileID                         = "slug-production-bip39-v1"
	SeedScheme                        = "bip39-english-24-empty-v1"
	PaymentDerivation                 = "bip32-standard-v1"
	GymScheme                         = "slug-gym-slip13-slip10-secp256k1-v1"
	CandidateCoinType          uint32 = 1397511495
	CandidateZero256                  = "candidate-zero256"
	CandidateIncrementing256          = "candidate-incrementing256"
	MaxNextIndex               uint32 = 0x80000000
	FixtureRuntimeMaxNextIndex uint32 = 4096
	MaxDescriptorSize                 = 8192
	MaxManifestSize                   = 16384
	MaxExportSize                     = 24576
	MaxPhraseSize                     = 256
)

var (
	ErrProfile            = errors.New("invalid or unsupported recovery profile")
	ErrManifest           = errors.New("invalid recovery manifest")
	ErrFixture            = errors.New("unsupported public candidate fixture")
	ErrDerivation         = errors.New("recovery derivation unavailable")
	ErrProfileUnfinalized = errors.New("production recovery profile is not finalized for issuance")
)

type Encodings struct {
	P2PKH      string `json:"p2pkh"`
	P2SH       string `json:"p2sh"`
	WIF        string `json:"wif"`
	WitnessHRP string `json:"witness_hrp"`
	HDPublic   string `json:"hd_public"`
	HDPrivate  string `json:"hd_private"`
}
type Payment struct {
	Purpose      uint32 `json:"purpose"`
	Account      uint32 `json:"account"`
	ExternalType string `json:"external_type"`
	InternalType string `json:"internal_type"`
}
type Descriptor struct {
	Version               uint32    `json:"version"`
	Profile               string    `json:"profile"`
	Seed                  string    `json:"seed"`
	PaymentDerivation     string    `json:"payment_derivation"`
	Network               uint32    `json:"network"`
	Genesis               string    `json:"genesis"`
	CoinType              uint32    `json:"coin_type"`
	Encodings             Encodings `json:"encodings"`
	Payments              []Payment `json:"payments"`
	DefaultReceivePurpose uint32    `json:"default_receive_purpose"`
	DefaultChangePurpose  uint32    `json:"default_change_purpose"`
	GymScheme             string    `json:"gym_scheme"`
	GymIdentityIndex      uint32    `json:"gym_identity_index"`
	ScanFromHeight        uint32    `json:"scan_from_height"`
}
type Cursor struct {
	Purpose      uint32 `json:"purpose"`
	NextExternal uint32 `json:"next_external"`
	NextInternal uint32 `json:"next_internal"`
}
type Account struct {
	Purpose          uint32 `json:"purpose"`
	Coin             uint32 `json:"coin"`
	Account          uint32 `json:"account"`
	ExternalType     string `json:"external_type"`
	InternalType     string `json:"internal_type"`
	KeyOrigin        string `json:"key_origin"`
	AccountPublicKey string `json:"account_public_key"`
	NextExternal     uint32 `json:"next_external"`
	NextInternal     uint32 `json:"next_internal"`
}
type Manifest struct {
	Version        uint32     `json:"version"`
	Descriptor     Descriptor `json:"descriptor"`
	DescriptorHash string     `json:"descriptor_hash"`
	RootPublicKey  string     `json:"root_public_key"`
	GymIdentityURI string     `json:"gym_identity_uri"`
	GymPath        []uint32   `json:"gym_path"`
	GymPublicKey   string     `json:"gym_public_key"`
	GymID          string     `json:"gym_id"`
	Accounts       []Account  `json:"accounts"`
}

// Export is secret local recovery material. Never log it or expose it through
// public RPC, a webview, status, or provider claims.
type Export struct {
	Version  uint32   `json:"version"`
	Mnemonic string   `json:"mnemonic"`
	Manifest Manifest `json:"manifest"`
}
type PaymentPublic struct {
	Purpose      uint32 `json:"purpose"`
	Branch       uint32 `json:"branch"`
	Index        uint32 `json:"index"`
	Path         string `json:"path"`
	PublicKey    string `json:"public_key"`
	ScriptPubKey string `json:"script_pub_key"`
	Address      string `json:"address"`
	InternalKey  string `json:"internal_key,omitempty"`
	OutputKey    string `json:"output_key,omitempty"`
}
