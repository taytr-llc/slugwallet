// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
)

const PoolSettlementManagerVersion uint32 = 16
const PoolSettlementDerivation = "slug-phase-a-operator-pool-native84-v1"

var poolSettlementGuardKey = []byte("poolsettlementguardv1")
var (
	ErrPoolSettlementInvalid  = errors.New("invalid operator pool wallet request")
	ErrPoolSettlementProfile  = errors.New("unsupported operator pool wallet profile")
	ErrPoolSettlementConflict = errors.New("operator pool wallet binding conflict")
	ErrPoolSettlementCorrupt  = errors.New("operator pool wallet state invalid")
)

type PoolSettlementGuard struct {
	Version            uint32 `json:"version"`
	ManagerSchema      uint32 `json:"manager_schema"`
	WalletOwnerID      string `json:"wallet_owner_id"`
	OperatorProfileID  string `json:"operator_profile_id"`
	SourceBindingID    string `json:"source_binding_id"`
	SettlementConfigID string `json:"settlement_config_id"`
	DerivationID       string `json:"derivation_id"`
	Network            uint32 `json:"network"`
	Genesis            string `json:"genesis"`
	RootPublicKey      string `json:"root_public_key"`
	FundingPublicKey   string `json:"funding_public_key"`
	FundingScript      string `json:"funding_script"`
}

func poolHex(s string, size int, nonzero bool) bool {
	if len(s) != size*2 {
		return false
	}
	raw, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(raw) == s && (!nonzero || !bytes.Equal(raw, make([]byte, size)))
}
func ValidatePoolSettlementGuard(g PoolSettlementGuard) error {
	if g.Version != 1 || g.ManagerSchema != 16 || g.DerivationID != PoolSettlementDerivation || g.Network != uint32(chaincfg.MainNetParams.Net) || g.Genesis != chaincfg.MainNetParams.GenesisHash.String() {
		return ErrPoolSettlementInvalid
	}
	for _, s := range []string{g.WalletOwnerID, g.OperatorProfileID, g.SourceBindingID, g.SettlementConfigID} {
		if !poolHex(s, 32, true) {
			return ErrPoolSettlementInvalid
		}
	}
	if len(g.RootPublicKey) == 0 || len(g.RootPublicKey) > 120 || !poolHex(g.FundingPublicKey, 33, false) || !poolHex(g.FundingScript, 22, false) {
		return ErrPoolSettlementInvalid
	}
	root, e := hdkeychain.NewKeyFromString(g.RootPublicKey)
	if e != nil {
		return ErrPoolSettlementInvalid
	}
	defer root.Zero()
	if root.IsPrivate() || !root.IsForNet(&chaincfg.MainNetParams) || root.Depth() != 0 || root.ParentFingerprint() != 0 || root.ChildIndex() != 0 || root.String() != g.RootPublicKey {
		return ErrPoolSettlementInvalid
	}
	raw, _ := hex.DecodeString(g.FundingPublicKey)
	pub, e := btcec.ParsePubKey(raw)
	if e != nil || !bytes.Equal(pub.SerializeCompressed(), raw) || g.FundingScript != "0014"+hex.EncodeToString(address.Hash160(raw)) {
		return ErrPoolSettlementInvalid
	}
	return nil
}
func MarshalPoolSettlementGuard(g PoolSettlementGuard) ([]byte, error) {
	if e := ValidatePoolSettlementGuard(g); e != nil {
		return nil, e
	}
	b, e := json.Marshal(g)
	if e != nil || len(b) > 4096 {
		return nil, ErrPoolSettlementInvalid
	}
	return b, nil
}
func ParsePoolSettlementGuard(raw []byte) (PoolSettlementGuard, error) {
	var g PoolSettlementGuard
	if len(raw) == 0 || len(raw) > 4096 {
		return g, ErrPoolSettlementCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&g) != nil {
		return g, ErrPoolSettlementCorrupt
	}
	canon, e := MarshalPoolSettlementGuard(g)
	if e != nil || !bytes.Equal(canon, raw) {
		return PoolSettlementGuard{}, ErrPoolSettlementCorrupt
	}
	return g, nil
}
func PoolSettlementGuardDigest(g PoolSettlementGuard) (string, error) {
	raw, e := MarshalPoolSettlementGuard(g)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	h.Write([]byte("SLUG operator pool wallet guard\x00v1\x00"))
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(raw)))
	h.Write(n[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (m *Manager) PoolSettlement() bool { return m != nil && m.poolSettlement }

// GenericSpendError classifies guarded purpose, never grants a signing capability.
func (m *Manager) GenericSpendError() error {
	if m.PoolSettlement() {
		return ErrPoolSettlementProfile
	}
	if m.HostedAllocation() {
		return ErrHostedAllocationProfile
	}
	return nil
}
