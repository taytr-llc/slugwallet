// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/poolservice"
	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

const PoolWalletMaxUnlockLifetime = 24 * time.Hour

var (
	ErrPoolWalletInvalid = errors.New("invalid operator pool wallet request")
	ErrPoolWalletBusy    = errors.New("operator pool wallet busy")
	ErrPoolWalletClosed  = errors.New("operator pool wallet closed")
	ErrPoolWalletBinding = errors.New("operator pool wallet binding conflict")
	ErrPoolWalletStorage = errors.New("operator pool wallet storage failed")
)

type PoolWalletBinding struct {
	Version           uint32                       `json:"version"`
	WalletOwnerID     string                       `json:"wallet_owner_id"`
	OperatorProfileID string                       `json:"operator_profile_id"`
	Source            poolshare.Config             `json:"source"`
	Settlement        poolsettle.Config            `json:"settlement"`
	Guard             waddrmgr.PoolSettlementGuard `json:"guard"`
}

func ownedPoolBinding(b PoolWalletBinding) PoolWalletBinding {
	b.Settlement.Destinations = append([]poolsettle.Destination(nil), b.Settlement.Destinations...)
	return b
}
func ValidatePoolWalletBinding(b PoolWalletBinding) error {
	if b.Version != 1 || b.WalletOwnerID != b.Guard.WalletOwnerID || b.OperatorProfileID != b.Guard.OperatorProfileID || waddrmgr.ValidatePoolSettlementGuard(b.Guard) != nil {
		return ErrPoolWalletInvalid
	}
	source, e := poolservice.BindingID(b.Source)
	if e != nil || source != b.Guard.SourceBindingID {
		return ErrPoolWalletBinding
	}
	config, e := poolsettle.ConfigBindingID(b.Settlement)
	if e != nil || config != b.Guard.SettlementConfigID || b.Settlement.ChangeScript != b.Guard.FundingScript {
		return ErrPoolWalletBinding
	}
	funding, e := address.DecodeAddress(b.Source.PayoutAddress, &chaincfg.MainNetParams)
	if e != nil || !funding.IsForNet(&chaincfg.MainNetParams) {
		return ErrPoolWalletBinding
	}
	script, e := txscript.PayToAddrScript(funding)
	if e != nil || hex.EncodeToString(script) != b.Guard.FundingScript {
		return ErrPoolWalletBinding
	}
	return nil
}
