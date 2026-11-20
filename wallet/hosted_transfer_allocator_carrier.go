// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/json"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// Only the concrete carrier owner can supply this already-selected funding
// capability. Public request JSON cannot call the financial allocation seam.
func (a *HostedAllocator2) planCarrier(ctx context.Context, id string, request AllocationRequest2, funding *preparedCarrierFunding) (*AllocationPlan2, error) {
	if request.Kind != "carrier_return" || funding == nil {
		return nil, ErrAllocationInvalid
	}
	return a.plan(ctx, id, request, nil, nil, funding)
}

func allocationCarrierPin2(b AllocationBinding2) (fightercarrier.Pin, error) {
	id, err := AllocationBindingID2(b)
	if err != nil {
		return fightercarrier.Pin{}, err
	}
	m := b.InitialManifest
	p := fightercarrier.Pin{Version: 1, OwnerMode: "hosted", ManagerSchema: 14, Network: m.Network, Genesis: m.Genesis, WalletProfile: m.Profile, RootPublicKey: m.RootPublicKey, GymPublicKey: m.GymPublicKey, GymID: m.GymID, WalletOwnerID: b.WalletOwnerID, OwnershipPinID: b.OwnershipPinID, AccountAuthorityID: b.AuthorityID, AccountID: b.AccountID, AllocationBindingID: id}
	return p, fightercarrier.ValidatePin(p)
}

func cloneCarrierPreparation2(p fightercarrier.Preparation) fightercarrier.Preparation {
	// Only internally retained, already bounded and validated values reach here.
	raw, _ := json.Marshal(p)
	var out fightercarrier.Preparation
	_ = json.Unmarshal(raw, &out)
	return out
}

func (a *HostedAllocator2) readAllocatedCarrierPreparation2(ctx context.Context, tx walletdb.ReadTx, link waddrmgr.HostedAllocationRecord2) (fightercarrier.Preparation, error) {
	if link.ConsumerKind != "carrier_return" || link.Outcome != "consumed" {
		return fightercarrier.Preparation{}, ErrAllocationConflict
	}
	pin, err := allocationCarrierPin2(a.inventory.binding)
	if err != nil {
		return fightercarrier.Preparation{}, err
	}
	state, err := readCarrierWalletState(ctx, tx, a.inventory.binding.CarrierJournalID, &pin)
	if err != nil {
		return fightercarrier.Preparation{}, err
	}
	for _, row := range state.records {
		if row.RequestID != link.ConsumerID {
			continue
		}
		p := row.Preparation
		if row.BindingID != link.ConsumerBindingID || row.PreparationDigest != link.PreparationDigest || p.Request.Kind != "transfer" || p.NewFunding == nil || p.NewFunding.AllocationID != link.AllocationID || p.NewFunding.ReservationDigest != link.ReservationDigest || p.NewFunding.ReturnPath.Address != link.Address || p.NewFunding.ReturnPath.Script != link.Script || p.NewFunding.ReturnPath.Index != link.SelectedIndex || p.NewFunding.ReturnPath.Branch != link.Branch {
			return fightercarrier.Preparation{}, ErrAllocationCorrupt
		}
		return cloneCarrierPreparation2(p), nil
	}
	return fightercarrier.Preparation{}, ErrAllocationCorrupt
}
