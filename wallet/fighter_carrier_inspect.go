// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// InspectPrepared returns only the exact retained unsigned preparation. This
// owned projection helps recover a lost Prepare acknowledgment; it does not
// mint a signing capability or assert current chain ownership/spendability.
// ResumePrepared/ResumeRecoveryPrepared still require a fresh concrete public
// ownership capability and validate the original saved tuple before disclosure.
func (o *FighterCarrierOwner) InspectPrepared(ctx context.Context, requestID string) (CarrierPreparation, error) {
	var result CarrierPreparation
	if o == nil || !withdrawalHex(requestID, 32, true) {
		return result, fightercarrier.ErrInvalid
	}
	work, end, err := o.owner.acquire(ctx)
	if err != nil {
		return result, err
	}
	defer end()
	check := func() error {
		if err := o.alive(); err != nil {
			return err
		}
		if o.allocated != nil {
			return o.allocated.check(work, gymaccount.View)
		}
		return work.Err()
	}
	if err = check(); err != nil {
		return result, err
	}
	err = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
		state, err := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
		if err != nil {
			return err
		}
		if err = o.auditExclusions(work, tx); err != nil {
			return err
		}
		for _, record := range state.records {
			if record.RequestID != requestID {
				continue
			}
			if record.State != "prepared" {
				return fightercarrier.ErrConflict
			}
			result = cloneCarrierPreparation(record.Preparation)
			return work.Err()
		}
		return fightercarrier.ErrNotFound
	})
	if err != nil {
		return CarrierPreparation{}, err
	}
	if err = check(); err != nil {
		return CarrierPreparation{}, err
	}
	return result, nil
}
