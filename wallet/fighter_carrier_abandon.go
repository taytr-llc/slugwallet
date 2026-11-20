// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// AbandonUnprepared burns only an exact, durably reserved return range whose
// carrier preparation never committed. The caller must release its journal
// lease first. This method does not abandon the app intent: the caller publishes
// that separately after this method succeeds, under its original action fence.
// A committed preparation must instead use the typed journal reconciliation.
func (o *FighterCarrierOwner) AbandonUnprepared(ctx context.Context, requestID string) error {
	if o == nil || !withdrawalHex(requestID, 32, true) {
		return fightercarrier.ErrInvalid
	}
	work, end, err := o.owner.acquire(ctx)
	if err != nil {
		return err
	}
	defer end()
	if err = o.authorize(work); err != nil {
		return err
	}
	app, err := o.journal.TryAcquire(work)
	if err != nil {
		return err
	}
	defer app.Close()
	operation, err := app.Lookup(requestID)
	if err != nil {
		return err
	}
	if operation.Stage != "intent" || operation.Preparation != nil || operation.SignedPackage != nil {
		return fightercarrier.ErrConflict
	}
	// The exact journal owner and carrier gate remain retained through the whole
	// operation. No other carrier action can prepare/sign this intent meanwhile.
	a := o.allocated
	var reserved, burned bool
	audit := func(tx walletdb.ReadTx) error {
		state, err := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
		if err != nil {
			return err
		}
		if err = o.auditExclusions(work, tx); err != nil {
			return err
		}
		for _, record := range state.records {
			if record.RequestID == requestID {
				return fightercarrier.ErrConflict
			}
		}
		if a == nil {
			return work.Err()
		}
		local, err := a.auditPair(work, tx)
		if err != nil {
			return err
		}
		for id, row := range a.inventory.rows {
			r := row.Reservation.Request
			if id != requestID && (r.Kind != "carrier_return" || r.ConsumerID != requestID) {
				continue
			}
			if id != requestID || r.Kind != "carrier_return" || r.ConsumerID != requestID || r.CarrierBindingID != o.binding || r.OwnershipPinID != o.pin.OwnershipPinID || r.PriorStateID != operation.Request.PriorStateID || r.RecipientGym != operation.Request.RecipientGym || operation.Request.Kind != "transfer" {
				return fightercarrier.ErrConflict
			}
			reserved = true
			if row.Phase != "reserved" && row.Phase != "burned" {
				return fightercarrier.ErrConflict
			}
		}
		for _, record := range local.Records {
			if record.AllocationID == requestID {
				if !reserved || record.Outcome != "burned" {
					return fightercarrier.ErrConflict
				}
				burned = true
			}
		}
		return work.Err()
	}
	if a != nil {
		// Serialize the paired inventory read, but release its permit before
		// invoking the concrete Resume/Burn/Resolve methods that acquire it.
		_, release, e := a.acquire(work)
		if e != nil {
			return e
		}
		err = walletdb.View(o.wallet.db, audit)
		release()
	} else {
		err = walletdb.View(o.wallet.db, audit)
	}
	if err != nil {
		return err
	}
	if err = o.authorize(work); err != nil {
		return err
	}
	if !reserved {
		return nil // Audited absence, including the schema15 no-local case.
	}
	mutated := false
	var ack *AllocationAcknowledgement2
	if burned {
		ack, err = a.Resolve(work, requestID)
	} else {
		var reservation *AllocationReservation2
		reservation, err = a.Resume(work, requestID)
		if err == nil {
			var receipt *AllocationReceipt2
			receipt, err = a.Burn(work, reservation)
			if err == nil {
				mutated = true
				ack, err = a.Acknowledge(work, receipt)
			}
		}
	}
	if err == nil {
		mutated = true // Completion may have persisted even after a lost burn ack.
		if ack == nil || ack.owner != a || ack.row.Reservation.AllocationID != requestID || ack.record.Outcome != "burned" || ack.row.Phase != "burned" || ack.carrier != nil {
			err = fightercarrier.ErrCorrupt
		} else {
			err = o.authorize(work)
		}
	}
	if err != nil && (mutated || errors.Is(err, ErrAllocationOutcomeUnknown) || a.poisoned.Load() || a.inventory.poisoned.Load()) {
		// Never turn an uncertain local or external commit into a release. A
		// fresh owner must audit the exact persisted range before trying again.
		o.poisoned.Store(true)
		a.poisoned.Store(true)
		o.wallet.hostedAllocationTainted.Store(true)
		return errors.Join(fightercarrier.ErrOutcomeUnknown, err)
	}
	return err
}
