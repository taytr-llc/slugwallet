// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (w *Wallet) rescanHostedAllocation(client chain.Interface, batch *rescanBatch) error {
	w.SetChainSynced(false)
	if !w.Manager.HostedAllocation() || w.recoveryWindow != 0 {
		return waddrmgr.ErrHostedAllocationProfile
	}
	if e := validateRecoveryWatchLimit(batch, 32768); e != nil {
		return e
	}
	e := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		allowed := make(map[string]bool)
		switch w.Manager.CarrierSchema() {
		case waddrmgr.HostedTransferManagerVersion:
			state, e := w.Manager.AuditHostedAllocation2(context.Background(), ns, tx.ReadBucket(hostedAllocationNamespace2))
			if e != nil {
				return e
			}
			for _, r := range state.Records {
				allowed[r.Address] = true
			}
		case waddrmgr.RestoredCarrierManagerVersion:
			if _, e := w.Manager.AuditRestoredCarrier(context.Background(), ns); e != nil {
				return e
			}
			// Activation preserves the already-issued four-scope inventory.
			// The manager iterator excludes unused scanner lookahead. Carrier
			// issuance remains native84-only; this read never extends a cursor.
			if e := w.Manager.ForEachRelevantActiveAddress(ns, func(a address.Address) error {
				select {
				case <-w.quitChan():
					return ErrWalletShuttingDown
				default:
				}
				if a == nil || allowed[a.EncodeAddress()] {
					return waddrmgr.ErrHostedAllocationFrontier
				}
				if len(allowed) >= 32768 {
					return ErrRecoveryCapacity
				}
				allowed[a.EncodeAddress()] = true
				return nil
			}); e != nil {
				return e
			}
		default:
			state, e := w.Manager.AuditHostedAllocation(context.Background(), ns, tx.ReadBucket(hostedAllocationNamespace))
			if e != nil {
				return e
			}
			for _, r := range state.Records {
				allowed[r.Address] = true
			}
		}
		seen := make(map[string]bool, len(batch.addrs))
		for _, a := range batch.addrs {
			select {
			case <-w.quitChan():
				return ErrWalletShuttingDown
			default:
			}
			if a == nil || !allowed[a.EncodeAddress()] || seen[a.EncodeAddress()] {
				return waddrmgr.ErrHostedAllocationFrontier
			}
			seen[a.EncodeAddress()] = true
		}
		// A full startup batch watches every durable consumed/burned address; a
		// smaller explicit rescan is permitted only for those same known paths.
		return nil
	})
	if e != nil {
		w.recoverySyncFailed.Store(true)
		return e
	}
	// A fresh carrier wallet can have no issued addresses. The batched watch
	// loop has no iterations in that case, so check cancellation before Rescan.
	if w.Manager.CarrierSchema() != 0 {
		select {
		case <-w.quitChan():
			return ErrWalletShuttingDown
		default:
		}
	}
	return w.rescanRecoveryLimit(client, batch, 32768)
}
