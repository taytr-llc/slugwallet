// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
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
		state, e := w.Manager.AuditHostedAllocation(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), tx.ReadBucket(hostedAllocationNamespace))
		if e != nil {
			return e
		}
		allowed := make(map[string]bool, len(state.Records))
		for _, r := range state.Records {
			allowed[r.Address] = true
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
	return w.rescanRecoveryLimit(client, batch, 32768)
}
