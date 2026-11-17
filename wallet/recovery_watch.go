// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"math"

	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// validateRecoveryWatch measures the actual JSON command with the longest
// uint64 request ID before any registration or rescan is dispatched. The
// authenticated node's unlimited WebSocket read setting is not our budget.
func validateRecoveryWatch(batch *rescanBatch) error {
	if len(batch.addrs) > int(waddrmgr.RecoveryAttemptLimit) || len(batch.outpoints) > MaxRecoveryOwnedOutputs {
		return ErrRecoveryCapacity
	}
	addresses := make([]string, 0, len(batch.addrs))
	for _, a := range batch.addrs {
		if a == nil {
			return ErrRecoverySource
		}
		addresses = append(addresses, a.EncodeAddress())
	}
	outputs := make([]btcjson.OutPoint, 0, len(batch.outpoints))
	for op := range batch.outpoints {
		outputs = append(outputs, btcjson.OutPoint{Hash: op.Hash.String(), Index: op.Index})
	}
	command := btcjson.NewRescanCmd(batch.bs.Hash.String(), addresses, outputs, nil)
	encoded, err := btcjson.MarshalCmd(btcjson.RpcVersion1, uint64(math.MaxUint64), command)
	if err != nil || len(encoded) > MaxRecoveryWatchRequestBytes {
		return ErrRecoveryCapacity
	}
	return nil
}

func (w *Wallet) rescanCandidate(chainClient chain.Interface, batch *rescanBatch) error {
	w.SetChainSynced(false)
	if err := validateRecoveryWatch(batch); err != nil {
		return err
	}
	for start := 0; start < len(batch.addrs); start += int(waddrmgr.RecoveryChunkSize) {
		select {
		case <-w.quitChan():
			return ErrWalletShuttingDown
		default:
		}
		end := start + int(waddrmgr.RecoveryChunkSize)
		if end > len(batch.addrs) {
			end = len(batch.addrs)
		}
		if err := chainClient.NotifyReceived(batch.addrs[start:end]); err != nil {
			return err
		}
	}
	w.recoverySyncFailed.Store(false)
	return chainClient.Rescan(&batch.bs.Hash, batch.addrs, batch.outpoints)
}
