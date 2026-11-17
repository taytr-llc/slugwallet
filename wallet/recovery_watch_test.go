// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"errors"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

type recoveryWatchBackend struct {
	chain.Interface
	batches     []int
	rescans     int
	afterNotify func()
	fail        error
}

func (b *recoveryWatchBackend) NotifyReceived(a []address.Address) error {
	b.batches = append(b.batches, len(a))
	if b.afterNotify != nil {
		b.afterNotify()
	}
	return b.fail
}
func (b *recoveryWatchBackend) Rescan(_ *chainhash.Hash, a []address.Address, _ map[wire.OutPoint]address.Address) error {
	b.rescans++
	return nil
}

func watchBatch(t *testing.T, count int) *rescanBatch {
	t.Helper()
	a, err := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	b := &rescanBatch{addrs: make([]address.Address, count), outpoints: make(map[wire.OutPoint]address.Address)}
	for i := range b.addrs {
		b.addrs[i] = a
	}
	return b
}

func TestRecoveryWatchRegistrationIsBounded(t *testing.T) {
	w := &Wallet{quit: make(chan struct{})}
	w.SetChainSynced(true)
	backend := &recoveryWatchBackend{}
	if err := w.rescanCandidate(backend, watchBatch(t, 257)); err != nil {
		t.Fatal(err)
	}
	if len(backend.batches) != 3 || backend.batches[0] != 128 || backend.batches[1] != 128 || backend.batches[2] != 1 || backend.rescans != 1 {
		t.Fatal("watch batching omitted addresses", backend)
	}
	if w.ChainSynced() {
		t.Fatal("registration alone claimed canonical sync")
	}
	tooLarge := watchBatch(t, int(waddrmgr.RecoveryAttemptLimit)+1)
	backend = &recoveryWatchBackend{}
	if err := w.rescanCandidate(backend, tooLarge); !errors.Is(err, ErrRecoveryCapacity) || len(backend.batches) != 0 || backend.rescans != 0 {
		t.Fatal("capacity rejection dispatched a partial watch", err)
	}
}

func TestRecoveryWatchCancellationAndFailureDoNotRescan(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		w := &Wallet{quit: make(chan struct{})}
		w.SetChainSynced(true)
		backend := &recoveryWatchBackend{fail: errors.New("test node unavailable")}
		if cancel {
			backend.fail = nil
			backend.afterNotify = func() { close(w.quit) }
		}
		if err := w.rescanCandidate(backend, watchBatch(t, 257)); err == nil || backend.rescans != 0 || w.ChainSynced() {
			t.Fatal("failed registration advanced sync", err)
		}
	}
}

func TestRecoveryWatchOutputCeiling(t *testing.T) {
	b := watchBatch(t, 1)
	for i := 0; i <= MaxRecoveryOwnedOutputs; i++ {
		b.outpoints[wire.OutPoint{Index: uint32(i)}] = b.addrs[0]
	}
	if err := validateRecoveryWatch(b); !errors.Is(err, ErrRecoveryCapacity) {
		t.Fatal("unbounded output watch accepted", err)
	}
	delete(b.outpoints, wire.OutPoint{Index: uint32(MaxRecoveryOwnedOutputs)})
	if err := validateRecoveryWatch(b); err != nil {
		t.Fatal("exact watch limit refused", err)
	}
}
