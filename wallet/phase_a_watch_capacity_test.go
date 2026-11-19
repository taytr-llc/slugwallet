//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
)

// This is a transport-dispatch fixture, not a node or derivation oracle. Its
// distinct standard addresses make omissions/reordering observable cheaply.
func phaseAWatchCapacityBatch(t *testing.T, count int) *rescanBatch {
	t.Helper()
	batch := &rescanBatch{addrs: make([]address.Address, count), outpoints: make(map[wire.OutPoint]address.Address)}
	for index := range batch.addrs {
		var payload [20]byte
		binary.LittleEndian.PutUint32(payload[:4], uint32(index))
		item, err := address.NewAddressWitnessPubKeyHash(payload[:], &chaincfg.MainNetParams)
		if err != nil {
			t.Fatal(err)
		}
		batch.addrs[index] = item
	}
	return batch
}

type phaseAWatchCapacityBackend struct {
	chain.Interface
	t       *testing.T
	want    []address.Address
	seen    int
	batches int
	rescans int
	after   func(int)
	failAt  int
	failure error
}

func (b *phaseAWatchCapacityBackend) NotifyReceived(items []address.Address) error {
	b.t.Helper()
	b.batches++
	if len(items) != 128 || b.seen+len(items) > len(b.want) {
		b.t.Fatal("unbounded or extra watch batch", len(items), b.seen)
	}
	for index, item := range items {
		if item.EncodeAddress() != b.want[b.seen+index].EncodeAddress() {
			b.t.Fatal("watch omitted, substituted or reordered an address")
		}
	}
	b.seen += len(items)
	if b.after != nil {
		b.after(b.batches)
	}
	if b.batches == b.failAt {
		return b.failure
	}
	return nil
}
func (b *phaseAWatchCapacityBackend) Rescan(_ *chainhash.Hash, items []address.Address, _ map[wire.OutPoint]address.Address) error {
	b.t.Helper()
	b.rescans++
	if b.seen != len(b.want) || len(items) != len(b.want) {
		b.t.Fatal("rescan began with an incomplete maximum watch")
	}
	for index, item := range items {
		if item.EncodeAddress() != b.want[index].EncodeAddress() {
			b.t.Fatal("rescan substituted the original watch inventory")
		}
	}
	return nil
}

func TestPhaseARecoveryMaximumWatchDispatch(t *testing.T) {
	_, session := phaseABegin(t, phaseABundle(t, false))
	// A real validated schema12 manager selects the production dispatch limit.
	// No ready/synced claim is inferred from this isolated backend test.
	for _, mode := range []string{"complete", "capacity", "cancel", "failure"} {
		t.Run(mode, func(t *testing.T) {
			count := 32768
			if mode == "capacity" {
				count++
			}
			batch := phaseAWatchCapacityBatch(t, count)
			w := &Wallet{Manager: session.manager, quit: make(chan struct{})}
			w.SetChainSynced(true)
			failure := errors.New("watch registration unavailable")
			backend := &phaseAWatchCapacityBackend{t: t, want: batch.addrs, failure: failure}
			switch mode {
			case "cancel":
				backend.after = func(number int) {
					if number == 1 {
						close(w.quit)
					}
				}
			case "failure":
				backend.failAt = 128
			}
			err := w.rescanCandidate(backend, batch)
			if w.ChainSynced() {
				t.Fatal("watch registration asserted chain synchronization")
			}
			switch mode {
			case "complete":
				if err != nil || backend.batches != 256 || backend.seen != 32768 || backend.rescans != 1 {
					t.Fatal("maximum watch omitted a chunk", err, backend.batches, backend.seen, backend.rescans)
				}
			case "capacity":
				if !errors.Is(err, ErrRecoveryCapacity) || backend.batches != 0 || backend.rescans != 0 {
					t.Fatal("over-capacity watch partially dispatched", err)
				}
			case "cancel":
				if !errors.Is(err, ErrWalletShuttingDown) || backend.batches != 1 || backend.rescans != 0 {
					t.Fatal("cancelled watch continued or rescanned", err)
				}
			case "failure":
				if !errors.Is(err, failure) || backend.batches != 128 || backend.rescans != 0 {
					t.Fatal("failed watch continued or rescanned", err)
				}
			}
		})
	}
}
