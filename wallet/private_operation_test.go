// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

func TestPrivateOperationCancelledContention(t *testing.T) {
	w := &Wallet{started: true, quit: make(chan struct{})}
	w.quitMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := w.holdUnlockContext(ctx)
	cancel()
	w.quitMu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lifecycle lock: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := w.holdUnlockContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("already cancelled: %v", err)
	}
	if _, err := new(Wallet).holdUnlockContext(context.Background()); !errors.Is(err, ErrWalletShuttingDown) {
		t.Fatalf("unstarted wallet: %v", err)
	}
}

// Delay the response after the locker accepts a request. Cancellation must
// drain that accepted handshake and release its hold, not abandon the receiver.
func TestPrivateOperationCancellationAfterAcceptance(t *testing.T) {
	w := &Wallet{
		started: true, quit: make(chan struct{}),
		holdUnlockRequests: make(chan chan heldUnlock),
	}
	accepted, reply, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		request := <-w.holdUnlockRequests
		close(accepted)
		<-reply
		hold := make(heldUnlock)
		request <- hold
		<-hold
		close(released)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := w.holdUnlockContext(ctx); result <- err }()
	<-accepted
	cancel()
	close(reply)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("accepted cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled accepted request left an unlock hold")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("locker did not receive its release")
	}
}

func TestPrivateOperationRealLocker(t *testing.T) {
	// Published BIP32 vector seed, not an account or operator key.
	seed := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	password := []byte("PUBLIC fixture encryption password")
	loader := NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 20)
	w, err := loader.CreateNewWallet([]byte("public"), password, seed, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loader.UnloadWallet(); err != nil {
			t.Error(err)
		}
	})
	if _, err := w.holdUnlockContext(context.Background()); !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		t.Fatalf("locked wallet: %v", err)
	}
	if err := w.Unlock(password, nil); err != nil {
		t.Fatal(err)
	}
	lease, err := w.holdUnlockContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = w.holdUnlockContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		lease.release()
		t.Fatalf("waiting behind another lease: %v", err)
	}

	// Start may hold quitMu while joining the old locker. The captured quit
	// channel allows the outstanding operation to finish and release anyway.
	w.Stop()
	restarted := make(chan struct{})
	go func() { w.Start(); close(restarted) }()
	deadline := time.Now().Add(time.Second)
	for w.quitMu.TryLock() {
		w.quitMu.Unlock()
		if time.Now().After(deadline) {
			lease.release()
			t.Fatal("restart did not wait for held operation")
		}
		time.Sleep(time.Millisecond)
	}
	if err := lease.err(context.Background()); !errors.Is(err, ErrWalletShuttingDown) {
		lease.release()
		t.Fatalf("captured shutdown state: %v", err)
	}
	lease.release()
	select {
	case <-restarted:
	case <-time.After(time.Second):
		t.Fatal("restart failed to drain held operation")
	}
	lease, err = w.holdUnlockContext(context.Background())
	if err != nil {
		t.Fatalf("lease after restart: %v", err)
	}
	lease.release()
}
