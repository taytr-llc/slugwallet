//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.

package recoveryvault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestVaultRotationRejectsPreparedStaleOperation(t *testing.T) {
	for _, operation := range []string{"export", "rewrap"} {
		t.Run(operation, func(t *testing.T) {
			h := vtSetup(t)
			login := vtLogin(t, h, "alice", 1)
			original := vtReady(t, h, login.Token)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var blocked atomic.Bool
			h.w.setHook(func(ctx context.Context, _ string) error {
				if blocked.CompareAndSwap(false, true) {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
			path := filepath.Join(t.TempDir(), "recovery.json")
			done := make(chan error, 1)
			go func() {
				if operation == "export" {
					done <- h.v.ExportRecoveryFile(ctx, login.Token, path)
					return
				}
				receipt, changed, err := h.v.Rewrap(ctx, login.Token, "recovery-new", "gym-new")
				if err != nil && (receipt.Binding != (Binding{}) || changed) {
					done <- errors.New("stale rotation returned a committed receipt")
					return
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("original operation did not reach provider")
			}
			winner, changed, err := h.v.Rewrap(ctx, login.Token, "recovery-new", "gym-new")
			close(release)
			staleErr := <-done
			if err != nil || !changed || !reflect.DeepEqual(winner, original) {
				t.Fatal("concurrent rotation failed or changed identity", err)
			}
			if !errors.Is(staleErr, ErrConflict) {
				t.Fatal("prepared old revision was published", staleErr)
			}
			if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stale operation wrote plaintext")
			}
			h.w.setHook(nil)
			vtReopen(t, h)
			status, err := h.v.Status(ctx, login.Token)
			if err != nil || status.Revision != 5 || status.RecoveryWrapRevision != 2 || status.GymWrapRevision != 2 || status.Receipt == nil || !reflect.DeepEqual(*status.Receipt, original) {
				t.Fatal("stale preparation replaced the committed rotation", err)
			}
		})
	}
}
