// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

func TestRecoveryLoaderRejectsBeforeFilesystem(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "never-created")
	l := NewLoader(&chaincfg.MainNetParams, path, true, time.Second, 0)
	cursors := productionprofile.DefaultCursors()
	cursors[0].NextExternal = waddrmgr.RecoveryAttemptLimit
	bundle, err := productionprofile.FixtureExport(ctx, productionprofile.CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.BeginCandidateRecovery(ctx, retainedPubPass, retainedPrivPass, bundle); err == nil {
		t.Fatal("oversized runtime accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal created directory", err)
	}
	if _, err := l.BeginCandidateFixture(ctx, retainedPubPass, retainedPrivPass, "production"); err == nil {
		t.Fatal("unknown production fixture accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unknown fixture created directory", err)
	}
	if wire.TestPoW {
		bundle, err = productionprofile.FixtureExport(ctx, productionprofile.CandidateZero256, productionprofile.DefaultCursors())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = l.BeginCandidateRecovery(ctx, retainedPubPass, retainedPrivPass, bundle); err == nil {
			t.Fatal("cheap recovery created production identity")
		}
		if _, err := l.OpenCandidateRecovery(ctx, retainedPubPass); err == nil {
			t.Fatal("cheap recovery open accepted")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cheap refusal created directory", err)
		}
	}
}

func TestRecoveryLoaderExclusivePendingOwnership(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal candidate recovery")
	}
	ctx := context.Background()
	l := NewLoader(&chaincfg.MainNetParams, filepath.Join(t.TempDir(), "wallet"), true, time.Second, 0)
	s, err := l.BeginCandidateFixture(ctx, retainedPubPass, retainedPrivPass, productionprofile.CandidateZero256)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, loaded := l.LoadedWallet(); loaded {
		t.Fatal("pending session exposed usable wallet")
	}
	if _, err := l.OpenExistingWallet(retainedPubPass, false); !errors.Is(err, ErrLoaded) {
		t.Fatal("normal wallet stole session", err)
	}
	if _, err := l.OpenCandidateRecovery(ctx, retainedPubPass); !errors.Is(err, ErrLoaded) {
		t.Fatal("second session opened", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.OpenExistingWallet(retainedPubPass, false); !errors.Is(err, waddrmgr.ErrRecoveryInProgress) {
		t.Fatal("pending wallet loaded normally", err)
	}
	s, err = l.OpenCandidateRecovery(ctx, retainedPubPass)
	if err != nil {
		t.Fatal("pending session could not reopen", err)
	}
	if _, err := s.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
