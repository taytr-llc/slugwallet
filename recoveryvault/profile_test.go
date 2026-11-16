//go:build slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/prospectnode"
)

func TestVaultRejectsCheapProfileBeforeFiles(t *testing.T) {
	ctx := context.Background()
	accounts, err := gymaccount.CreateIdentity(filepath.Join(t.TempDir(), "accounts"), gymaccount.IdentityConfig{
		Version: 2, VerifierConfigHash: strings.Repeat("a", 64), MaxLoginAttempts: 128,
		Accounts: gymaccount.Config{Version: 1, Principals: []gymaccount.FixturePrincipal{
			{Issuer: "fixture:vault", Subject: "alice", Fixture: "zero256"},
			{Issuer: "fixture:vault", Subject: "bob", Fixture: "incrementing256"},
		}, MaxSessions: 256, MaxChallenges: 128, MaxEvents: 512},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	config, err := normalizedConfig(Config{Version: 1, WrapperID: "core-public-fixture", RecoveryKeyRef: "recovery-old", GymKeyRef: "gym-old", AllowedRecoveryKeyRefs: []string{"recovery-old", "recovery-new"}, AllowedGymKeyRefs: []string{"gym-old", "gym-new"}, MaxOperations: 128, Policy: prospectnode.Policy{Version: 1, Network: gymaccount.FixtureNetwork, Genesis: gymaccount.FixtureGenesis, DNAVersion: 1, ProspectTarget: strings.Repeat("f", 64)}})
	if err != nil {
		t.Fatal("otherwise-valid configuration", err)
	}
	authority, err := accounts.AuthorityInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := new(coreWrapper)
	t.Run("create", func(t *testing.T) {
		createPath := filepath.Join(t.TempDir(), "uncreated")
		vault, err := Create(ctx, createPath, config, accounts, wrapper)
		if vault != nil {
			vault.Close()
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatal("cheap profile accepted valid creation", err)
		}
		if _, err = os.Stat(createPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cheap profile touched files")
		}

	})

	// Construct an otherwise-valid empty retained database without calling the
	// guarded Create. Removing its profile check would let Open succeed here.
	t.Run("open", func(t *testing.T) {
		openPath := t.TempDir()
		header := vaultHeader{Application: vaultApplication, Version: Version1, Authority: authority, Config: config}
		raw, err := json.Marshal(header)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(openPath, vaultMarker), raw, 0600); err != nil {
			t.Fatal(err)
		}
		db, err := leveldb.OpenFile(filepath.Join(openPath, "db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		metadata := vaultMetadata{Header: header, Accounts: []reservationIndex{}}
		batch := new(leveldb.Batch)
		if err = putVault(batch, "meta", metadata); err != nil {
			t.Fatal(err)
		}
		if err = db.Write(batch, &opt.WriteOptions{Sync: true}); err != nil {
			t.Fatal(err)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
		vault, err := Open(ctx, openPath, config, accounts, wrapper)
		if vault != nil {
			vault.Close()
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatal("cheap profile opened otherwise-valid retained database", err)
		}
	})
}
