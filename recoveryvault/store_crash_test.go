//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
)

func TestVaultCrashAtDurableBoundaries(t *testing.T) {
	const rootEnv = "SLUG_VAULT_PUBLIC_FIXTURE_CRASH_ROOT"
	const stageEnv = "SLUG_VAULT_PUBLIC_FIXTURE_CRASH_STAGE"
	if root := os.Getenv(rootEnv); root != "" {
		ctx := context.Background()
		h := &vaultHarness{path: filepath.Join(root, "vault"), accountPath: filepath.Join(root, "accounts"), config: vtConfig(), w: &vaultTestWrapper{}}
		var err error
		h.accounts, err = gymaccount.CreateIdentity(h.accountPath, vtAccountConfig())
		if err != nil {
			t.Fatal(err)
		}
		h.v, err = Create(ctx, h.path, h.config, h.accounts, h.w)
		if err != nil {
			t.Fatal(err)
		}
		login := vtLogin(t, h, "alice", 1)
		ack := func(id string) {
			fmt.Println("VAULT_STAGE_SYNCED " + id)
			for {
				time.Sleep(time.Second)
			}
		}
		stage := os.Getenv(stageEnv)
		if stage != "account-enrolled" {
			realWrite := h.v.writeBatch
			h.v.writeBatch = func(batch *leveldb.Batch, options *opt.WriteOptions) error {
				if err := realWrite(batch, options); err != nil {
					return err
				}
				record := new(vtBatchRecord)
				batch.Replay(record)
				if record.record.State == stage {
					ack(record.record.Binding.ProvisionID)
				}
				return nil
			}
		}
		receipt, _, err := h.v.ProvisionFixture(ctx, login.Token)
		if err != nil {
			t.Fatal(err)
		}
		if stage == "account-enrolled" {
			challenge, err := h.accounts.BeginChallenge(ctx, login.Token, "enroll")
			if err != nil {
				t.Fatal(err)
			}
			auth, err := h.v.SignAccountChallenge(ctx, login.Token, challenge)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = h.accounts.CompleteChallenge(ctx, login.Token, challenge.ChallengeID, auth); err != nil {
				t.Fatal(err)
			}
			ack(receipt.Binding.ProvisionID)
		}
		if _, err = h.v.EnsureEnrollment(ctx, login.Token); err != nil {
			t.Fatal(err)
		}
		t.Fatal("target durable stage not reached")
	}
	for _, stage := range []string{"reserved", "sealed", "verified", "account-enrolled", "enrolled"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultCrashAtDurableBoundaries$")
			cmd.Env = append(os.Environ(), rootEnv+"="+root, stageEnv+"="+stage)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			acknowledged := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					if strings.HasPrefix(scanner.Text(), "VAULT_STAGE_SYNCED ") {
						acknowledged <- strings.TrimPrefix(scanner.Text(), "VAULT_STAGE_SYNCED ")
						return
					}
				}
				acknowledged <- ""
			}()
			var original string
			select {
			case original = <-acknowledged:
				if !canonicalHex(original, 32) {
					t.Fatal("child did not acknowledge durable reservation")
				}
			case <-ctx.Done():
				t.Fatal("child timed out")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("child unexpectedly closed cleanly")
			}
			h := &vaultHarness{path: filepath.Join(root, "vault"), accountPath: filepath.Join(root, "accounts"), config: vtConfig(), w: &vaultTestWrapper{}}
			h.accounts, err = gymaccount.OpenIdentity(h.accountPath, vtAccountConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer h.accounts.Close()
			h.v, err = Open(context.Background(), h.path, h.config, h.accounts, h.w)
			if err != nil {
				t.Fatal(err)
			}
			defer h.v.Close()
			login := vtLogin(t, h, "alice", 1)
			receipt, _, err := h.v.ProvisionFixture(context.Background(), login.Token)
			if err != nil || receipt.Binding.ProvisionID != original {
				t.Fatal("crash created replacement provision", err)
			}
			enrolled, err := h.v.EnsureEnrollment(context.Background(), login.Token)
			if err != nil || enrolled.Binding != receipt.Binding {
				t.Fatal("cross-store enrollment reconciliation failed", err)
			}
			status, err := h.v.Status(context.Background(), login.Token)
			if err != nil || status.State != "enrolled" || len(h.v.meta.Accounts) != 1 {
				t.Fatal("crash reservation lost", err)
			}
		})
	}
}
