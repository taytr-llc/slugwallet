//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type reviewRecoveryCrashState struct {
	Directory string `json:"directory"`
	Stage     string `json:"stage"`
}

func reviewRecoveryCrashSource(t *testing.T, fork bool) (*reviewRecoverySource, []*wire.MsgBlock) {
	t.Helper()
	genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	first := reviewFundingBlock(t, genesis, 1, 17, reviewPayment(t, 84, 0, 26))
	second := reviewFundingBlock(t, first, 2, 23, reviewPayment(t, 84, 0, 25))
	replacement := reviewFundingBlock(t, genesis, 1, 31, reviewPayment(t, 84, 0, 0))
	source := &reviewRecoverySource{}
	if fork {
		source.set(genesis, replacement)
	} else {
		source.set(genesis, first, second)
	}
	return source, []*wire.MsgBlock{genesis, replacement}
}

// The parent kills this process while a private checkpoint is blocked. No
// deferred manager/database cleanup runs: this tests real OS lock release and
// synchronized transaction recovery, not an orderly close disguised as crash.
func TestRecoveryReviewCrashChild(t *testing.T) {
	statePath := os.Getenv("SLUG_TEST_RECOVERY_CRASH_STATE")
	if statePath == "" {
		t.Skip("subprocess helper")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state reviewRecoveryCrashState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	stop := func() {
		file, err := os.OpenFile(statePath+".ready", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(state.Stage)); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	loader := reviewRecoveryLoader(state.Directory)
	var session *RecoverySession
	if state.Stage == "initialized" {
		loader.recoveryCheckpoint = func(stage string) {
			if stage == "initialized" {
				stop()
			}
		}
		session, err = loader.BeginCandidateRecovery(context.Background(), retainedPubPass, retainedPrivPass, reviewRecoveryExport(t, 6))
	} else {
		session, err = loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	}
	if err != nil {
		t.Fatal(err)
	}
	if state.Stage == "deriving-uncommitted" {
		real := session.update
		session.update = func(fn func(walletdb.ReadWriteTx) error) error {
			return real(func(tx walletdb.ReadWriteTx) error {
				if err := fn(tx); err != nil {
					return err
				}
				// The first bounded derivation transaction has changed its
				// private write view but has not published a durable commit.
				stop()
				return nil
			})
		}
	}
	source, fork := reviewRecoveryCrashSource(t, false)
	flipped := false
	session.checkpoint = func(stage string) {
		if state.Stage == "reset" && !flipped && (stage == "expanded" || stage == "scanned") && len(reviewRecoveryCredits(t, session)) != 0 {
			flipped = true
			source.set(fork...)
		}
		if stage != state.Stage {
			return
		}
		if stage == "scanned" && len(reviewRecoveryCredits(t, session)) == 0 {
			return
		}
		stop()
	}
	if state.Stage == "fetch" {
		source.beforeBlock = func(hash chainhash.Hash) {
			if hash != *chaincfg.MainNetParams.GenesisHash {
				stop()
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	for i := 0; i < 1000; i++ {
		progress, err := session.Step(ctx, source)
		if err != nil && !errors.Is(err, ErrRecoverySource) {
			t.Fatal(err)
		}
		if progress.Ready {
			break
		}
	}
	t.Fatal("requested crash stage was never reached")
}

func TestRecoveryReviewDurableBoundaryProcessKill(t *testing.T) {
	for _, stage := range []string{"initialized", "deriving-uncommitted", "derived", "fetch", "scanned", "expanded", "reset", "before-ready", "ready"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			state := reviewRecoveryCrashState{Directory: filepath.Join(dir, "wallet"), Stage: stage}
			if stage != "initialized" {
				loader := reviewRecoveryLoader(state.Directory)
				session, err := loader.BeginCandidateRecovery(context.Background(), retainedPubPass, retainedPrivPass, reviewRecoveryExport(t, 6))
				if err != nil {
					t.Fatal(err)
				}
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
			}
			statePath := filepath.Join(dir, "public-crash-state.json")
			raw, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryReviewCrashChild$", "-test.timeout=40s")
			command.Env = append(os.Environ(), "SLUG_TEST_RECOVERY_CRASH_STATE="+statePath)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			deadline := time.NewTimer(38 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			waiting := true
			for waiting {
				select {
				case err := <-done:
					t.Fatalf("crash child exited before stage: %v\n%s", err, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatalf("crash checkpoint timeout\n%s", output.String())
				case <-tick.C:
					if _, err := os.Stat(statePath + ".ready"); err == nil {
						waiting = false
					} else if !errors.Is(err, os.ErrNotExist) {
						_ = command.Process.Kill()
						<-done
						t.Fatal(err)
					}
				}
			}
			if err := command.Process.Kill(); err != nil {
				<-done
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("crash child exited cleanly instead of being killed")
			}
			if bytes.Contains(output.Bytes(), []byte("DATA RACE")) {
				t.Fatalf("child race report:\n%s", output.String())
			}
			loader := reviewRecoveryLoader(state.Directory)
			session, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
			if err != nil {
				t.Fatalf("restart after%s: %v", stage, err)
			}
			t.Cleanup(func() { _ = session.Close() })
			status, err := session.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (stage == "ready") != status.Ready {
				t.Fatalf("wrong durable ready boundary: %#v", status)
			}
			if (stage == "initialized" || stage == "deriving-uncommitted") && status.Derived != 0 {
				t.Fatal("unacknowledged initialization invented derivation")
			}
			if stage == "derived" && status.Derived != 128 {
				t.Fatalf("chunk ACK not exact: %#v", status)
			}
			source, _ := reviewRecoveryCrashSource(t, stage == "reset")
			final := reviewFinishRecovery(t, session, source)
			credits := reviewRecoveryCredits(t, session)
			wantCount, wantValue := 2, int64(40e6)
			if stage == "reset" {
				wantCount, wantValue = 1, 31e6
			}
			var total int64
			for _, credit := range credits {
				total += int64(credit.Amount)
			}
			if len(credits) != wantCount || total != wantValue || !final.Ready {
				t.Fatalf("crash resume lost/duplicated credits: count%d sum%d progress%#v", len(credits), total, final)
			}
			branch := reviewRecoveryBranch(t, session, 84, 0)
			if branch.ImportedNext != 6 || branch.IssuedNext < 26 || branch.DerivedNext != branch.TargetNext {
				t.Fatalf("crash changed address facts: %#v", branch)
			}
		})
	}
}
