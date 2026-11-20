//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
)

func hostedEpoch(ctx context.Context, fn func(func() error) error) error {
	return fn(func() error { return ctx.Err() })
}
func htSetup(t *testing.T) (*vaultHarness, *HostedVault) {
	t.Helper()
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultHarness{path: filepath.Join(root, "hosted"), accountPath: filepath.Join(root, "accounts"), w: &vaultTestWrapper{}, config: vtConfig()}
	h.accounts, err = gymaccount.CreateIdentity(h.accountPath, vtAccountConfig())
	if err != nil {
		t.Fatal(err)
	}
	v, err := CreateHosted(context.Background(), h.path, h.config, h.accounts, h.w, strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close(); h.accounts.Close() })
	return h, v
}
func htReady(t *testing.T, h *vaultHarness, v *HostedVault, session gymaccount.Session) Receipt {
	t.Helper()
	ctx := context.Background()
	r, _, err := v.ProvisionFixture(ctx, session.Token, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.EnsureEnrollment(ctx, session.Token, hostedEpoch); !errors.Is(err, ErrConflict) {
		t.Fatal("acknowledgment created enrollment", err)
	}
	challenge, err := h.accounts.BeginChallenge(ctx, session.Token, "enroll")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := v.SignAccountChallenge(ctx, session.Token, challenge, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.accounts.CompleteChallenge(ctx, session.Token, challenge.ChallengeID, auth); err != nil {
		t.Fatal(err)
	}
	got, err := v.EnsureEnrollment(ctx, session.Token, hostedEpoch)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("acknowledgment", err)
	}
	return got
}
func TestHostedVaultNamespaceOriginalReceiptAndEmptyInit(t *testing.T) {
	h, v := htSetup(t)
	ctx := context.Background()
	a := vtLogin(t, h, "alice", 1)
	receipt := htReady(t, h, v, a)
	b := vtLogin(t, h, "bob", 1)
	other := htReady(t, h, v, b)
	if receipt.RetentionID == other.RetentionID {
		t.Fatal("cross-account identity")
	}
	if old, err := Open(ctx, h.path, h.config, h.accounts, h.w); err == nil {
		old.Close()
		t.Fatal("legacy opened hosted namespace")
	}
	if _, err := OpenHosted(ctx, h.path, h.config, h.accounts, h.w, strings.Repeat("8", 64)); err == nil {
		t.Fatal("foreign expected id accepted")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenHosted(ctx, h.path, h.config, h.accounts, h.w, strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.Status(ctx, a.Token, hostedEpoch)
	if err != nil || status.Receipt == nil || !reflect.DeepEqual(*status.Receipt, receipt) {
		t.Fatal("receipt reopen", err)
	}
	status.Receipt.Manifest.Accounts[0].NextExternal = 4096
	status, err = reopened.Status(ctx, a.Token, hostedEpoch)
	if err != nil || status.Receipt.Manifest.Accounts[0].NextExternal != 0 {
		t.Fatal("owned receipt alias")
	}
	empty := filepath.Join(filepath.Dir(h.path), "empty")
	e, err := CreateHosted(ctx, empty, h.config, h.accounts, h.w, strings.Repeat("9", 64))
	if err != nil {
		t.Fatal(err)
	}
	if e.Close() != nil {
		t.Fatal("empty close")
	}
	if os.Remove(filepath.Join(empty, vaultMarker)) != nil {
		t.Fatal("fixture marker removal")
	}
	e, err = OpenHosted(ctx, empty, h.config, h.accounts, h.w, strings.Repeat("9", 64))
	if err != nil {
		t.Fatal("exact empty initialization resume", err)
	}
	e.Close()
	if os.Rename(filepath.Join(empty, "db"), filepath.Join(empty, "old-db")) != nil {
		t.Fatal("fixture db removal")
	}
	if _, err = OpenHosted(ctx, empty, h.config, h.accounts, h.w, strings.Repeat("9", 64)); err == nil {
		t.Fatal("established missing state recreated")
	}
	legacyPath := filepath.Join(filepath.Dir(h.path), "legacy")
	legacy, err := Create(ctx, legacyPath, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	if _, err = OpenHosted(ctx, legacyPath, h.config, h.accounts, h.w, strings.Repeat("9", 64)); err == nil {
		t.Fatal("hosted adopted legacy")
	}
}
func TestHostedVaultResetDoesNotWaitForProviderAndHeldGymOnly(t *testing.T) {
	h, v := htSetup(t)
	ctx := context.Background()
	first := vtLogin(t, h, "alice", 1)
	receipt := htReady(t, h, v, first)
	vtReset(t, h, "alice", 1)
	second := vtLogin(t, h, "alice", 2)
	if _, _, err := v.ProvisionFixture(ctx, second.Token, hostedEpoch); !errors.Is(err, gymaccount.ErrHeld) {
		t.Fatal("held provisioning", err)
	}
	challenge, err := h.accounts.BeginChallenge(ctx, second.Token, "recover")
	if err != nil {
		t.Fatal(err)
	}
	beforeRecovery, beforeGym := h.w.counts()
	entered, release := make(chan struct{}), make(chan struct{})
	h.w.setHook(func(ctx context.Context, _ string) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	result := make(chan error, 1)
	go func() {
		auth, e := v.SignAccountChallenge(ctx, second.Token, challenge, hostedEpoch)
		if e == nil || auth.Signature != "" {
			result <- errors.New("revoked signature escaped")
			return
		}
		result <- nil
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider not reached")
	}
	if _, err = v.Status(ctx, second.Token, hostedEpoch); !errors.Is(err, ErrBusy) {
		close(release)
		<-result
		t.Fatal("permit waited", err)
	}
	resetDone := make(chan struct{})
	go func() { vtReset(t, h, "alice", 2); close(resetDone) }()
	select {
	case <-resetDone:
	case <-time.After(5 * time.Second):
		close(release)
		<-result
		t.Fatal("reset waited for provider")
	}
	close(release)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	h.w.setHook(nil)
	third := vtLogin(t, h, "alice", 3)
	challenge, err = h.accounts.BeginChallenge(ctx, third.Token, "recover")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := v.SignAccountChallenge(ctx, third.Token, challenge, hostedEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.accounts.CompleteChallenge(ctx, third.Token, challenge.ChallengeID, auth); err != nil {
		t.Fatal(err)
	}
	got, err := v.EnsureEnrollment(ctx, third.Token, hostedEpoch)
	if err != nil || !reflect.DeepEqual(receipt, got) {
		t.Fatal("held retention changed", err)
	}
	afterRecovery, afterGym := h.w.counts()
	if afterRecovery != beforeRecovery || afterGym <= beforeGym {
		t.Fatal("held purpose separation")
	}
	if _, err = v.Status(ctx, second.Token, hostedEpoch); err == nil {
		t.Fatal("old token reused")
	}
}
func TestHostedVaultFenceFailuresAndLostCommit(t *testing.T) {
	h, v := htSetup(t)
	ctx := context.Background()
	session := vtLogin(t, h, "alice", 1)
	receipt := htReady(t, h, v, session)
	fences := map[string]EpochFence{
		"missing": func(context.Context, func(func() error) error) error { return nil },
		"double": func(ctx context.Context, fn func(func() error) error) error {
			_ = fn(ctx.Err)
			_ = fn(ctx.Err)
			return nil
		},
		"swallowed": func(ctx context.Context, fn func(func() error) error) error {
			_ = fn(func() error { return ErrConflict })
			return nil
		},
		"outer": func(ctx context.Context, fn func(func() error) error) error { _ = fn(ctx.Err); return ErrConflict },
	}
	for name, fence := range fences {
		t.Run(name, func(t *testing.T) {
			status, e := v.Status(ctx, session.Token, fence)
			if e == nil || status.Receipt != nil {
				t.Fatal("failed fence disclosed")
			}
		})
	}
	var retained func(func() error) error
	_, err := v.Status(ctx, session.Token, func(_ context.Context, fn func(func() error) error) error { retained = fn; return nil })
	if err == nil || retained == nil {
		t.Fatal("missing callback")
	}
	if retained(func() error { return nil }) == nil {
		t.Fatal("late callback admitted")
	}
	status, err := v.Status(ctx, session.Token, hostedEpoch)
	if err != nil || status.Receipt.RetentionID != receipt.RetentionID {
		t.Fatal("failed read changed state")
	}
	b := vtLogin(t, h, "bob", 1)
	write := v.core.writeBatch
	v.core.writeBatch = func(batch *leveldb.Batch, o *opt.WriteOptions) error {
		if e := write(batch, o); e != nil {
			return e
		}
		return errors.New("fixture lost ack")
	}
	if _, _, err = v.ProvisionFixture(ctx, b.Token, hostedEpoch); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("lost write not uncertain", err)
	}
	if _, err = v.Status(ctx, session.Token, hostedEpoch); !errors.Is(err, ErrPoisoned) {
		t.Fatal("poison not retained")
	}
	v.Close()
	reopened, err := OpenHosted(ctx, h.path, h.config, h.accounts, h.w, strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	prior, err := reopened.record(b.Account.ID)
	if err != nil || prior.State != "reserved" {
		t.Fatal("durable exact reservation lost", err)
	}
	got, _, err := reopened.ProvisionFixture(ctx, b.Token, hostedEpoch)
	if err != nil || got.Binding != prior.Binding {
		t.Fatal("resume replaced identity", err)
	}
}
