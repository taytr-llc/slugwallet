//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slugwallet/recovery"
)

type vaultTestWrapper struct {
	core                        coreWrapper
	mu                          sync.Mutex
	recoveryUnwraps, gymUnwraps int
	hook                        func(context.Context, string) error
}

func (w *vaultTestWrapper) ID() string { return w.core.ID() }
func (w *vaultTestWrapper) Wrap(ctx context.Context, ref string, key [32]byte, aad []byte) ([]byte, error) {
	return w.core.Wrap(ctx, ref, key, aad)
}
func (w *vaultTestWrapper) Unwrap(ctx context.Context, ref string, blob, aad []byte) ([32]byte, error) {
	w.mu.Lock()
	if strings.HasPrefix(ref, "recovery-") {
		w.recoveryUnwraps++
	} else {
		w.gymUnwraps++
	}
	hook := w.hook
	w.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, ref); err != nil {
			return [32]byte{}, err
		}
	}
	return w.core.Unwrap(ctx, ref, blob, aad)
}
func (w *vaultTestWrapper) counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recoveryUnwraps, w.gymUnwraps
}
func (w *vaultTestWrapper) setHook(hook func(context.Context, string) error) {
	w.mu.Lock()
	w.hook = hook
	w.mu.Unlock()
}
func vtAccountConfig() gymaccount.IdentityConfig {
	return gymaccount.IdentityConfig{Version: 2, VerifierConfigHash: strings.Repeat("a", 64), MaxLoginAttempts: 128, Accounts: gymaccount.Config{Version: 1, Principals: []gymaccount.FixturePrincipal{{Issuer: "fixture:vault", Subject: "alice", Fixture: "zero256"}, {Issuer: "fixture:vault", Subject: "bob", Fixture: "incrementing256"}}, MaxSessions: 256, MaxChallenges: 128, MaxEvents: 512}}
}
func vtConfig() Config {
	return Config{Version: 1, WrapperID: "core-public-fixture", RecoveryKeyRef: "recovery-old", GymKeyRef: "gym-old", AllowedRecoveryKeyRefs: []string{"recovery-old", "recovery-new"}, AllowedGymKeyRefs: []string{"gym-old", "gym-new"}, MaxOperations: 128, Policy: prospectnode.Policy{Version: 1, Network: gymaccount.FixtureNetwork, Genesis: gymaccount.FixtureGenesis, DNAVersion: 1, ProspectTarget: strings.Repeat("f", 64)}}
}

type vaultHarness struct {
	accounts          *gymaccount.Store
	v                 *Vault
	w                 *vaultTestWrapper
	path, accountPath string
	config            Config
}

func vtSetup(t *testing.T) *vaultHarness {
	t.Helper()
	root := t.TempDir()
	h := &vaultHarness{path: filepath.Join(root, "vault"), accountPath: filepath.Join(root, "accounts"), w: &vaultTestWrapper{}, config: vtConfig()}
	var err error
	h.accounts, err = gymaccount.CreateIdentity(h.accountPath, vtAccountConfig())
	if err != nil {
		t.Fatal(err)
	}
	h.v, err = Create(context.Background(), h.path, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if h.v != nil {
			h.v.Close()
		}
		if h.accounts != nil {
			h.accounts.Close()
		}
	})
	return h
}
func vtLogin(t *testing.T, h *vaultHarness, subject string, epoch uint64) gymaccount.Session {
	t.Helper()
	ctx := context.Background()
	attempt, err := h.accounts.IssueLogin(ctx, "fixture:vault")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix() * 1000
	p := gymaccount.VerifiedLogin{VerifierConfigHash: vtAccountConfig().VerifierConfigHash, Issuer: "fixture:vault", Subject: subject, Nonce: attempt.Nonce, AuthenticatedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000, CredentialEpoch: epoch}
	session, err := h.accounts.LoginWithAssertion(ctx, attempt.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func vtReset(t *testing.T, h *vaultHarness, subject string, epoch uint64) gymaccount.ResetBarrier {
	t.Helper()
	now := time.Now().Unix() * 1000
	p := gymaccount.VerifiedReset{VerifierConfigHash: vtAccountConfig().VerifierConfigHash, Issuer: "fixture:vault", Subject: subject, EventID: strings.Repeat(strconv.FormatUint(epoch, 16), 64), Stage: "begin", FromEpoch: epoch, ToEpoch: epoch + 1, VerifiedAtMS: now, IssuedAtMS: now, ExpiresAtMS: now + 300000}
	if _, _, err := h.accounts.BeginReset(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Stage = "complete"
	result, _, err := h.accounts.CompleteReset(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func vtReady(t *testing.T, h *vaultHarness, token string) Receipt {
	t.Helper()
	receipt, _, err := h.v.ProvisionFixture(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := h.v.EnsureEnrollment(context.Background(), token)
	if err != nil || !reflect.DeepEqual(enrolled, receipt) {
		t.Fatal("enrollment receipt mismatch", err)
	}
	return receipt
}
func vtReopen(t *testing.T, h *vaultHarness) {
	t.Helper()
	if err := h.v.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	h.v, err = Open(context.Background(), h.path, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVaultSameWalletIsolationAndRewrap(t *testing.T) {
	h := vtSetup(t)
	ctx := context.Background()
	alice := vtLogin(t, h, "alice", 1)
	bob := vtLogin(t, h, "bob", 1)
	first := vtReady(t, h, alice.Token)
	second := vtReady(t, h, bob.Token)
	if first.Binding.AccountID == second.Binding.AccountID || first.Binding.GymID == second.Binding.GymID {
		t.Fatal("account identities aliased")
	}
	again, changed, err := h.v.ProvisionFixture(ctx, alice.Token)
	if err != nil || changed || !reflect.DeepEqual(again, first) {
		t.Fatal("provision replay changed retained identity", err)
	}
	first.Manifest.Accounts[0].NextExternal = 99
	again, _, err = h.v.ProvisionFixture(ctx, alice.Token)
	if err != nil || again.Manifest.Accounts[0].NextExternal != 0 {
		t.Fatal("receipt retained caller slice")
	}
	first = again
	before, err := h.v.record(alice.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	rotated, changed, err := h.v.Rewrap(ctx, alice.Token, "recovery-new", "gym-new")
	if err != nil || !changed || !reflect.DeepEqual(rotated, first) {
		t.Fatal("rewrap changed public retention", err)
	}
	after, err := h.v.record(alice.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Recovery.Ciphertext != after.Recovery.Ciphertext || before.Recovery.Nonce != after.Recovery.Nonce || before.Gym.Ciphertext != after.Gym.Ciphertext || after.Recovery.WrapRevision != 2 || after.Gym.WrapRevision != 2 {
		t.Fatal("rewrap changed content or pair revision")
	}
	if _, changed, err = h.v.Rewrap(ctx, alice.Token, "recovery-new", "gym-new"); err != nil || changed {
		t.Fatal("identical rotation not idempotent", err)
	}
	vtReopen(t, h)
	export := filepath.Join(t.TempDir(), "recovery.json")
	if err = h.v.ExportRecoveryFile(ctx, alice.Token, export); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(export)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := recovery.ParseExport(raw)
	if err != nil || !reflect.DeepEqual(bundle.Manifest, first.Manifest) {
		t.Fatal("export differs from retained snapshot", err)
	}
	info, _ := os.Stat(export)
	if info.Mode().Perm() != 0600 {
		t.Fatal("export not private")
	}
	if err = h.v.ExportRecoveryFile(ctx, bob.Token, export); err == nil {
		t.Fatal("export overwrote existing file")
	}
	if _, _, err = h.v.Rewrap(ctx, alice.Token, "gym-new", "recovery-new"); !errors.Is(err, ErrConfig) {
		t.Fatal("purpose keyrefs crossed", err)
	}
	if err = h.v.Close(); err != nil {
		t.Fatal(err)
	}
	bad := h.config
	bad.Policy.ProspectTarget = strings.Repeat("e", 64)
	if opened, err := Open(ctx, h.path, bad, h.accounts, h.w); err == nil {
		opened.Close()
		t.Fatal("policy swap accepted")
	}
}

func TestVaultConcurrentProvisionHasOneIdentity(t *testing.T) {
	h := vtSetup(t)
	session := vtLogin(t, h, "alice", 1)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, _, err := h.v.ProvisionFixture(context.Background(), session.Token)
			results <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil && !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	receipt, _, err := h.v.ProvisionFixture(context.Background(), session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.v.meta.Accounts) != 1 || h.v.meta.Accounts[0].ProvisionID != receipt.Binding.ProvisionID {
		t.Fatal("concurrent provisioning replaced identity")
	}
	vtReopen(t, h)
	after, changed, err := h.v.ProvisionFixture(context.Background(), session.Token)
	if err != nil || changed || !reflect.DeepEqual(after, receipt) {
		t.Fatal("lost-reply retry changed receipt", err)
	}
}

// Move only this public-fixture authority's complete canonical timeline into
// the past to exercise hold expiry without a runtime clock override or waiting
// 24 hours. All timestamp-bearing records are rebased together, then audited by
// the ordinary OpenIdentity path. This is test fixture construction only.
func vtAgeAuthority(t *testing.T, h *vaultHarness) {
	vtShiftAuthority(t, h, -gymaccount.RecoveryHoldMS-10000)
}
func vtShiftAuthority(t *testing.T, h *vaultHarness, delta int64) {
	t.Helper()
	if err := h.v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.accounts.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := leveldb.OpenFile(filepath.Join(h.accountPath, "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"(?:clock_ms|authenticated_at_ms|issued_at_ms|expires_at_ms|at_ms|began_at_ms|completed_at_ms|verified_at_ms|hold_until_ms|consumed_at_ms)":([0-9]+)`)
	batch := new(leveldb.Batch)
	it := db.NewIterator(nil, nil)
	for it.Next() {
		key := append([]byte(nil), it.Key()...)
		raw := append([]byte(nil), it.Value()...)
		raw = pattern.ReplaceAllFunc(raw, func(match []byte) []byte {
			colon := strings.LastIndexByte(string(match), ':')
			n, _ := strconv.ParseInt(string(match[colon+1:]), 10, 64)
			if n == 0 {
				return match
			}
			return []byte(string(match[:colon+1]) + strconv.FormatInt(n+delta, 10))
		})
		batch.Put(key, raw)
	}
	if err = it.Error(); err != nil {
		t.Fatal(err)
	}
	it.Release()
	if err = db.Write(batch, &opt.WriteOptions{Sync: true}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	h.accounts, err = gymaccount.OpenIdentity(h.accountPath, vtAccountConfig())
	if err != nil {
		t.Fatal("historical fixture invalid", err)
	}
	h.v, err = Open(context.Background(), h.path, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVaultInterruptedProvisionHoldAndResume(t *testing.T) {
	for _, wantedState := range []string{"reserved", "sealed"} {
		t.Run(wantedState, func(t *testing.T) {
			h := vtSetup(t)
			login := vtLogin(t, h, "alice", 1)
			recoveryCalls := 0
			h.w.setHook(func(_ context.Context, ref string) error {
				if strings.HasPrefix(ref, "recovery-") {
					recoveryCalls++
					if (wantedState == "reserved" && recoveryCalls == 1) || (wantedState == "sealed" && recoveryCalls == 2) {
						return errors.New("fixture provider unavailable")
					}
				}
				return nil
			})
			if _, _, err := h.v.ProvisionFixture(context.Background(), login.Token); err == nil {
				t.Fatal("provider failure not propagated")
			}
			h.w.setHook(nil)
			state, err := h.v.Status(context.Background(), login.Token)
			if err != nil || state.State != wantedState {
				t.Fatal("wrong retained phase", state.State, err)
			}
			original := state.Binding
			vtReset(t, h, "alice", 1)
			fresh := vtLogin(t, h, "alice", 2)
			before, _ := h.w.counts()
			if _, _, err = h.v.ProvisionFixture(context.Background(), fresh.Token); !errors.Is(err, gymaccount.ErrHeld) {
				t.Fatal("held recovery preparation allowed", err)
			}
			after, _ := h.w.counts()
			if after != before {
				t.Fatal("held provisioning unwrapped recovery")
			}
			vtAgeAuthority(t, h)
			fresh = vtLogin(t, h, "alice", 2)
			receipt, _, err := h.v.ProvisionFixture(context.Background(), fresh.Token)
			if err != nil || receipt.Binding != original {
				t.Fatal("resume replaced original reservation", err)
			}
			if _, err = h.v.EnsureEnrollment(context.Background(), fresh.Token); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVaultResetDuringUnwrapRejectsOriginalOperation(t *testing.T) {
	h := vtSetup(t)
	login := vtLogin(t, h, "alice", 1)
	vtReady(t, h, login.Token)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.w.setHook(func(ctx context.Context, ref string) error {
		if strings.HasPrefix(ref, "recovery-") {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	path := filepath.Join(t.TempDir(), "secret.json")
	done := make(chan error, 1)
	go func() { done <- h.v.ExportRecoveryFile(context.Background(), login.Token, path) }()
	<-entered
	vtReset(t, h, "alice", 1)
	close(release)
	if err := <-done; err == nil {
		t.Fatal("stale export completed")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unauthorized export wrote plaintext")
	}
	h.w.setHook(nil)
	fresh := vtLogin(t, h, "alice", 2)
	beforeRecovery, beforeGym := h.w.counts()
	if _, err := h.v.EnsureEnrollment(context.Background(), fresh.Token); err != nil {
		t.Fatal("gym-only recovery failed", err)
	}
	afterRecovery, afterGym := h.w.counts()
	if afterRecovery != beforeRecovery || afterGym <= beforeGym {
		t.Fatal("held recovery was not gym-envelope-only")
	}
	before, _ := h.w.counts()
	if err := h.v.ExportRecoveryFile(context.Background(), fresh.Token, path); !errors.Is(err, gymaccount.ErrHeld) {
		t.Fatal(err)
	}
	if _, _, err := h.v.Rewrap(context.Background(), fresh.Token, "recovery-new", "gym-new"); !errors.Is(err, gymaccount.ErrHeld) {
		t.Fatal(err)
	}
	after, _ := h.w.counts()
	if before != after {
		t.Fatal("held sensitive action called recovery wrapper")
	}
}

func TestVaultCloseCancelsAndJoinsUnwrap(t *testing.T) {
	h := vtSetup(t)
	login := vtLogin(t, h, "alice", 1)
	vtReady(t, h, login.Token)
	entered := make(chan struct{})
	returned := make(chan struct{})
	h.w.setHook(func(ctx context.Context, _ string) error {
		close(entered)
		<-ctx.Done()
		close(returned)
		return ctx.Err()
	})
	opDone := make(chan error, 1)
	go func() {
		opDone <- h.v.ExportRecoveryFile(context.Background(), login.Token, filepath.Join(t.TempDir(), "export.json"))
	}()
	<-entered
	if err := h.v.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-returned:
	default:
		t.Fatal("Close returned before provider exited")
	}
	if err := <-opDone; err == nil {
		t.Fatal("canceled export reported success")
	}
	if _, err := h.v.Status(context.Background(), login.Token); !errors.Is(err, ErrClosed) {
		t.Fatal("closed handle remained usable", err)
	}
}

func TestVaultExportRejectsProtectedDirectoryAlias(t *testing.T) {
	h := vtSetup(t)
	login := vtLogin(t, h, "alice", 1)
	vtReady(t, h, login.Token)
	alias := filepath.Join(t.TempDir(), "vault-alias")
	if err := os.Symlink(h.path, alias); err != nil {
		t.Fatal(err)
	}
	if err := h.v.ExportRecoveryFile(context.Background(), login.Token, filepath.Join(alias, "plaintext.json")); !errors.Is(err, ErrExport) {
		t.Fatal("alias to vault root accepted", err)
	}
	if _, err := os.Stat(filepath.Join(h.path, "plaintext.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plaintext entered protected directory")
	}
}

func TestVaultUncertainTransitionsPoisonAndReconcile(t *testing.T) {
	for _, stage := range []string{"reserved", "sealed", "verified", "enrolled", "rewrapped"} {
		for _, commitFirst := range []bool{false, true} {
			t.Run(stage+strconv.FormatBool(commitFirst), func(t *testing.T) {
				h := vtSetup(t)
				login := vtLogin(t, h, "alice", 1)
				ctx := context.Background()
				if stage == "enrolled" {
					if _, _, err := h.v.ProvisionFixture(ctx, login.Token); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "rewrapped" {
					vtReady(t, h, login.Token)
				}
				realWrite := h.v.writeBatch
				fired := false
				h.v.writeBatch = func(batch *leveldb.Batch, options *opt.WriteOptions) error {
					if fired {
						return realWrite(batch, options)
					}
					// Read the record the batch would publish, without deriving expected
					// ciphertext or relying on implementation outputs as cryptographic vectors.
					collector := new(vtBatchRecord)
					batch.Replay(collector)
					match := collector.record.State == stage || (stage == "rewrapped" && collector.record.State == "enrolled" && collector.record.Revision > 4)
					if !match {
						return realWrite(batch, options)
					}
					fired = true
					if commitFirst {
						if err := realWrite(batch, options); err != nil {
							return err
						}
					}
					return errors.New("lost durable acknowledgement")
				}
				var err error
				switch stage {
				case "enrolled":
					_, err = h.v.EnsureEnrollment(ctx, login.Token)
				case "rewrapped":
					_, _, err = h.v.Rewrap(ctx, login.Token, "recovery-new", "gym-new")
				default:
					_, _, err = h.v.ProvisionFixture(ctx, login.Token)
				}
				if !fired || !errors.Is(err, ErrPoisoned) {
					t.Fatal("target transition did not poison", err)
				}
				if _, err = h.v.Status(ctx, login.Token); !errors.Is(err, ErrPoisoned) {
					t.Fatal("poisoned handle usable")
				}
				h.v.Close()
				h.v, err = Open(ctx, h.path, h.config, h.accounts, h.w)
				if err != nil {
					t.Fatal(err)
				}
				receipt, _, err := h.v.ProvisionFixture(ctx, login.Token)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = h.v.EnsureEnrollment(ctx, login.Token); err != nil {
					t.Fatal(err)
				}
				if stage == "rewrapped" {
					if _, _, err = h.v.Rewrap(ctx, login.Token, "recovery-new", "gym-new"); err != nil {
						t.Fatal(err)
					}
				}
				state, err := h.v.Status(ctx, login.Token)
				if err != nil || state.Binding != receipt.Binding || len(h.v.meta.Accounts) != 1 {
					t.Fatal("reconciliation replaced identity", err)
				}
			})
		}
	}
}

type vtBatchRecord struct{ record vaultRecord }

func (b *vtBatchRecord) Put(key, value []byte) {
	if strings.HasPrefix(string(key), "account:") {
		json.Unmarshal(value, &b.record)
	}
}
func (b *vtBatchRecord) Delete([]byte) {}

func TestVaultMissingEstablishedMaterialNeverRegenerates(t *testing.T) {
	for _, missing := range []string{"record", "recovery", "gym", "receipt"} {
		t.Run(missing, func(t *testing.T) {
			h := vtSetup(t)
			login := vtLogin(t, h, "alice", 1)
			vtReady(t, h, login.Token)
			key := "account:" + login.Account.ID
			if missing == "record" {
				if err := h.v.db.Delete([]byte(key), nil); err != nil {
					t.Fatal(err)
				}
			} else {
				var record vaultRecord
				if h.v.load(key, &record) != nil {
					t.Fatal("record missing")
				}
				switch missing {
				case "recovery":
					record.Recovery = nil
				case "gym":
					record.Gym = nil
				case "receipt":
					record.Receipt = nil
				}
				b := new(leveldb.Batch)
				putVault(b, key, record)
				h.v.db.Write(b, nil)
			}
			beforeRecovery, beforeGym := h.w.counts()
			if _, _, err := h.v.ProvisionFixture(context.Background(), login.Token); !errors.Is(err, ErrCorrupt) {
				t.Fatal("missing established record regenerated", err)
			}
			afterRecovery, afterGym := h.w.counts()
			if beforeRecovery != afterRecovery || beforeGym != afterGym {
				t.Fatal("corruption called wrapping provider")
			}
			h.v.Close()
			if opened, err := Open(context.Background(), h.path, h.config, h.accounts, h.w); err == nil {
				opened.Close()
				t.Fatal("corrupt store reopened")
			}
		})
	}
}

func TestVaultReservedCapacityCompletesOriginalAccount(t *testing.T) {
	h := vtSetup(t)
	h.v.Close()
	h.path = filepath.Join(t.TempDir(), "small")
	h.config.MaxOperations = 4
	var err error
	h.v, err = Create(context.Background(), h.path, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
	alice := vtLogin(t, h, "alice", 1)
	bob := vtLogin(t, h, "bob", 1)
	vtReady(t, h, alice.Token)
	if h.v.meta.Operations != 4 || h.v.meta.Reserved != 0 {
		t.Fatal("creation did not consume exact reservation")
	}
	if _, _, err = h.v.ProvisionFixture(context.Background(), bob.Token); !errors.Is(err, ErrCapacity) {
		t.Fatal("unreserved second creation accepted", err)
	}
	if _, _, err = h.v.Rewrap(context.Background(), alice.Token, "recovery-new", "gym-new"); !errors.Is(err, ErrCapacity) {
		t.Fatal("rotation exceeded journal bound", err)
	}
	vtReopen(t, h)
	if _, err = h.v.Status(context.Background(), alice.Token); err != nil {
		t.Fatal("capacity lost first record", err)
	}
}

func TestVaultAuthorityClockRollbackFailsBeforeProvider(t *testing.T) {
	h := vtSetup(t)
	login := vtLogin(t, h, "alice", 1)
	vtReady(t, h, login.Token)
	// A later observed authority clock needs no enrollment/timestamp changes:
	// existing signed challenges remain byte-exact. This models restarting on
	// a host whose current clock is behind the synchronized highwater.
	if err := h.v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.accounts.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := leveldb.OpenFile(filepath.Join(h.accountPath, "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.Get([]byte("meta"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"clock_ms":([0-9]+)`)
	if len(pattern.FindAll(raw, -1)) != 1 {
		t.Fatal("fixture clock missing")
	}
	raw = pattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		colon := strings.LastIndexByte(string(match), ':')
		n, _ := strconv.ParseInt(string(match[colon+1:]), 10, 64)
		return []byte(string(match[:colon+1]) + strconv.FormatInt(n+60000, 10))
	})
	if err := db.Put([]byte("meta"), raw, &opt.WriteOptions{Sync: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	h.accounts, err = gymaccount.OpenIdentity(h.accountPath, vtAccountConfig())
	if err != nil {
		t.Fatal("future highwater fixture invalid", err)
	}
	h.v, err = Open(context.Background(), h.path, h.config, h.accounts, h.w)
	if err != nil {
		t.Fatal(err)
	}
	beforeRecovery, beforeGym := h.w.counts()
	if _, err := h.v.Status(context.Background(), login.Token); !errors.Is(err, gymaccount.ErrClock) {
		t.Fatal("clock rollback allowed status authorization", err)
	}
	if _, _, err := h.v.ProvisionFixture(context.Background(), login.Token); !errors.Is(err, gymaccount.ErrClock) {
		t.Fatal("clock rollback allowed provisioning", err)
	}
	if err := h.v.ExportRecoveryFile(context.Background(), login.Token, filepath.Join(t.TempDir(), "export.json")); !errors.Is(err, gymaccount.ErrClock) {
		t.Fatal("clock rollback allowed export", err)
	}
	afterRecovery, afterGym := h.w.counts()
	if beforeRecovery != afterRecovery || beforeGym != afterGym {
		t.Fatal("rollback called provider")
	}
}
