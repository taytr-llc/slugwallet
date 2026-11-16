// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/prospectnode"
)

// These disposable KEKs are literal public test material. This behavioral
// wrapper is not a shipped provider adapter or a cryptographic golden oracle.
type coreWrapper struct {
	mu                     sync.Mutex
	wraps, unwraps         int
	wrapError, unwrapError error
	oversize, wrongUnwrap  bool
	wrapHook               func()
}

func (*coreWrapper) ID() string { return "core-public-fixture" }

func coreKEK(ref string) ([32]byte, error) {
	var key [32]byte
	switch ref {
	case "recovery-old":
		key[0] = 1
	case "recovery-new":
		key[0] = 2
	case "gym-old":
		key[0] = 3
	case "gym-new":
		key[0] = 4
	default:
		return key, errors.New("unknown public test key")
	}
	return key, nil
}

func (w *coreWrapper) Wrap(ctx context.Context, ref string, key [32]byte, aad []byte) ([]byte, error) {
	defer clear(key[:])
	w.mu.Lock()
	w.wraps++
	counter := w.wraps
	wrapErr := w.wrapError
	oversize := w.oversize
	hook := w.wrapHook
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	if wrapErr != nil {
		return nil, wrapErr
	}
	if oversize {
		return make([]byte, MaxWrappedKeySize+1), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kek, err := coreKEK(ref)
	if err != nil {
		return nil, err
	}
	defer clear(kek[:])
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	nonce[0] = byte(counter)
	nonce[1] = byte(counter >> 8)
	return aead.Seal(nonce, nonce, key[:], aad), nil
}

func (w *coreWrapper) Unwrap(ctx context.Context, ref string, blob, aad []byte) ([32]byte, error) {
	var result [32]byte
	w.mu.Lock()
	w.unwraps++
	unwrapErr := w.unwrapError
	wrong := w.wrongUnwrap
	w.mu.Unlock()
	if unwrapErr != nil {
		return result, unwrapErr
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(blob) != 60 {
		return result, errors.New("invalid fixture wrapped key")
	}
	kek, err := coreKEK(ref)
	if err != nil {
		return result, err
	}
	defer clear(kek[:])
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return result, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}
	plain, err := aead.Open(nil, blob[:12], blob[12:], aad)
	if err != nil {
		return result, err
	}
	defer clear(plain)
	copy(result[:], plain)
	if wrong {
		result[0] ^= 1
	}
	return result, nil
}

func coreBinding(t *testing.T) Binding {
	t.Helper()
	identity, err := gymaccount.FixtureIdentity("zero256")
	if err != nil {
		t.Fatal(err)
	}
	return Binding{Version: Version1, AuthorityID: strings.Repeat("1", 64), AccountID: strings.Repeat("2", 64), PrincipalID: strings.Repeat("3", 64), ProvisionID: strings.Repeat("4", 64), Network: identity.Network, Genesis: identity.Genesis, Profile: identity.Profile, RootPublicKey: identity.RootPublicKey, GymPublicKey: identity.GymPublicKey, GymID: identity.GymID}
}

func coreSeal(t *testing.T, w KeyWrapper) (Envelope, []byte) {
	t.Helper()
	plaintext := []byte("public fixture payload for cipher behavior only")
	e, err := sealEnvelope(context.Background(), w, coreBinding(t), RecoveryPurpose, 1, strings.Repeat("a", 64), plaintext, "recovery-old", bytes.NewReader(bytes.Repeat([]byte{9}, 44)))
	if err != nil {
		t.Fatal(err)
	}
	return e, plaintext
}

func TestCipherBindsEveryEnvelopeField(t *testing.T) {
	w := new(coreWrapper)
	original, want := coreSeal(t, w)
	tests := map[string]func(*Envelope){
		"version":         func(e *Envelope) { e.Version = 2 },
		"binding version": func(e *Envelope) { e.Binding.Version = 2 },
		"authority":       func(e *Envelope) { e.Binding.AuthorityID = strings.Repeat("5", 64) },
		"account":         func(e *Envelope) { e.Binding.AccountID = strings.Repeat("5", 64) },
		"principal":       func(e *Envelope) { e.Binding.PrincipalID = strings.Repeat("5", 64) },
		"reservation":     func(e *Envelope) { e.Binding.ProvisionID = strings.Repeat("5", 64) },
		"network":         func(e *Envelope) { e.Binding.Network++ },
		"genesis":         func(e *Envelope) { e.Binding.Genesis = strings.Repeat("5", 64) },
		"profile":         func(e *Envelope) { e.Binding.Profile += "-other" },
		"other public fixture": func(e *Envelope) {
			id, err := gymaccount.FixtureIdentity("incrementing256")
			if err != nil {
				t.Fatal(err)
			}
			e.Binding.RootPublicKey = id.RootPublicKey
			e.Binding.GymPublicKey = id.GymPublicKey
			e.Binding.GymID = id.GymID
		},
		"purpose":            func(e *Envelope) { e.Purpose = GymPurpose },
		"content revision":   func(e *Envelope) { e.ContentRevision++ },
		"manifest":           func(e *Envelope) { e.ManifestHash = strings.Repeat("b", 64) },
		"nonce":              func(e *Envelope) { e.Nonce = "ff" + e.Nonce[2:] },
		"ciphertext":         func(e *Envelope) { e.Ciphertext = "ff" + e.Ciphertext[2:] },
		"wrapper":            func(e *Envelope) { e.WrapperID += "-other" },
		"key":                func(e *Envelope) { e.KeyRef = "recovery-new" },
		"wrap revision":      func(e *Envelope) { e.WrapRevision++ },
		"wrapped ciphertext": func(e *Envelope) { e.WrappedKey = "ff" + e.WrappedKey[2:] },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			e := original
			change(&e)
			got, err := openEnvelope(context.Background(), w, e)
			if !errors.Is(err, ErrEnvelope) || got != nil {
				t.Fatalf("tamper accepted: %v", err)
			}
		})
	}
	got, err := openEnvelope(context.Background(), w, original)
	defer clear(got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("original envelope changed: %v", err)
	}
}

func TestRewrapKeepsContentAndRejectsBadProvider(t *testing.T) {
	w := new(coreWrapper)
	original, want := coreSeal(t, w)
	rotated, err := rewrapEnvelope(context.Background(), w, original, "recovery-new", 2)
	if err != nil {
		t.Fatal(err)
	}
	content := rotated
	content.KeyRef = original.KeyRef
	content.WrapRevision = original.WrapRevision
	content.WrappedKey = original.WrappedKey
	if content != original || rotated.WrappedKey == original.WrappedKey {
		t.Fatal("rewrap changed content or failed to replace wrapping")
	}
	plain, err := openEnvelope(context.Background(), w, rotated)
	defer clear(plain)
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatalf("rotated plaintext: %v", err)
	}
	if result, err := rewrapEnvelope(context.Background(), w, original, "recovery-new", 3); !errors.Is(err, ErrEnvelope) || result != (Envelope{}) {
		t.Fatal("nonsequential rotation accepted")
	}
	w.wrongUnwrap = true
	if result, err := rewrapEnvelope(context.Background(), w, original, "recovery-new", 2); !errors.Is(err, ErrEnvelope) || result != (Envelope{}) {
		t.Fatalf("bad provider accepted: %v", err)
	}
}

func TestCipherProviderFailureBoundsAndCancellation(t *testing.T) {
	for _, mode := range []string{"wrap-error", "unwrap-error", "oversized-blob", "wrong-key", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			w := new(coreWrapper)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("provider-secret-sentinel")
			switch mode {
			case "wrap-error":
				w.wrapError = sentinel
			case "unwrap-error":
				w.unwrapError = sentinel
			case "oversized-blob":
				w.oversize = true
			case "wrong-key":
				w.wrongUnwrap = true
			case "cancel":
				w.wrapHook = cancel
			}
			result, err := sealEnvelope(ctx, w, coreBinding(t), RecoveryPurpose, 1, strings.Repeat("a", 64), []byte("fixture"), "recovery-old", bytes.NewReader(make([]byte, 44)))
			if err == nil || result != (Envelope{}) || strings.Contains(err.Error(), "sentinel") {
				t.Fatalf("provider failure escaped: %v", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
	w := new(coreWrapper)
	_, err := sealEnvelope(context.Background(), w, coreBinding(t), RecoveryPurpose, 1, strings.Repeat("a", 64), []byte("fixture"), "recovery-old", bytes.NewReader(make([]byte, 43)))
	if !errors.Is(err, ErrEnvelope) || w.wraps != 0 {
		t.Fatal("short randomness reached provider")
	}
	e, _ := coreSeal(t, w)
	for _, change := range []func(*Envelope){func(e *Envelope) { e.Ciphertext = strings.Repeat("a", (MaxPayloadSize+16)*2+2) }, func(e *Envelope) { e.WrappedKey = strings.Repeat("a", MaxWrappedKeySize*2+2) }, func(e *Envelope) { e.Nonce = "AA" + e.Nonce[2:] }, func(e *Envelope) { e.Ciphertext += "a" }} {
		bad := e
		change(&bad)
		calls := w.unwraps
		if p, err := openEnvelope(context.Background(), w, bad); !errors.Is(err, ErrEnvelope) || p != nil || w.unwraps != calls {
			t.Fatal("invalid envelope reached provider")
		}
	}
}

func TestCipherCopiesPayloadAndConcurrentReads(t *testing.T) {
	w := new(coreWrapper)
	e, want := coreSeal(t, w)
	saved := append([]byte(nil), want...)
	clear(want)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := openEnvelope(context.Background(), w, e)
			defer clear(p)
			if err != nil || !bytes.Equal(p, saved) {
				t.Errorf("concurrent open: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestVaultConfigOwnsAllowlistAndPolicy(t *testing.T) {
	c := Config{Version: Version1, WrapperID: "core-public-fixture", RecoveryKeyRef: "recovery-old", GymKeyRef: "gym-old", AllowedRecoveryKeyRefs: []string{"recovery-old", "recovery-new"}, AllowedGymKeyRefs: []string{"gym-old", "gym-new"}, MaxOperations: MaxOperations, Policy: prospectnode.Policy{Version: 1, Network: gymaccount.FixtureNetwork, Genesis: gymaccount.FixtureGenesis, DNAVersion: 1, ProspectTarget: strings.Repeat("f", 64)}}
	normalized, err := normalizedConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	c.AllowedRecoveryKeyRefs[0] = "attacker"
	c.AllowedGymKeyRefs[0] = "attacker"
	if !allowedKey(normalized, RecoveryPurpose, "recovery-old") || !allowedKey(normalized, GymPurpose, "gym-old") {
		t.Fatal("caller modified pinned allowlists")
	}
	for _, change := range []func(*Config){func(c *Config) { c.AllowedGymKeyRefs = []string{"recovery-old"}; c.GymKeyRef = "recovery-old" }, func(c *Config) { c.RecoveryKeyRef = "not-allowed" }, func(c *Config) { c.MaxOperations = 0 }, func(c *Config) { c.Policy.Genesis = strings.Repeat("0", 64) }, func(c *Config) { c.Policy.ProspectTarget = "" }, func(c *Config) { c.WrapperID = "bad\nprovider" }} {
		bad := normalized
		change(&bad)
		if _, err := normalizedConfig(bad); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid config accepted: %v", err)
		}
	}
	zero := coreBinding(t)
	zero.AuthorityID = strings.Repeat("0", 64)
	if validateBinding(zero) != nil {
		t.Fatal("canonical zero identity incorrectly rejected")
	}
}
