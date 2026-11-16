// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/taytr-llc/slugwallet/recovery"
)

type vaultReferenceCase struct {
	Name                  string            `json:"name"`
	FixtureName           string            `json:"fixture_name"`
	Manifest              recovery.Manifest `json:"manifest"`
	CanonicalManifest     string            `json:"canonical_manifest"`
	TestOnlyDEK           string            `json:"test_only_dek"`
	TestOnlyWrapNonce     string            `json:"test_only_wrap_nonce"`
	TestOnlyRewrapNonce   string            `json:"test_only_rewrap_nonce"`
	ExpectedPlaintext     string            `json:"expected_plaintext"`
	ExpectedContentAAD    string            `json:"expected_content_aad"`
	ExpectedWrappingAAD   string            `json:"expected_wrapping_aad"`
	Envelope              Envelope          `json:"envelope"`
	ExpectedRewrappingAAD string            `json:"expected_rewrapping_aad"`
	RewrappedEnvelope     Envelope          `json:"rewrapped_envelope"`
}

type vaultReferenceFile struct {
	FixtureOnly bool   `json:"fixture_only"`
	Version     uint32 `json:"version"`
	NISTSource  string `json:"nist_source"`
	NISTVectors []struct {
		Name       string `json:"name"`
		Key        string `json:"key"`
		Nonce      string `json:"nonce"`
		Plaintext  string `json:"plaintext"`
		AAD        string `json:"aad"`
		Ciphertext string `json:"ciphertext"`
		Tag        string `json:"tag"`
	} `json:"nist_vectors"`
	PublicTestKEKs map[string]string    `json:"public_test_keks"`
	Cases          []vaultReferenceCase `json:"cases"`
}

func vaultReferences(t *testing.T) vaultReferenceFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vault_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var result vaultReferenceFile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.FixtureOnly || result.Version != 1 || len(result.Cases) != 4 || len(result.NISTVectors) != 5 {
		t.Fatal("expected five NIST cases and four public wallet-purpose vectors")
	}
	return result
}

func referenceBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func referenceGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// This wrapper exists only in a _test file. Keys and nonces are explicitly
// public, deterministic inputs from the independently generated fixture. It is
// not a simulated production KMS, and must never be selected by runtime code.
type referenceWrapper struct {
	id       string
	keys     map[string][]byte
	nonce    []byte
	wraps    int
	unwraps  int
	wrongDEK bool
}

func newReferenceWrapper(t *testing.T, f vaultReferenceFile, c vaultReferenceCase) *referenceWrapper {
	t.Helper()
	w := &referenceWrapper{id: c.Envelope.WrapperID, nonce: referenceBytes(t, c.TestOnlyWrapNonce), keys: make(map[string][]byte)}
	for ref, encoded := range f.PublicTestKEKs {
		w.keys[ref] = referenceBytes(t, encoded)
	}
	return w
}

func (w *referenceWrapper) ID() string { return w.id }
func (w *referenceWrapper) Wrap(ctx context.Context, ref string, dek [32]byte, aad []byte) ([]byte, error) {
	w.wraps++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aead, err := referenceGCM(w.keys[ref])
	if err != nil || len(w.nonce) != 12 {
		return nil, errors.New("public fixture wrapper unavailable")
	}
	if w.wrongDEK {
		dek[0] ^= 1
	}
	blob := append([]byte(nil), w.nonce...)
	return aead.Seal(blob, w.nonce, dek[:], aad), nil
}
func (w *referenceWrapper) Unwrap(ctx context.Context, ref string, blob, aad []byte) ([32]byte, error) {
	w.unwraps++
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	aead, err := referenceGCM(w.keys[ref])
	if err != nil || len(blob) != 12+32+16 {
		return [32]byte{}, errors.New("public fixture wrapping unavailable")
	}
	plain, err := aead.Open(nil, blob[:12], blob[12:], aad)
	if err != nil || len(plain) != 32 {
		return [32]byte{}, errors.New("public fixture wrapping rejected")
	}
	var dek [32]byte
	copy(dek[:], plain)
	clear(plain)
	return dek, nil
}

// The Python oracle implements AES key expansion/block encryption and GHASH
// directly and first reproduces NIST's published AES256-GCM examples. These
// tests cross-check that independent arithmetic against Go's standard library.
func TestReferenceNISTAES256GCM(t *testing.T) {
	f := vaultReferences(t)
	for _, c := range f.NISTVectors {
		t.Run(c.Name, func(t *testing.T) {
			aead, err := referenceGCM(referenceBytes(t, c.Key))
			if err != nil {
				t.Fatal(err)
			}
			nonce, plain, aad := referenceBytes(t, c.Nonce), referenceBytes(t, c.Plaintext), referenceBytes(t, c.AAD)
			sealed := aead.Seal(nil, nonce, plain, aad)
			if !bytes.Equal(sealed, referenceBytes(t, c.Ciphertext+c.Tag)) {
				t.Fatal("Go AES-GCM differs from published NIST/Python reference")
			}
			opened, err := aead.Open(nil, nonce, sealed, aad)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("published NIST ciphertext did not authenticate")
			}
		})
	}
}

func TestReferenceVaultEnvelopeBytes(t *testing.T) {
	f := vaultReferences(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			manifest, err := json.Marshal(c.Manifest)
			if err != nil || string(manifest) != c.CanonicalManifest {
				t.Fatal("public manifest encoding differs from independent canonical bytes")
			}
			hash := sha256.Sum256(manifest)
			if hex.EncodeToString(hash[:]) != c.Envelope.ManifestHash {
				t.Fatal("manifest commitment mismatch")
			}
			aad, err := contentAAD(c.Envelope.Binding, c.Envelope.Purpose, c.Envelope.ContentRevision, c.Envelope.ManifestHash)
			if err != nil || !bytes.Equal(aad, referenceBytes(t, c.ExpectedContentAAD)) {
				t.Fatal("content AAD differs from independent binary framing", err)
			}
			wrapAAD, err := wrappingAAD(c.Envelope)
			if err != nil || !bytes.Equal(wrapAAD, referenceBytes(t, c.ExpectedWrappingAAD)) {
				t.Fatal("wrapping AAD differs from independent cipher-hash binding", err)
			}
			w := newReferenceWrapper(t, f, c)
			random := bytes.NewReader(referenceBytes(t, c.TestOnlyDEK+c.Envelope.Nonce))
			plain := referenceBytes(t, c.ExpectedPlaintext)
			got, err := sealEnvelope(context.Background(), w, c.Envelope.Binding,
				c.Envelope.Purpose, c.Envelope.ContentRevision, c.Envelope.ManifestHash,
				plain, c.Envelope.KeyRef, random)
			if err != nil || !reflect.DeepEqual(got, c.Envelope) || random.Len() != 0 {
				t.Fatal("sealed envelope differs from independent full ciphertext/wrapping", err)
			}
			opened, err := openEnvelope(context.Background(), w, c.Envelope)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("independent envelope failed exact plaintext authentication", err)
			}
			clear(opened)
			w.nonce = referenceBytes(t, c.TestOnlyRewrapNonce)
			rewrapped, err := rewrapEnvelope(context.Background(), w, c.Envelope,
				c.RewrappedEnvelope.KeyRef, c.RewrappedEnvelope.WrapRevision)
			if err != nil || !reflect.DeepEqual(rewrapped, c.RewrappedEnvelope) {
				t.Fatal("rewrapped envelope differs from independent expected bytes", err)
			}
			rewrapAAD, err := wrappingAAD(rewrapped)
			if err != nil || !bytes.Equal(rewrapAAD, referenceBytes(t, c.ExpectedRewrappingAAD)) {
				t.Fatal("rewrapping AAD mismatch", err)
			}
			opened, err = openEnvelope(context.Background(), w, rewrapped)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("key rotation changed retained material", err)
			}
			clear(opened)
		})
	}
}

func flipReferenceHex(t *testing.T, s string) string {
	t.Helper()
	raw := referenceBytes(t, s)
	raw[0] ^= 1
	return hex.EncodeToString(raw)
}

func TestReferenceVaultRejectsSwappedBindings(t *testing.T) {
	f := vaultReferences(t)
	for i, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			other := f.Cases[(i+2)%len(f.Cases)].Envelope
			otherPurpose := f.Cases[i^1].Envelope
			mutations := map[string]func(*Envelope){
				"authority":                   func(e *Envelope) { e.Binding.AuthorityID = flipReferenceHex(t, e.Binding.AuthorityID) },
				"account":                     func(e *Envelope) { e.Binding.AccountID = other.Binding.AccountID },
				"principal":                   func(e *Envelope) { e.Binding.PrincipalID = other.Binding.PrincipalID },
				"provision":                   func(e *Envelope) { e.Binding.ProvisionID = other.Binding.ProvisionID },
				"entire_other_wallet_binding": func(e *Envelope) { e.Binding = other.Binding },
				"network":                     func(e *Envelope) { e.Binding.Network++ },
				"genesis":                     func(e *Envelope) { e.Binding.Genesis = flipReferenceHex(t, e.Binding.Genesis) },
				"profile":                     func(e *Envelope) { e.Binding.Profile += "-other" },
				"root":                        func(e *Envelope) { e.Binding.RootPublicKey = other.Binding.RootPublicKey },
				"gym_public":                  func(e *Envelope) { e.Binding.GymPublicKey = other.Binding.GymPublicKey },
				"gym_id":                      func(e *Envelope) { e.Binding.GymID = other.Binding.GymID },
				"purpose":                     func(e *Envelope) { e.Purpose = otherPurpose.Purpose },
				"content_revision":            func(e *Envelope) { e.ContentRevision++ },
				"manifest_hash":               func(e *Envelope) { e.ManifestHash = other.ManifestHash },
				"nonce":                       func(e *Envelope) { e.Nonce = flipReferenceHex(t, e.Nonce) },
				"ciphertext":                  func(e *Envelope) { e.Ciphertext = flipReferenceHex(t, e.Ciphertext) },
				"other_wallet_ciphertext":     func(e *Envelope) { e.Ciphertext = other.Ciphertext },
				"wrapper_id":                  func(e *Envelope) { e.WrapperID += "-other" },
				"key_reference":               func(e *Envelope) { e.KeyRef = c.RewrappedEnvelope.KeyRef },
				"other_purpose_key_reference": func(e *Envelope) { e.KeyRef = otherPurpose.KeyRef },
				"wrap_revision":               func(e *Envelope) { e.WrapRevision++ },
				"wrapped_key":                 func(e *Envelope) { e.WrappedKey = flipReferenceHex(t, e.WrappedKey) },
				"other_wallet_wrapped_key":    func(e *Envelope) { e.WrappedKey = other.WrappedKey },
				"other_purpose_wrapped_key":   func(e *Envelope) { e.WrappedKey = otherPurpose.WrappedKey },
				"envelope_version":            func(e *Envelope) { e.Version++ },
				"binding_version":             func(e *Envelope) { e.Binding.Version++ },
				"uppercase_nonce":             func(e *Envelope) { e.Nonce = strings.ToUpper(e.Nonce) },
				"truncated_tag":               func(e *Envelope) { e.Ciphertext = e.Ciphertext[:len(e.Ciphertext)-2] },
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					bad := c.Envelope
					mutate(&bad)
					w := newReferenceWrapper(t, f, c)
					plain, err := openEnvelope(context.Background(), w, bad)
					if err == nil || len(plain) != 0 {
						t.Fatal("altered envelope exposed plaintext")
					}
				})
			}
			bad := c.RewrappedEnvelope
			bad.WrapRevision = c.Envelope.WrapRevision
			if plain, err := openEnvelope(context.Background(), newReferenceWrapper(t, f, c), bad); err == nil || len(plain) != 0 {
				t.Fatal("rotated ciphertext accepted a substituted old wrapping revision")
			}
		})
	}
}

func TestReferenceVaultFailureDoesNotReturnMaterial(t *testing.T) {
	f := vaultReferences(t)
	c := f.Cases[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if plain, err := openEnvelope(ctx, newReferenceWrapper(t, f, c), c.Envelope); err == nil || len(plain) != 0 {
		t.Fatal("cancelled unwrap exposed plaintext")
	}
	for _, length := range []int{0, 31, 32, 43} {
		w := newReferenceWrapper(t, f, c)
		e, err := sealEnvelope(context.Background(), w, c.Envelope.Binding,
			c.Envelope.Purpose, c.Envelope.ContentRevision, c.Envelope.ManifestHash,
			referenceBytes(t, c.ExpectedPlaintext), c.Envelope.KeyRef, bytes.NewReader(make([]byte, length)))
		if err == nil || e != (Envelope{}) || w.wraps != 0 {
			t.Fatalf("short DEK/nonce read (%d bytes) reached wrapping or returned material", length)
		}
	}
	for _, next := range []uint64{0, 1, 3, math.MaxUint64} {
		e, err := rewrapEnvelope(context.Background(), newReferenceWrapper(t, f, c),
			c.Envelope, c.RewrappedEnvelope.KeyRef, next)
		if err == nil || e != (Envelope{}) {
			t.Fatal("nonconsecutive wrapping revision accepted")
		}
	}
	w := newReferenceWrapper(t, f, c)
	w.wrongDEK = true
	e, err := rewrapEnvelope(context.Background(), w, c.Envelope, c.RewrappedEnvelope.KeyRef, 2)
	if err == nil || e != (Envelope{}) {
		t.Fatal("wrapper returning a different validly wrapped DEK was accepted")
	}
}

func TestReferenceVaultPlaintextProjection(t *testing.T) {
	f := vaultReferences(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			plain := referenceBytes(t, c.ExpectedPlaintext)
			defer clear(plain)
			if c.Envelope.Purpose == RecoveryPurpose {
				record := vaultRecord{Binding: c.Envelope.Binding, Manifest: c.Manifest}
				entropy, err := decodeRecovery(plain, record)
				if err != nil || !bytes.Equal(entropy[:], plain[4:36]) {
					t.Fatal("independent recovery payload projection differs", err)
				}
				clear(entropy[:])
				for _, offset := range []int{0, 4, 36, 40} {
					bad := append([]byte(nil), plain...)
					bad[offset] ^= 1
					got, err := decodeRecovery(bad, record)
					clear(bad)
					if err == nil || got != ([32]byte{}) {
						t.Fatal("corrupt recovery version/entropy/length/manifest exposed entropy")
					}
				}
				return
			}
			key, err := decodeGym(plain, c.Envelope.Binding)
			if err != nil {
				t.Fatal("independent gym-only payload rejected", err)
			}
			if hex.EncodeToString(key.PubKey().SerializeCompressed()) != c.Envelope.Binding.GymPublicKey {
				key.Zero()
				t.Fatal("gym payload did not project the independently derived public key")
			}
			key.Zero()
			for _, offset := range []int{0, 4} {
				bad := append([]byte(nil), plain...)
				bad[offset] ^= 1
				got, err := decodeGym(bad, c.Envelope.Binding)
				clear(bad)
				if err == nil || got != nil {
					if got != nil {
						got.Zero()
					}
					t.Fatal("corrupt gym version/scalar exposed private key")
				}
			}
		})
	}
}
