// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
)

type referenceGym struct {
	Genesis           string   `json:"genesis"`
	IdentityURI       string   `json:"identity_uri"`
	IdentityInput     string   `json:"identity_input"`
	IdentityHash      string   `json:"identity_hash"`
	Path              []uint32 `json:"path"`
	PathText          string   `json:"path_text"`
	SerializedIndices []string `json:"serialized_indices"`
	PublicKey         string   `json:"public_key"`
	GymID             string   `json:"gym_id"`
}
type referenceCase struct {
	Name              string          `json:"name"`
	Entropy           string          `json:"entropy"`
	Seed              string          `json:"seed"`
	Export            Export          `json:"export"`
	CanonicalManifest string          `json:"canonical_manifest"`
	CanonicalExport   string          `json:"canonical_export"`
	Payments          []PaymentPublic `json:"payments"`
	Gym               referenceGym    `json:"gym"`
	OtherGenesis      referenceGym    `json:"non_runnable_genesis_example"`
}
type referenceCall struct{ Key, Data, Output string }
type referenceTranscript struct {
	Name, Kind, Seed string
	ParentKey        string `json:"parent_key"`
	ParentChain      string `json:"parent_chain"`
	Index            uint32
	Calls            []referenceCall
	ExpectedKey      string `json:"expected_key"`
	ExpectedChain    string `json:"expected_chain"`
}
type publishedBIP32 struct{ Seed, Path, XPub, XPrv string }
type referenceCorpus struct {
	Descriptor          Descriptor
	CanonicalDescriptor string `json:"canonical_descriptor"`
	DescriptorHash      string `json:"descriptor_hash"`
	Cases               []referenceCase
	Injected            []referenceTranscript `json:"injected_hmac"`
	BIP32               []publishedBIP32      `json:"bip32_published"`
}

func readReference(t *testing.T) referenceCorpus {
	t.Helper()
	b, err := os.ReadFile("testdata/candidate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var out referenceCorpus
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Cases) != 2 || len(out.BIP32) != 17 {
		t.Fatal("incomplete independent corpus")
	}
	return out
}
func referenceHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func referenceCursors(m Manifest) []Cursor {
	var result []Cursor
	for _, a := range m.Accounts {
		result = append(result, Cursor{Purpose: a.Purpose, NextExternal: a.NextExternal, NextInternal: a.NextInternal})
	}
	return result
}
func referencePath(t *testing.T, path string) []uint32 {
	t.Helper()
	if path == "m" {
		return nil
	}
	var result []uint32
	for _, s := range strings.Split(strings.TrimPrefix(path, "m/"), "/") {
		hardened := strings.HasSuffix(s, "'")
		n, err := strconv.ParseUint(strings.TrimSuffix(s, "'"), 10, 31)
		if err != nil {
			t.Fatal(err)
		}
		if hardened {
			n += 1 << 31
		}
		result = append(result, uint32(n))
	}
	return result
}

// Expected values were generated before reading the Go implementation. The
// Python oracle validates pinned published standards before emitting this file.
func TestReferenceCandidateBytesAndPayments(t *testing.T) {
	c := readReference(t)
	if !reflect.DeepEqual(CandidateDescriptor(), c.Descriptor) {
		t.Fatal("candidate descriptor differs from independent contract")
	}
	encoded, err := MarshalDescriptor(c.Descriptor)
	if err != nil || string(encoded) != c.CanonicalDescriptor {
		t.Fatalf("descriptor bytes: %v", err)
	}
	hash, err := DescriptorHash(c.Descriptor)
	if err != nil || hash != c.DescriptorHash {
		t.Fatalf("descriptor digest: %v", err)
	}
	for _, fixture := range c.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			ctx := context.Background()
			got, err := FixtureExport(ctx, fixture.Name, referenceCursors(fixture.Export.Manifest))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, fixture.Export) {
				t.Fatal("derived export/root/account/gym differs from independent fixture")
			}
			b, err := MarshalExport(got)
			if err != nil || string(b) != fixture.CanonicalExport {
				t.Fatalf("canonical export: %v", err)
			}
			m, err := MarshalManifest(got.Manifest)
			if err != nil || string(m) != fixture.CanonicalManifest {
				t.Fatalf("canonical manifest: %v", err)
			}
			parsed, err := ParseExport([]byte(fixture.CanonicalExport))
			if err != nil || !reflect.DeepEqual(parsed, fixture.Export) {
				t.Fatalf("parse independent export: %v", err)
			}
			name, err := ValidateFixtureExport(ctx, parsed)
			if err != nil || name != fixture.Name {
				t.Fatalf("strong fixture binding: %v", err)
			}
			if len(fixture.Payments) != 40 {
				t.Fatal("missing payment coverage")
			}
			for _, expected := range fixture.Payments {
				t.Run(expected.Path, func(t *testing.T) {
					actual, err := DerivePaymentPublic(ctx, parsed.Manifest, expected.Purpose, expected.Branch, expected.Index)
					if err != nil {
						t.Fatal(err)
					}
					if actual != expected {
						t.Fatalf("public payment mismatch\ngot %#v\nwant %#v", actual, expected)
					}
				})
			}
			// A different genesis binds the URI and gym key, without changing
			// payment paths. This is a private derivation check, not issuance.
			d := c.Descriptor
			d.Genesis = fixture.OtherGenesis.Genesis
			var entropy [32]byte
			copy(entropy[:], referenceHex(t, fixture.Entropy))
			other, err := deriveManifest(ctx, entropy, d, referenceCursors(fixture.Export.Manifest))
			if err != nil {
				t.Fatal(err)
			}
			g := fixture.OtherGenesis
			if other.GymIdentityURI != g.IdentityURI || !reflect.DeepEqual(other.GymPath, g.Path) || other.GymPublicKey != g.PublicKey || other.GymID != g.GymID {
				t.Fatal("second genesis independent gym binding mismatch")
			}
			if other.GymID == parsed.Manifest.GymID || !reflect.DeepEqual(other.Accounts, parsed.Manifest.Accounts) {
				t.Fatal("wrong chain/payment separation")
			}
		})
	}
}

func TestReferencePublishedBIP32IncludingLeadingZero(t *testing.T) {
	// Exact published xprv/xpub strings include the leading-zero cases in
	// vectors3/4. This explicitly exercises standard Derive, not legacy mode.
	params := chaincfg.MainNetParams
	for _, fixture := range readReference(t).BIP32 {
		t.Run(fixture.Path+"/"+fixture.Seed[:8], func(t *testing.T) {
			key, err := hdkeychain.NewMaster(referenceHex(t, fixture.Seed), &params)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { key.Zero() }()
			for _, index := range referencePath(t, fixture.Path) {
				next, err := key.Derive(index)
				if err != nil {
					t.Fatal(err)
				}
				key.Zero()
				key = next
			}
			// Re-encode only the four version bytes for the published Bitcoin
			// strings; don't register a second global network in package tests.
			publishedPrivate, err := key.CloneWithVersion([]byte{0x04, 0x88, 0xad, 0xe4})
			if err != nil {
				t.Fatal(err)
			}
			defer publishedPrivate.Zero()
			if publishedPrivate.String() != fixture.XPrv {
				t.Fatal("published private extended key mismatch")
			}
			pub, err := key.Neuter()
			if err != nil {
				t.Fatal(err)
			}
			defer pub.Zero()
			publishedPublic, err := pub.CloneWithVersion([]byte{0x04, 0x88, 0xb2, 0x1e})
			if err != nil {
				t.Fatal(err)
			}
			defer publishedPublic.Zero()
			if publishedPublic.String() != fixture.XPub {
				t.Fatal("published public extended key mismatch")
			}
		})
	}
}

func TestReferencePublishedSLIP10Secp256k1(t *testing.T) {
	var corpus struct {
		Vectors []struct {
			Seed, Path, Private, Public string
			ChainCode                   string `json:"chain_code"`
		}
	}
	b, err := os.ReadFile("testdata/slip10_secp256k1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 12 {
		t.Fatal("missing published vectors")
	}
	for _, f := range corpus.Vectors {
		t.Run(f.Path+"/"+f.Seed[:8], func(t *testing.T) {
			got, err := slip10Path(context.Background(), referenceHex(t, f.Seed), referencePath(t, f.Path))
			if err != nil {
				t.Fatal(err)
			}
			defer got.zero()
			if hex.EncodeToString(got.key[:]) != f.Private || hex.EncodeToString(got.chain[:]) != f.ChainCode {
				t.Fatal("published SLIP10 private/chain mismatch")
			}
			key, pub := btcec.PrivKeyFromBytes(got.key[:])
			defer key.Zero()
			if hex.EncodeToString(pub.SerializeCompressed()) != f.Public {
				t.Fatal("published SLIP10 public mismatch")
			}
		})
	}
}

func TestReferenceSLIP10ExactRetryTranscripts(t *testing.T) {
	for _, f := range readReference(t).Injected {
		if f.Kind == "payment-invalid" {
			continue
		} // standard BIP32 routing has separate unit coverage
		t.Run(f.Name, func(t *testing.T) {
			calls := 0
			mac := func(key, data []byte) [64]byte {
				if calls >= len(f.Calls) {
					t.Fatal("unexpected extra HMAC/retry")
				}
				expected := f.Calls[calls]
				calls++
				if !bytes.Equal(key, referenceHex(t, expected.Key)) || !bytes.Equal(data, referenceHex(t, expected.Data)) {
					t.Fatalf("HMAC call%d: wrong key/data; retry must preserve exact index and fixed-width scalar", calls)
				}
				var result [64]byte
				copy(result[:], referenceHex(t, expected.Output))
				return result
			}
			var got slip10Node
			var err error
			switch f.Kind {
			case "master":
				got, err = slip10Master(context.Background(), referenceHex(t, f.Seed), mac)
			case "child":
				var parent slip10Node
				copy(parent.key[:], referenceHex(t, f.ParentKey))
				copy(parent.chain[:], referenceHex(t, f.ParentChain))
				defer parent.zero()
				got, err = slip10Child(context.Background(), parent, f.Index, mac)
			default:
				t.Fatal(fmt.Sprintf("unknown transcript kind %q", f.Kind))
			}
			defer got.zero()
			if err != nil {
				t.Fatal(err)
			}
			if calls != len(f.Calls) || hex.EncodeToString(got.key[:]) != f.ExpectedKey || hex.EncodeToString(got.chain[:]) != f.ExpectedChain {
				t.Fatal("retry result differs from independent transcript")
			}
		})
	}
}
