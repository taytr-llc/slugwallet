// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slugwallet/recovery"
)

func testManifest(t *testing.T) Manifest {
	t.Helper()
	m, err := FixtureManifest(context.Background(), CandidateZero256, DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestProductionGateIsClosed(t *testing.T) {
	candidate := CandidateDescriptor()
	hash, err := DescriptorHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", hash, strings.Repeat("0", 64), strings.Repeat("f", 64), strings.ToUpper(hash)} {
		got, err := ResolveProduction(value)
		if !errors.Is(err, ErrProfileUnfinalized) || !reflect.DeepEqual(got, Descriptor{}) {
			t.Fatal("unfinalized identity was accepted")
		}
	}
	raw, _ := MarshalDescriptor(candidate)
	raw = append(raw[:len(raw)-1], []byte(`,"finalized":true}`)...)
	if _, err := ParseDescriptor(raw); err == nil {
		t.Fatal("caller finalization accepted")
	}
	for _, name := range []string{"zero256", "incrementing256", "production", strings.ToUpper(CandidateZero256), CandidateZero256 + " "} {
		entropy, err := FixtureEntropy(name)
		if !errors.Is(err, ErrFixture) || entropy != ([32]byte{}) {
			t.Fatal("unknown fixture accepted")
		}
	}
}
func TestProfileOwnsItsInputsAndOutputs(t *testing.T) {
	d := CandidateDescriptor()
	d.Payments[0].Purpose = 999
	if CandidateDescriptor().Payments[0].Purpose != 44 {
		t.Fatal("descriptor mutation retained")
	}
	cursors := DefaultCursors()
	cursors[2].NextExternal = 26
	m, err := FixtureManifest(context.Background(), CandidateZero256, cursors)
	if err != nil {
		t.Fatal(err)
	}
	cursors[2].NextExternal = 99
	if m.Accounts[2].NextExternal != 26 {
		t.Fatal("cursor alias retained")
	}
	m.Accounts[2].NextExternal = 99
	m.Descriptor.Payments[0].Purpose = 999
	m.GymPath[0] = 0
	good := testManifest(t)
	if good.Accounts[2].NextExternal != 0 || good.Descriptor.Payments[0].Purpose != 44 || good.GymPath[0] != 0x8000000d {
		t.Fatal("fixture output changed template")
	}
}
func TestDescriptorRefusesUnsupportedRules(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Descriptor)
	}{
		{"coin0", func(d *Descriptor) { d.CoinType = 0 }}, {"coin1", func(d *Descriptor) { d.CoinType = 1 }}, {"hardenedcoin", func(d *Descriptor) { d.CoinType = MaxNextIndex }},
		{"zerochain", func(d *Descriptor) { d.Genesis = strings.Repeat("0", 64) }}, {"upperchain", func(d *Descriptor) { d.Genesis = strings.ToUpper(d.Genesis) }},
		{"network", func(d *Descriptor) { d.Network = 0 }}, {"passphrase", func(d *Descriptor) { d.Seed = "bip39-passphrase" }},
		{"legacyderive", func(d *Descriptor) { d.PaymentDerivation = "legacy" }}, {"mixed49", func(d *Descriptor) { d.Payments[1].InternalType = "p2wpkh" }},
		{"default44", func(d *Descriptor) { d.DefaultReceivePurpose = 44 }}, {"gymindex", func(d *Descriptor) { d.GymIdentityIndex = 1 }},
		{"gymbip32", func(d *Descriptor) { d.GymScheme = "bip32" }}, {"scan", func(d *Descriptor) { d.ScanFromHeight = 1 }},
		{"xpub", func(d *Descriptor) { d.Encodings.HDPublic = "0488b21e" }}, {"scopeorder", func(d *Descriptor) { d.Payments[0], d.Payments[1] = d.Payments[1], d.Payments[0] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := CandidateDescriptor()
			tt.change(&d)
			if ValidateDescriptor(d) == nil {
				t.Fatal("unsupported rule accepted")
			}
		})
	}
}
func TestStrictProfileJSON(t *testing.T) {
	m := testManifest(t)
	manifest, _ := MarshalManifest(m)
	descriptor, _ := MarshalDescriptor(m.Descriptor)
	e, err := FixtureExport(context.Background(), CandidateZero256, DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	export, _ := MarshalExport(e)
	for _, tt := range []struct {
		name  string
		raw   []byte
		parse func([]byte) error
		bound int
	}{
		{"descriptor", descriptor, func(b []byte) error { _, err := ParseDescriptor(b); return err }, MaxDescriptorSize},
		{"manifest", manifest, func(b []byte) error { _, err := ParseManifest(b); return err }, MaxManifestSize},
		{"export", export, func(b []byte) error { _, err := ParseExport(b); return err }, MaxExportSize},
	} {
		t.Run(tt.name, func(t *testing.T) {
			invalid := [][]byte{nil, []byte("null"), append(append([]byte(nil), tt.raw...), []byte(` {}`)...), bytes.Repeat([]byte(" "), tt.bound+1), bytes.Replace(tt.raw, []byte(`"version":`), []byte(`"Version":`), 1), bytes.Replace(tt.raw, []byte(`"version":`), []byte(`"version":1,"version":`), 1), bytes.Replace(tt.raw, []byte(`"version":`), []byte(`"\u0076ersion":1,"version":`), 1), bytes.Replace(tt.raw, []byte(`"version":1`), []byte(`"version":null`), 1)}
			for _, raw := range invalid {
				if bytes.Equal(raw, tt.raw) {
					continue
				}
				if tt.parse(raw) == nil {
					t.Fatal("malformed schema accepted")
				}
			}
			// Ordinary formatting is accepted; canonical emission remains deterministic.
			var object any
			if json.Unmarshal(tt.raw, &object) != nil {
				t.Fatal("fixture")
			}
			pretty, _ := json.MarshalIndent(object, "", "  ")
			if err := tt.parse(pretty); err != nil {
				t.Fatal("valid whitespace/order", err)
			}
		})
	}
	for _, raw := range [][]byte{
		bytes.Replace(manifest, []byte(`"gym_path":[`), []byte(`"gym_path":[null,`), 1),
		bytes.Replace(manifest, []byte(`"next_external":0`), []byte(`"next_external":2147483649`), 1),
		bytes.Replace(manifest, []byte(`"next_external":0`), []byte(`"next_external":-1`), 1),
		bytes.Replace(manifest, []byte(`"next_external":0`), []byte(`"next_external":0.0`), 1),
		bytes.Replace(manifest, []byte(`"account_public_key":`), []byte(`"unknown":`), 1),
		bytes.Replace(manifest, []byte(`"purpose":44`), []byte(`"purpose":44,"purpose":44`), 1),
	} {
		if _, err := ParseManifest(raw); err == nil {
			t.Fatal("malformed nested schema accepted")
		}
	}
	v1, err := recovery.NewExport([32]byte{}, recovery.DefaultAccounts())
	if err != nil {
		t.Fatal(err)
	}
	v1raw, _ := recovery.MarshalExport(v1)
	if _, err := ParseExport(v1raw); err == nil {
		t.Fatal("v1 silently relabeled")
	}
	if _, err := recovery.ParseExport(export); err == nil {
		t.Fatal("v1 accepted version2")
	}
}
func TestFixtureBindingAndCursorBoundary(t *testing.T) {
	ctx := context.Background()
	m := testManifest(t)
	other, err := FixtureManifest(ctx, CandidateIncrementing256, DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	m.Accounts[0].AccountPublicKey = other.Accounts[0].AccountPublicKey
	if err := ValidateManifest(m); err != nil {
		t.Fatal("structural validation incorrectly claims ancestry", err)
	}
	if _, err := ValidateFixtureManifest(ctx, m); err == nil {
		t.Fatal("unrelated hardened account accepted")
	}
	cursors := DefaultCursors()
	cursors[2].NextExternal = MaxNextIndex
	cursors[2].NextInternal = 4097
	m, err = FixtureManifest(ctx, CandidateZero256, cursors)
	if err != nil {
		t.Fatal("public full-range inventory rejected", err)
	}
	if _, err := DerivePaymentPublic(ctx, m, 84, 0, MaxNextIndex-1); err != nil {
		t.Fatal("last public index rejected", err)
	}
	for _, request := range [][3]uint32{{84, 0, MaxNextIndex}, {84, 2, 0}, {45, 0, 0}} {
		if _, err := DerivePaymentPublic(ctx, m, request[0], request[1], request[2]); err == nil {
			t.Fatal("invalid exact path accepted")
		}
	}
	cursors[2].NextExternal = MaxNextIndex + 1
	if _, err := FixtureManifest(ctx, CandidateZero256, cursors); err == nil {
		t.Fatal("exhaustion overflow accepted")
	}
	e, err := FixtureExport(ctx, CandidateZero256, DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := FixtureExport(ctx, CandidateIncrementing256, DefaultCursors())
	e.Mnemonic = foreign.Mnemonic
	if _, err := ValidateFixtureExport(ctx, e); err == nil {
		t.Fatal("wrong phrase accepted")
	}
}
func TestExactPaymentPathDoesNotRetryOrShift(t *testing.T) {
	entropy, _ := FixtureEntropy(CandidateZero256)
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	defer clear(entropy[:])
	root, err := hdkeychain.NewMaster(seed[:], profileParams())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	calls := 0
	path := []uint32{44 | MaxNextIndex, CandidateCoinType | MaxNextIndex, MaxNextIndex}
	key, err := deriveExactPathWith(context.Background(), root, path, func(_ *hdkeychain.ExtendedKey, index uint32) (*hdkeychain.ExtendedKey, error) {
		calls++
		if index != path[0] {
			t.Fatal("fixed path shifted")
		}
		return nil, hdkeychain.ErrInvalidChild
	})
	if key != nil || !errors.Is(err, hdkeychain.ErrInvalidChild) || calls != 1 {
		t.Fatal("BIP32 fixed-path failure changed derivation")
	}
}
func TestDerivationCancellationAndRetryBound(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if m, err := FixtureManifest(canceled, CandidateZero256, DefaultCursors()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(m, Manifest{}) {
		t.Fatal("canceled fixture returned material")
	}
	m := testManifest(t)
	if out, err := DerivePaymentPublic(canceled, m, 84, 0, 0); !errors.Is(err, context.Canceled) || out != (PaymentPublic{}) {
		t.Fatal("canceled public derivation succeeded")
	}
	calls := 0
	zeroMAC := func(_, _ []byte) [64]byte { calls++; return [64]byte{} }
	if out, err := slip10Master(context.Background(), make([]byte, 64), zeroMAC); !errors.Is(err, ErrDerivation) || out != (slip10Node{}) || calls != 256 {
		t.Fatal("invalid master retry unbounded")
	}
	parent := slip10Node{}
	parent.key[31] = 1
	calls = 0
	// IL=n-parent makes the derived scalar zero on every attempt.
	invalid := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40}
	childMAC := func(_, data []byte) [64]byte {
		calls++
		if calls > 1 && data[0] != 1 {
			t.Fatal("retry did not use SLIP10 prefix")
		}
		var out [64]byte
		copy(out[:32], invalid)
		return out
	}
	if out, err := slip10Child(context.Background(), parent, 0x8000000d, childMAC); !errors.Is(err, ErrDerivation) || out != (slip10Node{}) || calls != 256 {
		t.Fatal("invalid child retry unbounded")
	}
	ctx, stop := context.WithCancel(context.Background())
	calls = 0
	cancelMAC := func(_, _ []byte) [64]byte { calls++; stop(); var out [64]byte; out[31] = 1; return out }
	if out, err := slip10Master(ctx, make([]byte, 64), cancelMAC); !errors.Is(err, context.Canceled) || out != (slip10Node{}) || calls != 1 {
		t.Fatal("cancellation after HMAC leaked success")
	}
}
