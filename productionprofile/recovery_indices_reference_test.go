// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Expected scripts, keys and addresses come from the independently frozen
// Python arithmetic, after rechecking its published standards and old vectors.
// Sparse derivation is not evidence of recovery scanning or supported quota.
func TestReferenceRecoveryHighIndices(t *testing.T) {
	raw, err := os.ReadFile("testdata/recovery_indices_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		PublicFixturesOnly bool     `json:"public_fixtures_only"`
		Indices            []uint32 `json:"indices"`
		Cases              []struct {
			Name          string          `json:"name"`
			RootPublicKey string          `json:"root_public_key"`
			GymPublicKey  string          `json:"gym_public_key"`
			GymID         string          `json:"gym_id"`
			Payments      []PaymentPublic `json:"payments"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if !corpus.PublicFixturesOnly || len(corpus.Cases) != 2 || !reflect.DeepEqual(corpus.Indices, []uint32{4096, 4097, 4116, 4128, 8191, 8192, 65535}) {
		t.Fatal("incomplete independent high-index corpus")
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			base, err := FixtureExport(context.Background(), fixture.Name, DefaultCursors())
			if err != nil {
				t.Fatal(err)
			}
			if base.Manifest.RootPublicKey != fixture.RootPublicKey || base.Manifest.GymPublicKey != fixture.GymPublicKey || base.Manifest.GymID != fixture.GymID || len(fixture.Payments) != 56 {
				t.Fatal("high-index fixture changed immutable identity or coverage")
			}
			seen := make(map[[3]uint32]bool)
			for _, expected := range fixture.Payments {
				key := [3]uint32{expected.Purpose, expected.Branch, expected.Index}
				if seen[key] {
					t.Fatal("duplicate independent path")
				}
				seen[key] = true
				got, err := DerivePaymentPublic(context.Background(), base.Manifest, expected.Purpose, expected.Branch, expected.Index)
				if err != nil || got != expected {
					t.Fatalf("independent public derivation at %s: %v", expected.Path, err)
				}
			}
		})
	}
}
