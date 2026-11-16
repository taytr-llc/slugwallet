// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/taytr-llc/slug/gymaccount"
)

// This is a corruption test, not another cryptographic oracle. It starts with
// actual sealed public-fixture records, changes persisted public bookkeeping,
// and invokes the same structural audit that Open must pass before any unwrap.
func auditReviewFixture(t *testing.T) (*Vault, []vaultRecord) {
	t.Helper()
	db, err := leveldb.OpenFile(filepath.Join(t.TempDir(), "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	v := &Vault{db: db, authority: gymaccount.AuthorityInfo{AuthorityID: strings.Repeat("1", 64)}, config: Config{
		MaxOperations: MaxOperations, WrapperID: "core-public-fixture",
		AllowedRecoveryKeyRefs: []string{"recovery-old", "recovery-new"},
		AllowedGymKeyRefs:      []string{"gym-old", "gym-new"},
	}}
	w := new(coreWrapper)
	var records []vaultRecord
	for i, name := range []string{"zero256", "incrementing256"} {
		identity, err := gymaccount.FixtureIdentity(name)
		if err != nil {
			t.Fatal(err)
		}
		binding := coreBinding(t)
		binding.AccountID = strings.Repeat(string(rune('2'+i)), 64)
		binding.PrincipalID = strings.Repeat(string(rune('4'+i)), 64)
		binding.ProvisionID = strings.Repeat(string(rune('6'+i)), 64)
		binding.RootPublicKey, binding.GymPublicKey, binding.GymID = identity.RootPublicKey, identity.GymPublicKey, identity.GymID
		manifest, recoveryPlain, gymPlain, err := materialPayloads(identity)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := manifestDigest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		r := vaultRecord{Binding: binding, Manifest: manifest, ManifestHash: hash, State: "reserved", Revision: 1}
		if i == 0 {
			recoveryEnvelope, err := sealEnvelope(context.Background(), w, binding, RecoveryPurpose, 1, hash, recoveryPlain, "recovery-old", bytes.NewReader(bytes.Repeat([]byte{21}, 44)))
			if err != nil {
				t.Fatal(err)
			}
			gymEnvelope, err := sealEnvelope(context.Background(), w, binding, GymPurpose, 1, hash, gymPlain, "gym-old", bytes.NewReader(bytes.Repeat([]byte{22}, 44)))
			if err != nil {
				t.Fatal(err)
			}
			r.State, r.Revision, r.Recovery, r.Gym = "enrolled", 4, &recoveryEnvelope, &gymEnvelope
			receipt := retentionReceipt(r)
			r.Receipt = &receipt
		}
		clear(recoveryPlain)
		clear(gymPlain)
		records = append(records, r)
	}
	return v, records
}

func auditReviewWrite(t *testing.T, v *Vault, records []vaultRecord) {
	t.Helper()
	v.meta = vaultMetadata{Accounts: []reservationIndex{}}
	batch := new(leveldb.Batch)
	for _, r := range records {
		v.meta.Accounts = append(v.meta.Accounts, reservationIndex{AccountID: r.Binding.AccountID, PrincipalID: r.Binding.PrincipalID, ProvisionID: r.Binding.ProvisionID})
		v.meta.Operations += uint32(r.Revision)
		v.meta.Reserved += remaining(r)
		if err := putVault(batch, "account:"+r.Binding.AccountID, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := putVault(batch, "meta", v.meta); err != nil {
		t.Fatal(err)
	}
	if err := v.db.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAuditReviewRejectsCapacityCounterOverflow(t *testing.T) {
	v, records := auditReviewFixture(t)
	auditReviewWrite(t, v, records)
	if err := v.audit(); err != nil {
		t.Fatal("valid baseline rejected", err)
	}
	// 4294967294 operations plus three reserved transitions used to wrap to one
	// in uint32. Record sums still matched metadata, bypassing the second check.
	records[0].Revision = uint64(math.MaxUint32) - 2
	records[0].Recovery.WrapRevision = records[0].Revision - 3
	records[0].Gym.WrapRevision = records[0].Revision - 3
	auditReviewWrite(t, v, records)
	if v.meta.Operations+v.meta.Reserved != 1 {
		t.Fatal("test no longer exercises uint32 overflow")
	}
	if err := v.audit(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("overflowing retained operation budget was accepted", err)
	}
}

func TestAuditReviewRequiresStateAndWrappingRevisionAgreement(t *testing.T) {
	v, records := auditReviewFixture(t)
	original := records[0]
	tests := []struct {
		name, state                     string
		revision, recoveryWrap, gymWrap uint64
	}{
		{"sealed-rotated", "sealed", 2, 2, 2},
		{"verified-rotated", "verified", 3, 2, 2},
		{"enrolled-ahead", "enrolled", 4, 2, 2},
		{"rotation-behind", "enrolled", 5, 1, 1},
		{"split-pair", "enrolled", 5, 2, 1},
		{"unbounded-revision", "enrolled", uint64(MaxOperations) + 1, uint64(MaxOperations) - 2, uint64(MaxOperations) - 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cloneRecord(original)
			r.State, r.Revision = tt.state, tt.revision
			r.Recovery.WrapRevision, r.Gym.WrapRevision = tt.recoveryWrap, tt.gymWrap
			if tt.state == "sealed" {
				r.Receipt = nil
			}
			if err := v.validateRecord(r); !errors.Is(err, ErrCorrupt) {
				t.Fatal("incoherent state/wrapping revisions accepted before unwrap", err)
			}
		})
	}
}
