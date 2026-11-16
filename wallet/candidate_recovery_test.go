// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type candidateVector struct {
	Name     string                            `json:"name"`
	Export   productionprofile.Export          `json:"export"`
	Payments []productionprofile.PaymentPublic `json:"payments"`
}

func candidateVectors(t *testing.T) []candidateVector {
	t.Helper()
	raw, err := os.ReadFile("../productionprofile/testdata/candidate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		FixtureOnly bool              `json:"candidate_fixtures_only"`
		Production  bool              `json:"production_issuance_enabled"`
		Cases       []candidateVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &data); err != nil || !data.FixtureOnly || data.Production || len(data.Cases) != 2 {
		t.Fatal("invalid independent candidate fixtures", err)
	}
	return data.Cases
}

func TestCandidateWalletRoundTrip(t *testing.T) {
	for _, vector := range candidateVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			loader := retainedLoader(t)
			w, err := loader.CreateCandidateFixtureWallet(retainedPubPass, retainedPrivPass, vector.Name)
			if err != nil {
				t.Fatal(err)
			}
			if w.Manager.RecoveryVersion() != 2 || w.Manager.DerivationMode() != waddrmgr.DerivationStandard {
				t.Fatal("candidate schema/mode not retained")
			}
			identity, err := w.CandidateGymIdentity(context.Background())
			if err != nil || identity.PublicKey != vector.Export.Manifest.GymPublicKey || identity.GymID != vector.Export.Manifest.GymID {
				t.Fatal("candidate gym differs from independent derivation", err)
			}
			if _, err := w.GymIdentity(context.Background()); err == nil {
				t.Fatal("candidate acquired v1 gym identity")
			}
			if got, err := w.ExportCandidateRecovery(context.Background()); err == nil || got.Mnemonic != "" {
				t.Fatal("locked candidate export returned material")
			}
			retainedUnlock(t, w, retainedPrivPass)
			if got, err := w.ExportRecovery(context.Background()); err == nil || got.Mnemonic != "" {
				t.Fatal("candidate acquired v1 export")
			}
			want := vector.Export
			for i := range want.Manifest.Accounts {
				want.Manifest.Accounts[i].NextExternal = 1
				want.Manifest.Accounts[i].NextInternal = 1
			}
			for _, payment := range vector.Payments {
				if payment.Index != 0 {
					continue
				}
				scope, err := w.Manager.PaymentScope(payment.Purpose)
				if err != nil {
					t.Fatal(err)
				}
				got := retainedAddress(t, w, scope, payment.Branch == 1)
				if got != payment.Address {
					t.Fatalf("independent address mismatch for %s: %s", payment.Path, got)
				}
			}
			// External candidate addresses must be part of the active rescan set.
			var relevant int
			if err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				return w.Manager.ForEachRelevantActiveAddress(tx.ReadBucket(waddrmgrNamespaceKey), func(address.Address) error { relevant++; return nil })
			}); err != nil || relevant != 8 {
				t.Fatalf("candidate active address coverage %d: %v", relevant, err)
			}
			got, err := w.ExportCandidateRecovery(context.Background())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("candidate export differs from independent vector", err)
			}
			newPass := []byte("candidate public fixture rotated password")
			if err := w.ChangePrivatePassphrase(retainedPrivPass, newPass); err != nil {
				t.Fatal(err)
			}
			if err := loader.UnloadWallet(); err != nil {
				t.Fatal(err)
			}
			w, err = loader.OpenExistingWallet(retainedPubPass, false)
			if err != nil {
				t.Fatal("reopen candidate", err)
			}
			if err := w.Unlock(retainedPrivPass, nil); err == nil {
				t.Fatal("old private password accepted")
			}
			retainedUnlock(t, w, newPass)
			got, err = w.ExportCandidateRecovery(context.Background())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("reopened export changed", err)
			}
			raw, err := productionprofile.MarshalExport(got)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := productionprofile.ParseExport(raw)
			clear(raw)
			if err != nil {
				t.Fatal(err)
			}
			restoredLoader := retainedLoader(t)
			restored, err := restoredLoader.RestoreCandidateFixtureWallet(retainedPubPass, retainedPrivPass, bundle)
			if err != nil {
				t.Fatal("file-only candidate restore", err)
			}
			retainedUnlock(t, restored, retainedPrivPass)
			again, err := restored.ExportCandidateRecovery(context.Background())
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatal("restored candidate changed", err)
			}
			for _, a := range want.Manifest.Accounts {
				scope := waddrmgr.KeyScope{Purpose: a.Purpose, Coin: a.Coin}
				for _, internal := range []bool{false, true} {
					if retainedAddress(t, restored, scope, internal) != retainedAddress(t, w, scope, internal) {
						t.Fatal("candidate cursor restoration mismatch")
					}
				}
			}
		})
	}
}

func TestCandidateWalletRefusalBeforeCreation(t *testing.T) {
	loader := retainedLoader(t)
	if _, err := loader.CreateCandidateFixtureWallet(retainedPubPass, retainedPrivPass, "production"); !errors.Is(err, productionprofile.ErrFixture) {
		t.Fatal("unknown fixture accepted", err)
	}
	vector := candidateVectors(t)[0]
	vector.Export.Manifest.Accounts[2].NextExternal = productionprofile.FixtureRuntimeMaxNextIndex + 1
	if _, err := loader.RestoreCandidateFixtureWallet(retainedPubPass, retainedPrivPass, vector.Export); !errors.Is(err, ErrRecoveryScanRequired) {
		t.Fatal("oversized fixture restore was not explicitly refused", err)
	}
	if exists, err := loader.WalletExists(); err != nil || exists {
		t.Fatal("refusal created wallet storage", err)
	}
}

func TestCandidateWalletMissingRetentionDoesNotDowngrade(t *testing.T) {
	loader := retainedLoader(t)
	if _, err := loader.CreateCandidateFixtureWallet(retainedPubPass, retainedPrivPass, productionprofile.CandidateZero256); err != nil {
		t.Fatal(err)
	}
	if err := loader.UnloadWallet(); err != nil {
		t.Fatal(err)
	}
	db, err := walletdb.Open("bdb", filepath.Join(loader.dbDirPath, WalletDBName), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket([]byte("main"))
		if binary.LittleEndian.Uint32(b.Get([]byte("mgrver"))) != waddrmgr.CandidateManagerVersion {
			t.Fatal("candidate schema not persisted")
		}
		for _, key := range []string{"slug-derivation-mode", "slug-recovery-version", "slug-recovery-public", "slug-recovery-private", "slug-candidate-fixture"} {
			if err := b.Delete([]byte(key)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.OpenExistingWallet(retainedPubPass, false); !errors.Is(err, waddrmgr.ErrRecoveryState) {
		t.Fatal("damaged candidate downgraded or reopened", err)
	}
}
