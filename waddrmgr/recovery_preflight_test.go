// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestResumableEarlyDecoderRefusals(t *testing.T) {
	db, _ := resumableManager(t, productionprofile.DefaultCursors())
	rollback := errors.New("rollback corruption fixture")
	tests := []struct {
		name        string
		bucket, key []byte
		size        int
	}{
		{"public-parameters-short", mainBucketName, masterPubKeyName, 87},
		{"private-parameters-long", mainBucketName, masterPrivKeyName, 89},
		{"crypto-public-short", mainBucketName, cryptoPubKeyName, 71},
		{"crypto-private-long", mainBucketName, cryptoPrivKeyName, 73},
		{"crypto-script-missing", mainBucketName, cryptoScriptKeyName, -1},
		{"root-public-long", mainBucketName, masterHDPubName, 297},
		{"root-private-missing", mainBucketName, masterHDPrivName, -1},
		{"root-private-empty", mainBucketName, masterHDPrivName, 40},
		{"watch-only-short", mainBucketName, watchingOnlyName, 0},
		{"fixture-name-long", mainBucketName, candidateFixtureName, 33},
		{"sync-short", syncBucketName, syncedToName, 36},
		{"sync-long", syncBucketName, syncedToName, 41},
		{"start-short", syncBucketName, startBlockName, 35},
		{"birthday-short", syncBucketName, birthdayName, 7},
		{"birthday-block-short", syncBucketName, birthdayBlockName, 43},
		{"birthday-verification-short", syncBucketName, birthdayBlockVerifiedName, 1},
		{"birthday-verification-long", syncBucketName, birthdayBlockVerifiedName, 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				b := ns.NestedReadWriteBucket(test.bucket)
				var err error
				if test.size < 0 {
					err = b.Delete(test.key)
				} else {
					err = b.Put(test.key, make([]byte, test.size))
				}
				if err != nil {
					return err
				}
				got, err := OpenCandidateRecovery(ns, []byte("intentionally-wrong"), &chaincfg.MainNetParams)
				if got != nil {
					got.Close()
				}
				if got != nil || !errors.Is(err, ErrRecoveryState) {
					t.Fatalf("decoder reached password derivation: %v", err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
		})
	}
	for _, key := range [][]byte{masterPubKeyName, masterPrivKeyName} {
		for _, field := range []int{64, 72, 80} {
			err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				b := ns.NestedReadWriteBucket(mainBucketName)
				raw := bytes.Clone(b.Get(key))
				binary.LittleEndian.PutUint64(raw[field:field+8], ^uint64(0))
				if err := b.Put(key, raw); err != nil {
					return err
				}
				got, err := OpenCandidateRecovery(ns, pubPassphrase, &chaincfg.MainNetParams)
				if got != nil {
					got.Close()
				}
				if got != nil || !errors.Is(err, ErrRecoveryState) {
					t.Fatalf("unbounded KDF accepted: %v", err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
		}
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if err := ns.DeleteNestedBucket(syncBucketName); err != nil {
			return err
		}
		if got, err := OpenCandidateRecovery(ns, pubPassphrase, &chaincfg.MainNetParams); got != nil || !errors.Is(err, ErrRecoveryState) {
			t.Fatalf("missing sync: %v", err)
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if got, err := OpenCandidateRecovery(nil, pubPassphrase, &chaincfg.MainNetParams); got != nil || !errors.Is(err, ErrRecoveryState) {
		t.Fatalf("missing manager namespace: %v", err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		got, err := OpenCandidateRecovery(tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams)
		if got != nil {
			got.Close()
		}
		return err
	}); err != nil {
		t.Fatal("rolled-back corruption changed wallet", err)
	}
}

func TestResumableKDFAdmission(t *testing.T) {
	db, mgr := resumableManager(t, productionprofile.DefaultCursors())
	for _, config := range []ScryptOptions{{N: 1, R: 8, P: 1}, {N: 3, R: 8, P: 1}, {N: 1 << 19, R: 8, P: 1}, {N: 16, R: 0, P: 1}, {N: 16, R: 9, P: 1}, {N: 16, R: 8, P: 2}} {
		if _, err := recoveryScryptOptions(&config); !errors.Is(err, ErrRecoveryState) {
			t.Fatal("invalid creation options accepted", config, err)
		}
		for _, private := range []bool{false, true} {
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return mgr.ChangePassphrase(tx.ReadWriteBucket(waddrmgrNamespaceKey), []byte("wrong-old"), []byte("new"), private, &config)
			}); !errors.Is(err, ErrRecoveryState) {
				t.Fatal("rotation reached old KDF before parameter refusal", config, err)
			}
		}
	}
	for _, config := range []ScryptOptions{FastScryptOptions, DefaultScryptOptions} {
		owned, err := recoveryScryptOptions(&config)
		if err != nil || owned != config {
			t.Fatal("valid supported options rejected", err)
		}
		config.N = 1
		if owned.N == 1 {
			t.Fatal("options were not owned")
		}
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return mgr.ChangePassphrase(tx.ReadWriteBucket(waddrmgrNamespaceKey), pubPassphrase, []byte("PUBLIC-ROTATION-FIXTURE"), false, &FastScryptOptions)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		opened, err := OpenCandidateRecovery(tx.ReadBucket(waddrmgrNamespaceKey), []byte("PUBLIC-ROTATION-FIXTURE"), &chaincfg.MainNetParams)
		if opened != nil {
			opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal("supported rotation broke reopen", err)
	}
}

func TestResumableCreationRejectsKDFBeforeMutation(t *testing.T) {
	db, _ := resumableManager(t, productionprofile.DefaultCursors())
	ctx := context.Background()
	manifest, err := productionprofile.FixtureManifest(ctx, productionprofile.CandidateZero256, productionprofile.DefaultCursors())
	if err != nil {
		t.Fatal(err)
	}
	public, err := productionprofile.MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entropy, err := productionprofile.FixtureEntropy(productionprofile.CandidateZero256)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	root, err := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	private := make([]byte, 68)
	defer clear(private)
	binary.LittleEndian.PutUint32(private, 2)
	copy(private[4:36], entropy[:])
	digest := sha256.Sum256(public)
	copy(private[36:], digest[:])
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket([]byte("rejected-creation"))
		if err != nil {
			return err
		}
		config := ScryptOptions{N: 1 << 19, R: 8, P: 1}
		err = CreateWithResumableCandidateRecovery(ctx, ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, &config, time.Time{}, public, private)
		if !errors.Is(err, ErrRecoveryState) || ns.NestedReadBucket(mainBucketName) != nil {
			t.Fatalf("over-budget KDF reached creation: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
