// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
	_ "github.com/taytr-llc/slugwallet/walletdb/bdb"
)

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0x2a, 0x64, 0xdf, 0x08, 0x5e, 0xef, 0xed, 0xd8, 0xbf,
		0xdb, 0xb3, 0x31, 0x76, 0xb5, 0xba, 0x2e, 0x62, 0xe8,
		0xbe, 0x8b, 0x56, 0xc8, 0x83, 0x77, 0x95, 0x59, 0x8b,
		0xb6, 0xc4, 0x40, 0xc0, 0x64,
	}

	rootKey, _ = hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)

	pubPassphrase   = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase  = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")
	pubPassphrase2  = []byte("-0NV4P~VSJBWbunw}%<Z]fuGpbN[ZI")
	privPassphrase2 = []byte("~{<]08%6!-?2s<$(8$8:f(5[4/!/{Y")

	// fastScrypt are parameters used throughout the tests to speed up the
	// scrypt operations.
	fastScrypt = &FastScryptOptions

	// waddrmgrNamespaceKey is the namespace key for the waddrmgr package.
	waddrmgrNamespaceKey = []byte("waddrmgrNamespace")

	// expectedAddrs is the list of all expected addresses generated from the
	// seed. Network encodings were independently converted from the upstream
	// fixtures by testdata/reencode_vectors.py, preserving the key payloads.
	expectedAddrs = []expectedAddr{
		{
			address:     "aTzxLfZGJghJsswJadWxnYCET2GuFKReD3",
			addressHash: hexToBytes("2b49ecd0cf72006173e6e95acf416b6735b5f889"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("02d8f88468c5a2e8e1815faf555f59cbd1979e3dbdf823f80c271b6fb70d2d519b"),
			privKey:     hexToBytes("c27d6581b92785834b381fa697c4b0ffc4574b495743722e0acb7601b1b68b99"),
			privKeyWIF:  "YKs7HMyivN9mDUZ7w46Fc2iXqNfsE45onSPbyEkY2K3W1BgmmnMx",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          0,
				Index:           0,
			},
		},
		{
			address:     "am6GrkhwWPNCkHm4FWCYoo3nf1szCet5Dd",
			addressHash: hexToBytes("e6c59a1542138d1bf08f45cd18899557cf56b356"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("02b9c175b908624f8a8eaac227d0e8c77c0eec327b8c512ad1b8b7a4b5b676971f"),
			privKey:     hexToBytes("18f3b191019e83878a81557abebb2afda199e31d22e150d8bf4df4561671be6c"),
			privKeyWIF:  "YEBYq7XfgGBHcKM7xC9xUfxuCqszFyKTRSuk5TQt6a3YdJFxZ7ME",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          0,
				Index:           1,
			},
		},
		{
			address:     "aQYXPwwyeGKMuZw3SyUixhxF3awZNcRmz8",
			addressHash: hexToBytes("0561e9373986965b647a57a09718e9c050215cfe"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("0329faddf1254d490d6add49e2b08cf52b561038c72baec0edb3cfacff71ff1021"),
			privKey:     hexToBytes("ccb8f6305b73136b363644b647f6efc0fd27b6b7d9c11c7e560662ed38db7b34"),
			privKeyWIF:  "YLCzxe1D9s5WYAuToTuF1PGqzh5YbaYtnbJdCSumMS1BwrNCwREH",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          0,
				Index:           2,
			},
		},
		{
			address:     "aSWgxjoZdTNG8h1mCsm6atnEatuz5WFdCP",
			addressHash: hexToBytes("1af950be02584ca230b7078cec0cfd38dd71b468"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03d738324e2f0ce42e46975d7f8c7117c1670e3d7912b0291aea452add99674774"),
			privKey:     hexToBytes("d6bc8ff768814fede2adcdb74826bd846924341b3862e3b6e31cdc084e992940"),
			privKeyWIF:  "YLYTzNsCwjRrhR3V3DuDxnyXEAQBgtf5766YV7uxyD1ZtDcaVbf9",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          0,
				Index:           3,
			},
		},
		{
			address:     "ajWoAhSf7d5Ax84vG9Q6HSbbCN28Y77G42",
			addressHash: hexToBytes("d578a267a7174c6ba7f76b0ab2397ce0ba0c5c3c"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03a917acd5cd5b6f544b43f1921a35677e4d5320e5d2add2056039b4b44fdf905e"),
			privKey:     hexToBytes("8563ade061110e03aee50695ffc5cb1c06c8310bde0a3674257c853c966968c0"),
			privKeyWIF:  "YHpLYgpTVZpMp1McjGAW7A7CASMQQCXEZFedYCNuckTM2bTX3hmt",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          0,
				Index:           4,
			},
		},
		{
			address:     "aULSSwjEdqoJEqb2TT3pG8G6YQs5Gzqx7o",
			addressHash: hexToBytes("2ef94abb9ee8f785d087c3ec8d6ee467e92d0d0a"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("020a1290b997c0a234a95213962e7edcb761c7360f0230f698a1a3e71c37047bb0"),
			privKey:     hexToBytes("fe4f855fcf059ec6ddf7b25f63b19aa49c771d1fcb9850b68ae3d65e20657a60"),
			privKeyWIF:  "YMsPk7qW4gr7q8TapDyADAL7NAaoEQBH5TfxTG8QR4bDnzpE9ewh",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          1,
				Index:           0,
			},
		},
		{
			address:     "ajMszruHwty1nuEUsb8N8pRYjQzryfigGa",
			addressHash: hexToBytes("d3c8ec46891f599bfeaa4c25918bfb3d46ea334c"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03f79bbde32af42dde98195f011d95982602fcd0dab657fe4a1f49f9d5ada1e02d"),
			privKey:     hexToBytes("bfef521317c65b018ae7e6d7ecc3aa700d5d0f7ea84d567be9270382d0b5e3e6"),
			privKeyWIF:  "YKn9DsVQKDFkvLhtAkpEvHNtuxstDZLsd3FBbU2uhj7L6hHfEYJE",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          1,
				Index:           1,
			},
		},
		{
			address:     "aSRmFymh8JpfFtFCVNkNBz76CgSCQbqoYJ",
			addressHash: hexToBytes("1a0ad2a04fde3b2afe068057591e1871c289c4b8"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("023ded84afe4fe91b52b45c3deb26fd263f749cbc27747dc964dae9e0739cbc579"),
			privKey:     hexToBytes("f506dffd4494c24006df7a35f3291f7ca0297a1a431557a1339bfed6f48738ca"),
			privKeyWIF:  "YMZM3tK8vbSztPzsvx6vXGdgroHXxMfjjgX8QDBfa1zG11tPU1w9",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          1,
				Index:           2,
			},
		},
		{
			address:     "aZbAhB2qjiPY8bE7CYG9amNbuq4X9L2P89",
			addressHash: hexToBytes("689b0249c628265215fd1de6142d5d5594eb8dc2"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("030f1e79f06824e10a259914ec310528bb2d5b8d6356341fe9dff55498591af6af"),
			privKey:     hexToBytes("b3629de8ef6a275b4ffae41aa2bbbc2952eb92282ea6402435abbb010ecc1fb8"),
			privKeyWIF:  "YKMkKfYuKjaBCY1hyMNP8fG4rW5ND1RFkafrwjdipQCz8ai5fDLd",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          1,
				Index:           3,
			},
		},
		{
			address:     "ahfAtnnDmiT9HSugsvA9J88iMe6UBgoGms",
			addressHash: hexToBytes("c11dd8a3577978807a0453febedee2994a6144d4"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("0317d7182e26b6ca3e0f3db531c474b9cab7a763a75eabff2e14ac92f62a793238"),
			privKey:     hexToBytes("ca747a7ef815ea0dbe68655272cecbfbd65f2a109019a9ed28e0d3dcaffe05c3"),
			privKeyWIF:  "YL8bJyWmcBS1LBS5uDmMLdtFrpK4wT1FHVUhRDpVKtV4LfrUhzoA",
			derivationInfo: DerivationPath{
				InternalAccount: 0,
				Account:         hdkeychain.HardenedKeyStart,
				Branch:          1,
				Index:           4,
			},
		},
	}

	// expectedExternalAddrs is the list of expected external addresses
	// generated from the seed
	expectedExternalAddrs = expectedAddrs[:5]

	// expectedInternalAddrs is the list of expected internal addresses
	// generated from the seed
	expectedInternalAddrs = expectedAddrs[5:]

	// defaultDBTimeout specifies the timeout value when opening the wallet
	// database.
	defaultDBTimeout = 10 * time.Second
)

// checkManagerError ensures the passed error is a ManagerError with an error
// code that matches the passed  error code.
func checkManagerError(t *testing.T, testName string, gotErr error,
	wantErrCode ErrorCode) bool {

	merr, ok := gotErr.(ManagerError)
	if !ok {
		t.Errorf("%s: unexpected error type - got %T, want %T",
			testName, gotErr, ManagerError{})
		return false
	}
	if merr.ErrorCode != wantErrCode {
		t.Errorf("%s: unexpected error code - got %s (%s), want %s",
			testName, merr.ErrorCode, merr.Description, wantErrCode)
		return false
	}

	return true
}

// hexToBytes is a wrapper around hex.DecodeString that panics if there is an
// error.  It MUST only be used with hard coded values in the tests.
func hexToBytes(origHex string) []byte {
	buf, err := hex.DecodeString(origHex)
	if err != nil {
		panic(err)
	}
	return buf
}

func emptyDB(t *testing.T) (tearDownFunc func(), db walletdb.DB) {
	dirName := t.TempDir()
	dbPath := filepath.Join(dirName, "mgrtest.db")
	db, err := walletdb.Create(
		"bdb", dbPath, true, defaultDBTimeout, false,
	)
	if err != nil {
		_ = os.RemoveAll(dirName)
		t.Fatalf("createDbNamespace: unexpected error: %v", err)
	}
	tearDownFunc = func() {
		db.Close()
	}
	return
}

// setupManager creates a new address manager and returns a teardown function
// that should be invoked to ensure it is closed and removed upon completion.
func setupManager(t *testing.T) (tearDownFunc func(), db walletdb.DB, mgr *Manager) {
	// Create a new manager in a temp directory.
	dirName := t.TempDir()

	dbPath := filepath.Join(dirName, "mgrtest.db")
	db, err := walletdb.Create("bdb", dbPath, true, defaultDBTimeout, false)
	if err != nil {
		_ = os.RemoveAll(dirName)
		t.Fatalf("createDbNamespace: unexpected error: %v", err)
	}
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		err = Create(
			ns, rootKey, pubPassphrase, privPassphrase,
			&chaincfg.MainNetParams, fastScrypt, time.Time{},
		)
		if err != nil {
			return err
		}
		mgr, err = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		return err
	})
	if err != nil {
		db.Close()
		_ = os.RemoveAll(dirName)
		t.Fatalf("Failed to create Manager: %v", err)
	}
	tearDownFunc = func() {
		mgr.Close()
		db.Close()
	}
	return tearDownFunc, db, mgr
}
