//go:build slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
)

func TestCandidateCheapProfileRefusal(t *testing.T) {
	for _, restore := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "must-not-create")
		loader := NewLoader(&chaincfg.MainNetParams, dir, false, time.Second, 20)
		var err error
		if restore {
			_, err = loader.RestoreCandidateFixtureWallet([]byte("public-fixture"), []byte("private-fixture"), candidateVectors(t)[0].Export)
		} else {
			_, err = loader.CreateCandidateFixtureWallet([]byte("public-fixture"), []byte("private-fixture"), productionprofile.CandidateZero256)
		}
		if err == nil {
			t.Fatal("cheap profile initialized candidate wallet")
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Fatal("cheap profile touched candidate data directory", statErr)
		}
	}
}
