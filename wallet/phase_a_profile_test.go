package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

func TestPhaseACheapProfileRefusesBeforeFilesystem(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("cheap-only refusal")
	}
	bundle, e := recovery.NewExport([32]byte{}, recovery.DefaultAccounts())
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "absent")
	l := NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, 0)
	if _, e = l.BeginPhaseARecovery(context.Background(), retainedPubPass, retainedPrivPass, bundle); e == nil {
		t.Fatal("cheap begin accepted")
	}
	if _, e = l.OpenPhaseARecovery(context.Background(), retainedPubPass, bundle.Manifest); e == nil {
		t.Fatal("cheap open accepted")
	}
	if _, e = os.Stat(dir); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("profile refusal touched filesystem", e)
	}
}
func TestPhaseARecoveryWatchProfileLimit(t *testing.T) {
	batch := watchBatch(t, 32768)
	if e := validateRecoveryWatchLimit(batch, 32768); e != nil {
		t.Fatal(e)
	}
	batch = watchBatch(t, 32769)
	if e := validateRecoveryWatchLimit(batch, 32768); !errors.Is(e, ErrRecoveryCapacity) {
		t.Fatal("unbounded Phase A watch", e)
	}
}
