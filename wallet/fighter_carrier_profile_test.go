//go:build slugtestpow

package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

func TestFighterCarrierCheapProfileRefusesBeforeFilesystem(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-remain-absent")
	l := NewLoader(&chaincfg.MainNetParams, root, true, time.Second, 0)
	ctx := context.Background()
	if _, err := l.CreateHostedTransferWallet(ctx, nil, nil, [32]byte{}, time.Unix(0, 0), waddrmgr.HostedAllocationGuard2{}); !errors.Is(err, waddrmgr.ErrHostedAllocationProfile) {
		t.Fatal(err)
	}
	if _, err := l.OpenHostedTransferWallet(ctx, nil, waddrmgr.HostedAllocationGuard2{}); !errors.Is(err, waddrmgr.ErrHostedAllocationProfile) {
		t.Fatal(err)
	}
	// A zero concrete owner is deliberately unusable: the profile refusal must
	// happen before reading its identity, opening a database or creating a path.
	j := new(fightercarrier.Journal)
	if _, _, err := l.ActivateRestoredCarrierWallet(ctx, nil, recovery.Manifest{}, j); !errors.Is(err, fightercarrier.ErrProfile) {
		t.Fatal(err)
	}
	if _, err := l.OpenRestoredCarrierWallet(ctx, nil, waddrmgr.RestoredCarrierGuard{}, j); !errors.Is(err, fightercarrier.ErrProfile) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported profile accessed filesystem", err)
	}
	if _, loaded := l.LoadedWallet(); loaded {
		t.Fatal("unsupported profile loaded wallet")
	}
}
