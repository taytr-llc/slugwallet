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

func TestRestoredCarrierActivationCheapProfileBeforeFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-created")
	l := NewLoader(&chaincfg.MainNetParams, path, true, time.Second, 0)
	j := &fightercarrier.Journal{}
	if _, e := l.InspectRestoredCarrierActivation(context.Background(), nil, recovery.Manifest{}, j); !errors.Is(e, fightercarrier.ErrProfile) {
		t.Fatal("inspection accepted cheap profile", e)
	}
	if _, e := l.ActivateRestoredCarrierWalletExpected(context.Background(), nil, waddrmgr.RestoredCarrierGuard{}, j); !errors.Is(e, fightercarrier.ErrProfile) {
		t.Fatal("expected activation accepted cheap profile", e)
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("profile refusal touched filesystem", e)
	}
}
