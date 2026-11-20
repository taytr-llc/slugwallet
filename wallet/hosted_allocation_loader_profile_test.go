//go:build slugtestpow

package wallet

import (
	"context"
	"errors"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostedAllocationLoaderCheapProfileBeforeFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	l := NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, 0)
	if _, e := l.CreateHostedAllocationWallet(context.Background(), nil, nil, [32]byte{}, time.Time{}, waddrmgr.HostedAllocationGuard{}); !errors.Is(e, waddrmgr.ErrHostedAllocationProfile) {
		t.Fatal(e)
	}
	if _, e := l.OpenHostedAllocationWallet(context.Background(), nil, waddrmgr.HostedAllocationGuard{}); !errors.Is(e, waddrmgr.ErrHostedAllocationProfile) {
		t.Fatal(e)
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("cheap profile touched storage", e)
	}
}
