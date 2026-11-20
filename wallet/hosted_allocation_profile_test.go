//go:build slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHostedAllocationCheapProfileBeforeFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent")
	for _, mode := range []string{"create", "resume", "open"} {
		_, e := openAllocationInventory(context.Background(), p, nil, AllocationBinding{}, mode)
		if !errors.Is(e, ErrAllocationProfile) {
			t.Fatal(mode, e)
		}
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("cheap profile touched storage", mode, e)
		}
	}
}
