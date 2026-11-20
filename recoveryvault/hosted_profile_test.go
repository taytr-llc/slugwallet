//go:build slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostedCurrentCheapProfileRefusesBeforeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	for _, open := range []bool{false, true} {
		var err error
		if open {
			_, err = OpenHosted(context.Background(), path, Config{}, nil, nil, strings.Repeat("1", 64))
		} else {
			_, err = CreateHosted(context.Background(), path, Config{}, nil, nil, strings.Repeat("1", 64))
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
	for _, open := range []bool{false, true} {
		var err error
		if open {
			_, err = OpenCurrentStore(context.Background(), path, nil, nil)
		} else {
			_, err = CreateCurrentStore(context.Background(), path, nil, nil)
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cheap profile touched path")
	}
}
