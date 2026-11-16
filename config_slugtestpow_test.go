//go:build slugtestpow

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestPoWRefusesBeforeConfigOrWalletFiles(t *testing.T) {
	appDir := filepath.Join(t.TempDir(), "not-created")
	previous := os.Args
	os.Args = []string{"slugwallet", "--appdata=" + appDir,
		"--configfile=" + filepath.Join(appDir, "must-not-be-read.conf")}
	defer func() { os.Args = previous }()
	_, _, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "slugtestpow wallet daemon is disabled") {
		t.Fatalf("unexpected profile refusal: %v", err)
	}
	if _, err := os.Stat(appDir); !os.IsNotExist(err) {
		t.Fatalf("disabled profile accessed wallet namespace: %v", err)
	}
}
