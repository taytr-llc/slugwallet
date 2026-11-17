//go:build slugtestpow

// Copyright (c) 2026 The SLUG developers. ISC license.

package wallet

import (
	"errors"
	"testing"
)

func TestRecoveryRPCSourceCheapProfileRefused(t *testing.T) {
	source, err := NewRecoveryRPCSource(RecoveryRPCConfig{URL: "ws://127.0.0.1:29332/ws", Username: "fixture", Password: "PUBLIC-TEST-PASSWORD"})
	if source != nil || !errors.Is(err, ErrRecoverySource) {
		t.Fatal("cheap profile created a production recovery transport", err)
	}
}
