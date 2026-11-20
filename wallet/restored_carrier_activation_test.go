//go:build !slugtestpow

package wallet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// This fixture uses the inherited independently pinned public manifest. The
// test asserts transaction/lifecycle properties, not a product-derived golden.
func inspectedCarrierFixture(t *testing.T) (*Loader, *RecoverySession, recovery.Export, *fightercarrier.Journal) {
	t.Helper()
	c := carrierReference(t)["zero256/restored/transfer/one/preparation"]
	b, e := recovery.NewExport([32]byte{}, c.Context.Original.Accounts)
	if e != nil {
		t.Fatal(e)
	}
	l, s := phaseABegin(t, b)
	j, e := fightercarrier.Create(context.Background(), filepath.Join(t.TempDir(), "carrier"), fightercarrier.Identity{JournalID: c.Context.JournalID, Pin: c.Context.Pin})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close(); _ = l.UnloadWallet() })
	return l, s, b, j
}

func TestRestoredCarrierActivationInspectionAndExactResume(t *testing.T) {
	ctx := context.Background()
	l, s, b, j := inspectedCarrierFixture(t)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	if p := reviewFinishRecovery(t, s, source); !p.Ready {
		t.Fatal("recovery not ready")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	g, e := l.InspectRestoredCarrierActivation(ctx, retainedPubPass, b.Manifest, j)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := waddrmgr.MarshalRestoredCarrierGuard(g)
	if e != nil {
		t.Fatal(e)
	}
	// Inspection has joined its owner and performed no activation: exact12
	// remains reopenable, and a second independent inspection agrees.
	s, e = l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal("inspection changed schema or retained owner", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	got, e := l.InspectRestoredCarrierActivation(ctx, retainedPubPass, b.Manifest, j)
	if e != nil {
		t.Fatal(e)
	}
	gotRaw, _ := waddrmgr.MarshalRestoredCarrierGuard(got)
	if !bytes.Equal(raw, gotRaw) {
		t.Fatal("read-only inspection changed activation snapshot")
	}
	bad, e := waddrmgr.ParseRestoredCarrierGuard(raw)
	if e != nil {
		t.Fatal(e)
	}
	bad.ActivationCursors[0]++
	if _, e = l.ActivateRestoredCarrierWalletExpected(ctx, retainedPubPass, bad, j); !errors.Is(e, fightercarrier.ErrConflict) || errors.Is(e, fightercarrier.ErrOutcomeUnknown) {
		t.Fatal("changed precommitted guard must refuse before mutation", e)
	}
	got, e = l.InspectRestoredCarrierActivation(ctx, retainedPubPass, b.Manifest, j)
	if e != nil {
		t.Fatal("failed expected activation changed12 or retained owner", e)
	}
	gotRaw, _ = waddrmgr.MarshalRestoredCarrierGuard(got)
	if !bytes.Equal(raw, gotRaw) {
		t.Fatal("refused activation changed snapshot")
	}
	// Persist the public expectation before mutation, then model a lost
	// activation/READY acknowledgment by closing and using only saved bytes.
	path := filepath.Join(t.TempDir(), "expected-guard.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	w, e := l.ActivateRestoredCarrierWalletExpected(ctx, retainedPubPass, g, j)
	if e != nil || w == nil || w.Manager.CarrierSchema() != 15 {
		t.Fatal("exact activation", e)
	}
	if e = l.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
	saved, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := waddrmgr.ParseRestoredCarrierGuard(saved)
	if e != nil {
		t.Fatal(e)
	}
	w, e = l.OpenRestoredCarrierWallet(ctx, retainedPubPass, expected, j)
	if e != nil || w == nil {
		t.Fatal("saved exact guard cannot recover lost activation acknowledgment", e)
	}
	if e = l.UnloadWallet(); e != nil {
		t.Fatal(e)
	}
	if _, e = l.InspectRestoredCarrierActivation(ctx, retainedPubPass, b.Manifest, j); e == nil {
		t.Fatal("inspection adopted existing15")
	}
	if _, e = l.OpenRestoredCarrierWallet(ctx, retainedPubPass, expected, j); e != nil {
		t.Fatal("failed inspection leaked its DB owner", e)
	}
}

func TestRestoredCarrierActivationInspectionPendingCancellationAndOriginal(t *testing.T) {
	ctx := context.Background()
	l, s, b, j := inspectedCarrierFixture(t)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := l.InspectRestoredCarrierActivation(ctx, retainedPubPass, b.Manifest, j); !errors.Is(e, ErrRecoveryInProgress) {
		t.Fatal("pending12 accepted", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := l.InspectRestoredCarrierActivation(canceled, retainedPubPass, b.Manifest, j); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored", e)
	}
	wrong := b.Manifest
	wrong.Accounts = append([]recovery.Account(nil), b.Manifest.Accounts...)
	wrong.Accounts[0].NextExternal++
	if _, e := l.InspectRestoredCarrierActivation(ctx, retainedPubPass, wrong, j); e == nil {
		t.Fatal("different original inventory accepted")
	}
	s, e := l.OpenPhaseARecovery(ctx, retainedPubPass, b.Manifest)
	if e != nil {
		t.Fatal("refused inspection leaked pending owner", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}
