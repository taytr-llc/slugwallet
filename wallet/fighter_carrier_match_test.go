//go:build !slugtestpow

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

func TestFighterCarrierIntentFreeMatchReadLeaf(t *testing.T) {
	ctx := context.Background()
	c := carrierReference(t)["zero256/restored/recover_reveal/recovery/preparation"]
	_, w, journal, owner, _ := restoredCarrierFixture(t, c, false)
	var p fightercarrier.Preparation
	if err := json.Unmarshal(c.Value, &p); err != nil {
		t.Fatal(err)
	}
	var inspected fightertransfer.CommitInspection
	key, _ := hex.DecodeString(p.RecoveryFunding.FundingPublicKey)
	script, _ := hex.DecodeString(p.RecoveryFunding.ReturnPath.Script)
	copy(inspected.FundingKey[:], key)
	copy(inspected.ReturnScript[:], script)
	// Hold the app journal throughout: this public read leaf must neither
	// acquire it nor consume the 128-operation budget while probing history.
	j, err := journal.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	before, err := j.Snapshot()
	if err != nil || before.Count != 0 {
		t.Fatal("expected empty journal", err)
	}
	var dbBefore, dbAfter bytes.Buffer
	if err = w.db.Copy(&dbBefore); err != nil {
		t.Fatal(err)
	}
	if !w.Manager.IsLocked() {
		t.Fatal("fixture must remain locked")
	}
	for candidate := 0; candidate < 129; candidate++ {
		m, err := owner.matchRecoveryStep(ctx, waddrmgr.RestoredCarrierMatch{}, inspected)
		if err != nil || m.Next != m.Total || m.Next > 128 || !m.FundingFound || !m.ReturnFound || m.FundingBranch != p.RecoveryFunding.FundingBranch || m.FundingIndex != p.RecoveryFunding.FundingIndex || m.ReturnBranch != p.RecoveryFunding.ReturnPath.Branch || m.ReturnIndex != p.RecoveryFunding.ReturnPath.Index {
			t.Fatal("independent original-export match", m, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = owner.matchRecoveryStep(cancelled, waddrmgr.RestoredCarrierMatch{}, inspected); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled match", err)
	}
	after, err := j.Snapshot()
	if err != nil || before != after || !w.Manager.IsLocked() {
		t.Fatal("public lookup changed journal or lock", err)
	}
	if err = w.db.Copy(&dbAfter); err != nil || !bytes.Equal(dbBefore.Bytes(), dbAfter.Bytes()) {
		t.Fatal("public lookup changed wallet database", err)
	}
	// An empty foreign public capability cannot enter discovery. This test
	// does not fabricate a canonical public capability; actual recovery covers
	// its complete source/node composition separately.
	if _, err = owner.BeginRecoveryMatch(ctx, &fighterownership.PreparedRecovery{}); !errors.Is(err, fightercarrier.ErrConflict) {
		t.Fatal("foreign capability accepted", err)
	}
}

func TestFighterCarrierRecoveryMatchLifetimeRefusal(t *testing.T) {
	ctx := context.Background()
	var empty *CarrierRecoveryMatchScan
	if _, err := empty.Step(ctx); !errors.Is(err, fightercarrier.ErrInvalid) {
		t.Fatal(err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	s := &CarrierRecoveryMatchScan{scan: &CarrierRecoveryScan{}}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Step(ctx); !errors.Is(err, fightercarrier.ErrClosed) {
		t.Fatal(err)
	}
	owner := &FighterCarrierOwner{}
	if _, err := owner.PrepareMatchedRecovery(ctx, CarrierRequest{}, s); !errors.Is(err, fightercarrier.ErrInvalid) {
		t.Fatal("foreign match", err)
	}
}
