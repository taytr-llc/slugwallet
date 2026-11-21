// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

const dailyWalletReferenceSHA = "9b8e52f41690db7ca1fee37c34f99dfcd0a7266b81a7793859871bd9b006ae30"

type dailyWalletReferences struct {
	Positives []struct {
		Fixture     string
		Binding     PoolWalletBinding
		SourceID    string `json:"source_id"`
		ConfigID    string `json:"config_id"`
		GuardHex    string `json:"guard_hex"`
		GuardDigest string `json:"guard_digest"`
		BindingHex  string `json:"binding_hex"`
	}
	Refusals []struct {
		Name     string
		Binding  PoolWalletBinding
		Accepted bool
	}
}

func dailyWalletReference(t *testing.T) dailyWalletReferences {
	t.Helper()
	raw, e := os.ReadFile("../../slug/poolsettle/testdata/operator-wallet/daily-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != dailyWalletReferenceSHA {
		t.Fatal("independent daily corpus")
	}
	var v dailyWalletReferences
	if json.Unmarshal(raw, &v) != nil || len(v.Positives) != 3 || len(v.Refusals) != 12 {
		t.Fatal("daily corpus shape")
	}
	return v
}
func TestDailyPoolWalletBindingReference(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal source/config profile; cheap constructors separately refuse")
	}
	refs := dailyWalletReference(t)
	for _, v := range refs.Positives {
		if e := ValidateDailyPoolWalletBinding(v.Binding); e != nil {
			t.Fatal(v.Fixture, e)
		}
		sid, e := poolshare.DailyConfigID(v.Binding.Source)
		if e != nil || sid != v.SourceID {
			t.Fatal("source identity", e)
		}
		cid, e := poolsettle.DailyConfigBindingID(v.Binding.Settlement)
		if e != nil || cid != v.ConfigID {
			t.Fatal("config identity", e)
		}
		raw, e := waddrmgr.MarshalPoolSettlementGuard(v.Binding.Guard)
		if e != nil || hex.EncodeToString(raw) != v.GuardHex {
			t.Fatal("guard bytes", e)
		}
		gid, e := waddrmgr.PoolSettlementGuardDigest(v.Binding.Guard)
		if e != nil || gid != v.GuardDigest {
			t.Fatal("guard identity", e)
		}
		raw, e = json.Marshal(v.Binding)
		if e != nil || hex.EncodeToString(raw) != v.BindingHex {
			t.Fatal("binding bytes", e)
		}
		if ValidatePoolWalletBinding(v.Binding) == nil {
			t.Fatal("legacy binding widened")
		}
	}
	for _, v := range refs.Refusals {
		if v.Accepted || ValidateDailyPoolWalletBinding(v.Binding) == nil {
			t.Fatal("daily refusal", v.Name)
		}
	}
	if ValidateDailyPoolWalletBinding(poolTestBinding(t)) == nil {
		t.Fatal("legacy guard adopted")
	}
}
func TestDailyPoolWalletFreshOwnerAndLegacyRefusal(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal schema16 custody")
	}
	b := dailyWalletReference(t).Positives[0].Binding
	root := poolTestRoot(t)
	defer root.Zero()
	path := filepath.Join(poolTestDirectory(t), "daily-owner")
	o, e := CreateDailyPoolSettlementWallet(context.Background(), path, b, poolTestPublic, poolTestPrivate, root, time.Unix(1795000000, 0))
	if e != nil {
		if o != nil {
			_ = o.Close()
		}
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := o.Close(); e != nil {
			t.Error(e)
		}
	})
	if !o.daily || !o.wallet.Manager.PoolSettlement() || !o.wallet.Manager.IsLocked() {
		t.Fatal("daily purpose/initial lock")
	}
	copy := o.Binding()
	copy.Settlement.Destinations[0].Script = "changed"
	if o.Binding().Settlement.Destinations[0].Script == "changed" {
		t.Fatal("binding aliases caller")
	}
	if e = o.Unlock(context.Background(), poolTestPrivate, 24*time.Hour+time.Nanosecond); !errors.Is(e, ErrPoolWalletInvalid) {
		t.Fatal("unlock bound", e)
	}
	if e = o.Unlock(context.Background(), poolTestPrivate, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e = o.wallet.DumpPrivKeys(); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("generic key access", e)
	}
	if _, e = o.wallet.Manager.Encrypt(waddrmgr.CKTPrivate, []byte("public-fixture")); !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("generic crypto", e)
	}
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	if old, e := OpenPoolSettlementWallet(context.Background(), path, b, poolTestPublic); e == nil || old != nil {
		if old != nil {
			_ = old.Close()
		}
		t.Fatal("old owner opened Binding2", e)
	}
	reopened, e := OpenDailyPoolSettlementWallet(context.Background(), path, b, poolTestPublic)
	if e != nil {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := reopened.Close(); e != nil {
			t.Error(e)
		}
	})
	if reopened.Binding().Guard != b.Guard || !reopened.wallet.Manager.IsLocked() {
		t.Fatal("reopen changed original guard/lock")
	}
	// A daily wallet cannot attach a legacy node even though Config pins match.
	node, _ := poolTestNode(t, b)
	if backend, e := NewDailyPoolSettlementBackend(context.Background(), reopened, node, b); e == nil || backend != nil {
		if backend != nil {
			_ = backend.Close()
		}
		t.Fatal("legacy node selected", e)
	}
	if reopened.backend != nil {
		t.Fatal("failed constructor claimed wallet")
	}
	if backend, e := NewPoolSettlementBackend(context.Background(), reopened, node, b); e == nil || backend != nil {
		t.Fatal("legacy backend selected daily wallet", e)
	}
}
func TestDailyPoolWalletCheapRefusal(t *testing.T) {
	if !wire.TestPoW {
		return
	}
	if o, e := CreateDailyPoolSettlementWallet(context.Background(), "", PoolWalletBinding{}, nil, nil, nil, time.Time{}); o != nil || !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("daily cheap custody", e)
	}
	if b, e := NewDailyPoolSettlementBackend(context.Background(), nil, nil, PoolWalletBinding{}); b != nil || !errors.Is(e, waddrmgr.ErrPoolSettlementProfile) {
		t.Fatal("daily cheap backend", e)
	}
}
