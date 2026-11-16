// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

type gymPublicFixture struct {
	Name    string
	Entropy string
	Export  recovery.Export
}

func gymFixtures(t *testing.T) []gymPublicFixture {
	t.Helper()
	data, err := os.ReadFile("../recovery/testdata/recovery_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		FixtureOnly bool `json:"fixture_only"`
		Cases       []gymPublicFixture
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if !fixtures.FixtureOnly || len(fixtures.Cases) != 3 {
		t.Fatal("missing independent public fixture vectors")
	}
	return fixtures.Cases
}

func TestRecoveryGymIndependentDerivation(t *testing.T) {
	for _, fixture := range gymFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			entropyBytes, err := hex.DecodeString(fixture.Entropy)
			if err != nil || len(entropyBytes) != 32 {
				t.Fatal("invalid public fixture entropy")
			}
			key, err := deriveRecoveryGymKey([32]byte(entropyBytes), &chaincfg.MainNetParams)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Zero()
			public := hex.EncodeToString(key.PubKey().SerializeCompressed())
			if public != fixture.Export.Manifest.GymPublicKey {
				t.Fatal("derived key differs from source-independent standard BIP32 vector")
			}
			id, err := gymauth.GymID(prospect.Context{Version: 1, Network: recovery.Network, Genesis: recovery.Genesis}, public)
			if err != nil || id != fixture.Export.Manifest.GymID {
				t.Fatal("derived gym differs from source-independent identity vector")
			}
		})
	}
}

func gymFixtureWallet(t *testing.T) (*Wallet, gymPublicFixture, []byte) {
	t.Helper()
	fixture := gymFixtures(t)[0]
	entropy, err := recovery.Entropy(fixture.Export.Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("PUBLIC recovery signer fixture password")
	loader := NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 20)
	w, err := loader.CreateNewRecoveryWallet([]byte("public"), password, entropy, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loader.UnloadWallet(); err != nil {
			t.Error(err)
		}
	})
	return w, fixture, password
}

// This deliberately is only an admission ACTION, with an invalid coinbase and
// no claimed work. The signer must authorize bounded action bytes without
// pretending that its signature certifies mining, issuance or canonicality.
func gymSigningAction(fixture gymPublicFixture) (prospect.Context, prospect.Proof, prospectnode.Policy) {
	c := prospect.Context{Version: 1, Network: recovery.Network, Genesis: recovery.Genesis,
		DNAVersion: 1, ProspectTarget: strings.Repeat("ff", 32), ParentHash: strings.Repeat("11", 32),
		ParentHeight: 61, ExpectedBits: 0x207fffff, MinTimestamp: 999, MaxTimestamp: 1001}
	var header [80]byte
	binary.LittleEndian.PutUint32(header[:4], 4)
	for i := 4; i < 36; i++ {
		header[i] = 0x11
	}
	binary.LittleEndian.PutUint32(header[68:72], 1000)
	binary.LittleEndian.PutUint32(header[72:76], c.ExpectedBits)
	p := prospect.Proof{Version: 2, GymID: fixture.Export.Manifest.GymID,
		JobID: strings.Repeat("22", 32), Header: hex.EncodeToString(header[:]), Coinbase: "00",
		MerkleBranch: []string{strings.Repeat("33", 32)}}
	policy := prospectnode.Policy{Version: 1, Network: c.Network, Genesis: c.Genesis,
		DNAVersion: c.DNAVersion, ProspectTarget: c.ProspectTarget}
	return c, p, policy
}

func TestRecoveryGymSigningLifecycleAndPolicy(t *testing.T) {
	if wire.TestPoW {
		w := new(Wallet)
		if _, err := w.GymIdentity(context.Background()); err == nil {
			t.Fatal("cheap profile identity accepted")
		}
		if _, err := w.SignProspectAdmission(context.Background(), prospect.Context{}, prospect.Proof{Version: 2}); err == nil {
			t.Fatal("cheap profile signing accepted")
		}
		return
	}
	w, fixture, password := gymFixtureWallet(t)
	c, p, policy := gymSigningAction(fixture)
	identity, err := w.GymIdentity(context.Background())
	if err != nil || identity.PublicKey != fixture.Export.Manifest.GymPublicKey || identity.GymID != fixture.Export.Manifest.GymID {
		t.Fatalf("locked public identity mismatch: %v", err)
	}
	if !w.Locked() {
		t.Fatal("public identity unlocked wallet")
	}
	if a, err := w.SignProspectAdmission(context.Background(), c, p); !waddrmgr.IsError(err, waddrmgr.ErrLocked) || a != (gymauth.Authorization{}) {
		t.Fatalf("locked signing did not fail closed: %v", err)
	}
	if err := w.Unlock(password, nil); err != nil {
		t.Fatal(err)
	}
	sign, err := w.ProspectSigner(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := sign(context.Background(), c, p)
	if err != nil || auth.PublicKey != identity.PublicKey || auth.Version != 2 {
		t.Fatalf("sign: %v", err)
	}
	if err := gymauth.VerifyAuthorization(c, p, auth); err != nil {
		t.Fatal(err)
	}
	if _, err := prospect.Verify(c, p); err == nil {
		t.Fatal("invalid coinbase unexpectedly became a verified proof")
	}
	upperC, upperP := c, p
	upperC.Genesis, upperC.ProspectTarget = strings.ToUpper(c.Genesis), strings.ToUpper(c.ProspectTarget)
	upperP.GymID = strings.ToUpper(p.GymID)
	upperAuth, err := sign(context.Background(), upperC, upperP)
	if err != nil || upperAuth != auth {
		t.Fatalf("hexadecimal case changed authorization: %v", err)
	}

	mutations := []struct {
		name   string
		change func(*prospect.Context, *prospect.Proof)
	}{
		{"chain", func(c *prospect.Context, _ *prospect.Proof) { c.Network++ }},
		{"genesis", func(c *prospect.Context, _ *prospect.Proof) { c.Genesis = strings.Repeat("44", 32) }},
		{"context-version", func(c *prospect.Context, _ *prospect.Proof) { c.Version++ }},
		{"dna-policy", func(c *prospect.Context, _ *prospect.Proof) { c.DNAVersion++ }},
		{"target-policy", func(c *prospect.Context, _ *prospect.Proof) { c.ProspectTarget = strings.Repeat("ee", 32) }},
		{"parent", func(c *prospect.Context, _ *prospect.Proof) { c.ParentHash = strings.Repeat("44", 32) }},
		{"bits", func(c *prospect.Context, _ *prospect.Proof) { c.ExpectedBits-- }},
		{"time", func(c *prospect.Context, _ *prospect.Proof) { c.MinTimestamp = 1001 }},
		{"gym", func(_ *prospect.Context, p *prospect.Proof) { p.GymID = strings.Repeat("44", 32) }},
		{"version1", func(_ *prospect.Context, p *prospect.Proof) { p.Version, p.JobID = 1, "" }},
		{"unknown-version", func(_ *prospect.Context, p *prospect.Proof) { p.Version = 3 }},
		{"missing-job", func(_ *prospect.Context, p *prospect.Proof) { p.JobID = "" }},
		{"oversized-branch", func(_ *prospect.Context, p *prospect.Proof) { p.MerkleBranch = make([]string, 21) }},
		{"coinbase", func(_ *prospect.Context, p *prospect.Proof) { p.Coinbase = "" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			mc, mp := c, p
			test.change(&mc, &mp)
			if a, err := sign(context.Background(), mc, mp); err == nil || a != (gymauth.Authorization{}) {
				t.Fatal("mutated request returned an authorization")
			}
		})
	}
	for _, field := range []string{"version", "chain", "genesis", "target"} {
		bad := policy
		switch field {
		case "version":
			bad.Version++
		case "chain":
			bad.Network++
		case "genesis":
			bad.Genesis = strings.Repeat("44", 32)
		case "target":
			bad.ProspectTarget = "00"
		}
		if _, err := w.ProspectSigner(context.Background(), bad); err == nil {
			t.Fatalf("accepted bad policy %s", field)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a, err := sign(ctx, c, p); !errors.Is(err, context.Canceled) || a != (gymauth.Authorization{}) {
		t.Fatalf("cancelled signing: %v", err)
	}
	w.Lock()
	if !w.Locked() {
		t.Fatal("wallet failed to lock")
	}
	if a, err := sign(context.Background(), c, p); !waddrmgr.IsError(err, waddrmgr.ErrLocked) || a != (gymauth.Authorization{}) {
		t.Fatalf("relocked signing: %v", err)
	}
	if err := w.Unlock(password, nil); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	w.WaitForShutdown()
	if a, err := sign(context.Background(), c, p); !errors.Is(err, ErrWalletShuttingDown) || a != (gymauth.Authorization{}) {
		t.Fatalf("stopped signing: %v", err)
	}
}

func TestRecoveryGymLegacyUnavailable(t *testing.T) {
	if wire.TestPoW {
		return
	} // Production identity is separately refused above.
	loader := NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 20)
	// Published BIP32 vector 1, not a generated or operator key.
	seed := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	w, err := loader.CreateNewWallet([]byte("public"), []byte("PUBLIC fixture password"), seed, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := loader.UnloadWallet(); err != nil {
			t.Error(err)
		}
	}()
	if identity, err := w.GymIdentity(context.Background()); !errors.Is(err, waddrmgr.ErrRecoveryUnavailable) || identity != (GymIdentity{}) {
		t.Fatalf("legacy gym identity: %v", err)
	}
}

func TestRecoveryGymQueuedActionOwnsBranch(t *testing.T) {
	if wire.TestPoW {
		return
	}
	w, fixture, password := gymFixtureWallet(t)
	if err := w.Unlock(password, nil); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	w.WaitForShutdown()
	// Replace the handshake only after joining every real wallet goroutine.
	w.quitMu.Lock()
	w.quit, w.started = make(chan struct{}), true
	w.holdUnlockRequests = make(chan chan heldUnlock)
	w.quitMu.Unlock()
	c, proof, _ := gymSigningAction(fixture)
	original := proof
	original.MerkleBranch = append([]string(nil), proof.MerkleBranch...)
	type result struct {
		auth gymauth.Authorization
		err  error
	}
	done := make(chan result, 1)
	go func() {
		auth, err := w.SignProspectAdmission(context.Background(), c, proof)
		done <- result{auth, err}
	}()
	var request chan heldUnlock
	select {
	case request = <-w.holdUnlockRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not reach lease handshake")
	}
	// Preflight completed before this rendezvous; caller mutation now must not
	// modify the action that eventually receives a signature.
	proof.MerkleBranch[0] = strings.Repeat("44", 32)
	hold := make(heldUnlock)
	request <- hold
	select {
	case <-hold:
	case <-time.After(5 * time.Second):
		t.Fatal("signer leaked accepted lease")
	}
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not finish")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := gymauth.VerifyAuthorization(c, original, got.auth); err != nil {
		t.Fatal("caller mutation changed signed action:", err)
	}
	if err := gymauth.VerifyAuthorization(c, proof, got.auth); err == nil {
		t.Fatal("authorization accepted caller's later branch mutation")
	}
}
