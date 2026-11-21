// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/pooltxshape"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func dailyManagerReferences(t *testing.T) []poolGuardVector {
	t.Helper()
	raw, e := os.ReadFile("../../slug/poolsettle/testdata/operator-wallet/daily-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "9b8e52f41690db7ca1fee37c34f99dfcd0a7266b81a7793859871bd9b006ae30" {
		t.Fatal("independent daily reference identity")
	}
	var refs struct {
		Positives []struct {
			Fixture string
			Binding struct {
				Guard      PoolSettlementGuard
				Source     poolshare.Config
				Settlement poolsettle.Config
			}
			GuardHex    string `json:"guard_hex"`
			GuardDigest string `json:"guard_digest"`
		}
	}
	if json.Unmarshal(raw, &refs) != nil || len(refs.Positives) != 3 {
		t.Fatal("daily reference shape")
	}
	result := make([]poolGuardVector, len(refs.Positives))
	for i, v := range refs.Positives {
		result[i] = poolGuardVector{Fixture: v.Fixture, Guard: v.Binding.Guard, Source: v.Binding.Source, Settlement: v.Binding.Settlement, Canonical: v.GuardHex, Digest: v.GuardDigest}
	}
	return result
}

// Conditional private leaf coverage, not proof of a live daily ledger capability.
// Only the published key fixtures and prior independent signed bytes are used.
func TestDailyPoolSettlementConditionalIndependentSignatures(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal schema16 signing only")
	}
	old := poolReference(t)
	for _, g := range dailyManagerReferences(t) {
		t.Run(g.Fixture, func(t *testing.T) {
			db, m := poolManagerFixture(t, g)
			if e := walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) }); e != nil {
				t.Fatal(e)
			}
			for _, v := range old.Transactions {
				if v.Fixture != g.Fixture {
					continue
				}
				raw, _ := hex.DecodeString(v.Unsigned)
				e := walletdb.View(db, func(tx walletdb.ReadTx) error {
					ns := tx.ReadBucket(waddrmgrNamespaceKey)
					signed, e := m.signPoolSettlementProfile(context.Background(), ns, g.Guard, g.Settlement, v.Coins, raw, context.Background().Err, true)
					if e != nil {
						return e
					}
					if hex.EncodeToString(signed) != v.Signed {
						t.Fatal("daily mode altered independent signature bytes")
					}
					// Add public claims solely so the input-copy boundary succeeds. DTOs
					// still cannot create the original active Store capability.
					coins := append([]poolsettle.Coin(nil), v.Coins...)
					for i := range coins {
						coins[i].Claims = []poolsettle.Claim{{RoundHash: strings.Repeat("01", 32), RoundHeight: 1, Amount: poolsettle.Fraction{Numerator: "1", Denominator: "1"}}}
					}
					if got, e := m.SignDailyPoolSettlement(context.Background(), ns, g.Guard, nil, nil, g.Settlement, g.Source, coins, raw); e == nil || got != nil {
						t.Fatal("DTO authorized daily public signer", e)
					}
					if got, e := m.SignPoolSettlement(context.Background(), ns, g.Guard, nil, nil, g.Settlement, g.Source, coins, raw); e == nil || got != nil {
						t.Fatal("DTO authorized legacy public signer", e)
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func dailyManagerTransaction(t *testing.T, g poolGuardVector, n int) ([]poolsettle.Coin, []byte) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	coins := make([]poolsettle.Coin, n)
	for i := range coins {
		id := fmt.Sprintf("%064x", i+1)
		h, e := chainhash.NewHashFromStr(id)
		if e != nil {
			t.Fatal(e)
		}
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, 0), nil, nil))
		coins[i] = poolsettle.Coin{TxID: id, Atoms: 1000000, Script: g.Guard.FundingScript, Claims: []poolsettle.Claim{{RoundHash: id, RoundHeight: uint32(i + 1), Amount: poolsettle.Fraction{Numerator: "1000000", Denominator: "1"}}}}
	}
	payee, _ := hex.DecodeString(g.Settlement.Destinations[0].Script)
	change, _ := hex.DecodeString(g.Guard.FundingScript)
	tx.AddTxOut(wire.NewTxOut(1000000, payee))
	tx.AddTxOut(wire.NewTxOut(int64(n)*1000000-1000000-100000, change))
	var raw bytes.Buffer
	if e := tx.SerializeNoWitness(&raw); e != nil {
		t.Fatal(e)
	}
	return coins, raw.Bytes()
}

func TestDailyPoolSettlementConditional721AndCancellation(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal conditional signer leaf")
	}
	g := dailyManagerReferences(t)[0]
	db, m := poolManagerFixture(t, g)
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) }); e != nil {
		t.Fatal(e)
	}
	coins, raw := dailyManagerTransaction(t, g, 721)
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if signed, e := m.signPoolSettlement(context.Background(), ns, g.Guard, g.Settlement, coins, raw, context.Background().Err); e == nil || signed != nil {
			t.Fatal("legacy 256-input boundary widened")
		}
		checks := 0
		signed, e := m.signPoolSettlementProfile(context.Background(), ns, g.Guard, g.Settlement, coins, raw, func() error { checks++; return nil }, true)
		if e != nil {
			return e
		}
		if checks != 2*721+1 || len(signed) <= 100000 {
			t.Fatal("daily leaf did not traverse all signatures/engines", checks, len(signed))
		}
		var parsed wire.MsgTx
		if e = parsed.Deserialize(bytes.NewReader(signed)); e != nil {
			return e
		}
		var unsigned bytes.Buffer
		if e = parsed.SerializeNoWitness(&unsigned); e != nil {
			return e
		}
		if !bytes.Equal(unsigned.Bytes(), raw) || len(parsed.TxIn) != 721 || len(parsed.TxOut) != 2 {
			t.Fatal("daily economic bytes changed")
		}
		// Real per-input signatures are internally executed by the leaf. This
		// proves crypto/shape only; a real Store capability is a separate gate.
		for _, in := range parsed.TxIn {
			if len(in.Witness) != 2 || len(in.Witness[0]) > 73 || len(in.Witness[1]) != 33 {
				t.Fatal("native witness")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		checks = 0
		got, e := m.signPoolSettlementProfile(ctx, ns, g.Guard, g.Settlement, coins, raw, func() error {
			checks++
			if checks == 4 {
				cancel()
			}
			return ctx.Err()
		}, true)
		if !errors.Is(e, context.Canceled) || got != nil || checks != 4 {
			t.Fatal("original canceled check disclosed signed result", e, checks)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestDailyPoolSettlementOwnedInputsAndShapeRefusals(t *testing.T) {
	g := dailyManagerReferences(t)[0]
	coins, raw := dailyManagerTransaction(t, g, 721)
	own, body, e := poolDailyOwnedInputs(context.Background(), coins, raw)
	if e != nil {
		t.Fatal(e)
	}
	coins[0].Claims[0].Amount.Numerator = "changed"
	raw[0] ^= 1
	if own[0].Claims[0].Amount.Numerator == "changed" || bytes.Equal(body, raw) {
		t.Fatal("daily copy aliases request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, b, e := poolDailyOwnedInputs(ctx, own, body); !errors.Is(e, context.Canceled) || c != nil || b != nil {
		t.Fatal("canceled copy", e)
	}
	claim := own[0].Claims[0]
	// Maximal bounded text is shared immutable data, not a320MiB allocation.
	// It deliberately exceeds129MiB, the obsolete draft ceiling. This only
	// tests bounded copying; these claims grant no accounting/signing authority.
	wide := []poolsettle.Coin{own[0]}
	wide[0].Claims = make([]poolsettle.Claim, 32768)
	largeClaim := claim
	largeClaim.Amount = poolsettle.Fraction{Numerator: strings.Repeat("9", 4096), Denominator: strings.Repeat("8", 4096)}
	for i := range wide[0].Claims {
		wide[0].Claims[i] = largeClaim
	}
	if c, b, e := poolDailyOwnedInputs(context.Background(), wide, body); e != nil || len(c) != 1 || len(c[0].Claims) != 32768 || !bytes.Equal(b, body) {
		t.Fatal("selected maximal input text refused", e)
	}
	tooMany := []poolsettle.Coin{own[0], own[1]}
	tooMany[0].Claims = make([]poolsettle.Claim, 16384)
	tooMany[1].Claims = make([]poolsettle.Claim, 16385)
	for i := range tooMany {
		for j := range tooMany[i].Claims {
			tooMany[i].Claims[j] = claim
		}
	}
	if c, b, e := poolDailyOwnedInputs(context.Background(), tooMany, body); e == nil || c != nil || b != nil {
		t.Fatal("aggregate claims unbounded")
	}
	if c, b, e := poolDailyOwnedInputs(context.Background(), own, make([]byte, pooltxshape.MaxStandardWeight+1)); e == nil || c != nil || b != nil {
		t.Fatal("raw bound")
	}
	var tx wire.MsgTx
	if e := tx.Deserialize(bytes.NewReader(body)); e != nil {
		t.Fatal(e)
	}
	if e := poolDailySigningShape(&tx, g.Settlement, len(body), false); e != nil {
		t.Fatal(e)
	}
	// A canonical native shape with two payees plus change and1464 inputs
	// exceeds standard weight; no key/DB access may make it signable.
	_, over := dailyManagerTransaction(t, g, 1464)
	var heavy wire.MsgTx
	if e := heavy.Deserialize(bytes.NewReader(over)); e != nil {
		t.Fatal(e)
	}
	heavy.TxOut = append(heavy.TxOut[:1], heavy.TxOut[0], heavy.TxOut[1])
	var overweight bytes.Buffer
	if e := heavy.SerializeNoWitness(&overweight); e != nil {
		t.Fatal(e)
	}
	if e := poolDailySigningShape(&heavy, g.Settlement, overweight.Len(), false); e == nil {
		t.Fatal("overweight native shape accepted")
	}
}

func TestDailyPoolSettlementCheapRefusal(t *testing.T) {
	if !wire.TestPoW {
		return
	}
	var m *Manager
	if raw, e := m.SignDailyPoolSettlement(context.Background(), nil, PoolSettlementGuard{}, nil, nil, poolsettle.Config{}, poolshare.Config{}, nil, nil); raw != nil || !errors.Is(e, ErrPoolSettlementProfile) {
		t.Fatal("daily cheap signer", e)
	}
}
