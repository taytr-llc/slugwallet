// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

const poolReferenceSHA = "c1f2d725fcdbc3af7ba1b0a30f4dd4dfc6983352ffb0b4f72d83f7c09ac7b087"

type poolGuardVector struct {
	Fixture    string              `json:"fixture"`
	Guard      PoolSettlementGuard `json:"guard"`
	Canonical  string              `json:"canonical_hex"`
	Digest     string              `json:"digest"`
	Source     poolshare.Config    `json:"source"`
	Settlement poolsettle.Config   `json:"settlement"`
}
type poolTxVector struct {
	Fixture  string             `json:"fixture"`
	Coins    poolReferenceCoins `json:"coins"`
	Unsigned string             `json:"unsigned_hex"`
	Signed   string             `json:"signed_hex"`
	Fee      int64              `json:"fee_atoms"`
}

// The independent corpus encodes outpoint hashes in wire order. Convert only
// that representation to the public Coin API's reversed display hex; preserve
// every amount, index and script, including deliberately invalid refusal cases.
type poolReferenceCoins []poolsettle.Coin

func (coins *poolReferenceCoins) UnmarshalJSON(raw []byte) error {
	var rows []struct {
		HashWire string `json:"hash_wire"`
		Index    uint32 `json:"index"`
		Atoms    int64  `json:"atoms"`
		Script   string `json:"script"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&rows); e != nil {
		return e
	}
	if len(rows) < 1 || len(rows) > 256 {
		return errors.New("invalid reference coin count")
	}
	result := make(poolReferenceCoins, len(rows))
	for i, row := range rows {
		hash, e := hex.DecodeString(row.HashWire)
		if e != nil || len(hash) != 32 || hex.EncodeToString(hash) != row.HashWire {
			return errors.New("invalid reference wire hash")
		}
		for left, right := 0, len(hash)-1; left < right; left, right = left+1, right-1 {
			hash[left], hash[right] = hash[right], hash[left]
		}
		result[i] = poolsettle.Coin{TxID: hex.EncodeToString(hash), Index: row.Index, Atoms: row.Atoms, Script: row.Script}
	}
	*coins = result
	return nil
}

type poolReferences struct {
	Guards        []poolGuardVector `json:"guards"`
	Transactions  []poolTxVector    `json:"transactions"`
	GuardRefusals []struct {
		Name  string              `json:"name"`
		Guard PoolSettlementGuard `json:"guard"`
	} `json:"guard_refusals"`
	RawRefusals []struct {
		Name string `json:"name"`
		Raw  string `json:"raw_hex"`
	} `json:"raw_refusals"`
	TransactionRefusals []struct {
		Name     string             `json:"name"`
		Unsigned string             `json:"unsigned_hex"`
		Coins    poolReferenceCoins `json:"coins"`
		Fee      int64              `json:"fee_atoms"`
	} `json:"transaction_refusals"`
}

func poolReference(t *testing.T) poolReferences {
	t.Helper()
	f, e := os.Open("../../slug/poolsettle/testdata/operator-wallet/reference-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(io.LimitReader(f, 2<<20))
	ce := f.Close()
	if e != nil || ce != nil {
		t.Fatal(e, ce)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != poolReferenceSHA {
		t.Fatal("independent corpus identity")
	}
	var v poolReferences
	if json.Unmarshal(raw, &v) != nil || len(v.Guards) != 3 || len(v.Transactions) != 9 || len(v.GuardRefusals) != 12 || len(v.RawRefusals) != 12 || len(v.TransactionRefusals) != 12 {
		t.Fatal("reference scope")
	}
	return v
}
func poolRoot(t *testing.T, name string) *hdkeychain.ExtendedKey {
	t.Helper()
	entropyHex := map[string]string{"zero256": "0000000000000000000000000000000000000000000000000000000000000000", "incrementing256": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "official-leading-zero-account": "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"}[name]
	raw, e := hex.DecodeString(entropyHex)
	if e != nil || len(raw) != 32 {
		t.Fatal("published fixture")
	}
	var entropy [32]byte
	copy(entropy[:], raw)
	clear(raw)
	seed := recovery.SeedFromEntropy(entropy)
	clear(entropy[:])
	root, e := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	clear(seed[:])
	if e != nil {
		t.Fatal(e)
	}
	return root
}
func poolManagerFixture(t *testing.T, v poolGuardVector) (walletdb.DB, *Manager) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile only")
	}
	root := poolRoot(t, v.Fixture)
	defer root.Zero()
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "pool.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		return CreateWithPoolSettlement(context.Background(), ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Unix(1795000000, 0), v.Guard)
	})
	if e != nil {
		db.Close()
		t.Fatal("create", e)
	}
	var m *Manager
	e = walletdb.View(db, func(tx walletdb.ReadTx) error {
		var e error
		m, e = OpenPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams, v.Guard)
		return e
	})
	if e != nil {
		db.Close()
		t.Fatal("open", e)
	}
	t.Cleanup(func() {
		m.Close()
		if e := db.Close(); e != nil {
			t.Error(e)
		}
	})
	return db, m
}
func TestPoolSettlementGuardReference(t *testing.T) {
	refs := poolReference(t)
	for _, v := range refs.Guards {
		raw, e := MarshalPoolSettlementGuard(v.Guard)
		if e != nil || hex.EncodeToString(raw) != v.Canonical {
			t.Fatal(v.Fixture, "canonical", e)
		}
		id, e := PoolSettlementGuardDigest(v.Guard)
		if e != nil || id != v.Digest {
			t.Fatal(v.Fixture, "digest", e)
		}
		got, e := ParsePoolSettlementGuard(raw)
		if e != nil || got != v.Guard {
			t.Fatal("roundtrip", e)
		}
	}
	for _, v := range refs.GuardRefusals {
		if _, e := MarshalPoolSettlementGuard(v.Guard); e == nil {
			t.Fatal("guard accepted", v.Name)
		}
	}
	for _, v := range refs.RawRefusals {
		raw, e := hex.DecodeString(v.Raw)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ParsePoolSettlementGuard(raw); e == nil {
			t.Fatal("raw accepted", v.Name)
		}
	}
}
func TestPoolSettlementManagerIndependentSigning(t *testing.T) {
	refs := poolReference(t)
	for _, g := range refs.Guards {
		t.Run(g.Fixture, func(t *testing.T) {
			db, m := poolManagerFixture(t, g)
			if !m.PoolSettlement() || m.HostedAllocation() || m.RecoveryEnabled() || m.DerivationMode() != DerivationStandard {
				t.Fatal("mixed manager purpose")
			}
			e := walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) })
			if e != nil {
				t.Fatal(e)
			}
			for _, v := range refs.Transactions {
				if v.Fixture != g.Fixture {
					continue
				}
				raw, _ := hex.DecodeString(v.Unsigned)
				e = walletdb.View(db, func(tx walletdb.ReadTx) error {
					ns := tx.ReadBucket(waddrmgrNamespaceKey)
					// This package-private codec leaf proves independent bytes only. The
					// exported signer must refuse the same DTO without original authority.
					if _, e := m.SignPoolSettlement(context.Background(), ns, g.Guard, nil, nil, g.Settlement, g.Source, v.Coins, raw); e == nil {
						t.Fatal("DTO authorized public signer")
					}
					signed, e := m.signPoolSettlement(context.Background(), ns, g.Guard, g.Settlement, v.Coins, raw, context.Background().Err)
					if e != nil {
						return e
					}
					if hex.EncodeToString(signed) != v.Signed {
						t.Fatal("independent signed bytes mismatch")
					}
					var parsed wire.MsgTx
					if e = parsed.Deserialize(bytes.NewReader(raw)); e != nil {
						return e
					}
					fee, e := poolUnsignedOutputs(&parsed, g.Settlement, v.Coins)
					if e != nil || fee != v.Fee {
						t.Fatal("independent exact fee", fee, e)
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			m.Close()
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				var e error
				m, e = OpenPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams, g.Guard)
				return e
			})
			if e != nil {
				t.Fatal("reopen", e)
			}
			defer m.Close()
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				raw, _ := hex.DecodeString(refs.Transactions[0].Unsigned)
				_, e := m.signPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), g.Guard, g.Settlement, refs.Transactions[0].Coins, raw, context.Background().Err)
				return e
			})
			if e == nil {
				t.Fatal("reopen unlocked or signed wrong fixture")
			}
		})
	}
}
func TestPoolSettlementManagerTransactionRefusals(t *testing.T) {
	refs := poolReference(t)
	g := refs.Guards[0]
	db, m := poolManagerFixture(t, g)
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error { return m.Unlock(tx.ReadBucket(waddrmgrNamespaceKey), privPassphrase) }); e != nil {
		t.Fatal(e)
	}
	for _, v := range refs.TransactionRefusals {
		raw, _ := hex.DecodeString(v.Unsigned)
		e := walletdb.View(db, func(tx walletdb.ReadTx) error {
			if v.Name == "fee" { // No caller fee field exists in the signer API. This is
				// an independent corpus consistency refusal, not a Go authority claim.
				var parsed wire.MsgTx
				if e := parsed.Deserialize(bytes.NewReader(raw)); e != nil {
					return e
				}
				fee, e := poolUnsignedOutputs(&parsed, g.Settlement, v.Coins)
				if e != nil {
					return e
				}
				if fee == v.Fee {
					t.Fatal("inconsistent reference fee")
				}
				return ErrPoolSettlementInvalid
			}
			_, e := m.signPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), g.Guard, g.Settlement, v.Coins, raw, context.Background().Err)
			return e
		})
		if e == nil {
			t.Fatal("transaction accepted", v.Name)
		}
	}
}
func TestPoolSettlementManagerGenericRefusals(t *testing.T) {
	g := poolReference(t).Guards[0]
	db, m := poolManagerFixture(t, g)
	e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		old, e := Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		if old != nil {
			old.Close()
		}
		if e == nil {
			t.Fatal("generic Open accepted16")
		}
		if e = m.Unlock(ns, privPassphrase); e != nil {
			return e
		}
		scoped, e := m.FetchScopedKeyManager(KeyScopeBIP0084)
		if e != nil {
			return e
		}
		addr, e := address.DecodeAddress(g.Source.PayoutAddress, &chaincfg.MainNetParams)
		if e != nil {
			return e
		}
		calls := []func() error{
			func() error {
				_, e := m.NewScopedKeyManager(ns, KeyScopeBIP0044, ScopeAddrSchema{ExternalAddrType: PubKeyHash, InternalAddrType: PubKeyHash})
				return e
			},
			func() error { _, e := scoped.NextExternalAddresses(ns, 0, 1); return e }, func() error { _, e := scoped.NextInternalAddresses(ns, 0, 1); return e },
			func() error { _, e := scoped.NewAccount(ns, "other"); return e }, func() error { return scoped.RenameAccount(ns, 0, "other") },
			func() error { _, e := scoped.DeriveFromKeyPath(ns, DerivationPath{}); return e }, func() error { _, e := scoped.DeriveFromKeyPathCache(DerivationPath{}); return e },
			func() error { _, e := m.Address(ns, addr); return e }, func() error { return scoped.MarkUsed(ns, addr) },
			func() error { _, e := m.Decrypt(CKTPrivate, []byte("not ciphertext")); return e }, func() error { return m.NeuterRootKey(ns) }, func() error { return m.ConvertToWatchingOnly(ns) },
		}
		for i, call := range calls {
			if e := call(); !errors.Is(e, ErrPoolSettlementProfile) {
				t.Fatalf("generic path %d: %v", i, e)
			}
		}
		return m.AuditPoolSettlement(context.Background(), ns, g.Guard)
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestPoolSettlementManagerMutationRefusals(t *testing.T) {
	g := poolReference(t).Guards[0]
	for _, name := range []string{"guard", "mode", "root", "scope", "account", "cursor", "address", "foreign-main", "recovery", "genesis-missing", "genesis-short", "genesis-wrong", "extra-height"} {
		t.Run(name, func(t *testing.T) {
			db, m := poolManagerFixture(t, g)
			e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				main := ns.NestedReadWriteBucket(mainBucketName)
				scope, e := fetchWriteScopeBucket(ns, &KeyScopeBIP0084)
				if e != nil {
					return e
				}
				switch name {
				case "guard":
					other := g.Guard
					other.WalletOwnerID = other.OperatorProfileID
					raw, _ := MarshalPoolSettlementGuard(other)
					return main.Put(poolSettlementGuardKey, raw)
				case "mode":
					return main.Put(derivationModeName, uint32ToBytes(0))
				case "root":
					return main.Put(masterHDPubName, make([]byte, 100))
				case "scope":
					_, e := ns.NestedReadWriteBucket(scopeBucketName).CreateBucket([]byte("foreign"))
					return e
				case "account":
					return scope.NestedReadWriteBucket(acctBucketName).Put(uint32ToBytes(1), []byte{0})
				case "cursor":
					return putDefaultAccountInfo(ns, &KeyScopeBIP0084, 0, []byte("bad"), []byte("bad"), 2, 0, defaultAccountName)
				case "address":
					return scope.NestedReadWriteBucket(addrBucketName).Put(make([]byte, 32), make([]byte, 26))
				case "foreign-main":
					return main.Put([]byte("unrecognized"), []byte{1})
				case "recovery":
					return main.Put(recoveryVersionName, uint32ToBytes(1))
				case "genesis-missing":
					return ns.NestedReadWriteBucket(syncBucketName).Delete([]byte{0, 0, 0, 0})
				case "genesis-short":
					return ns.NestedReadWriteBucket(syncBucketName).Put([]byte{0, 0, 0, 0}, chaincfg.MainNetParams.GenesisHash[:31])
				case "genesis-wrong":
					wrong := *chaincfg.MainNetParams.GenesisHash
					wrong[0] ^= 1
					return ns.NestedReadWriteBucket(syncBucketName).Put([]byte{0, 0, 0, 0}, wrong[:])
				case "extra-height":
					return ns.NestedReadWriteBucket(syncBucketName).Put([]byte{0, 0, 0, 1}, chaincfg.MainNetParams.GenesisHash[:])
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				return m.AuditPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), g.Guard)
			})
			if e == nil {
				t.Fatal("mutated manager accepted")
			}
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				opened, e := OpenPoolSettlement(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey), pubPassphrase, &chaincfg.MainNetParams, g.Guard)
				if opened != nil {
					opened.Close()
					t.Fatal("mutated manager reopened")
				}
				return e
			})
			if e == nil {
				t.Fatal("mutated manager open admitted")
			}
		})
	}
}
func TestPoolSettlementManagerProfileRefusal(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("cheap-profile refusal control")
	}
	g := poolReference(t).Guards[0]
	// The independent normal-PoW guard binds the normal genesis and must
	// remain invalid in a build whose genesis hash uses slugtestpow.
	if !errors.Is(ValidatePoolSettlementGuard(g.Guard), ErrPoolSettlementInvalid) {
		t.Fatal("normal genesis guard accepted by cheap profile")
	}
	// Make only this local refusal request structurally valid for the compiled
	// genesis, so the constructor's separate execution-profile gate is tested.
	g.Guard.Genesis = chaincfg.MainNetParams.GenesisHash.String()
	if e := ValidatePoolSettlementGuard(g.Guard); e != nil {
		t.Fatal("cheap refusal request shape", e)
	}
	root := poolRoot(t, g.Fixture)
	defer root.Zero()
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "cheap.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		e = CreateWithPoolSettlement(context.Background(), ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Unix(1795000000, 0), g.Guard)
		if k, _ := ns.ReadCursor().First(); k != nil {
			t.Fatal("cheap constructor wrote manager state")
		}
		return e
	})
	if !errors.Is(e, ErrPoolSettlementProfile) {
		t.Fatal("cheap purpose admitted", e)
	}
}

// Neuter returns a public alias sharing buffers with its private parent. A
// read-only binding check must preserve the caller's complete original root.
func TestPoolSettlementRootCheckPreservesOriginal(t *testing.T) {
	for _, v := range poolReference(t).Guards {
		t.Run(v.Fixture, func(t *testing.T) {
			root := poolRoot(t, v.Fixture)
			defer root.Zero()
			original := root.String()
			before, e := poolDerive(root)
			if e != nil {
				t.Fatal(e)
			}
			defer before.Zero()
			beforePublic, e := before.Neuter()
			if e != nil {
				t.Fatal(e)
			}
			fixedChild := beforePublic.String()
			if e = poolRootMatches(root, v.Guard); e != nil {
				t.Fatal(e)
			}
			if root.String() != original {
				t.Fatal("binding check mutated original root")
			}
			after, e := poolDerive(root)
			if e != nil {
				t.Fatal(e)
			}
			defer after.Zero()
			afterPublic, e := after.Neuter()
			if e != nil {
				t.Fatal(e)
			}
			point, e := after.ECPubKey()
			if e != nil || afterPublic.String() != fixedChild || hex.EncodeToString(point.SerializeCompressed()) != v.Guard.FundingPublicKey {
				t.Fatal("binding check changed fixed child")
			}
		})
	}
}
