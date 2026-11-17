// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wtxmgr

import (
	"bytes"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestOutputsToWatchBounded(t *testing.T) {
	s, db, err := testStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, 0), nil, nil))
	for i := 0; i < 3; i++ {
		tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	}
	record, err := NewTxRecordFromMsgTx(tx, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		if err := s.InsertTx(ns, record, nil); err != nil {
			return err
		}
		for i := uint32(0); i < 3; i++ {
			if err := s.AddCredit(ns, record, nil, i, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(namespaceKey)
		for _, limit := range []int{0, 2, 65537} {
			if got, err := s.OutputsToWatchBounded(ns, limit); err == nil || got != nil {
				t.Fatalf("limit%d returned partial/successful watch set", limit)
			}
		}
		got, err := s.OutputsToWatchBounded(ns, 3)
		if err != nil || len(got) != 3 {
			t.Fatal("exact budget", len(got), err)
		}
		legacy, err := s.OutputsToWatch(ns)
		if err != nil || len(legacy) != 3 {
			t.Fatal("legacy watch changed", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedWatchRejectsCorruptOutpoint(t *testing.T) {
	s, db, err := testStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	txn := wire.NewMsgTx(2)
	txn.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, 0), nil, nil))
	txn.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	record, err := NewTxRecordFromMsgTx(txn, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	block := &BlockMeta{Block: Block{Hash: chainhash.Hash{2}, Height: 1}, Time: record.Received}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		if err := s.InsertTx(ns, record, block); err != nil {
			return err
		}
		return s.AddCredit(ns, record, block, 0, false)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(namespaceKey)
		ops, err := s.UnspentOutpointsBounded(ns, 1)
		if err != nil || len(ops) != 1 || ops[wire.OutPoint{Hash: record.Hash}] != block.Block {
			t.Fatal("metadata projection", ops, err)
		}
		amount, err := s.MinedBalance(ns)
		if err != nil || amount != 1000 {
			t.Fatal("metadata balance", amount, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(namespaceKey).NestedReadWriteBucket(bucketUnspent)
		key := canonicalOutPoint(&record.Hash, 0)
		value := append([]byte(nil), b.Get(key)...)
		if err := b.Delete(key); err != nil {
			return err
		}
		return b.Put(canonicalOutPoint(&record.Hash, ^uint32(0)), value)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		got, err := s.OutputsToWatchBounded(tx.ReadBucket(namespaceKey), 1)
		if err == nil || got != nil {
			t.Fatal("corrupt index returned data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket(namespaceKey).NestedReadWriteBucket(bucketUnspent)
		key := canonicalOutPoint(&record.Hash, ^uint32(0))
		value := append([]byte(nil), b.Get(key)...)
		if err := b.Delete(key); err != nil {
			return err
		}
		return b.Put(append(key, 0), value)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(namespaceKey)
		if got, err := s.UnspentOutpointsBounded(ns, 1); err == nil || got != nil {
			t.Fatal("noncanonical outpoint key accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(namespaceKey).DeleteNestedBucket(bucketUnspent)
	}); err != nil {
		t.Fatal(err)
	}
	if err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(namespaceKey)
		if _, err := s.UnspentOutpointsBounded(ns, 1); err == nil {
			t.Fatal("missing unspent metadata accepted")
		}
		if _, err := s.OutputsToWatchBounded(ns, 1); err == nil {
			t.Fatal("missing watch bucket accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRecoveryStore(t *testing.T) {
	for _, name := range [][]byte{bucketBlocks, bucketTxRecords, bucketCredits, bucketDebits, bucketUnspent, bucketUnmined, bucketUnminedCredits, bucketUnminedInputs, bucketLockedOutputs} {
		t.Run("missing-"+string(name), func(t *testing.T) {
			s, db, err := testStore(t)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(namespaceKey)
				if _, err := s.ValidateRecoveryStore(ns); err != nil {
					return err
				}
				if err := ns.DeleteNestedBucket(name); err != nil {
					return err
				}
				if _, err := s.ValidateRecoveryStore(ns); err == nil {
					t.Fatal("missing mandatory bucket accepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range [][]byte{bucketUnmined, bucketUnminedCredits, bucketUnminedInputs, bucketLockedOutputs, bucketTxLabels} {
		t.Run("local-state-"+string(name), func(t *testing.T) {
			s, db, err := testStore(t)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(namespaceKey)
				b, err := ns.CreateBucketIfNotExists(name)
				if err != nil {
					return err
				}
				if err := b.Put([]byte("unexpected"), []byte{1}); err != nil {
					return err
				}
				if _, err := s.ValidateRecoveryStore(ns); err == nil {
					t.Fatal("local state accepted during pending recovery")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryStoreRawLimits(t *testing.T) {
	tests := []struct {
		name                    string
		bucket                  []byte
		keyLen, valueLen, count int
		blockCount              uint32
	}{
		{"transaction-key", bucketTxRecords, 69, 9, 1, 0},
		{"transaction-size", bucketTxRecords, 68, wire.MaxBlockPayload + 9, 1, 0},
		{"transaction-total", bucketTxRecords, 68, wire.MaxBlockPayload + 8, 9, 0},
		{"transaction-count", bucketTxRecords, 68, 9, 16385, 0},
		{"credit-key", bucketCredits, 73, 9, 1, 0},
		{"credit-size", bucketCredits, 72, 82, 1, 0},
		{"credit-count", bucketCredits, 72, 9, 16385, 0},
		{"debit-size", bucketDebits, 72, 81, 1, 0},
		{"debit-count", bucketDebits, 72, 80, 16385, 0},
		{"block-empty", bucketBlocks, 4, 44, 1, 0},
		{"block-count-lie", bucketBlocks, 4, 76, 1, ^uint32(0)},
		{"block-tail", bucketBlocks, 4, 77, 1, 1},
		{"block-references", bucketBlocks, 4, 44 + 8193*32, 2, 8193},
		{"unspent-size", bucketUnspent, 36, 37, 1, 0},
		{"unspent-count", bucketUnspent, 36, 36, 16385, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, db, err := testStore(t)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(namespaceKey)
				b := ns.NestedReadWriteBucket(test.bucket)
				value := make([]byte, test.valueLen)
				if string(test.bucket) == string(bucketBlocks) {
					byteOrder.PutUint32(value[40:44], test.blockCount)
				}
				for i := 0; i < test.count; i++ {
					key := make([]byte, test.keyLen)
					byteOrder.PutUint32(key, uint32(i))
					if err := b.Put(key, value); err != nil {
						return err
					}
				}
				if _, err := s.ValidateRecoveryStore(ns); err == nil {
					t.Fatal("corrupt raw inventory passed preflight")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryStoreGraph(t *testing.T) {
	tests := []string{"duplicate-block-reference", "missing-block-reference", "foreign-block-reference", "wrong-block-hash", "unindexed-transaction", "unindexed-credit", "unindexed-debit", "debit-credit-pointer", "credit-debit-pointer", "zero-block-time", "oversized-block-time", "received-time"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			s, db, err := testStore(t)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			fund := wire.NewMsgTx(2)
			fund.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, 0), nil, nil))
			fund.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
			fundRecord, err := NewTxRecordFromMsgTx(fund, time.Unix(1700000000, 0))
			if err != nil {
				t.Fatal(err)
			}
			spend := wire.NewMsgTx(2)
			spend.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&fundRecord.Hash, 0), nil, nil))
			spend.AddTxOut(wire.NewTxOut(900, []byte{0x51}))
			spendRecord, err := NewTxRecordFromMsgTx(spend, fundRecord.Received.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			first := &BlockMeta{Block: Block{Hash: chainhash.Hash{2}, Height: 1}, Time: fundRecord.Received}
			second := &BlockMeta{Block: Block{Hash: chainhash.Hash{3}, Height: 2}, Time: spendRecord.Received}
			if err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(namespaceKey)
				if err := s.InsertTx(ns, fundRecord, first); err != nil {
					return err
				}
				if err := s.AddCredit(ns, fundRecord, first, 0, false); err != nil {
					return err
				}
				if err := s.InsertTx(ns, spendRecord, second); err != nil {
					return err
				}
				summary, err := s.ValidateRecoveryStore(ns)
				if err != nil || summary.Transactions != 2 || summary.Credits != 1 || summary.Debits != 1 || summary.TransactionBytes != uint64(fund.SerializeSize()+spend.SerializeSize()) {
					t.Fatalf("valid graph: %+v %v", summary, err)
				}
				bucket := ns.NestedReadWriteBucket(bucketBlocks)
				key := keyBlockRecord(1)
				value := bytes.Clone(bucket.Get(key))
				switch name {
				case "duplicate-block-reference":
					value = append(value, fundRecord.Hash[:]...)
					byteOrder.PutUint32(value[40:44], 2)
				case "missing-block-reference":
					if err := bucket.Delete(key); err != nil {
						return err
					}
					value = nil
				case "foreign-block-reference":
					value[44] ^= 1
				case "wrong-block-hash":
					value[0] ^= 1
				case "zero-block-time":
					byteOrder.PutUint64(value[32:40], 0)
				case "oversized-block-time":
					byteOrder.PutUint64(value[32:40], 1<<32)
				case "received-time":
					bucket = ns.NestedReadWriteBucket(bucketTxRecords)
					key = keyTxRecord(&fundRecord.Hash, &first.Block)
					value = bytes.Clone(bucket.Get(key))
					value[0] ^= 1
				case "unindexed-transaction":
					bucket = ns.NestedReadWriteBucket(bucketTxRecords)
					key = keyTxRecord(&fundRecord.Hash, &first.Block)
					value = bytes.Clone(bucket.Get(key))
					key[0] ^= 1
				case "unindexed-credit", "credit-debit-pointer":
					bucket = ns.NestedReadWriteBucket(bucketCredits)
					key = keyCredit(&fundRecord.Hash, 0, &first.Block)
					value = bytes.Clone(bucket.Get(key))
					if name == "unindexed-credit" {
						key[0] ^= 1
					} else {
						value[9] ^= 1
					}
				case "unindexed-debit", "debit-credit-pointer":
					bucket = ns.NestedReadWriteBucket(bucketDebits)
					key = keyDebit(&spendRecord.Hash, 0, &second.Block)
					value = bytes.Clone(bucket.Get(key))
					if name == "unindexed-debit" {
						key[0] ^= 1
					} else {
						value[8] ^= 1
					}
				}
				if value != nil {
					if err := bucket.Put(key, value); err != nil {
						return err
					}
				}
				if got, err := s.ValidateRecoveryStore(ns); err == nil || got != (RecoveryStoreSummary{}) {
					t.Fatalf("corrupt graph returned summary: %+v %v", got, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
