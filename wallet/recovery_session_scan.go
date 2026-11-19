// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/taytr-llc/slug/blockchain"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// Step performs at most128 raw public derivation attempts, or one full block.
// Reorg/lookahead replay clears only a separately bounded pending ledger. It
// never rolls back address issuance. The source is trusted full-node assistance;
// hash/merkle checks here do not replace the node's consensus validation.
func (s *RecoverySession) Step(ctx context.Context, source RecoveryBlockSource) (RecoveryProgress, error) {
	op, leave, err := s.enter(ctx)
	if err != nil {
		return RecoveryProgress{}, err
	}
	defer leave()
	result := func(e error) (RecoveryProgress, error) {
		var p RecoveryProgress
		v := walletdb.View(s.db, func(tx walletdb.ReadTx) error { var x error; p, x = s.status(tx); return x })
		if e != nil {
			return p, e
		}
		return p, v
	}
	var d recoveryScanState
	var m waddrmgr.RecoveryState
	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		var e error
		d, e = readRecoveryScan(tx.ReadBucket(s.scanBucket))
		if e != nil {
			return e
		}
		m, e = s.manager.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	})
	if err != nil {
		return result(err)
	}
	if m.Ready != (d.Phase == "complete") {
		return result(waddrmgr.ErrRecoveryState)
	}
	if m.Ready {
		return result(nil)
	}
	if err = op.Err(); err != nil {
		return result(err)
	}
	if d.Phase == "deriving" {
		replayed := false
		err = s.committed("derived", func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			rows, e := s.manager.DeriveRecoveryChunk(op, ns)
			if e != nil {
				return e
			}
			b := tx.ReadWriteBucket(s.scanBucket)
			scripts := b.NestedReadWriteBucket(recoveryScripts)
			for _, row := range rows {
				h := sha256.Sum256(row.PkScript)
				if scripts.Get(h[:]) != nil {
					return waddrmgr.ErrRecoveryState
				}
				raw, e := json.Marshal(recoveryScript{row.Scope.Purpose, row.Branch, row.Index, append([]byte(nil), row.PkScript...)})
				if e != nil {
					return e
				}
				if e = scripts.Put(h[:], raw); e != nil {
					return e
				}
			}
			current, e := s.manager.CandidateRecoveryState(ns)
			if e != nil {
				return e
			}
			complete := true
			for _, branch := range current.Branches {
				if branch.DerivedNext != branch.TargetNext {
					complete = false
				}
			}
			if complete {
				d.Phase = "scanning"
				// Newly indexed lookahead may have been paid before the address that
				// caused expansion. Replay all bounded history with the enlarged index.
				if d.Height >= 0 {
					if e = resetPendingRecoveryBucket(tx, &d, s.scanBucket); e != nil {
						return e
					}
					replayed = true
				}
			}
			if e = putRecoveryScan(b, d); e != nil {
				return e
			}
			return op.Err()
		})
		if err == nil && replayed && s.checkpoint != nil {
			s.checkpoint("reset")
		}
		return result(err)
	}
	if source == nil {
		return result(ErrRecoverySource)
	}
	identity, err := source.Identity(op)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	if identity.Network != uint32(s.params.Net) || identity.Genesis != *s.params.GenesisHash || identity.CSVHeight != chaincfg.PhaseAActivationHeight || identity.SegwitHeight != chaincfg.PhaseAActivationHeight || identity.TaprootHeight != chaincfg.PhaseAActivationHeight {
		return result(ErrRecoverySource)
	}
	tip, err := source.BestBlock(op)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	if tip.Height < 0 {
		return result(ErrRecoverySource)
	}
	tipHash, err := source.BlockHash(op, tip.Height)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	if tipHash != tip.Hash {
		return result(ErrRecoverySource)
	}
	d.TargetHeight = tip.Height
	d.TargetHash = tip.Hash.String()
	reset := d.Height > tip.Height
	if d.Height >= 0 && !reset {
		h, e := source.BlockHash(op, d.Height)
		if e != nil {
			return result(scanSourceError(op, e))
		}
		reset = h.String() != d.Hash
	}
	if reset {
		err = s.committed("reset", func(tx walletdb.ReadWriteTx) error {
			if e := op.Err(); e != nil {
				return e
			}
			return resetPendingRecoveryBucket(tx, &d, s.scanBucket)
		})
		return result(err)
	}
	if d.Height == tip.Height {
		if s.checkpoint != nil {
			s.checkpoint("before-ready")
		}
		// Observe the exact same canonical tip again immediately before the
		// database commit. A later reorg belongs to ordinary ready-wallet sync.
		final, e := source.BestBlock(op)
		if e != nil {
			return result(scanSourceError(op, e))
		}
		h, e := source.BlockHash(op, tip.Height)
		if e != nil {
			return result(scanSourceError(op, e))
		}
		if final != tip || h != tip.Hash {
			return result(ErrRecoverySource)
		}
		if e = op.Err(); e != nil {
			return result(e)
		}
		err = s.committed("ready", func(tx walletdb.ReadWriteTx) error {
			if e := op.Err(); e != nil {
				return e
			}
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			if e := s.manager.SetSyncedTo(ns, &waddrmgr.BlockStamp{Height: d.Height, Hash: tip.Hash, Timestamp: time.Unix(d.Time, 0)}); e != nil {
				return e
			}
			// This session has scanned from the pinned genesis. Persist that
			// verified birthday so ordinary startup retains this completed tip
			// instead of restarting an inherited birthday-discovery scan.
			if e := s.manager.SetBirthdayBlock(ns, waddrmgr.BlockStamp{Height: 0, Hash: *s.params.GenesisHash, Timestamp: s.params.GenesisBlock.Header.Timestamp}, true); e != nil {
				return e
			}
			if e := s.manager.SetCandidateRecoveryReady(ns); e != nil {
				return e
			}
			d.Phase = "complete"
			return putRecoveryScan(tx.ReadWriteBucket(s.scanBucket), d)
		})
		return result(err)
	}
	next := d.Height + 1
	hash, err := source.BlockHash(op, next)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	block, err := source.Block(op, hash)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	owned, err := ownRecoveryBlock(block)
	if err != nil {
		return result(err)
	}
	if err = op.Err(); err != nil {
		return result(err)
	}
	// Exactly one potentially expensive header hash per scanned block.
	if owned.Header.BlockHash() != hash {
		return result(ErrRecoverySource)
	}
	if next == 0 {
		if hash != *s.params.GenesisHash {
			return result(ErrRecoverySource)
		}
	} else {
		previous, e := chainhash.NewHashFromStr(d.Hash)
		if e != nil || owned.Header.PrevBlock != *previous {
			return result(ErrRecoverySource)
		}
	}
	txs := make([]*btcutil.Tx, len(owned.Transactions))
	for i, tx := range owned.Transactions {
		txs[i] = btcutil.NewTx(tx)
	}
	if blockchain.CalcMerkleRoot(txs, false) != owned.Header.MerkleRoot || blockchain.ValidateWitnessCommitment(btcutil.NewBlock(owned)) != nil {
		return result(ErrRecoverySource)
	}
	if s.checkpoint != nil {
		s.checkpoint("before-scan-commit")
	}
	latest, err := source.BlockHash(op, next)
	if err != nil {
		return result(scanSourceError(op, err))
	}
	if latest != hash {
		return result(ErrRecoverySource)
	}
	if err = op.Err(); err != nil {
		return result(err)
	}
	expanded := false
	err = s.committed("scanned", func(tx walletdb.ReadWriteTx) error {
		var e error
		if next > 0 {
			expanded, e = s.scanRecoveryTransactions(op, tx, owned, hash, next, &d)
			if e != nil {
				return e
			}
		}
		d.Height = next
		d.Hash = hash.String()
		d.Time = owned.Header.Timestamp.Unix()
		// Preserve the manager's normal bounded recent-block history as part
		// of this same checkpoint. Updating only the final tip would leave
		// ordinary ready-wallet reorg traversal without its parent hashes.
		if e = waddrmgr.PutSyncedTo(tx.ReadWriteBucket(waddrmgrNamespaceKey), &waddrmgr.BlockStamp{Height: next, Hash: hash, Timestamp: owned.Header.Timestamp}); e != nil {
			return e
		}
		if expanded {
			d.Phase = "deriving"
		}
		if e = putRecoveryScan(tx.ReadWriteBucket(s.scanBucket), d); e != nil {
			return e
		}
		return op.Err()
	})
	if err == nil && expanded && s.checkpoint != nil {
		s.checkpoint("expanded")
	}
	return result(err)
}

func scanSourceError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrRecoverySource
}

func ownRecoveryBlock(block *wire.MsgBlock) (*wire.MsgBlock, error) {
	if block == nil || len(block.Transactions) == 0 || len(block.Transactions) > 100000 {
		return nil, ErrRecoverySource
	}
	// Check caller-controlled containers before calling wire's serializer, which
	// assumes non-nil inputs/outputs. The source adapter independently bounds raw
	// messages, while this path also protects typed test/custom callers.
	var items uint64
	var scriptBytes uint64
	for _, tx := range block.Transactions {
		if tx == nil || len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
			return nil, ErrRecoverySource
		}
		items += uint64(len(tx.TxIn)) + uint64(len(tx.TxOut))
		if items > 400000 {
			return nil, ErrRecoverySource
		}
		for _, in := range tx.TxIn {
			if in == nil {
				return nil, ErrRecoverySource
			}
			scriptBytes += uint64(len(in.SignatureScript))
			items += uint64(len(in.Witness))
			if items > 400000 {
				return nil, ErrRecoverySource
			}
			for _, w := range in.Witness {
				scriptBytes += uint64(len(w))
				if scriptBytes > wire.MaxBlockPayload {
					return nil, ErrRecoverySource
				}
			}
		}
		for _, out := range tx.TxOut {
			if out == nil {
				return nil, ErrRecoverySource
			}
			scriptBytes += uint64(len(out.PkScript))
			if scriptBytes > wire.MaxBlockPayload {
				return nil, ErrRecoverySource
			}
		}
	}
	if block.SerializeSize() > wire.MaxBlockPayload {
		return nil, ErrRecoverySource
	}
	var b bytes.Buffer
	if err := block.Serialize(&b); err != nil || b.Len() > wire.MaxBlockPayload {
		return nil, ErrRecoverySource
	}
	var result wire.MsgBlock
	if err := result.Deserialize(bytes.NewReader(b.Bytes())); err != nil {
		return nil, ErrRecoverySource
	}
	return &result, nil
}

func (s *RecoverySession) scanRecoveryTransactions(ctx context.Context, tx walletdb.ReadWriteTx, block *wire.MsgBlock, hash chainhash.Hash, height int32, d *recoveryScanState) (bool, error) {
	b := tx.ReadWriteBucket(s.scanBucket)
	scripts := b.NestedReadWriteBucket(recoveryScripts)
	outputs := b.NestedReadWriteBucket(recoveryOutputs)
	transactions := b.NestedReadWriteBucket(recoveryTransactions)
	ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
	ledger := tx.ReadWriteBucket(wtxmgrNamespaceKey)
	meta := &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: hash, Height: height}, Time: block.Header.Timestamp}
	expanded := false
	for _, msg := range block.Transactions {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		matches := make(map[uint32]recoveryScript)
		relevant := false
		for _, in := range msg.TxIn {
			if outputs.Get(recoveryOutpointKey(in.PreviousOutPoint)) != nil {
				relevant = true
			}
		}
		for i, out := range msg.TxOut {
			key := sha256.Sum256(out.PkScript)
			raw := scripts.Get(key[:])
			if raw == nil {
				continue
			}
			row, err := decodeRecoveryScriptLimit(raw, s.manager.RecoveryIndexLimit())
			if err != nil {
				return false, err
			}
			if !bytes.Equal(row.Script, out.PkScript) {
				return false, waddrmgr.ErrRecoveryState
			}
			matches[uint32(i)] = row
			relevant = true
		}
		if !relevant {
			continue
		}
		rec, err := wtxmgr.NewTxRecordFromMsgTx(msg, block.Header.Timestamp)
		if err != nil {
			return false, ErrRecoverySource
		}
		if transactions.Get(rec.Hash[:]) == nil {
			size := uint64(msg.SerializeSize())
			if d.Transactions >= MaxRecoveryTransactions || size > MaxRecoveryTransactionBytes-d.TransactionBytes {
				return false, ErrRecoveryCapacity
			}
			d.Transactions++
			d.TransactionBytes += size
			var n [8]byte
			binary.LittleEndian.PutUint64(n[:], size)
			if err = transactions.Put(rec.Hash[:], n[:]); err != nil {
				return false, err
			}
		}
		if err = s.txStore.InsertTx(ledger, rec, meta); err != nil {
			return false, err
		}
		for index, row := range matches {
			key := recoveryOutpointKey(wire.OutPoint{Hash: rec.Hash, Index: index})
			if outputs.Get(key) == nil {
				if d.Outputs >= MaxRecoveryOwnedOutputs {
					return false, ErrRecoveryCapacity
				}
				h := sha256.Sum256(row.Script)
				if err = outputs.Put(key, h[:]); err != nil {
					return false, err
				}
				d.Outputs++
			}
			if err = s.txStore.AddCredit(ledger, rec, meta, index, row.Branch == 1); err != nil {
				return false, err
			}
			_, addresses, _, err := txscript.ExtractPkScriptAddrs(row.Script, s.params)
			if err != nil || len(addresses) != 1 {
				return false, waddrmgr.ErrRecoveryState
			}
			if err = s.manager.MarkUsed(ns, addresses[0]); err != nil {
				return false, err
			}
			scope, err := s.manager.PaymentScope(row.Purpose)
			if err != nil {
				return false, err
			}
			grew, err := s.manager.ObserveRecoveryAddress(ns, scope, row.Branch, row.Index)
			if err != nil {
				return false, err
			}
			expanded = expanded || grew
		}
	}
	return expanded, nil
}
