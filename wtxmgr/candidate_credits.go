// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wtxmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var (
	ErrCandidateCreditCapacity = errors.New("candidate credit capacity")
	ErrCandidateCreditCorrupt  = errors.New("invalid candidate credit")
)

const (
	CandidateCreditMaxRows             = 4096
	CandidateCreditMaxTransactionBytes = 4 << 20
	CandidateCreditMaxDecodedBytes     = 16 << 20
)

// CandidateCreditReader belongs to one caller-held read transaction. It does
// not retain decoded transactions or input/output arrays. Never retain it after
// that transaction ends. The budget includes every row visited before skips and
// every previous transaction parsed, including repeat parses.
type CandidateCreditReader struct {
	store            *Store
	ns               walletdb.ReadBucket
	visited, decoded int
}

func (s *Store) NewCandidateCreditReader(ns walletdb.ReadBucket) (*CandidateCreditReader, error) {
	if ns == nil {
		return nil, ErrCandidateCreditCorrupt
	}
	for _, name := range [][]byte{bucketUnspent, bucketCredits, bucketTxRecords, bucketUnminedInputs, bucketLockedOutputs} {
		if ns.NestedReadBucket(name) == nil {
			return nil, ErrCandidateCreditCorrupt
		}
	}
	return &CandidateCreditReader{store: s, ns: ns}, nil
}
func (r *CandidateCreditReader) Visit(ctx context.Context, fn func(Credit) error) error {
	if ctx == nil || fn == nil {
		return ErrCandidateCreditCorrupt
	}
	return r.ns.NestedReadBucket(bucketUnspent).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		r.visited++
		if r.visited > CandidateCreditMaxRows {
			return ErrCandidateCreditCapacity
		}
		if len(k) != 36 || len(v) != 36 {
			return ErrCandidateCreditCorrupt
		}
		var op wire.OutPoint
		copy(op.Hash[:], k[:32])
		op.Index = byteOrder.Uint32(k[32:])
		c, ok, e := r.lookup(ctx, op, k, v)
		if e != nil || !ok {
			return e
		}
		return fn(c)
	})
}
func (r *CandidateCreditReader) Lookup(ctx context.Context, op wire.OutPoint) (Credit, bool, error) {
	if ctx == nil {
		return Credit{}, false, ErrCandidateCreditCorrupt
	}
	if e := ctx.Err(); e != nil {
		return Credit{}, false, e
	}
	r.visited++
	if r.visited > CandidateCreditMaxRows {
		return Credit{}, false, ErrCandidateCreditCapacity
	}
	k := canonicalOutPoint(&op.Hash, op.Index)
	v := r.ns.NestedReadBucket(bucketUnspent).Get(k)
	if v == nil {
		return Credit{}, false, nil
	}
	return r.lookup(ctx, op, k, v)
}
func (r *CandidateCreditReader) lookup(ctx context.Context, op wire.OutPoint, k, v []byte) (Credit, bool, error) {
	bad := func() (Credit, bool, error) { return Credit{}, false, ErrCandidateCreditCorrupt }
	if len(v) != 36 {
		return bad()
	}
	lock := r.ns.NestedReadBucket(bucketLockedOutputs).Get(k)
	// Existing lock formats are 40-byte time locks and 48-byte depth locks.
	if lock != nil && len(lock) != 40 && len(lock) != 48 {
		return bad()
	}
	if _, _, locked := isLockedOutput(r.ns, op, r.store.clock.Now()); locked {
		return Credit{}, false, nil
	}
	if existsRawUnminedInput(r.ns, k) != nil {
		return Credit{}, false, nil
	}
	var block Block
	if readUnspentBlock(v, &block) != nil || block.Height < 0 {
		return bad()
	}
	_, cv := existsCredit(r.ns, &op.Hash, op.Index, &block)
	if (len(cv) != 9 && len(cv) != 81) || cv[8]&^byte(3) != 0 || cv[8]&1 != 0 {
		return bad()
	}
	amount := byteOrder.Uint64(cv[:8])
	if amount == 0 || amount > uint64(btcutil.MaxSatoshi) {
		return bad()
	}
	_, tv := existsTxRecord(r.ns, &op.Hash, &block)
	if len(tv) < 8 {
		return bad()
	}
	n := len(tv) - 8
	if n > CandidateCreditMaxTransactionBytes || n > CandidateCreditMaxDecodedBytes-r.decoded {
		return Credit{}, false, ErrCandidateCreditCapacity
	}
	r.decoded += n
	atoms, script, coinbase, e := candidatePreviousOutput(ctx, tv[8:], op.Hash, op.Index)
	if e != nil {
		return Credit{}, false, e
	}
	if atoms != int64(amount) {
		return bad()
	}
	if script == nil {
		return Credit{}, false, nil
	}
	return Credit{OutPoint: op, BlockMeta: BlockMeta{Block: block}, Amount: btcutil.Amount(atoms), PkScript: script, FromCoinBase: coinbase}, true, nil
}

// candidatePreviousOutput parses the entire canonical transaction without
// allocating claimant-sized slices. Only one native84 output script is copied.
// It validates the non-witness hash independently of the stored record key.
func candidatePreviousOutput(ctx context.Context, raw []byte, expected chainhash.Hash, wanted uint32) (int64, []byte, bool, error) {
	bad := func() (int64, []byte, bool, error) { return 0, nil, false, ErrCandidateCreditCorrupt }
	c := candidateTxCursor{raw: raw}
	version, ok := c.take(4)
	if !ok {
		return bad()
	}
	witness := false
	if c.i < len(raw) && raw[c.i] == 0 {
		if c.i+2 > len(raw) || raw[c.i+1] != 1 {
			return bad()
		}
		witness = true
		c.i += 2
	}
	baseStart := c.i
	ni, ok := c.compact()
	if !ok || ni == 0 || ni > uint64(len(raw)-c.i)/41 {
		return bad()
	}
	coinbase := ni == 1
	for i := uint64(0); i < ni; i++ {
		if e := ctx.Err(); e != nil {
			return 0, nil, false, e
		}
		prev, ok := c.take(36)
		if !ok {
			return bad()
		}
		if i == 0 {
			coinbase = coinbase && bytes.Equal(prev[:32], make([]byte, 32)) && binary.LittleEndian.Uint32(prev[32:]) == math.MaxUint32
		}
		n, ok := c.compact()
		if !ok || !c.skip(n) || !c.skip(4) {
			return bad()
		}
	}
	no, ok := c.compact()
	if !ok || no == 0 || no > uint64(len(raw)-c.i)/9 || uint64(wanted) >= no {
		return bad()
	}
	var atoms, sum int64
	var script []byte
	for i := uint64(0); i < no; i++ {
		if e := ctx.Err(); e != nil {
			return 0, nil, false, e
		}
		value, ok := c.take(8)
		if !ok {
			return bad()
		}
		v := binary.LittleEndian.Uint64(value)
		if v > uint64(btcutil.MaxSatoshi) || int64(v) > int64(btcutil.MaxSatoshi)-sum {
			return bad()
		}
		sum += int64(v)
		n, ok := c.compact()
		if !ok || n > uint64(len(raw)-c.i) {
			return bad()
		}
		s, _ := c.take(int(n))
		if i == uint64(wanted) {
			atoms = int64(v)
			if len(s) == 22 && s[0] == 0 && s[1] == 20 {
				script = append([]byte(nil), s...)
			}
		}
	}
	baseEnd := c.i
	nonempty := false
	if witness {
		for i := uint64(0); i < ni; i++ {
			if e := ctx.Err(); e != nil {
				return 0, nil, false, e
			}
			n, ok := c.compact()
			if !ok || n > uint64(len(raw)-c.i) {
				return bad()
			}
			if n != 0 {
				nonempty = true
			}
			for j := uint64(0); j < n; j++ {
				size, ok := c.compact()
				if !ok || !c.skip(size) {
					return bad()
				}
			}
		}
		if !nonempty {
			return bad()
		}
	}
	lock, ok := c.take(4)
	if !ok || c.i != len(raw) {
		return bad()
	}
	h := sha256.New()
	h.Write(version)
	h.Write(raw[baseStart:baseEnd])
	h.Write(lock)
	sum256 := sha256.Sum256(h.Sum(nil))
	if !bytes.Equal(sum256[:], expected[:]) {
		return bad()
	}
	return atoms, script, coinbase, nil
}

type candidateTxCursor struct {
	raw []byte
	i   int
}

func (c *candidateTxCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(c.raw)-c.i {
		return nil, false
	}
	s := c.raw[c.i : c.i+n]
	c.i += n
	return s, true
}
func (c *candidateTxCursor) skip(n uint64) bool {
	if n > uint64(len(c.raw)-c.i) {
		return false
	}
	c.i += int(n)
	return true
}
func (c *candidateTxCursor) compact() (uint64, bool) {
	b, ok := c.take(1)
	if !ok {
		return 0, false
	}
	switch b[0] {
	case 253:
		s, k := c.take(2)
		if !k {
			return 0, false
		}
		v := uint64(binary.LittleEndian.Uint16(s))
		return v, v >= 253
	case 254:
		s, k := c.take(4)
		if !k {
			return 0, false
		}
		v := uint64(binary.LittleEndian.Uint32(s))
		return v, v > math.MaxUint16
	case 255:
		s, k := c.take(8)
		if !k {
			return 0, false
		}
		v := binary.LittleEndian.Uint64(s)
		return v, v > math.MaxUint32
	default:
		return uint64(b[0]), true
	}
}
