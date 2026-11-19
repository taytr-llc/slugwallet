// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wtxmgr

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sort"

	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var (
	ErrOwnActivityCapacity = errors.New("own activity capacity")
	ErrOwnActivityCorrupt  = errors.New("invalid own activity storage")
)

const (
	OwnActivityMaxRecords  = 256
	OwnActivityMaxRaw      = 262144
	OwnActivityMaxRawTotal = 8388608
	ownActivityMaxMetadata = 8192
	ownActivityMaxTime     = 253402300799999
)

type OwnActivityBlock struct {
	Height uint32
	Hash   chainhash.Hash
	TimeMS int64
}
type OwnActivityCredit struct {
	Index  uint32
	Atoms  int64
	Change bool
}
type OwnActivityDebit struct {
	Index uint32
	Atoms int64
}
type OwnActivityRecord struct {
	TxID         chainhash.Hash
	Raw          []byte
	RecordedAtMS int64
	Block        *OwnActivityBlock
	Credits      []OwnActivityCredit
	Debits       []OwnActivityDebit
}
type activityMetadata struct {
	hash     chainhash.Hash
	recorded int64
}
type activitySelection struct {
	hash     chainhash.Hash
	recorded int64
	block    *OwnActivityBlock
}
type activityReader struct {
	ns     walletdb.ReadBucket
	visits int
}

func activityTime(raw []byte) (int64, error) {
	if len(raw) != 8 {
		return 0, ErrOwnActivityCorrupt
	}
	n := byteOrder.Uint64(raw)
	if n > ownActivityMaxTime/1000 {
		return 0, ErrOwnActivityCorrupt
	}
	return int64(n) * 1000, nil
}
func activityHashLess(a, b chainhash.Hash) bool {
	for i := 31; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
func (r *activityReader) charge(n int) error {
	if n < 0 || n > ownActivityMaxMetadata-r.visits {
		return ErrOwnActivityCapacity
	}
	r.visits += n
	return nil
}
func activitySort(ctx context.Context, rows []activityMetadata) error {
	var cancelled error
	sort.Slice(rows, func(i, j int) bool {
		if cancelled == nil {
			cancelled = ctx.Err()
		}
		if cancelled != nil {
			return false
		}
		if rows[i].recorded != rows[j].recorded {
			return rows[i].recorded > rows[j].recorded
		}
		return activityHashLess(rows[i].hash, rows[j].hash)
	})
	return cancelled
}
func (r *activityReader) selectRecords(ctx context.Context, height uint32) ([]activitySelection, bool, error) {
	unmined := make([]activityMetadata, 0, 4096)
	cursor := r.ns.NestedReadBucket(bucketUnmined).ReadCursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := r.charge(1); err != nil {
			return nil, false, err
		}
		if len(unmined) == 4096 {
			return nil, false, ErrOwnActivityCapacity
		}
		if len(k) != 32 || len(v) < 8 {
			return nil, false, ErrOwnActivityCorrupt
		}
		stamp, err := activityTime(v[:8])
		if err != nil {
			return nil, false, err
		}
		var h chainhash.Hash
		copy(h[:], k)
		unmined = append(unmined, activityMetadata{hash: h, recorded: stamp})
	}
	if err := activitySort(ctx, unmined); err != nil {
		return nil, false, err
	}
	selected := make([]activitySelection, 0, OwnActivityMaxRecords)
	n := len(unmined)
	if n > OwnActivityMaxRecords {
		n = OwnActivityMaxRecords
	}
	for _, row := range unmined[:n] {
		selected = append(selected, activitySelection{hash: row.hash, recorded: row.recorded})
	}
	if len(unmined) > OwnActivityMaxRecords {
		return selected, true, nil
	}
	seen := make(map[chainhash.Hash]struct{}, OwnActivityMaxRecords)
	for _, row := range selected {
		seen[row.hash] = struct{}{}
	}
	blocks := r.ns.NestedReadBucket(bucketBlocks).ReadCursor()
	for k, v := blocks.Last(); k != nil; k, v = blocks.Prev() {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := r.charge(1); err != nil {
			return nil, false, err
		}
		if len(k) != 4 || len(v) < 44 {
			return nil, false, ErrOwnActivityCorrupt
		}
		h := byteOrder.Uint32(k)
		if h > height {
			return nil, false, ErrOwnActivityCorrupt
		}
		var hash chainhash.Hash
		copy(hash[:], v[:32])
		if hash == (chainhash.Hash{}) {
			return nil, false, ErrOwnActivityCorrupt
		}
		stamp, err := activityTime(v[32:40])
		if err != nil {
			return nil, false, err
		}
		count := byteOrder.Uint32(v[40:44])
		if count == 0 {
			return nil, false, ErrOwnActivityCorrupt
		}
		if count > 4096 {
			return nil, false, ErrOwnActivityCapacity
		}
		if len(v) != 44+32*int(count) {
			return nil, false, ErrOwnActivityCorrupt
		}
		if err := r.charge(int(count)); err != nil {
			return nil, false, err
		}
		rows := make([]chainhash.Hash, int(count))
		for i := range rows {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			copy(rows[i][:], v[44+32*i:76+32*i])
		}
		var cancelled error
		sort.Slice(rows, func(i, j int) bool {
			if cancelled == nil {
				cancelled = ctx.Err()
			}
			if cancelled != nil {
				return false
			}
			return activityHashLess(rows[i], rows[j])
		})
		if cancelled != nil {
			return nil, false, cancelled
		}
		for i := 1; i < len(rows); i++ {
			if rows[i] == rows[i-1] {
				return nil, false, ErrOwnActivityCorrupt
			}
		}
		for _, txid := range rows {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			if _, ok := seen[txid]; ok {
				continue
			}
			if len(selected) == OwnActivityMaxRecords {
				return selected, true, nil
			}
			selected = append(selected, activitySelection{hash: txid, block: &OwnActivityBlock{Height: h, Hash: hash, TimeMS: stamp}})
			seen[txid] = struct{}{}
		}
	}
	return selected, false, nil
}
func activityCredit(raw []byte, unspent, spent bool) (int64, bool, error) {
	if len(raw) != 9 && len(raw) != 81 {
		return 0, false, ErrOwnActivityCorrupt
	}
	amount := byteOrder.Uint64(raw[:8])
	flags := raw[8]
	if amount > uint64(btcutil.MaxSatoshi) || flags&^byte(3) != 0 {
		return 0, false, ErrOwnActivityCorrupt
	}
	isSpent := flags&1 != 0
	if isSpent && len(raw) != 81 || !isSpent && len(raw) != 9 || unspent && isSpent || spent && !isSpent {
		return 0, false, ErrOwnActivityCorrupt
	}
	return int64(amount), flags&2 != 0, nil
}
func activityIndexRows(ctx context.Context, b walletdb.ReadBucket, prefix []byte, bound, keySize int, fn func([]byte, []byte, uint32) error) error {
	c := b.ReadCursor()
	visited := 0
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > bound {
			return ErrOwnActivityCorrupt
		}
		if len(k) != keySize {
			return ErrOwnActivityCorrupt
		}
		i := byteOrder.Uint32(k[keySize-4:])
		if i >= uint32(bound) {
			return ErrOwnActivityCorrupt
		}
		if err := fn(k, v, i); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (r *activityReader) record(ctx context.Context, selection activitySelection, remaining int) (OwnActivityRecord, error) {
	empty := OwnActivityRecord{}
	bad := func() (OwnActivityRecord, error) { return empty, ErrOwnActivityCorrupt }
	var key [68]byte
	copy(key[:32], selection.hash[:])
	prefix := key[:32]
	bucket := bucketUnmined
	if selection.block != nil {
		byteOrder.PutUint32(key[32:36], selection.block.Height)
		copy(key[36:], selection.block.Hash[:])
		prefix = key[:]
		bucket = bucketTxRecords
	}
	value := r.ns.NestedReadBucket(bucket).Get(prefix)
	if len(value) < 8 {
		return bad()
	}
	if len(value)-8 > OwnActivityMaxRaw || len(value)-8 > remaining {
		return empty, ErrOwnActivityCapacity
	}
	stamp, err := activityTime(value[:8])
	if err != nil {
		return empty, err
	}
	tx, coinbase, err := parseOwnActivityTx(ctx, value[8:])
	if err != nil {
		return empty, err
	}
	if tx.TxHash() != selection.hash {
		return bad()
	}
	row := OwnActivityRecord{TxID: selection.hash, RecordedAtMS: stamp, Credits: make([]OwnActivityCredit, 0), Debits: make([]OwnActivityDebit, 0)}
	if selection.block != nil {
		b := *selection.block
		row.Block = &b
	} else if stamp != selection.recorded {
		return bad()
	}
	creditBucket, keySize := bucketUnminedCredits, 36
	if row.Block != nil {
		creditBucket, keySize = bucketCredits, 72
	}
	var received, spent, outputTotal int64
	err = activityIndexRows(ctx, r.ns.NestedReadBucket(creditBucket), prefix, len(tx.TxOut), keySize, func(k, v []byte, i uint32) error {
		amount, change, e := activityCredit(v, row.Block == nil, false)
		if e != nil {
			return e
		}
		if amount != tx.TxOut[i].Value || amount > int64(btcutil.MaxSatoshi)-received {
			return ErrOwnActivityCorrupt
		}
		received += amount
		row.Credits = append(row.Credits, OwnActivityCredit{Index: i, Atoms: amount, Change: change})
		return nil
	})
	if err != nil {
		return empty, err
	}
	addDebit := func(i uint32, amount int64) error {
		if coinbase || amount > int64(btcutil.MaxSatoshi)-spent {
			return ErrOwnActivityCorrupt
		}
		spent += amount
		row.Debits = append(row.Debits, OwnActivityDebit{Index: i, Atoms: amount})
		return nil
	}
	if row.Block != nil {
		err = activityIndexRows(ctx, r.ns.NestedReadBucket(bucketDebits), prefix, len(tx.TxIn), 72, func(k, v []byte, i uint32) error {
			if len(v) != 80 {
				return ErrOwnActivityCorrupt
			}
			amount := byteOrder.Uint64(v[:8])
			if amount > uint64(btcutil.MaxSatoshi) {
				return ErrOwnActivityCorrupt
			}
			prior := v[8:]
			op := tx.TxIn[i].PreviousOutPoint
			if !bytes.Equal(prior[:32], op.Hash[:]) || byteOrder.Uint32(prior[68:]) != op.Index {
				return ErrOwnActivityCorrupt
			}
			cv := r.ns.NestedReadBucket(bucketCredits).Get(prior)
			actual, _, e := activityCredit(cv, false, true)
			if e != nil {
				return e
			}
			if actual != int64(amount) || !bytes.Equal(cv[9:], k) {
				return ErrOwnActivityCorrupt
			}
			return addDebit(i, actual)
		})
		if err != nil {
			return empty, err
		}
	} else {
		for i, in := range tx.TxIn {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			var op [36]byte
			copy(op[:32], in.PreviousOutPoint.Hash[:])
			byteOrder.PutUint32(op[32:], in.PreviousOutPoint.Index)
			u := r.ns.NestedReadBucket(bucketUnspent).Get(op[:])
			var amount int64
			if u != nil {
				if len(u) != 36 {
					return bad()
				}
				var prior [72]byte
				copy(prior[:32], op[:32])
				copy(prior[32:68], u)
				copy(prior[68:], op[32:])
				amount, _, err = activityCredit(r.ns.NestedReadBucket(bucketCredits).Get(prior[:]), true, false)
			} else {
				mc := r.ns.NestedReadBucket(bucketUnminedCredits).Get(op[:])
				if mc == nil {
					continue
				}
				amount, _, err = activityCredit(mc, true, false)
			}
			if err != nil {
				return empty, err
			}
			if err = addDebit(uint32(i), amount); err != nil {
				return empty, err
			}
		}
	}
	if len(row.Credits)+len(row.Debits) == 0 {
		return bad()
	}
	for _, out := range tx.TxOut {
		outputTotal += out.Value
	}
	if !coinbase && len(row.Debits) == len(tx.TxIn) && spent < outputTotal {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	row.Raw = append([]byte(nil), value[8:]...)
	return row, nil
}

// CaptureOwnActivity reads only the bounded latest indexed wallet records from
// the caller's one read transaction. It never retains that transaction or reads
// labels, unmined spenders, reservations, or the complete mined history.
func (s *Store) CaptureOwnActivity(ctx context.Context, ns walletdb.ReadBucket, height uint32) ([]OwnActivityRecord, bool, error) {
	if ctx == nil || ns == nil || s == nil || height > math.MaxInt32 {
		return nil, false, ErrOwnActivityCorrupt
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	for _, name := range [][]byte{bucketUnmined, bucketBlocks, bucketTxRecords, bucketCredits, bucketDebits, bucketUnspent, bucketUnminedCredits} {
		if ns.NestedReadBucket(name) == nil {
			return nil, false, ErrOwnActivityCorrupt
		}
	}
	r := activityReader{ns: ns}
	selected, older, err := r.selectRecords(ctx, height)
	if err != nil {
		return nil, false, err
	}
	records := make([]OwnActivityRecord, 0, len(selected))
	remaining := OwnActivityMaxRawTotal
	for _, item := range selected {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		row, e := r.record(ctx, item, remaining)
		if e != nil {
			return nil, false, e
		}
		remaining -= len(row.Raw)
		records = append(records, row)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return records, older, nil
}
