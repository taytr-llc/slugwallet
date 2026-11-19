// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wtxmgr

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"

	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/wire/v2"
)

// parseOwnActivityTx bounds every variable allocation before the generic wire
// decoder. These display limits do not change consensus or candidate selection.
func parseOwnActivityTx(ctx context.Context, raw []byte) (*wire.MsgTx, bool, error) {
	bad := func() (*wire.MsgTx, bool, error) { return nil, false, ErrOwnActivityCorrupt }
	cap := func() (*wire.MsgTx, bool, error) { return nil, false, ErrOwnActivityCapacity }
	if ctx == nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if len(raw) > OwnActivityMaxRaw {
		return cap()
	}
	c := candidateTxCursor{raw: raw}
	if !c.skip(4) {
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
	ni, ok := c.compact()
	if !ok || ni == 0 {
		return bad()
	}
	if ni > 256 {
		return cap()
	}
	seen := make(map[[36]byte]struct{}, int(ni))
	coinbase := false
	for i := uint64(0); i < ni; i++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		prev, ok := c.take(36)
		if !ok {
			return bad()
		}
		var key [36]byte
		copy(key[:], prev)
		if _, ok = seen[key]; ok {
			return bad()
		}
		seen[key] = struct{}{}
		null := bytes.Equal(prev[:32], make([]byte, 32)) && binary.LittleEndian.Uint32(prev[32:]) == math.MaxUint32
		if null {
			if ni != 1 {
				return bad()
			}
			coinbase = true
		}
		n, ok := c.compact()
		if !ok {
			return bad()
		}
		if n > 10240 {
			return cap()
		}
		if !c.skip(n) || !c.skip(4) {
			return bad()
		}
	}
	no, ok := c.compact()
	if !ok || no == 0 {
		return bad()
	}
	if no > 256 {
		return cap()
	}
	var sum uint64
	for i := uint64(0); i < no; i++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		value, ok := c.take(8)
		if !ok {
			return bad()
		}
		amount := binary.LittleEndian.Uint64(value)
		if amount > uint64(btcutil.MaxSatoshi) || amount > uint64(btcutil.MaxSatoshi)-sum {
			return bad()
		}
		sum += amount
		n, ok := c.compact()
		if !ok {
			return bad()
		}
		if n > 10240 {
			return cap()
		}
		if !c.skip(n) {
			return bad()
		}
	}
	if witness {
		var total uint64
		for i := uint64(0); i < ni; i++ {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			n, ok := c.compact()
			if !ok {
				return bad()
			}
			if n > 128 || n > 4096-total {
				return cap()
			}
			total += n
			for j := uint64(0); j < n; j++ {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				size, ok := c.compact()
				if !ok {
					return bad()
				}
				if size > OwnActivityMaxRaw {
					return cap()
				}
				if !c.skip(size) {
					return bad()
				}
			}
		}
		if total == 0 {
			return bad()
		}
	}
	if !c.skip(4) || c.i != len(raw) {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	tx := new(wire.MsgTx)
	if tx.Deserialize(bytes.NewReader(raw)) != nil {
		return bad()
	}
	var canonical bytes.Buffer
	if tx.Serialize(&canonical) != nil || !bytes.Equal(canonical.Bytes(), raw) {
		return bad()
	}
	return tx, coinbase, nil
}
