// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"

	"github.com/taytr-llc/slug/btcec/v2"
)

const maxSLIP10Attempts = 256

// Private seams permit independent synthetic retry transcripts in package tests.
// No application API accepts a custom hash, seed, curve or derivation path.
type hmac512Func func(key, data []byte) [64]byte
type slip10Node struct{ key, chain [32]byte }

func (n *slip10Node) zero() { clear(n.key[:]); clear(n.chain[:]) }
func hmacSHA512(key, data []byte) [64]byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	var out [64]byte
	h.Sum(out[:0])
	return out
}
func checkedContext(ctx context.Context) error {
	if ctx == nil {
		return ErrDerivation
	}
	return ctx.Err()
}
func slip10Master(ctx context.Context, seed []byte, mac hmac512Func) (slip10Node, error) {
	var empty slip10Node
	if len(seed) < 16 || len(seed) > 64 || mac == nil {
		return empty, ErrDerivation
	}
	data := append([]byte(nil), seed...)
	defer func() { clear(data) }()
	for attempt := 0; attempt < maxSLIP10Attempts; attempt++ {
		if err := checkedContext(ctx); err != nil {
			return empty, err
		}
		result := mac([]byte("Bitcoin seed"), data)
		var scalar btcec.ModNScalar
		overflow := scalar.SetByteSlice(result[:32])
		valid := !overflow && !scalar.IsZero()
		scalar.Zero()
		if valid {
			var out slip10Node
			copy(out.key[:], result[:32])
			copy(out.chain[:], result[32:])
			clear(result[:])
			if err := checkedContext(ctx); err != nil {
				out.zero()
				return empty, err
			}
			return out, nil
		}
		clear(data)
		data = append(data[:0], result[:]...)
		clear(result[:])
	}
	return empty, ErrDerivation
}
func slip10Child(ctx context.Context, parent slip10Node, index uint32, mac hmac512Func) (slip10Node, error) {
	defer parent.zero()
	var empty slip10Node
	var parentScalar btcec.ModNScalar
	if mac == nil || parentScalar.SetByteSlice(parent.key[:]) || parentScalar.IsZero() {
		parentScalar.Zero()
		return empty, ErrDerivation
	}
	defer parentScalar.Zero()
	var data [37]byte
	defer clear(data[:])
	if index&MaxNextIndex != 0 {
		copy(data[1:33], parent.key[:])
	} else {
		key := btcec.PrivKeyFromScalar(&parentScalar)
		copy(data[:33], key.PubKey().SerializeCompressed())
		key.Zero()
	}
	binary.BigEndian.PutUint32(data[33:], index)
	for attempt := 0; attempt < maxSLIP10Attempts; attempt++ {
		if err := checkedContext(ctx); err != nil {
			return empty, err
		}
		result := mac(parent.chain[:], data[:])
		var child btcec.ModNScalar
		overflow := child.SetByteSlice(result[:32])
		if !overflow {
			child.Add(&parentScalar)
		}
		if !overflow && !child.IsZero() {
			var out slip10Node
			out.key = child.Bytes()
			copy(out.chain[:], result[32:])
			child.Zero()
			clear(result[:])
			if err := checkedContext(ctx); err != nil {
				out.zero()
				return empty, err
			}
			return out, nil
		}
		child.Zero()
		data[0] = 1
		copy(data[1:33], result[32:])
		clear(result[:])
	}
	return empty, ErrDerivation
}
func slip10Path(ctx context.Context, seed []byte, path []uint32) (slip10Node, error) {
	key, err := slip10Master(ctx, seed, hmacSHA512)
	if err != nil {
		return slip10Node{}, err
	}
	for _, index := range path {
		next, err := slip10Child(ctx, key, index, hmacSHA512)
		key.zero()
		if err != nil {
			return slip10Node{}, err
		}
		key = next
	}
	return key, nil
}
