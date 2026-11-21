// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"context"
	"encoding/hex"

	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/pooltxshape"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// SignDailyPoolSettlement admits only the original active Config2 Store request.
// Neither a parsed binding nor a caller-supplied check can authorize this path.
func (m *Manager) SignDailyPoolSettlement(ctx context.Context, ns walletdb.ReadBucket, expected PoolSettlementGuard, original *poolsettle.Store, backend poolsettle.Backend, config poolsettle.Config, source poolshare.Config, coins []poolsettle.Coin, unsigned []byte) ([]byte, error) {
	if m == nil || ctx == nil || ns == nil || !m.PoolSettlement() || wire.TestPoW {
		return nil, ErrPoolSettlementProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	sourceID, se := poolshare.DailyConfigID(source)
	configID, e := poolsettle.DailyConfigBindingID(config)
	if e != nil || se != nil || ValidatePoolSettlementGuard(expected) != nil || sourceID != expected.SourceBindingID || configID != expected.SettlementConfigID || config.ChangeScript != expected.FundingScript {
		return nil, ErrPoolSettlementConflict
	}
	// Keep destination slice and every coin/claim/raw slice private during signing.
	config.Destinations = append([]poolsettle.Destination(nil), config.Destinations...)
	coins, unsigned, e = poolDailyOwnedInputs(ctx, coins, unsigned)
	if e != nil {
		return nil, e
	}
	captured, e := poolsettle.CaptureDailySigningCheck(ctx, original, backend, config, source, coins, unsigned)
	if e != nil {
		return nil, e
	}
	signed, e := m.signPoolSettlementProfile(ctx, ns, expected, config, coins, unsigned, func() error { return captured.Check(ctx) }, true)
	if e != nil {
		return nil, e
	}
	if e = captured.Recheck(ctx, coins, unsigned); e != nil {
		clear(signed)
		return nil, e
	}
	return signed, nil
}

// The bounded copy grants no authority; the original capability must still
// exactly match every input and complete unsigned body before key access.
func poolDailyOwnedInputs(ctx context.Context, coins []poolsettle.Coin, unsigned []byte) ([]poolsettle.Coin, []byte, error) {
	if ctx == nil || len(coins) == 0 || len(coins) > pooltxshape.MaxNativeInputs || len(unsigned) == 0 || len(unsigned) > pooltxshape.MaxStandardWeight {
		return nil, nil, ErrPoolSettlementInvalid
	}
	const maxClaims = 32768
	// Input-only bound: 32768*9KiB claims +1464*512 coin overhead +raw400000.
	// Strings are immutable and shared; only the slice/struct layers are copied.
	const maxBytes = 320 << 20
	claims, total := 0, len(unsigned)
	for _, c := range coins {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		if len(c.TxID) != 64 || len(c.Script) != 44 || len(c.BlockHash) != 0 && len(c.BlockHash) != 64 || len(c.Claims) == 0 || len(c.Claims) > 256*257 || len(c.Claims) > maxClaims-claims {
			return nil, nil, ErrPoolSettlementInvalid
		}
		claims += len(c.Claims)
		total += len(c.TxID) + len(c.Script) + len(c.BlockHash) + 128
		for _, claim := range c.Claims {
			if len(claim.RoundHash) != 64 || len(claim.GymID) != 0 && len(claim.GymID) != 64 || len(claim.Amount.Numerator) == 0 || len(claim.Amount.Numerator) > 4096 || len(claim.Amount.Denominator) == 0 || len(claim.Amount.Denominator) > 4096 {
				return nil, nil, ErrPoolSettlementInvalid
			}
			n := len(claim.RoundHash) + len(claim.GymID) + len(claim.Amount.Numerator) + len(claim.Amount.Denominator) + 256
			if n > maxBytes-total {
				return nil, nil, ErrPoolSettlementInvalid
			}
			total += n
		}
	}
	out := make([]poolsettle.Coin, len(coins))
	for i, c := range coins {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		out[i] = c
		out[i].Claims = append([]poolsettle.Claim(nil), c.Claims...)
	}
	raw := append([]byte(nil), unsigned...)
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	return out, raw, nil
}

func poolDailySigningShape(tx *wire.MsgTx, config poolsettle.Config, rawBytes int, signed bool) error {
	change := len(tx.TxOut) > 0 && hex.EncodeToString(tx.TxOut[len(tx.TxOut)-1].PkScript) == config.ChangeScript
	payees := len(tx.TxOut)
	if change {
		payees--
	}
	shape, e := pooltxshape.NativeP2WPKH(len(tx.TxIn), payees, change)
	if e != nil || int64(tx.SerializeSizeStripped()) != shape.StrippedBytes {
		return ErrPoolSettlementInvalid
	}
	if !signed {
		if int64(rawBytes) != shape.StrippedBytes {
			return ErrPoolSettlementInvalid
		}
		return nil
	}
	if int64(rawBytes) > shape.RawBytes || rawBytes > pooltxshape.MaxStandardWeight || 3*shape.StrippedBytes+int64(rawBytes) > pooltxshape.MaxStandardWeight {
		return ErrPoolSettlementInvalid
	}
	return nil
}
