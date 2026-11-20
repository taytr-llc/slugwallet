// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/poolservice"
	"github.com/taytr-llc/slug/poolsettle"
	"github.com/taytr-llc/slug/poolshare"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// SignPoolSettlement is deliberately not a general fixed-key signer. The
// original Store's private, synchronous request capability is mandatory even
// for callers of this lower-level manager API. It neither broadcasts nor
// records spend state; the original Store owns the atomic ledger commit.
func (m *Manager) SignPoolSettlement(ctx context.Context, ns walletdb.ReadBucket, expected PoolSettlementGuard, original *poolsettle.Store, backend poolsettle.Backend, config poolsettle.Config, source poolshare.Config, coins []poolsettle.Coin, unsigned []byte) ([]byte, error) {
	check := func() error {
		return poolsettle.CheckSigningRequest(ctx, original, backend, config, source, coins, unsigned)
	}
	if m == nil || ctx == nil || ns == nil || !m.PoolSettlement() {
		return nil, ErrPoolSettlementProfile
	}
	if wire.TestPoW {
		return nil, ErrPoolSettlementProfile
	}
	if e := check(); e != nil {
		return nil, e
	}
	sourceID, se := poolservice.BindingID(source)
	configID, e := poolsettle.ConfigBindingID(config)
	if e != nil || se != nil || configID != expected.SettlementConfigID || sourceID != expected.SourceBindingID || config.ChangeScript != expected.FundingScript {
		return nil, ErrPoolSettlementConflict
	}
	return m.signPoolSettlement(ctx, ns, expected, config, coins, unsigned, check)
}

// Private codec leaf: only SignPoolSettlement admits a production caller.
func (m *Manager) signPoolSettlement(ctx context.Context, ns walletdb.ReadBucket, expected PoolSettlementGuard, config poolsettle.Config, coins []poolsettle.Coin, unsigned []byte, check func() error) ([]byte, error) {
	var e error
	if len(unsigned) == 0 || len(unsigned) > 100000 || len(coins) == 0 || len(coins) > 256 {
		return nil, ErrPoolSettlementInvalid
	}
	var tx wire.MsgTx
	reader := bytes.NewReader(unsigned)
	if tx.Deserialize(reader) != nil || reader.Len() != 0 || tx.Version != 2 || tx.LockTime != 0 || len(tx.TxIn) != len(coins) || len(tx.TxOut) == 0 || len(tx.TxOut) > 257 {
		return nil, ErrPoolSettlementInvalid
	}
	var canonical bytes.Buffer
	if tx.SerializeNoWitness(&canonical) != nil || !bytes.Equal(canonical.Bytes(), unsigned) {
		return nil, ErrPoolSettlementInvalid
	}
	script, _ := hex.DecodeString(expected.FundingScript)
	prevouts := txscript.NewMultiPrevOutFetcher(nil)
	seen := make(map[wire.OutPoint]bool)
	for i, coin := range coins {
		in := tx.TxIn[i]
		hash, e := chainhash.NewHashFromStr(coin.TxID)
		if e != nil || hash.String() != coin.TxID || coin.Atoms <= 0 || coin.Atoms > 21000000*100000000 || coin.Script != expected.FundingScript || in.PreviousOutPoint != (wire.OutPoint{Hash: *hash, Index: coin.Index}) || in.Sequence != wire.MaxTxInSequenceNum || len(in.SignatureScript) != 0 || len(in.Witness) != 0 || seen[in.PreviousOutPoint] {
			return nil, ErrPoolSettlementInvalid
		}
		seen[in.PreviousOutPoint] = true
		prevouts.AddPrevOut(in.PreviousOutPoint, &wire.TxOut{Value: coin.Atoms, PkScript: script})
	}
	if _, e = poolUnsignedOutputs(&tx, config, coins); e != nil {
		return nil, e
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if e = m.auditPool(ctx, ns, expected); e != nil {
		return nil, e
	}
	if m.IsLocked() {
		return nil, managerError(ErrLocked, "address manager is locked", nil)
	}
	privateCipher, _ := fetchMasterHDKeys(ns)
	plain, e := m.cryptoKeyPriv.Decrypt(privateCipher)
	clear(privateCipher)
	if e != nil {
		return nil, ErrPoolSettlementCorrupt
	}
	root, e := hdkeychain.NewKeyFromString(string(plain))
	clear(plain)
	if e != nil {
		return nil, ErrPoolSettlementCorrupt
	}
	defer root.Zero()
	if e = poolRootMatches(root, expected); e != nil {
		return nil, e
	}
	if e = m.poolPrivateAccounts(ns, root); e != nil {
		return nil, e
	}
	child, e := poolDerive(root)
	if e != nil {
		return nil, e
	}
	defer child.Zero()
	key, e := child.ECPrivKey()
	if e != nil {
		return nil, ErrPoolSettlementCorrupt
	}
	defer key.Zero()
	hashes := txscript.NewTxSigHashes(&tx, prevouts)
	for i, coin := range coins {
		if e = check(); e != nil {
			return nil, e
		}
		tx.TxIn[i].Witness, e = txscript.WitnessSignature(&tx, hashes, i, coin.Atoms, script, txscript.SigHashAll, key, true)
		if e != nil {
			return nil, ErrPoolSettlementCorrupt
		}
	}
	for i, coin := range coins {
		if e = check(); e != nil {
			return nil, e
		}
		engine, e := txscript.NewEngine(script, &tx, i, txscript.StandardVerifyFlags, nil, hashes, coin.Atoms, prevouts)
		if e != nil || engine.Execute() != nil {
			return nil, ErrPoolSettlementCorrupt
		}
	}
	canonical.Reset()
	if tx.SerializeNoWitness(&canonical) != nil || !bytes.Equal(canonical.Bytes(), unsigned) {
		return nil, ErrPoolSettlementCorrupt
	}
	var result bytes.Buffer
	if e = tx.Serialize(&result); e != nil || result.Len() > 100000 {
		return nil, ErrPoolSettlementInvalid
	}
	if e = check(); e != nil {
		return nil, e
	}
	return result.Bytes(), nil
}

// This shape check is defense in depth; only the private active Store request
// establishes exact fee/payment authority. No fee supplied as a DTO is trusted.
func poolUnsignedOutputs(tx *wire.MsgTx, config poolsettle.Config, coins []poolsettle.Coin) (int64, error) {
	if _, e := poolsettle.ConfigBindingID(config); e != nil {
		return 0, ErrPoolSettlementInvalid
	}
	const max = int64(21000000 * 100000000)
	total, out := int64(0), int64(0)
	for _, c := range coins {
		if c.Atoms <= 0 || c.Atoms > max-total {
			return 0, ErrPoolSettlementInvalid
		}
		total += c.Atoms
	}
	allowed := make(map[string]int, len(config.Destinations))
	for i, p := range config.Destinations {
		allowed[p.Script] = i
	}
	last := -1
	payments := 0
	for i, o := range tx.TxOut {
		if o.Value < 294 || o.Value > max-out {
			return 0, ErrPoolSettlementInvalid
		}
		out += o.Value
		script := hex.EncodeToString(o.PkScript)
		if script == config.ChangeScript {
			if i != len(tx.TxOut)-1 {
				return 0, ErrPoolSettlementInvalid
			}
			continue
		}
		index, ok := allowed[script]
		if !ok || index <= last {
			return 0, ErrPoolSettlementInvalid
		}
		last = index
		payments++
	}
	if payments == 0 || out > total {
		return 0, ErrPoolSettlementInvalid
	}
	return total - out, nil
}
func (m *Manager) poolPrivateAccounts(ns walletdb.ReadBucket, root *hdkeychain.ExtendedKey) error {
	scoped, e := fetchReadScopeBucket(ns, &KeyScopeBIP0084)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	purpose, e := root.Derive(84 + hdkeychain.HardenedKeyStart)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer purpose.Zero()
	coin, e := purpose.Derive(hdkeychain.HardenedKeyStart)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer coin.Zero()
	account, e := coin.Derive(hdkeychain.HardenedKeyStart)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer account.Zero()
	raw := scoped.NestedReadBucket(acctBucketName).Get(uint32ToBytes(0))
	n := int(binary.LittleEndian.Uint32(raw[5:9]))
	pos := 9 + n
	privLen := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
	pos += 4
	for _, row := range []struct {
		key       *hdkeychain.ExtendedKey
		priv, pub []byte
	}{{coin, scoped.Get(coinTypePrivKeyName), scoped.Get(coinTypePubKeyName)}, {account, raw[pos : pos+privLen], raw[9 : 9+n]}} {
		plain, e := m.cryptoKeyPriv.Decrypt(row.priv)
		if e != nil {
			return ErrPoolSettlementCorrupt
		}
		match := string(plain) == row.key.String()
		clear(plain)
		if !match {
			return ErrPoolSettlementConflict
		}
		pub, e := row.key.Neuter()
		if e != nil {
			return ErrPoolSettlementCorrupt
		}
		plain, e = m.cryptoKeyPub.Decrypt(row.pub)
		match = e == nil && string(plain) == pub.String()
		pub.Zero()
		clear(plain)
		if !match {
			return ErrPoolSettlementConflict
		}
	}
	return nil
}
