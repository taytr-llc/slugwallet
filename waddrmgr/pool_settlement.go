// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func poolDefaultScopes() map[KeyScope]ScopeAddrSchema {
	return map[KeyScope]ScopeAddrSchema{KeyScopeBIP0084: {ExternalAddrType: WitnessPubKey, InternalAddrType: WitnessPubKey}}
}
func poolDerive(root *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
	current := root
	owned := false
	for _, index := range []uint32{84 + hdkeychain.HardenedKeyStart, hdkeychain.HardenedKeyStart, hdkeychain.HardenedKeyStart, 0, 0} {
		next, e := current.Derive(index)
		if owned {
			current.Zero()
		}
		if e != nil {
			return nil, ErrPoolSettlementInvalid
		}
		current = next
		owned = true
	}
	return current, nil
}
func poolRootMatches(root *hdkeychain.ExtendedKey, g PoolSettlementGuard) error {
	if root == nil || !root.IsPrivate() || !root.IsForNet(&chaincfg.MainNetParams) || root.Depth() != 0 {
		return ErrPoolSettlementInvalid
	}
	pub, e := root.Neuter()
	if e != nil {
		return ErrPoolSettlementInvalid
	}
	// Neuter shares the borrowed root's chain code and public-key buffers.
	// Do not Zero this public alias: the caller still owns and needs root.
	if pub.String() != g.RootPublicKey {
		return ErrPoolSettlementConflict
	}
	child, e := poolDerive(root)
	if e != nil {
		return e
	}
	defer child.Zero()
	point, e := child.ECPubKey()
	if e != nil || hex.EncodeToString(point.SerializeCompressed()) != g.FundingPublicKey {
		return ErrPoolSettlementConflict
	}
	return nil
}

// CreateWithPoolSettlement is an exclusive schema16 constructor. The caller's
// one transaction publishes encrypted HD material, exact fixed address and guard.
// It never creates an intermediate legacy/recovery profile.
func CreateWithPoolSettlement(ctx context.Context, ns walletdb.ReadWriteBucket, root *hdkeychain.ExtendedKey, pubPass, privPass []byte, params *chaincfg.Params, config *ScryptOptions, birthday time.Time, expected PoolSettlementGuard) error {
	if ctx == nil || ns == nil || ValidatePoolSettlementGuard(expected) != nil || len(pubPass) > 1024 || len(privPass) == 0 || len(privPass) > 1024 {
		return ErrPoolSettlementInvalid
	}
	if wire.TestPoW || !candidateChain(params) {
		return ErrPoolSettlementProfile
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if k, _ := ns.ReadCursor().First(); k != nil {
		return ErrPoolSettlementConflict
	}
	opts, e := recoveryScryptOptions(config)
	if e != nil {
		return ErrPoolSettlementInvalid
	}
	if e = poolRootMatches(root, expected); e != nil {
		return e
	}
	if e = createManagerPurpose(ns, root, pubPass, privPass, params, &opts, birthday, DerivationStandard, nil, nil, nil, true); e != nil {
		return e
	}
	main := ns.NestedReadWriteBucket(mainBucketName)
	raw, _ := MarshalPoolSettlementGuard(expected)
	if e = main.Put(derivationModeName, uint32ToBytes(uint32(DerivationStandard))); e != nil {
		return e
	}
	if e = main.Put(poolSettlementGuardKey, raw); e != nil {
		return e
	}
	if e = putManagerVersion(ns, PoolSettlementManagerVersion); e != nil {
		return e
	}
	pub, _ := hex.DecodeString(expected.FundingPublicKey)
	if e = putChainedAddress(ns, &KeyScopeBIP0084, address.Hash160(pub), DefaultAccountNum, ssNone, 0, 0, adtChain); e != nil {
		return e
	}
	return ctx.Err()
}

func OpenPoolSettlement(ctx context.Context, ns walletdb.ReadBucket, pubPass []byte, params *chaincfg.Params, expected PoolSettlementGuard) (*Manager, error) {
	if ctx == nil || ns == nil || len(pubPass) > 1024 || ValidatePoolSettlementGuard(expected) != nil {
		return nil, ErrPoolSettlementInvalid
	}
	if wire.TestPoW || !candidateChain(params) {
		return nil, ErrPoolSettlementProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := poolPreflight(ns, expected); e != nil {
		return nil, e
	}
	m, e := loadManagerAllowedProfile(ns, pubPass, params, false, PoolSettlementManagerVersion)
	if e != nil {
		return nil, e
	}
	m.poolGuard = expected
	if e = m.AuditPoolSettlement(ctx, ns, expected); e != nil {
		m.Close()
		return nil, e
	}
	return m, nil
}

// poolBucket checks bounded exact keys and bucket/value kinds before inherited
// deserializers run. Nil expected values denote nested buckets, not wildcards.
func poolBucket(b walletdb.ReadBucket, keys map[string]bool) error {
	if b == nil {
		return ErrPoolSettlementCorrupt
	}
	count := 0
	e := b.ForEach(func(k, v []byte) error {
		count++
		bucket, ok := keys[string(k)]
		if !ok || count > len(keys) || bucket != (v == nil) || len(v) > 4096 {
			return ErrPoolSettlementCorrupt
		}
		return nil
	})
	if e != nil || count != len(keys) {
		return ErrPoolSettlementCorrupt
	}
	return nil
}
func poolKeys(buckets [][]byte, values [][]byte) map[string]bool {
	m := make(map[string]bool)
	for _, k := range buckets {
		m[string(k)] = true
	}
	for _, k := range values {
		m[string(k)] = false
	}
	return m
}
func poolPreflight(ns walletdb.ReadBucket, g PoolSettlementGuard) error {
	if e := poolBucket(ns, poolKeys([][]byte{mainBucketName, syncBucketName, scopeBucketName, scopeSchemaBucketName}, nil)); e != nil {
		return e
	}
	main := ns.NestedReadBucket(mainBucketName)
	if e := poolBucket(main, poolKeys(nil, [][]byte{mgrVersionName, mgrCreateDateName, masterPrivKeyName, masterPubKeyName, cryptoPrivKeyName, cryptoPubKeyName, cryptoScriptKeyName, watchingOnlyName, masterHDPrivName, masterHDPubName, derivationModeName, poolSettlementGuardKey})); e != nil {
		return e
	}
	version, e := fetchManagerVersion(ns)
	if e != nil || version != PoolSettlementManagerVersion {
		return ErrPoolSettlementProfile
	}
	found, e := ParsePoolSettlementGuard(main.Get(poolSettlementGuardKey))
	if e != nil {
		return e
	}
	if found != g {
		return ErrPoolSettlementConflict
	}
	mode := main.Get(derivationModeName)
	if !bytes.Equal(mode, uint32ToBytes(uint32(DerivationStandard))) || len(main.Get(mgrCreateDateName)) != 8 {
		return ErrPoolSettlementCorrupt
	}
	if e = validateRecoveryKeyFields(ns); e != nil {
		return ErrPoolSettlementCorrupt
	}
	sync := ns.NestedReadBucket(syncBucketName)
	// PutSyncedTo also stores the genesis hash under its big-endian height
	// index. This owner never advances that index beyond the initial block.
	var genesisHeight [4]byte
	if e = poolBucket(sync, poolKeys(nil, [][]byte{syncedToName, startBlockName, birthdayName, genesisHeight[:]})); e != nil {
		return e
	}
	if !bytes.Equal(sync.Get(genesisHeight[:]), chaincfg.MainNetParams.GenesisHash[:]) {
		return ErrPoolSettlementCorrupt
	}
	// This owner never synchronizes a generic wallet. Chain evidence comes from
	// the concrete settlement node and original ledger source instead.
	for _, key := range [][]byte{syncedToName, startBlockName} {
		raw := sync.Get(key)
		if binary.LittleEndian.Uint32(raw[:4]) != 0 || !bytes.Equal(raw[4:36], chaincfg.MainNetParams.GenesisHash[:]) {
			return ErrPoolSettlementCorrupt
		}
	}
	scopeKey := scopeToBytes(&KeyScopeBIP0084)
	if e = poolBucket(ns.NestedReadBucket(scopeBucketName), map[string]bool{string(scopeKey[:]): true}); e != nil {
		return e
	}
	schema := ns.NestedReadBucket(scopeSchemaBucketName)
	if e = poolBucket(schema, map[string]bool{string(scopeKey[:]): false}); e != nil {
		return e
	}
	actual, e := fetchScopeAddrSchema(ns, &KeyScopeBIP0084)
	if e != nil || *actual != poolDefaultScopes()[KeyScopeBIP0084] {
		return ErrPoolSettlementCorrupt
	}
	scoped, e := fetchReadScopeBucket(ns, &KeyScopeBIP0084)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	if e = poolBucket(scoped, poolKeys([][]byte{acctBucketName, addrBucketName, usedAddrBucketName, addrAcctIdxBucketName, acctNameIdxBucketName, acctIDIdxBucketName, metaBucketName}, [][]byte{coinTypePrivKeyName, coinTypePubKeyName})); e != nil {
		return e
	}
	for _, key := range [][]byte{coinTypePrivKeyName, coinTypePubKeyName} {
		n := len(scoped.Get(key))
		if n <= 40 || n > 296 {
			return ErrPoolSettlementCorrupt
		}
	}
	accounts := scoped.NestedReadBucket(acctBucketName)
	if e = poolBucket(accounts, map[string]bool{string(uint32ToBytes(0)): false, string(uint32ToBytes(ImportedAddrAccount)): false}); e != nil {
		return e
	}
	for _, id := range []uint32{0, ImportedAddrAccount} {
		raw := accounts.Get(uint32ToBytes(id))
		external, internal, e := currentAccountCursors(raw, id)
		want := uint32(0)
		name := ImportedAddrAccountName
		if id == 0 {
			want = 1
			name = defaultAccountName
		}
		if e != nil || external != want || internal != 0 {
			return ErrPoolSettlementCorrupt
		}
		if id == 0 {
			pubLen := int(binary.LittleEndian.Uint32(raw[5:9]))
			pos := 9 + pubLen
			privLen := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
			if pubLen <= 40 || pubLen > 296 || privLen <= 40 || privLen > 296 {
				return ErrPoolSettlementCorrupt
			}
		}
		row, e := deserializeAccountRow(uint32ToBytes(id), raw)
		if e != nil {
			return ErrPoolSettlementCorrupt
		}
		account, e := deserializeDefaultAccountRow(uint32ToBytes(id), row)
		if e != nil || account.name != name {
			return ErrPoolSettlementCorrupt
		}
	}
	names := scoped.NestedReadBucket(acctNameIdxBucketName)
	ids := scoped.NestedReadBucket(acctIDIdxBucketName)
	if e = poolBucket(names, map[string]bool{string(stringToBytes(defaultAccountName)): false, string(stringToBytes(ImportedAddrAccountName)): false}); e != nil {
		return e
	}
	if e = poolBucket(ids, map[string]bool{string(uint32ToBytes(0)): false, string(uint32ToBytes(ImportedAddrAccount)): false}); e != nil {
		return e
	}
	for _, row := range []struct {
		id   uint32
		name string
	}{{0, defaultAccountName}, {ImportedAddrAccount, ImportedAddrAccountName}} {
		if !bytes.Equal(names.Get(stringToBytes(row.name)), uint32ToBytes(row.id)) || !bytes.Equal(ids.Get(uint32ToBytes(row.id)), stringToBytes(row.name)) {
			return ErrPoolSettlementCorrupt
		}
	}
	meta := scoped.NestedReadBucket(metaBucketName)
	if e = poolBucket(meta, map[string]bool{string(lastAccountName): false}); e != nil || !bytes.Equal(meta.Get(lastAccountName), uint32ToBytes(0)) {
		return ErrPoolSettlementCorrupt
	}
	if e = poolBucket(scoped.NestedReadBucket(usedAddrBucketName), map[string]bool{}); e != nil {
		return e
	}
	script, _ := hex.DecodeString(g.FundingScript)
	hash := sha256.Sum256(script[2:])
	addresses := scoped.NestedReadBucket(addrBucketName)
	if e = poolBucket(addresses, map[string]bool{string(hash[:]): false}); e != nil {
		return e
	}
	row := addresses.Get(hash[:])
	if len(row) != 26 || row[0] != byte(adtChain) || binary.LittleEndian.Uint32(row[1:5]) != 0 || row[13] != byte(ssNone) || binary.LittleEndian.Uint32(row[14:18]) != 8 || binary.LittleEndian.Uint32(row[18:22]) != 0 || binary.LittleEndian.Uint32(row[22:]) != 0 {
		return ErrPoolSettlementCorrupt
	}
	index := scoped.NestedReadBucket(addrAcctIdxBucketName)
	if e = poolBucket(index, map[string]bool{string(hash[:]): false, string(uint32ToBytes(0)): true}); e != nil || !bytes.Equal(index.Get(hash[:]), uint32ToBytes(0)) {
		return ErrPoolSettlementCorrupt
	}
	sub := index.NestedReadBucket(uint32ToBytes(0))
	if e = poolBucket(sub, map[string]bool{string(hash[:]): false}); e != nil || !bytes.Equal(sub.Get(hash[:]), nullVal) {
		return ErrPoolSettlementCorrupt
	}
	return nil
}

// AuditPoolSettlement validates the closed public inventory and original
// expected binding. It does not grant signing or claim canonical funding.
func (m *Manager) AuditPoolSettlement(ctx context.Context, ns walletdb.ReadBucket, expected PoolSettlementGuard) error {
	if ctx == nil || m == nil || !m.PoolSettlement() {
		return ErrPoolSettlementProfile
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.auditPool(ctx, ns, expected)
}
func (m *Manager) auditPool(ctx context.Context, ns walletdb.ReadBucket, g PoolSettlementGuard) error {
	if m.closed || m.poolGuard != g || !m.poolSettlement {
		return ErrPoolSettlementConflict
	}
	if e := poolPreflight(ns, g); e != nil {
		return e
	}
	_, rootCipher := fetchMasterHDKeys(ns)
	plain, e := m.cryptoKeyPub.Decrypt(rootCipher)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	match := string(plain) == g.RootPublicKey
	clear(plain)
	if !match {
		return ErrPoolSettlementConflict
	}
	scoped, e := fetchReadScopeBucket(ns, &KeyScopeBIP0084)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	raw := scoped.NestedReadBucket(acctBucketName).Get(uint32ToBytes(0))
	n := int(binary.LittleEndian.Uint32(raw[5:9]))
	plain, e = m.cryptoKeyPub.Decrypt(raw[9 : 9+n])
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	account, e := hdkeychain.NewKeyFromString(string(plain))
	clear(plain)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer account.Zero()
	if account.IsPrivate() || !account.IsForNet(&chaincfg.MainNetParams) || account.Depth() != 3 || account.ChildIndex() != hdkeychain.HardenedKeyStart {
		return ErrPoolSettlementCorrupt
	}
	branch, e := account.Derive(0)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer branch.Zero()
	child, e := branch.Derive(0)
	if e != nil {
		return ErrPoolSettlementCorrupt
	}
	defer child.Zero()
	pub, e := child.ECPubKey()
	if e != nil || hex.EncodeToString(pub.SerializeCompressed()) != g.FundingPublicKey {
		return ErrPoolSettlementConflict
	}
	return ctx.Err()
}
