// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package waddrmgr

import (
	"context"
	"encoding/binary"
	"errors"
	"math"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/internal/zero"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var (
	ErrOwnActivityProfile     = errors.New("unsupported own activity profile")
	ErrOwnActivityCorrupt     = errors.New("invalid own activity identity")
	ErrOwnActivityUnavailable = errors.New("own activity manager unavailable")
)

// OwnActivityState contains only bounded public identity and the persisted sync
// stamp from one supplied manager bucket. It carries no signing authority.
type OwnActivityState struct {
	RootPublicKey string
	GymPublicKey  string
	GymID         string
	SyncedHeight  uint32
	SyncedHash    chainhash.Hash
}

// ReadOwnActivityState performs no private-field reads, address enumeration,
// unlock, KDF, migration or network work. The caller owns the read transaction.
func (m *Manager) ReadOwnActivityState(ctx context.Context, ns walletdb.ReadBucket) (OwnActivityState, error) {
	var none OwnActivityState
	if ctx == nil || ns == nil {
		return none, ErrOwnActivityCorrupt
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	if wire.TestPoW {
		return none, ErrOwnActivityProfile
	}
	if m == nil {
		return none, ErrOwnActivityUnavailable
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.closed {
		return none, ErrOwnActivityUnavailable
	}
	if m.derivationMode != DerivationStandard || !m.recoveryEnabled || m.recoveryVersion != 1 || m.resumableRecovery || m.WatchOnly() || m.chainParams == nil || m.chainParams.GenesisHash == nil || uint32(m.chainParams.Net) != recovery.Network || m.chainParams.GenesisHash.String() != recovery.Genesis {
		return none, ErrOwnActivityProfile
	}
	main, sync := ns.NestedReadBucket(mainBucketName), ns.NestedReadBucket(syncBucketName)
	if main == nil || sync == nil {
		return none, ErrOwnActivityCorrupt
	}
	v := main.Get(mgrVersionName)
	if len(v) != 4 {
		return none, ErrOwnActivityCorrupt
	}
	if binary.LittleEndian.Uint32(v) != RecoveryManagerVersion {
		return none, ErrOwnActivityProfile
	}
	mode, version, watch := main.Get(derivationModeName), main.Get(recoveryVersionName), main.Get(watchingOnlyName)
	if len(mode) != 4 || binary.LittleEndian.Uint32(mode) != uint32(DerivationStandard) || len(version) != 4 || binary.LittleEndian.Uint32(version) != 1 || len(watch) != 1 || watch[0] != 0 {
		return none, ErrOwnActivityCorrupt
	}
	public, root := main.Get(recoveryPublicName), main.Get(masterHDPubName)
	if len(public) <= 40 || len(public) > 65576 || len(root) <= 40 || len(root) > 168 {
		return none, ErrOwnActivityCorrupt
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	plain, e := m.cryptoKeyPub.Decrypt(public)
	if e != nil {
		return none, ErrOwnActivityCorrupt
	}
	defer zero.Bytes(plain)
	if len(plain) == 0 || len(plain) > 65536 {
		return none, ErrOwnActivityCorrupt
	}
	manifest, e := recovery.ParseManifest(plain)
	if e != nil {
		return none, ErrOwnActivityCorrupt
	}
	rootPlain, e := m.cryptoKeyPub.Decrypt(root)
	if e != nil {
		return none, ErrOwnActivityCorrupt
	}
	defer zero.Bytes(rootPlain)
	if len(rootPlain) == 0 || len(rootPlain) > 128 || string(rootPlain) != manifest.RootPublicKey {
		return none, ErrOwnActivityCorrupt
	}
	stamp := sync.Get(syncedToName)
	if len(stamp) != 36 && len(stamp) != 40 {
		return none, ErrOwnActivityCorrupt
	}
	height := binary.LittleEndian.Uint32(stamp[:4])
	var hash chainhash.Hash
	copy(hash[:], stamp[4:36])
	if height > math.MaxInt32 || hash == (chainhash.Hash{}) {
		return none, ErrOwnActivityCorrupt
	}
	if e := ctx.Err(); e != nil {
		return none, e
	}
	return OwnActivityState{RootPublicKey: manifest.RootPublicKey, GymPublicKey: manifest.GymPublicKey, GymID: manifest.GymID, SyncedHeight: height, SyncedHash: hash}, nil
}
