// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/prospectworker"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

// GymIdentity contains only public information. The recovery profile owns the
// fixed derivation; callers cannot select an account, path, or replacement key.
type GymIdentity struct {
	Version   uint32 `json:"version"`
	Profile   string `json:"profile"`
	Network   uint32 `json:"network"`
	Genesis   string `json:"genesis"`
	PublicKey string `json:"public_key"`
	GymID     string `json:"gym_id"`
}

// GymIdentity reads the public identity of a recovery-enabled wallet, including
// while it is locked. Legacy wallets do not acquire an implicit gym key.
func (w *Wallet) GymIdentity(ctx context.Context) (GymIdentity, error) {
	if err := ctx.Err(); err != nil {
		return GymIdentity{}, err
	}
	if wire.TestPoW {
		return GymIdentity{}, errors.New("gym wallet identity requires production PoW profile")
	}
	manifest, err := w.recoveryPublicManifest()
	if err != nil {
		return GymIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return GymIdentity{}, err
	}
	return GymIdentity{
		Version: gymauth.Version1, Profile: manifest.Profile,
		Network: manifest.Network, Genesis: manifest.Genesis,
		PublicKey: manifest.GymPublicKey, GymID: manifest.GymID,
	}, nil
}

// deriveRecoveryGymKey returns one owned private-key copy for the fixed fixture
// path. All intermediate seed/extended keys are cleared; no arbitrary path is
// accepted and no key is returned by the public signing API.
func deriveRecoveryGymKey(entropy [32]byte, params *chaincfg.Params) (*btcec.PrivateKey, error) {
	defer clear(entropy[:])
	seed := recovery.SeedFromEntropy(entropy)
	defer clear(seed[:])
	key, err := hdkeychain.NewMaster(seed[:], params)
	if err != nil {
		return nil, errors.New("cannot derive recovery gym identity")
	}
	defer func() { key.Zero() }()
	for _, index := range recovery.GymPathIndices() {
		next, err := key.Derive(index)
		if err != nil {
			return nil, errors.New("cannot derive recovery gym identity")
		}
		key.Zero()
		key = next
	}
	return key.ECPrivKey()
}

// SignProspectAdmission authorizes only a version-2 prospect admission by this
// wallet's enrolled gym. It validates bounded action bytes and chain/gym binding;
// it is not a proof-of-work, issuance, freshness, or canonicality certificate.
// The trusted worker/node/authority perform those checks separately. The
// private lease contains no Argon hashing, RPC, file export, or user interaction.
func (w *Wallet) SignProspectAdmission(ctx context.Context, chainContext prospect.Context,
	proof prospect.Proof) (gymauth.Authorization, error) {

	var empty gymauth.Authorization
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if wire.TestPoW || proof.Version != prospect.Version2 {
		return empty, errors.New("unsupported wallet admission signing profile")
	}
	// Own the only mutable proof field before preflight or waiting for an
	// unlock lease. The protocol bound precedes allocation.
	if len(proof.MerkleBranch) > 20 {
		return empty, errors.New("invalid wallet admission request")
	}
	proof.MerkleBranch = append([]string(nil), proof.MerkleBranch...)
	identity, err := w.GymIdentity(ctx)
	if err != nil {
		return empty, err
	}
	if chainContext.Network != identity.Network ||
		!strings.EqualFold(chainContext.Genesis, identity.Genesis) {
		return empty, errors.New("admission chain does not match wallet")
	}
	if _, err := gymauth.AdmissionDigest(chainContext, proof, identity.PublicKey); err != nil {
		return empty, errors.New("invalid wallet admission request")
	}

	lease, err := w.holdUnlockContext(ctx)
	if err != nil {
		return empty, err
	}
	defer lease.release()
	entropy, manifest, err := w.recoveryMaterial()
	defer clear(entropy[:])
	if err != nil {
		return empty, err
	}
	if manifest.GymPublicKey != identity.PublicKey || manifest.GymID != identity.GymID ||
		manifest.Profile != identity.Profile {
		return empty, errors.New("wallet gym identity changed")
	}
	if err := lease.err(ctx); err != nil {
		return empty, err
	}
	key, err := deriveRecoveryGymKey(entropy, w.chainParams)
	if err != nil {
		return empty, err
	}
	defer key.Zero()
	if hex.EncodeToString(key.PubKey().SerializeCompressed()) != identity.PublicKey {
		return empty, errors.New("wallet gym key does not match enrolled identity")
	}
	authorization, err := gymauth.SignAdmission(chainContext, proof, key)
	if err != nil {
		return empty, errors.New("cannot authorize wallet admission")
	}
	if err := lease.err(ctx); err != nil {
		return empty, err
	}
	return authorization, nil
}

// ProspectSigner binds the worker callback to a separately trusted operator
// policy and this wallet's current public gym identity. A policy change requires
// a new adapter; request context cannot replace the pinned target or DNA policy.
func (w *Wallet) ProspectSigner(ctx context.Context, policy prospectnode.Policy) (prospectworker.Signer, error) {
	identity, err := w.GymIdentity(ctx)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.New("invalid wallet signer policy")
	}
	policy, err = prospectnode.ParsePolicy(encoded)
	if err != nil || policy.Network != identity.Network || policy.Genesis != identity.Genesis {
		return nil, errors.New("invalid wallet signer policy")
	}
	return func(ctx context.Context, chainContext prospect.Context, proof prospect.Proof) (gymauth.Authorization, error) {
		if err := ctx.Err(); err != nil {
			return gymauth.Authorization{}, err
		}
		if chainContext.Network != policy.Network || chainContext.DNAVersion != policy.DNAVersion ||
			!strings.EqualFold(chainContext.Genesis, policy.Genesis) ||
			!strings.EqualFold(chainContext.ProspectTarget, policy.ProspectTarget) ||
			!strings.EqualFold(proof.GymID, identity.GymID) {
			return gymauth.Authorization{}, errors.New("admission does not match pinned wallet signer policy")
		}
		authorization, err := w.SignProspectAdmission(ctx, chainContext, proof)
		if err != nil {
			return gymauth.Authorization{}, err
		}
		if authorization.PublicKey != identity.PublicKey {
			return gymauth.Authorization{}, errors.New("wallet signer identity changed")
		}
		return authorization, nil
	}, nil
}
