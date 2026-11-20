// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/prospectworker"
	"github.com/taytr-llc/slug/wire/v2"
	"strings"
)

func (w *Wallet) hostedAllocationSign2(ctx context.Context, chainContext prospect.Context,
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
	identity, err := w.hostedAllocationGymIdentity2(ctx)
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
	entropy, manifest, err := w.hostedAllocationMaterial2(ctx)
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
func (w *Wallet) hostedAllocationProspectSigner2(ctx context.Context, policy prospectnode.Policy) (prospectworker.Signer, error) {
	identity, err := w.hostedAllocationGymIdentity2(ctx)
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
		authorization, err := w.hostedAllocationSign2(ctx, chainContext, proof)
		if err != nil {
			return gymauth.Authorization{}, err
		}
		if authorization.PublicKey != identity.PublicKey {
			return gymauth.Authorization{}, errors.New("wallet signer identity changed")
		}
		return authorization, nil
	}, nil
}
