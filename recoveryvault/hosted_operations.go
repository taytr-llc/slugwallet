// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slugwallet/recovery"
)

func (h *HostedVault) fence(ctx context.Context, token string, cap gymaccount.Capability, provision bool, epoch EpochFence, expected *gymaccount.Account, fn func(gymaccount.Account, gymaccount.Identity, func() error) error) error {
	if epoch == nil {
		return ErrConflict
	}
	action := func(a gymaccount.Account, id gymaccount.Identity, check func() error) error {
		if expected != nil && !sameAuthority(a, *expected) {
			return ErrConflict
		}
		return runEpoch(ctx, epoch, check, func(guard func() error) error { return fn(a, id, guard) })
	}
	if provision {
		return h.core.accounts.WithProvisioning(ctx, token, action)
	}
	return h.core.accounts.WithSession(ctx, token, cap, func(a gymaccount.Account, check func() error) error { return action(a, gymaccount.Identity{}, check) })
}
func (h *HostedVault) snapshot(ctx context.Context, token string, cap gymaccount.Capability, epoch EpochFence) (gymaccount.Account, vaultRecord, error) {
	var a gymaccount.Account
	err := h.fence(ctx, token, cap, false, epoch, nil, func(current gymaccount.Account, _ gymaccount.Identity, check func() error) error {
		a = current
		return check()
	})
	if err != nil {
		return gymaccount.Account{}, vaultRecord{}, err
	}
	r, err := h.record(a.ID)
	if err != nil {
		return gymaccount.Account{}, vaultRecord{}, err
	}
	if !bindingMatchesAccount(r.Binding, a) {
		return gymaccount.Account{}, vaultRecord{}, ErrConflict
	}
	return a, r, nil
}
func (h *HostedVault) disclose(ctx context.Context, token string, cap gymaccount.Capability, epoch EpochFence, a gymaccount.Account, r vaultRecord) error {
	return h.fence(ctx, token, cap, false, epoch, &a, func(current gymaccount.Account, _ gymaccount.Identity, check func() error) error {
		retained, ok := h.records[a.ID]
		if !ok || retained.Revision != r.Revision || retained.Binding != r.Binding || !bindingMatchesAccount(r.Binding, current) {
			return ErrConflict
		}
		return check()
	})
}
func (h *HostedVault) publish(ctx context.Context, token string, cap gymaccount.Capability, provision bool, epoch EpochFence, a gymaccount.Account, old, next vaultRecord) error {
	meta := h.core.meta
	if old.Revision == 0 || next.Revision != old.Revision+1 || next.Binding != old.Binding {
		return ErrConflict
	}
	before, after := remaining(old), remaining(next)
	if before < after || meta.Reserved < before-after {
		return ErrCorrupt
	}
	meta.Operations++
	meta.Reserved -= before - after
	if uint64(meta.Operations)+uint64(meta.Reserved) > uint64(h.core.config.MaxOperations) {
		return ErrCapacity
	}
	batch, err := h.stage(next, meta)
	if err != nil {
		return err
	}
	attempted := false
	err = h.fence(ctx, token, cap, provision, epoch, &a, func(current gymaccount.Account, id gymaccount.Identity, check func() error) error {
		retained, ok := h.records[a.ID]
		if !ok || retained.Revision != old.Revision || retained.Binding != old.Binding || !bindingMatchesAccount(next.Binding, current) || provision && id != identityForBinding(next.Binding) {
			return ErrConflict
		}
		if e := check(); e != nil {
			return e
		}
		attempted = true
		return h.commit(ctx, batch, next, meta)
	})
	if err != nil && attempted {
		h.core.poisoned = true
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return err
}
func (h *HostedVault) reserve(ctx context.Context, token string, epoch EpochFence) (gymaccount.Account, vaultRecord, bool, error) {
	var a gymaccount.Account
	var id gymaccount.Identity
	err := h.fence(ctx, token, gymaccount.Enrollment, true, epoch, nil, func(current gymaccount.Account, identity gymaccount.Identity, check func() error) error {
		a = current
		id = identity
		return check()
	})
	if err != nil {
		return a, vaultRecord{}, false, err
	}
	if r, e := h.record(a.ID); e == nil {
		if !bindingMatchesAccount(r.Binding, a) || identityForBinding(r.Binding) != id {
			return a, vaultRecord{}, false, ErrConflict
		}
		return a, r, false, nil
	} else if !errors.Is(e, ErrNotFound) {
		return a, vaultRecord{}, false, e
	}
	meta := h.core.meta
	if len(meta.Accounts) >= 2 || uint64(meta.Operations)+uint64(meta.Reserved)+4 > uint64(h.core.config.MaxOperations) {
		return a, vaultRecord{}, false, ErrCapacity
	}
	var random [32]byte
	if _, err = io.ReadFull(h.core.random, random[:]); err != nil {
		return a, vaultRecord{}, false, ErrEnvelope
	}
	provisionID := hex.EncodeToString(random[:])
	if !nonzeroID(provisionID) {
		return a, vaultRecord{}, false, ErrEnvelope
	}
	for _, r := range h.records {
		if r.Binding.ProvisionID == provisionID || r.Binding.GymID == id.GymID || r.Binding.RootPublicKey == id.RootPublicKey {
			return a, vaultRecord{}, false, ErrConflict
		}
	}
	binding := Binding{Version1, h.core.authority.AuthorityID, a.ID, a.PrincipalID, provisionID, id.Network, id.Genesis, id.Profile, id.RootPublicKey, id.GymPublicKey, id.GymID}
	manifest := recovery.Manifest{Version: recovery.Version1, Profile: id.Profile, Network: id.Network, Genesis: id.Genesis, Derivation: recovery.DerivationStandard, RootPublicKey: id.RootPublicKey, GymPath: recovery.GymPath, GymPublicKey: id.GymPublicKey, GymID: id.GymID, Accounts: recovery.DefaultAccounts()}
	hash, err := manifestDigest(manifest)
	if err != nil {
		return a, vaultRecord{}, false, err
	}
	r := vaultRecord{Binding: binding, Manifest: manifest, ManifestHash: hash, State: "reserved", Revision: 1}
	meta.Accounts = append(append([]reservationIndex(nil), meta.Accounts...), reservationIndex{a.ID, a.PrincipalID, provisionID})
	meta.Operations++
	meta.Reserved += 3
	batch, err := h.stage(r, meta)
	if err != nil {
		return a, vaultRecord{}, false, err
	}
	attempted := false
	err = h.fence(ctx, token, gymaccount.Enrollment, true, epoch, &a, func(current gymaccount.Account, identity gymaccount.Identity, check func() error) error {
		if identity != id || !bindingMatchesAccount(binding, current) {
			return ErrConflict
		}
		if _, ok := h.records[a.ID]; ok {
			return ErrConflict
		}
		if e := check(); e != nil {
			return e
		}
		attempted = true
		return h.commit(ctx, batch, r, meta)
	})
	if err != nil && attempted {
		h.core.poisoned = true
		err = errors.Join(ErrOutcomeUnknown, err)
	}
	if err != nil {
		return a, vaultRecord{}, false, err
	}
	return a, cloneRecord(r), true, nil
}

func (h *HostedVault) ProvisionFixture(ctx context.Context, token string, epoch EpochFence) (Receipt, bool, error) {
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return Receipt{}, false, err
	}
	defer done()
	a, r, changed, err := h.reserve(ctx, token, epoch)
	if err != nil {
		return Receipt{}, false, err
	}
	if r.State == "reserved" {
		manifest, recoveryRaw, gymRaw, e := materialPayloads(identityForBinding(r.Binding))
		defer clear(recoveryRaw)
		defer clear(gymRaw)
		if e != nil || !reflect.DeepEqual(manifest, r.Manifest) {
			return Receipt{}, false, ErrEnvelope
		}
		re, e := sealEnvelope(ctx, h.core.wrapper, r.Binding, RecoveryPurpose, 1, r.ManifestHash, recoveryRaw, h.core.config.RecoveryKeyRef, h.core.random)
		if e != nil {
			return Receipt{}, false, e
		}
		ge, e := sealEnvelope(ctx, h.core.wrapper, r.Binding, GymPurpose, 1, r.ManifestHash, gymRaw, h.core.config.GymKeyRef, h.core.random)
		if e != nil {
			return Receipt{}, false, e
		}
		next := cloneRecord(r)
		next.State = "sealed"
		next.Revision++
		next.Recovery = &re
		next.Gym = &ge
		if e = h.publish(ctx, token, gymaccount.Enrollment, true, epoch, a, r, next); e != nil {
			return Receipt{}, false, e
		}
		r = next
		changed = true
	}
	if r.State == "sealed" {
		// Reauthorize before any recovery-purpose unwrap after interrupted setup.
		err = h.fence(ctx, token, gymaccount.Enrollment, true, epoch, &a, func(_ gymaccount.Account, id gymaccount.Identity, check func() error) error {
			if id != identityForBinding(r.Binding) {
				return ErrConflict
			}
			return check()
		})
		if err != nil {
			return Receipt{}, false, err
		}
		rp, e := openEnvelope(ctx, h.core.wrapper, *r.Recovery)
		if e != nil {
			return Receipt{}, false, e
		}
		defer clear(rp)
		entropy, e := decodeRecovery(rp, r)
		defer clear(entropy[:])
		if e != nil {
			return Receipt{}, false, e
		}
		gp, e := openEnvelope(ctx, h.core.wrapper, *r.Gym)
		if e != nil {
			return Receipt{}, false, e
		}
		defer clear(gp)
		key, e := decodeGym(gp, r.Binding)
		if e != nil {
			return Receipt{}, false, e
		}
		key.Zero()
		next := cloneRecord(r)
		next.State = "verified"
		next.Revision++
		receipt := retentionReceipt(next)
		next.Receipt = &receipt
		if e = h.publish(ctx, token, gymaccount.Enrollment, true, epoch, a, r, next); e != nil {
			return Receipt{}, false, e
		}
		r = next
		changed = true
	}
	if r.Receipt == nil {
		return Receipt{}, false, ErrCorrupt
	}
	if err = h.disclose(ctx, token, gymaccount.Enrollment, epoch, a, r); err != nil {
		return Receipt{}, false, err
	}
	return cloneReceipt(*r.Receipt), changed, nil
}

func (h *HostedVault) SignAccountChallenge(ctx context.Context, token string, challenge gymaccount.EnrollmentChallenge, epoch EpochFence) (gymaccount.Authorization, error) {
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	defer done()
	if _, err = gymaccount.ChallengeDigest(challenge); err != nil {
		return gymaccount.Authorization{}, ErrEnvelope
	}
	a, r, err := h.snapshot(ctx, token, gymaccount.Enrollment, epoch)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	if r.Receipt == nil || challenge.AuthorityID != h.core.authority.AuthorityID || challenge.AccountID != a.ID || challenge.PrincipalID != a.PrincipalID || challenge.Generation != a.Generation || challenge.Network != r.Binding.Network || challenge.Genesis != r.Binding.Genesis || challenge.Profile != r.Binding.Profile || challenge.RootPublicKey != r.Binding.RootPublicKey || challenge.GymPublicKey != r.Binding.GymPublicKey || challenge.GymID != r.Binding.GymID {
		return gymaccount.Authorization{}, ErrConflict
	}
	if challenge.Action == "enroll" && a.Enrollment != nil || challenge.Action == "recover" && (a.Enrollment == nil || !a.RecoveryRequired) {
		return gymaccount.Authorization{}, ErrConflict
	}
	raw, err := openEnvelope(ctx, h.core.wrapper, *r.Gym)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	defer clear(raw)
	key, err := decodeGym(raw, r.Binding)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	defer key.Zero()
	auth, err := gymaccount.SignChallenge(challenge, key)
	if err != nil {
		return gymaccount.Authorization{}, ErrEnvelope
	}
	if err = h.disclose(ctx, token, gymaccount.Enrollment, epoch, a, r); err != nil {
		return gymaccount.Authorization{}, err
	}
	return auth, nil
}

// EnsureEnrollment acknowledges only an already-completed exact challenge.
// It never begins a challenge and never unwraps either envelope.
func (h *HostedVault) EnsureEnrollment(ctx context.Context, token string, epoch EpochFence) (Receipt, error) {
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer done()
	a, r, err := h.snapshot(ctx, token, gymaccount.Enrollment, epoch)
	if err != nil {
		return Receipt{}, err
	}
	if r.Receipt == nil || a.Enrollment == nil || *a.Enrollment != identityForBinding(r.Binding) || a.RecoveryRequired {
		return Receipt{}, ErrConflict
	}
	if r.State == "verified" {
		next := cloneRecord(r)
		next.State = "enrolled"
		next.Revision++
		if err = h.publish(ctx, token, gymaccount.Enrollment, false, epoch, a, r, next); err != nil {
			return Receipt{}, err
		}
		r = next
	} else if r.State != "enrolled" {
		return Receipt{}, ErrConflict
	}
	if err = h.disclose(ctx, token, gymaccount.Enrollment, epoch, a, r); err != nil {
		return Receipt{}, err
	}
	return cloneReceipt(*r.Receipt), nil
}
func (h *HostedVault) SignAdmission(ctx context.Context, token string, chainContext prospect.Context, proof prospect.Proof, epoch EpochFence) (gymauth.Authorization, error) {
	if len(proof.MerkleBranch) > 20 {
		return gymauth.Authorization{}, ErrEnvelope
	}
	proof.MerkleBranch = append([]string(nil), proof.MerkleBranch...)
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	defer done()
	p := h.core.config.Policy
	if proof.Version != prospect.Version2 || chainContext.Network != p.Network || chainContext.DNAVersion != p.DNAVersion || !strings.EqualFold(chainContext.Genesis, p.Genesis) || !strings.EqualFold(chainContext.ProspectTarget, p.ProspectTarget) {
		return gymauth.Authorization{}, ErrConflict
	}
	a, r, err := h.snapshot(ctx, token, gymaccount.Mining, epoch)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	if r.State != "enrolled" || !strings.EqualFold(proof.GymID, r.Binding.GymID) {
		return gymauth.Authorization{}, ErrConflict
	}
	if _, err = gymauth.AdmissionDigest(chainContext, proof, r.Binding.GymPublicKey); err != nil {
		return gymauth.Authorization{}, ErrEnvelope
	}
	raw, err := openEnvelope(ctx, h.core.wrapper, *r.Gym)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	defer clear(raw)
	key, err := decodeGym(raw, r.Binding)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	defer key.Zero()
	auth, err := gymauth.SignAdmission(chainContext, proof, key)
	if err != nil {
		return gymauth.Authorization{}, ErrEnvelope
	}
	if err = h.disclose(ctx, token, gymaccount.Mining, epoch, a, r); err != nil {
		return gymauth.Authorization{}, err
	}
	return auth, nil
}
func (h *HostedVault) Status(ctx context.Context, token string, epoch EpochFence) (Status, error) {
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return Status{}, err
	}
	defer done()
	a, r, err := h.snapshot(ctx, token, gymaccount.View, epoch)
	if err != nil {
		return Status{}, err
	}
	result := Status{Version: Version1, Binding: r.Binding, State: r.State, Revision: r.Revision, Receipt: r.Receipt}
	if r.Recovery != nil {
		result.RecoveryKeyRef = r.Recovery.KeyRef
		result.RecoveryWrapRevision = r.Recovery.WrapRevision
	}
	if r.Gym != nil {
		result.GymKeyRef = r.Gym.KeyRef
		result.GymWrapRevision = r.Gym.WrapRevision
	}
	if err = h.disclose(ctx, token, gymaccount.View, epoch, a, r); err != nil {
		return Status{}, err
	}
	return result, nil
}
