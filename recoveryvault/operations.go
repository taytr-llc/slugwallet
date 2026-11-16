// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slugwallet/recovery"
)

func bindingMatchesAccount(b Binding, a gymaccount.Account) bool {
	return b.AccountID == a.ID && b.PrincipalID == a.PrincipalID && (a.Enrollment == nil || *a.Enrollment == identityForBinding(b))
}
func sameAuthority(a, b gymaccount.Account) bool {
	return a.ID == b.ID && a.PrincipalID == b.PrincipalID && a.Generation == b.Generation
}
func (v *Vault) snapshot(ctx context.Context, token string, cap gymaccount.Capability) (gymaccount.Account, vaultRecord, error) {
	var account gymaccount.Account
	var r vaultRecord
	err := v.accounts.WithSession(ctx, token, cap, func(a gymaccount.Account, check func() error) error {
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		record, err := v.record(a.ID)
		if err != nil {
			return err
		}
		if !bindingMatchesAccount(record.Binding, a) {
			return ErrConflict
		}
		if err = check(); err != nil {
			return err
		}
		account = a
		r = cloneRecord(record)
		return nil
	})
	return account, r, err
}
func (v *Vault) publish(ctx context.Context, token string, cap gymaccount.Capability, account gymaccount.Account, old, nextRecord vaultRecord, provision bool) error {
	action := func(a gymaccount.Account, check func() error) error {
		if !sameAuthority(a, account) || !bindingMatchesAccount(nextRecord.Binding, a) {
			return ErrConflict
		}
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		current, err := v.record(a.ID)
		if err != nil {
			return err
		}
		if current.Revision != old.Revision || current.Binding != old.Binding {
			return ErrConflict
		}
		next := v.meta
		before, after := remaining(old), remaining(nextRecord)
		if before < after || next.Reserved < before-after {
			return ErrCorrupt
		}
		next.Reserved -= before - after
		if uint64(next.Operations)+uint64(next.Reserved)+1 > uint64(v.config.MaxOperations) {
			return ErrCapacity
		}
		if nextRecord.Revision != old.Revision+1 || v.validateRecord(nextRecord) != nil {
			return ErrCorrupt
		}
		next.Operations++
		if err = check(); err != nil {
			return err
		}
		return v.commit(ctx, nextRecord, next)
	}
	if provision {
		return v.accounts.WithProvisioning(ctx, token, func(a gymaccount.Account, i gymaccount.Identity, check func() error) error {
			if i != identityForBinding(nextRecord.Binding) {
				return ErrConflict
			}
			return action(a, check)
		})
	}
	return v.accounts.WithSession(ctx, token, cap, action)
}
func (v *Vault) reserve(ctx context.Context, token string) (gymaccount.Account, vaultRecord, bool, error) {
	var account gymaccount.Account
	var result vaultRecord
	created := false
	err := v.accounts.WithProvisioning(ctx, token, func(a gymaccount.Account, identity gymaccount.Identity, check func() error) error {
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		r, err := v.record(a.ID)
		if err == nil {
			if !bindingMatchesAccount(r.Binding, a) || identityForBinding(r.Binding) != identity {
				return ErrConflict
			}
			account = a
			result = cloneRecord(r)
			return check()
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if len(v.meta.Accounts) >= 2 || uint64(v.meta.Operations)+uint64(v.meta.Reserved)+4 > uint64(v.config.MaxOperations) {
			return ErrCapacity
		}
		for _, idx := range v.meta.Accounts {
			other, e := v.record(idx.AccountID)
			if e != nil {
				return e
			}
			if other.Binding.GymID == identity.GymID || other.Binding.RootPublicKey == identity.RootPublicKey {
				return ErrConflict
			}
		}
		var id [32]byte
		if _, err = io.ReadFull(v.random, id[:]); err != nil {
			return ErrEnvelope
		}
		provisionID := hex.EncodeToString(id[:])
		for _, idx := range v.meta.Accounts {
			if idx.ProvisionID == provisionID {
				return ErrConflict
			}
		}
		b := Binding{Version: Version1, AuthorityID: v.authority.AuthorityID, AccountID: a.ID, PrincipalID: a.PrincipalID, ProvisionID: provisionID, Network: identity.Network, Genesis: identity.Genesis, Profile: identity.Profile, RootPublicKey: identity.RootPublicKey, GymPublicKey: identity.GymPublicKey, GymID: identity.GymID}
		m := recovery.Manifest{Version: recovery.Version1, Profile: identity.Profile, Network: identity.Network, Genesis: identity.Genesis, Derivation: recovery.DerivationStandard, RootPublicKey: identity.RootPublicKey, GymPath: recovery.GymPath, GymPublicKey: identity.GymPublicKey, GymID: identity.GymID, Accounts: recovery.DefaultAccounts()}
		hash, err := manifestDigest(m)
		if err != nil {
			return err
		}
		r = vaultRecord{Binding: b, Manifest: m, ManifestHash: hash, State: "reserved", Revision: 1}
		if v.validateRecord(r) != nil {
			return ErrCorrupt
		}
		next := v.meta
		next.Accounts = append(append([]reservationIndex(nil), next.Accounts...), reservationIndex{AccountID: a.ID, PrincipalID: a.PrincipalID, ProvisionID: provisionID})
		next.Operations++
		next.Reserved += 3
		if err = check(); err != nil {
			return err
		}
		if err = v.commit(ctx, r, next); err != nil {
			return err
		}
		account = a
		result = cloneRecord(r)
		created = true
		return nil
	})
	return account, result, created, err
}

// ProvisionFixture retains only the account authority's configured public
// fixture and the immutable initial manifest. It never accepts caller entropy,
// replacement identity, arbitrary profile, or cursor updates.
func (v *Vault) ProvisionFixture(ctx context.Context, token string) (Receipt, bool, error) {
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return Receipt{}, false, err
	}
	defer done()
	account, r, changed, err := v.reserve(ctx, token)
	if err != nil {
		return Receipt{}, false, err
	}
	if r.State == "reserved" {
		manifest, recoveryPayload, gymPayload, err := materialPayloads(identityForBinding(r.Binding))
		defer clear(recoveryPayload)
		defer clear(gymPayload)
		if err != nil || !reflect.DeepEqual(manifest, r.Manifest) {
			return Receipt{}, false, ErrEnvelope
		}
		recoveryEnvelope, err := sealEnvelope(ctx, v.wrapper, r.Binding, RecoveryPurpose, 1, r.ManifestHash, recoveryPayload, v.config.RecoveryKeyRef, v.random)
		if err != nil {
			return Receipt{}, false, err
		}
		gymEnvelope, err := sealEnvelope(ctx, v.wrapper, r.Binding, GymPurpose, 1, r.ManifestHash, gymPayload, v.config.GymKeyRef, v.random)
		if err != nil {
			return Receipt{}, false, err
		}
		next := cloneRecord(r)
		next.State = "sealed"
		next.Revision++
		next.Recovery = &recoveryEnvelope
		next.Gym = &gymEnvelope
		if err = v.publish(ctx, token, gymaccount.Enrollment, account, r, next, true); err != nil {
			return Receipt{}, false, err
		}
		r = next
		changed = true
	}
	if r.State == "sealed" {
		a, identity, err := v.accounts.ProvisioningIdentity(ctx, token)
		if err != nil {
			return Receipt{}, false, err
		}
		if !sameAuthority(a, account) || identity != identityForBinding(r.Binding) {
			return Receipt{}, false, ErrConflict
		}
		recoveryPayload, err := openEnvelope(ctx, v.wrapper, *r.Recovery)
		if err != nil {
			return Receipt{}, false, err
		}
		defer clear(recoveryPayload)
		entropy, err := decodeRecovery(recoveryPayload, r)
		defer clear(entropy[:])
		if err != nil {
			return Receipt{}, false, err
		}
		gymPayload, err := openEnvelope(ctx, v.wrapper, *r.Gym)
		if err != nil {
			return Receipt{}, false, err
		}
		defer clear(gymPayload)
		key, err := decodeGym(gymPayload, r.Binding)
		if err != nil {
			return Receipt{}, false, err
		}
		key.Zero()
		next := cloneRecord(r)
		next.State = "verified"
		next.Revision++
		receipt := retentionReceipt(next)
		next.Receipt = &receipt
		if err = v.publish(ctx, token, gymaccount.Enrollment, account, r, next, true); err != nil {
			return Receipt{}, false, err
		}
		r = next
		changed = true
	}
	if r.Receipt == nil {
		return Receipt{}, false, ErrCorrupt
	}
	return cloneReceipt(*r.Receipt), changed, nil
}

func (v *Vault) SignAccountChallenge(ctx context.Context, token string, challenge gymaccount.EnrollmentChallenge) (gymaccount.Authorization, error) {
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	defer done()
	if _, err = gymaccount.ChallengeDigest(challenge); err != nil {
		return gymaccount.Authorization{}, ErrEnvelope
	}
	a, r, err := v.snapshot(ctx, token, gymaccount.Enrollment)
	if err != nil {
		return gymaccount.Authorization{}, err
	}
	if r.Receipt == nil || challenge.AuthorityID != v.authority.AuthorityID || challenge.AccountID != a.ID || challenge.PrincipalID != a.PrincipalID || challenge.Generation != a.Generation || challenge.Network != r.Binding.Network || challenge.Genesis != r.Binding.Genesis || challenge.Profile != r.Binding.Profile || challenge.RootPublicKey != r.Binding.RootPublicKey || challenge.GymPublicKey != r.Binding.GymPublicKey || challenge.GymID != r.Binding.GymID {
		return gymaccount.Authorization{}, ErrConflict
	}
	if (challenge.Action == "enroll" && a.Enrollment != nil) || (challenge.Action == "recover" && (a.Enrollment == nil || !a.RecoveryRequired)) {
		return gymaccount.Authorization{}, ErrConflict
	}
	raw, err := openEnvelope(ctx, v.wrapper, *r.Gym)
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
	if err = v.authorizeOutput(ctx, token, gymaccount.Enrollment, a, r); err != nil {
		return gymaccount.Authorization{}, err
	}
	return auth, nil
}
func (v *Vault) authorizeOutput(ctx context.Context, token string, cap gymaccount.Capability, account gymaccount.Account, r vaultRecord) error {
	return v.accounts.WithSession(ctx, token, cap, func(a gymaccount.Account, check func() error) error {
		if !sameAuthority(a, account) || !bindingMatchesAccount(r.Binding, a) {
			return ErrConflict
		}
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		current, err := v.record(a.ID)
		if err != nil {
			return err
		}
		if current.Revision != r.Revision || current.Binding != r.Binding {
			return ErrConflict
		}
		return check()
	})
}

// EnsureEnrollment reconciles the separate account commit with the retained
// verified receipt. No cross-database atomicity is assumed or claimed.
func (v *Vault) EnsureEnrollment(ctx context.Context, token string) (Receipt, error) {
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer done()
	a, r, err := v.snapshot(ctx, token, gymaccount.Enrollment)
	if err != nil {
		return Receipt{}, err
	}
	if r.Receipt == nil {
		return Receipt{}, ErrConflict
	}
	if a.Enrollment == nil || a.RecoveryRequired {
		action := "enroll"
		if a.Enrollment != nil {
			action = "recover"
		}
		challenge, err := v.accounts.BeginChallenge(ctx, token, action)
		if err != nil {
			return Receipt{}, err
		}
		authorization, err := v.SignAccountChallenge(ctx, token, challenge)
		if err != nil {
			return Receipt{}, err
		}
		result, _, err := v.accounts.CompleteChallenge(ctx, token, challenge.ChallengeID, authorization)
		if err != nil {
			return Receipt{}, err
		}
		if result.AccountID != a.ID || result.Generation != a.Generation || result.Identity != identityForBinding(r.Binding) {
			return Receipt{}, ErrConflict
		}
	}
	err = v.accounts.WithSession(ctx, token, gymaccount.Enrollment, func(current gymaccount.Account, check func() error) error {
		if !sameAuthority(a, current) || current.Enrollment == nil || *current.Enrollment != identityForBinding(r.Binding) || current.RecoveryRequired {
			return ErrConflict
		}
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		record, err := v.record(current.ID)
		if err != nil {
			return err
		}
		if record.Binding != r.Binding || record.Receipt == nil {
			return ErrConflict
		}
		if record.State == "enrolled" {
			r = cloneRecord(record)
			return check()
		}
		if record.State != "verified" || record.Revision != r.Revision || v.meta.Reserved == 0 {
			return ErrConflict
		}
		next := v.meta
		next.Operations++
		next.Reserved--
		record.State = "enrolled"
		record.Revision++
		if err = check(); err != nil {
			return err
		}
		if err = v.commit(ctx, record, next); err != nil {
			return err
		}
		r = cloneRecord(record)
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return cloneReceipt(*r.Receipt), nil
}

// SignAdmission uses only the gym envelope and the prospect policy pinned in
// Config. The signature does not certify work validity or canonicality.
func (v *Vault) SignAdmission(ctx context.Context, token string, chainContext prospect.Context, proof prospect.Proof) (gymauth.Authorization, error) {
	if len(proof.MerkleBranch) > 20 {
		return gymauth.Authorization{}, ErrEnvelope
	}
	proof.MerkleBranch = append([]string(nil), proof.MerkleBranch...)
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	defer done()
	policy := v.config.Policy
	if proof.Version != prospect.Version2 || chainContext.Network != policy.Network || chainContext.DNAVersion != policy.DNAVersion || !strings.EqualFold(chainContext.Genesis, policy.Genesis) || !strings.EqualFold(chainContext.ProspectTarget, policy.ProspectTarget) {
		return gymauth.Authorization{}, ErrConflict
	}
	a, r, err := v.snapshot(ctx, token, gymaccount.Mining)
	if err != nil {
		return gymauth.Authorization{}, err
	}
	if r.State != "enrolled" || !strings.EqualFold(proof.GymID, r.Binding.GymID) {
		return gymauth.Authorization{}, ErrConflict
	}
	if _, err = gymauth.AdmissionDigest(chainContext, proof, r.Binding.GymPublicKey); err != nil {
		return gymauth.Authorization{}, ErrEnvelope
	}
	raw, err := openEnvelope(ctx, v.wrapper, *r.Gym)
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
	if err = v.authorizeOutput(ctx, token, gymaccount.Mining, a, r); err != nil {
		return gymauth.Authorization{}, err
	}
	return auth, nil
}
func (v *Vault) Status(ctx context.Context, token string) (Status, error) {
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return Status{}, err
	}
	defer done()
	_, r, err := v.snapshot(ctx, token, gymaccount.View)
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
	return result, nil
}
func (v *Vault) ExportRecoveryFile(ctx context.Context, token, path string) error {
	if len(path) == 0 || len(path) > 1024 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n\t") {
		return ErrExport
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return ErrExport
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return ErrExport
	}
	destination := filepath.Join(parent, filepath.Base(path))
	rel, err := filepath.Rel(v.path, destination)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return ErrExport
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return ErrExport
	}
	destinationRoot, err := os.OpenRoot(parent)
	if err != nil {
		return ErrExport
	}
	defer destinationRoot.Close()
	pinnedInfo, err := destinationRoot.Stat(".")
	if err != nil || !os.SameFile(parentInfo, pinnedInfo) {
		return ErrExport
	}
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	account, r, err := v.snapshot(ctx, token, gymaccount.RecoveryExport)
	if err != nil {
		return err
	}
	if r.State != "enrolled" {
		return ErrConflict
	}
	raw, err := openEnvelope(ctx, v.wrapper, *r.Recovery)
	if err != nil {
		return err
	}
	defer clear(raw)
	entropy, err := decodeRecovery(raw, r)
	if err != nil {
		return err
	}
	defer clear(entropy[:])
	return v.accounts.WithSession(ctx, token, gymaccount.RecoveryExport, func(a gymaccount.Account, check func() error) error {
		if !sameAuthority(a, account) {
			return ErrConflict
		}
		if err := v.lock(ctx); err != nil {
			return err
		}
		defer v.unlock()
		current, err := v.record(a.ID)
		if err != nil {
			return err
		}
		if current.Revision != r.Revision || current.Binding != r.Binding {
			return ErrConflict
		}
		if err = check(); err != nil {
			return err
		}
		bundle, err := recovery.NewExport(entropy, r.Manifest.Accounts)
		if err != nil {
			return ErrEnvelope
		}
		encoded, err := recovery.MarshalExport(bundle)
		if err != nil {
			return ErrEnvelope
		}
		defer clear(encoded)
		if err = check(); err != nil {
			return err
		}
		file, err := destinationRoot.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return ErrExport
		}
		n, we := file.Write(encoded)
		se, ce := file.Sync(), file.Close()
		if we != nil || n != len(encoded) || se != nil || ce != nil || syncPinnedExportRoot(destinationRoot) != nil {
			return ErrExport
		}
		return nil
	})
}
func (v *Vault) Rewrap(ctx context.Context, token, recoveryRef, gymRef string) (Receipt, bool, error) {
	if !allowedKey(v.config, RecoveryPurpose, recoveryRef) || !allowedKey(v.config, GymPurpose, gymRef) {
		return Receipt{}, false, ErrConfig
	}
	ctx, done, err := v.begin(ctx)
	if err != nil {
		return Receipt{}, false, err
	}
	defer done()
	a, r, err := v.snapshot(ctx, token, gymaccount.RecoveryAuthority)
	if err != nil {
		return Receipt{}, false, err
	}
	if r.State != "enrolled" {
		return Receipt{}, false, ErrConflict
	}
	if r.Recovery.KeyRef == recoveryRef && r.Gym.KeyRef == gymRef {
		return cloneReceipt(*r.Receipt), false, nil
	}
	recoveryEnvelope, err := rewrapEnvelope(ctx, v.wrapper, *r.Recovery, recoveryRef, r.Recovery.WrapRevision+1)
	if err != nil {
		return Receipt{}, false, err
	}
	gymEnvelope, err := rewrapEnvelope(ctx, v.wrapper, *r.Gym, gymRef, r.Gym.WrapRevision+1)
	if err != nil {
		return Receipt{}, false, err
	}
	next := cloneRecord(r)
	next.Revision++
	next.Recovery = &recoveryEnvelope
	next.Gym = &gymEnvelope
	if err = v.publish(ctx, token, gymaccount.RecoveryAuthority, a, r, next, false); err != nil {
		return Receipt{}, false, err
	}
	return cloneReceipt(*next.Receipt), true, nil
}

func syncPinnedExportRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
