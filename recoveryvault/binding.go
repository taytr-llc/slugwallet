// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/prospectnode"
)

func normalizedConfig(c Config) (Config, error) {
	if c.Version != Version1 || !validReference(c.WrapperID) || !validReference(c.RecoveryKeyRef) || !validReference(c.GymKeyRef) || c.MaxOperations == 0 || c.MaxOperations > MaxOperations || len(c.AllowedRecoveryKeyRefs) == 0 || len(c.AllowedRecoveryKeyRefs) > MaxKeyReferences || len(c.AllowedGymKeyRefs) == 0 || len(c.AllowedGymKeyRefs) > MaxKeyReferences {
		return Config{}, ErrConfig
	}
	c.AllowedRecoveryKeyRefs = append([]string(nil), c.AllowedRecoveryKeyRefs...)
	c.AllowedGymKeyRefs = append([]string(nil), c.AllowedGymKeyRefs...)
	seen := make(map[string]bool)
	for _, refs := range [][]string{c.AllowedRecoveryKeyRefs, c.AllowedGymKeyRefs} {
		for _, ref := range refs {
			if !validReference(ref) || seen[ref] {
				return Config{}, ErrConfig
			}
			seen[ref] = true
		}
		sort.Strings(refs)
	}
	if !allowedKey(c, RecoveryPurpose, c.RecoveryKeyRef) || !allowedKey(c, GymPurpose, c.GymKeyRef) {
		return Config{}, ErrConfig
	}
	raw, err := json.Marshal(c.Policy)
	if err != nil {
		return Config{}, ErrConfig
	}
	c.Policy, err = prospectnode.ParsePolicy(raw)
	if err != nil || c.Policy.Network != gymaccount.FixtureNetwork || c.Policy.Genesis != gymaccount.FixtureGenesis {
		return Config{}, ErrConfig
	}
	return c, nil
}

func validReference(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func allowedKey(c Config, purpose Purpose, ref string) bool {
	var refs []string
	switch purpose {
	case RecoveryPurpose:
		refs = c.AllowedRecoveryKeyRefs
	case GymPurpose:
		refs = c.AllowedGymKeyRefs
	default:
		return false
	}
	for _, candidate := range refs {
		if ref == candidate {
			return true
		}
	}
	return false
}

func canonicalHex(s string, size int) bool {
	if len(s) != size*2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateBinding(b Binding) error {
	if b.Version != Version1 || !canonicalHex(b.AuthorityID, 32) || !canonicalHex(b.AccountID, 32) || !canonicalHex(b.PrincipalID, 32) || !canonicalHex(b.ProvisionID, 32) || b.Network != gymaccount.FixtureNetwork || b.Genesis != gymaccount.FixtureGenesis || b.Profile != gymaccount.FixtureProfile || !canonicalHex(b.GymPublicKey, 33) || !canonicalHex(b.GymID, 32) || len(b.RootPublicKey) > 160 {
		return ErrEnvelope
	}
	if gymaccount.ValidateFixtureIdentity(b.RootPublicKey, b.GymPublicKey, b.GymID) != nil {
		return ErrEnvelope
	}
	return nil
}

func appendString(b *bytes.Buffer, s string) {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

func appendHex(b *bytes.Buffer, s string) {
	x, _ := hex.DecodeString(s) // Callers validate every bounded field first.
	b.Write(x)
}

func contentAAD(binding Binding, purpose Purpose, revision uint64, manifestHash string) ([]byte, error) {
	if validateBinding(binding) != nil || (purpose != RecoveryPurpose && purpose != GymPurpose) || revision == 0 || !canonicalHex(manifestHash, 32) {
		return nil, ErrEnvelope
	}
	var b bytes.Buffer
	b.WriteString("SLUG recovery vault content\x00v1\x00")
	var n [8]byte
	binary.LittleEndian.PutUint32(n[:4], binding.Version)
	b.Write(n[:4])
	for _, s := range []string{binding.AuthorityID, binding.AccountID, binding.PrincipalID, binding.ProvisionID} {
		appendHex(&b, s)
	}
	binary.LittleEndian.PutUint32(n[:4], binding.Network)
	b.Write(n[:4])
	appendHex(&b, binding.Genesis)
	appendString(&b, binding.Profile)
	appendString(&b, binding.RootPublicKey)
	appendHex(&b, binding.GymPublicKey)
	appendHex(&b, binding.GymID)
	appendString(&b, string(purpose))
	binary.LittleEndian.PutUint64(n[:], revision)
	b.Write(n[:])
	appendHex(&b, manifestHash)
	return b.Bytes(), nil
}

// wrappingAAD accepts a not-yet-wrapped envelope; WrappedKey is not part of its
// own authenticated context. All other fields are bounded and validated first.
func wrappingAAD(e Envelope) ([]byte, error) {
	if e.Version != Version1 || e.WrapRevision == 0 || !validReference(e.WrapperID) || !validReference(e.KeyRef) || !canonicalHex(e.Nonce, 12) || len(e.Ciphertext) < 16*2 || len(e.Ciphertext) > (MaxPayloadSize+16)*2 || !canonicalHex(e.Ciphertext, len(e.Ciphertext)/2) {
		return nil, ErrEnvelope
	}
	aad, err := contentAAD(e.Binding, e.Purpose, e.ContentRevision, e.ManifestHash)
	if err != nil {
		return nil, err
	}
	contentHash := sha256.Sum256(aad)
	nonce, _ := hex.DecodeString(e.Nonce)
	ciphertext, _ := hex.DecodeString(e.Ciphertext)
	cipherHash := sha256.New()
	cipherHash.Write(nonce)
	cipherHash.Write(ciphertext)
	var b bytes.Buffer
	b.WriteString("SLUG recovery vault wrap\x00v1\x00")
	b.Write(contentHash[:])
	b.Write(cipherHash.Sum(nil))
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], e.WrapRevision)
	b.Write(n[:])
	appendString(&b, e.WrapperID)
	appendString(&b, e.KeyRef)
	return b.Bytes(), nil
}

func validateEnvelope(e Envelope) error {
	if len(e.WrappedKey) == 0 || len(e.WrappedKey) > MaxWrappedKeySize*2 || !canonicalHex(e.WrappedKey, len(e.WrappedKey)/2) {
		return ErrEnvelope
	}
	_, err := wrappingAAD(e)
	return err
}
