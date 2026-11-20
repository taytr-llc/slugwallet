// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

func validateCurrentBinding(b CurrentBinding, original recovery.Manifest) error {
	if b.Version != Version1 || !nonzeroID(b.HostedVaultID) || !nonzeroID(b.WalletOwnerID) || !canonicalHex(b.RetentionID, 32) || !canonicalHex(b.SourceBindingID, 32) || validateBinding(b.VaultBinding) != nil {
		return ErrConflict
	}
	v := b.VaultBinding
	if v.Network != original.Network || v.Genesis != original.Genesis || v.Profile != original.Profile || v.RootPublicKey != original.RootPublicKey || v.GymPublicKey != original.GymPublicKey || v.GymID != original.GymID {
		return ErrConflict
	}
	return nil
}
func validateCurrentBindings(bindings []CurrentBinding, originals []recovery.Manifest) error {
	if len(bindings) != 2 || len(originals) != 2 {
		return ErrConfig
	}
	for i, b := range bindings {
		if validateCurrentBinding(b, originals[i]) != nil {
			return ErrConflict
		}
		fixture := []string{"zero256", "incrementing256"}[i]
		id, _ := gymaccount.FixtureIdentity(fixture)
		if identityForBinding(b.VaultBinding) != id {
			return ErrConflict
		}
	}
	a, b := bindings[0], bindings[1]
	if a.HostedVaultID != b.HostedVaultID || a.SourceBindingID != b.SourceBindingID || a.VaultBinding.AuthorityID != b.VaultBinding.AuthorityID || a.WalletOwnerID == b.WalletOwnerID || a.VaultBinding.AccountID == b.VaultBinding.AccountID || a.VaultBinding.PrincipalID == b.VaultBinding.PrincipalID || a.VaultBinding.RootPublicKey == b.VaultBinding.RootPublicKey || a.VaultBinding.GymID == b.VaultBinding.GymID {
		return ErrConflict
	}
	return nil
}

// CurrentBindingID is a public commitment, never a live capture capability.
func CurrentBindingID(b CurrentBinding) (string, error) {
	if b.Version != Version1 || !nonzeroID(b.HostedVaultID) || !nonzeroID(b.WalletOwnerID) || !canonicalHex(b.RetentionID, 32) || !canonicalHex(b.SourceBindingID, 32) || validateBinding(b.VaultBinding) != nil {
		return "", ErrConfig
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", ErrConfig
	}
	sum := sha256.Sum256(append([]byte("SLUG hosted current recovery binding\x00v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}
func currentManifest(m, original recovery.Manifest) error {
	if recovery.ValidateManifest(m) != nil || len(m.Accounts) != 4 || len(original.Accounts) != 4 {
		return ErrConflict
	}
	x, y := m, original
	x.Accounts = nil
	y.Accounts = nil
	if !reflect.DeepEqual(x, y) {
		return ErrConflict
	}
	for i, a := range m.Accounts {
		b := original.Accounts[i]
		a.NextExternal = 0
		a.NextInternal = 0
		b.NextExternal = 0
		b.NextInternal = 0
		if a != b {
			return ErrConflict
		}
	}
	raw, err := recovery.MarshalManifest(m)
	if err != nil || len(raw) > MaxCurrentManifestBytes {
		return ErrCapacity
	}
	return nil
}
func cursorMonotone(m, previous recovery.Manifest) bool {
	if len(m.Accounts) != 4 || len(previous.Accounts) != 4 {
		return false
	}
	for i, a := range m.Accounts {
		if a.NextExternal < previous.Accounts[i].NextExternal || a.NextInternal < previous.Accounts[i].NextInternal {
			return false
		}
	}
	return true
}
func validateCheckpoint(c CurrentCheckpoint, b CurrentBinding, original recovery.Manifest) error {
	if c.Version != Version1 || c.Binding != b || validateCurrentBinding(c.Binding, original) != nil || c.Revision < 1 || c.Revision > MaxCurrentActions || c.ExpectedRevision != c.Revision-1 || !nonzeroID(c.CaptureID) || c.CapturedAtMS < 1 || c.CapturedAtMS > maxCurrentTimeMS || c.CommittedAtMS < c.CapturedAtMS || c.CommittedAtMS > maxCurrentTimeMS || currentManifest(c.Manifest, original) != nil || !cursorMonotone(c.Manifest, original) {
		return ErrConflict
	}
	hash, err := manifestDigest(c.Manifest)
	if err != nil || hash != c.ManifestSHA256 {
		return ErrConflict
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > MaxCurrentCheckpointBytes {
		return ErrCapacity
	}
	return nil
}
func (s *CurrentStore) audit() error {
	if validateCurrentBindings(s.marker.Bindings, s.originals) != nil {
		return ErrCorrupt
	}
	expectedHash, _ := jsonSHA(s.marker)
	var meta currentMetadata
	actions := map[string]CurrentCheckpoint{}
	rows := [2][]CurrentCheckpoint{}
	it := s.db.NewIterator(nil, nil)
	defer it.Release()
	count, total := 0, 0
	for it.Next() {
		count++
		if count > 129 {
			return ErrCapacity
		}
		key, value := it.Key(), it.Value()
		if len(key) > 71 || len(value) > MaxCurrentCheckpointBytes {
			return ErrCorrupt
		}
		total += len(key) + len(value)
		if total > MaxCurrentStateBytes {
			return ErrCapacity
		}
		if bytes.Equal(key, []byte("meta")) {
			if strictHosted(value, &meta, 4096) != nil {
				return ErrCorrupt
			}
			continue
		}
		if len(key) != 71 || !bytes.HasPrefix(key, []byte("action/")) || !nonzeroID(string(key[7:])) {
			return ErrCorrupt
		}
		var c CurrentCheckpoint
		if strictHosted(value, &c, MaxCurrentCheckpointBytes) != nil || c.CaptureID != string(key[7:]) {
			return ErrCorrupt
		}
		index := -1
		for i, b := range s.marker.Bindings {
			if c.Binding == b {
				index = i
			}
		}
		if index < 0 || validateCheckpoint(c, s.marker.Bindings[index], s.originals[index]) != nil {
			return ErrCorrupt
		}
		actions[c.CaptureID] = c
		rows[index] = append(rows[index], c)
	}
	if it.Error() != nil || meta.Version != Version1 || meta.MarkerSHA256 != expectedHash || meta.Actions != uint32(len(actions)) || count != 1+len(actions) || len(meta.Current) != 2 || meta.ClockHighWaterMS < 0 || meta.ClockHighWaterMS > maxCurrentTimeMS {
		return ErrCorrupt
	}
	clock := int64(0)
	for i, row := range rows {
		sort.Slice(row, func(a, b int) bool { return row[a].Revision < row[b].Revision })
		previous := s.originals[i]
		lastCapture, lastCommit := int64(0), int64(0)
		for n, c := range row {
			if c.Revision != uint32(n+1) || c.CapturedAtMS < lastCapture || c.CommittedAtMS < lastCommit || !cursorMonotone(c.Manifest, previous) {
				return ErrCorrupt
			}
			previous = c.Manifest
			lastCapture = c.CapturedAtMS
			lastCommit = c.CommittedAtMS
			if lastCommit > clock {
				clock = lastCommit
			}
		}
		p := currentPointer{AccountID: s.marker.Bindings[i].VaultBinding.AccountID}
		if len(row) > 0 {
			last := row[len(row)-1]
			p.Revision = last.Revision
			p.CaptureID = last.CaptureID
		}
		if meta.Current[i] != p {
			return ErrCorrupt
		}
	}
	if meta.ClockHighWaterMS != clock {
		return ErrCorrupt
	}
	s.meta = meta
	s.actions = actions
	s.bytes = total
	return nil
}

// currentIntent is deliberately private: parsed public manifests cannot mint a
// capture. It also makes the independent byte/state corpus testable without work.
type currentIntent struct {
	Binding          CurrentBinding    `json:"binding"`
	CaptureID        string            `json:"capture_id"`
	ExpectedRevision uint32            `json:"expected_revision"`
	CapturedAtMS     int64             `json:"captured_at_ms"`
	Manifest         recovery.Manifest `json:"manifest"`
}

func (s *CurrentStore) stageCheckpoint(index int, req currentIntent, now int64) (CurrentCheckpoint, currentMetadata, []byte, []byte, bool, error) {
	if index < 0 || index >= 2 || req.Binding != s.marker.Bindings[index] || !nonzeroID(req.CaptureID) || req.ExpectedRevision >= MaxCurrentActions || req.CapturedAtMS < 1 || req.CapturedAtMS > maxCurrentTimeMS || now < 1 || now > maxCurrentTimeMS || now < s.meta.ClockHighWaterMS || currentManifest(req.Manifest, s.originals[index]) != nil {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrConflict
	}
	if old, ok := s.actions[req.CaptureID]; ok {
		if old.Binding != req.Binding || old.ExpectedRevision != req.ExpectedRevision || old.CapturedAtMS != req.CapturedAtMS || !reflect.DeepEqual(old.Manifest, req.Manifest) {
			return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrConflict
		}
		return cloneCheckpoint(old), s.meta, nil, nil, false, nil
	}
	if s.meta.Actions >= MaxCurrentActions {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrCapacity
	}
	p := s.meta.Current[index]
	previous := s.originals[index]
	if p.Revision > 0 {
		old := s.actions[p.CaptureID]
		previous = old.Manifest
		if req.CapturedAtMS < old.CapturedAtMS {
			return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrConflict
		}
	}
	if req.ExpectedRevision != p.Revision || !cursorMonotone(req.Manifest, previous) || now < req.CapturedAtMS {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrConflict
	}
	hash, err := manifestDigest(req.Manifest)
	if err != nil {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, err
	}
	c := CurrentCheckpoint{Version1, req.Binding, req.ExpectedRevision + 1, req.CaptureID, req.ExpectedRevision, req.CapturedAtMS, now, cloneManifest(req.Manifest), hash}
	if err = validateCheckpoint(c, req.Binding, s.originals[index]); err != nil {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, err
	}
	meta := s.meta
	meta.Current = append([]currentPointer(nil), meta.Current...)
	meta.Current[index] = currentPointer{req.Binding.VaultBinding.AccountID, c.Revision, c.CaptureID}
	meta.Actions++
	meta.ClockHighWaterMS = now
	raw, _ := json.Marshal(c)
	mr, _ := json.Marshal(meta)
	oldMeta, _ := json.Marshal(s.meta)
	if len(mr) > 4096 || len(raw)+len(mr)+75 > maxCurrentCommitBytes || s.bytes-len(oldMeta)+len(mr)+71+len(raw) > MaxCurrentStateBytes {
		return CurrentCheckpoint{}, currentMetadata{}, nil, nil, false, ErrCapacity
	}
	return c, meta, raw, mr, true, nil
}
