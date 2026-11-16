// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errJSON = errors.New("invalid recovery JSON schema")

func fields(data []byte, required []string, limit int) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > limit {
		return nil, errJSON
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errJSON
	}
	allowed := make(map[string]bool, len(required))
	for _, key := range required {
		allowed[key] = true
	}
	values := make(map[string]json.RawMessage, len(required))
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] {
			return nil, errJSON
		}
		if _, exists := values[key]; exists {
			return nil, errJSON
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errJSON
		}
		values[key] = raw
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(values) != len(required) {
		return nil, errJSON
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errJSON
	}
	return values, nil
}
func scalar(raw json.RawMessage, target any) error {
	if json.Unmarshal(raw, target) != nil {
		return errJSON
	}
	return nil
}

// ParseManifest rejects missing, duplicate, unknown, null and noncanonical
// typed values, then validates the fixed public profile. It never accepts paths.
func ParseManifest(data []byte) (Manifest, error) {
	values, err := fields(data, []string{"version", "profile", "network", "genesis", "derivation", "scan_from_height", "root_public_key", "gym_path", "gym_public_key", "gym_id", "accounts"}, MaxManifestSize)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	for key, target := range map[string]any{"version": &m.Version, "profile": &m.Profile, "network": &m.Network, "genesis": &m.Genesis, "derivation": &m.Derivation, "scan_from_height": &m.ScanFromHeight, "root_public_key": &m.RootPublicKey, "gym_path": &m.GymPath, "gym_public_key": &m.GymPublicKey, "gym_id": &m.GymID} {
		if scalar(values[key], target) != nil {
			return Manifest{}, errJSON
		}
	}
	var accounts []json.RawMessage
	if scalar(values["accounts"], &accounts) != nil || len(accounts) != 4 {
		return Manifest{}, errJSON
	}
	m.Accounts = make([]Account, 4)
	for i, raw := range accounts {
		a, err := fields(raw, []string{"purpose", "coin", "account", "external_type", "internal_type", "next_external", "next_internal"}, MaxManifestSize)
		if err != nil {
			return Manifest{}, err
		}
		item := &m.Accounts[i]
		for key, target := range map[string]any{"purpose": &item.Purpose, "coin": &item.Coin, "account": &item.Account, "external_type": &item.ExternalType, "internal_type": &item.InternalType, "next_external": &item.NextExternal, "next_internal": &item.NextInternal} {
			if scalar(a[key], target) != nil {
				return Manifest{}, errJSON
			}
		}
	}
	if err = ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ParseExport validates a complete, bounded secret export including its phrase
// binding. Errors never include input strings or secret material.
func ParseExport(data []byte) (Export, error) {
	values, err := fields(data, []string{"version", "mnemonic", "manifest"}, MaxExportSize)
	if err != nil {
		return Export{}, err
	}
	var e Export
	if scalar(values["version"], &e.Version) != nil || scalar(values["mnemonic"], &e.Mnemonic) != nil {
		return Export{}, errJSON
	}
	e.Manifest, err = ParseManifest(values["manifest"])
	if err != nil {
		return Export{}, err
	}
	if err = ValidateExport(e); err != nil {
		return Export{}, err
	}
	return e, nil
}

// MarshalManifest emits deterministic JSON after public-profile validation.
func MarshalManifest(m Manifest) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	data, err := json.Marshal(m)
	if err != nil || len(data) > MaxManifestSize {
		return nil, errJSON
	}
	return data, nil
}

// MarshalExport validates phrase binding before emitting secret JSON bytes.
func MarshalExport(e Export) ([]byte, error) {
	if err := ValidateExport(e); err != nil {
		return nil, err
	}
	data, err := json.Marshal(e)
	if err != nil || len(data) > MaxExportSize {
		return nil, errJSON
	}
	return data, nil
}
