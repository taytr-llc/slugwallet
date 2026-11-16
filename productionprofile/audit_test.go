// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/taytr-llc/slug/address/v2/base58"
)

// Recompute the real checksum so failures exercise key validation, not a
// corrupted transport checksum. All material comes from published test seeds.
func auditAlterExtended(t *testing.T, encoded string, alter func([]byte)) string {
	t.Helper()
	raw := base58.Decode(encoded)
	if len(raw) != 82 {
		t.Fatal("unexpected extended-key fixture length")
	}
	payload := raw[:78]
	alter(payload)
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	copy(raw[78:], second[:4])
	return base58.Encode(raw)
}

func TestAuditManifestRejectsChecksumValidInvalidExtendedKeys(t *testing.T) {
	base := readReference(t).Cases[0].Export.Manifest
	for _, test := range []struct {
		name  string
		root  bool
		alter func([]byte)
	}{
		{"root-parent-fingerprint", true, func(b []byte) { b[5] = 1 }},
		{"root-child-index", true, func(b []byte) { binary.BigEndian.PutUint32(b[9:13], 1) }},
		{"root-depth", true, func(b []byte) { b[4] = 1 }},
		{"account-depth", false, func(b []byte) { b[4] = 2 }},
		{"account-unhardened-child", false, func(b []byte) { binary.BigEndian.PutUint32(b[9:13], 0) }},
		{"account-wrong-hardened-child", false, func(b []byte) { binary.BigEndian.PutUint32(b[9:13], 0x80000001) }},
		{"bitcoin-version", false, func(b []byte) { copy(b[:4], []byte{4, 0x88, 0xb2, 0x1e}) }},
		{"private-scalar-with-public-version", false, func(b []byte) { clear(b[45:78]); b[77] = 1 }},
		{"point-outside-field", false, func(b []byte) {
			b[45] = 2
			copy(b[46:], referenceHex(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"))
		}},
		{"invalid-compressed-prefix", false, func(b []byte) { b[45] = 4 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := cloneManifest(base)
			key := &manifest.Accounts[0].AccountPublicKey
			if test.root {
				key = &manifest.RootPublicKey
			}
			*key = auditAlterExtended(t, *key, test.alter)
			if ValidateManifest(manifest) == nil {
				t.Fatal("invalid extended key accepted structurally")
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseManifest(raw); err == nil {
				t.Fatal("checksum-valid malformed key accepted by public parser")
			}
			if _, err := ValidateFixtureManifest(context.Background(), manifest); err == nil {
				t.Fatal("malformed key accepted as a fixture")
			}
		})
	}
}

func TestAuditSLIP10ChildCancellationClearsOwnedWorkingBytes(t *testing.T) {
	var parent slip10Node
	parent.key[31] = 7
	for i := range parent.chain {
		parent.chain[i] = byte(i + 1)
	}
	original := parent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var borrowedKey, borrowedData []byte
	calls := 0
	mac := func(key, data []byte) [64]byte {
		calls++
		borrowedKey, borrowedData = key, data
		cancel()
		var result [64]byte
		result[31] = 2 // mathematically valid child, but cancellation wins publication
		result[63] = 9
		return result
	}
	got, err := slip10Child(ctx, parent, 0x8000002a, mac)
	if !errors.Is(err, context.Canceled) || got != (slip10Node{}) || calls != 1 {
		t.Fatal("canceled child published material or retried")
	}
	if !bytes.Equal(borrowedKey, make([]byte, len(borrowedKey))) || !bytes.Equal(borrowedData, make([]byte, len(borrowedData))) {
		t.Fatal("owned HMAC input remained after canceled child")
	}
	if parent != original {
		t.Fatal("child cleanup mutated caller-owned parent")
	}
}
