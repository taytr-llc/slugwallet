// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/taytr-llc/slugwallet/recovery"
)

type currentRefEntries []struct {
	Key      string `json:"key"`
	ValueHex string `json:"value_hex"`
}
type currentRefState struct {
	Marker     currentMarker     `json:"marker"`
	MarkerFile string            `json:"marker_file_utf8"`
	MarkerHash string            `json:"marker_sha256"`
	Entries    currentRefEntries `json:"entries"`
	Bytes      int               `json:"stored_key_value_bytes"`
}
type currentReference struct {
	Originals    []recovery.Manifest `json:"original_manifests"`
	Bindings     []CurrentBinding    `json:"expected_bindings"`
	BindingCases struct {
		Positives []struct {
			Name      string
			Binding   CurrentBinding
			Canonical string `json:"canonical_utf8"`
			Hash      string `json:"binding_sha256"`
		}
		Negatives []struct {
			Name            string
			ExpectedBinding CurrentBinding `json:"expected_binding"`
			Supplied        json.RawMessage
			Original        recovery.Manifest
		}
	} `json:"bindings"`
	Manifests []struct {
		Name      string
		Manifest  recovery.Manifest
		Canonical string `json:"canonical_utf8"`
		Hash      string `json:"manifest_sha256"`
	}
	States []struct {
		Name  string
		State currentRefState
	}
	Transitions []struct {
		Name       string
		Initial    string `json:"initial_state"`
		Index      int
		Request    json.RawMessage
		Now        int64 `json:"now_ms"`
		Expected   string
		Checkpoint CurrentCheckpoint
		Canonical  string `json:"canonical_utf8"`
		Meta       currentMetadata
		MetaUTF8   string `json:"meta_utf8"`
	}
	StorageNegatives []struct {
		Name       string
		MarkerFile string `json:"marker_file_utf8"`
		Entries    currentRefEntries
	} `json:"storage_negatives"`
	Raw []struct {
		Name   string
		Valid  bool
		RawHex string `json:"raw_hex"`
	} `json:"raw_cases"`
}

func loadCurrentReference(t *testing.T) currentReference {
	t.Helper()
	raw, err := os.ReadFile("testdata/hosted-current-recovery/current.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != "d8b3f965fe83272568042b21cf378c86c60f1d4d220a0ec92c1f837109f3756a" {
		t.Fatal("independent reference changed")
	}
	var v currentReference
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("reference shape")
	}
	return v
}
func referenceCurrentStore(t *testing.T, v currentReference, entries currentRefEntries) *CurrentStore {
	t.Helper()
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	batch := new(leveldb.Batch)
	for _, row := range entries {
		raw, e := hex.DecodeString(row.ValueHex)
		if e != nil {
			t.Fatal(e)
		}
		batch.Put([]byte(row.Key), raw)
	}
	if db.Write(batch, nil) != nil {
		t.Fatal("install reference")
	}
	return &CurrentStore{db: db, marker: currentMarker{currentApplication, Version1, v.Bindings}, originals: v.Originals}
}
func TestHostedCurrentIndependentBytesAndAudit(t *testing.T) {
	v := loadCurrentReference(t)
	for _, x := range v.BindingCases.Positives {
		t.Run("binding/"+x.Name, func(t *testing.T) {
			raw, _ := json.Marshal(x.Binding)
			got, err := CurrentBindingID(x.Binding)
			if err != nil || got != x.Hash || string(raw) != x.Canonical {
				t.Fatal("binding mismatch", err)
			}
		})
	}
	for _, x := range v.BindingCases.Negatives {
		t.Run("binding-refusal/"+x.Name, func(t *testing.T) {
			var b CurrentBinding
			err := json.Unmarshal(x.Supplied, &b)
			if err == nil {
				err = validateCurrentBinding(b, x.Original)
			}
			if err == nil && b == x.ExpectedBinding {
				t.Fatal("accepted changed binding")
			}
		})
	}
	for _, x := range v.Manifests {
		t.Run("manifest/"+x.Name, func(t *testing.T) {
			raw, err := recovery.MarshalManifest(x.Manifest)
			hash, e := manifestDigest(x.Manifest)
			if err != nil || e != nil || string(raw) != x.Canonical || hash != x.Hash {
				t.Fatal("manifest mismatch")
			}
		})
	}
	states := map[string]currentRefState{}
	for _, x := range v.States {
		states[x.Name] = x.State
		t.Run("state/"+x.Name, func(t *testing.T) {
			s := referenceCurrentStore(t, v, x.State.Entries)
			if err := s.audit(); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(s.marker)
			hash, _ := jsonSHA(s.marker)
			if string(raw)+"\n" != x.State.MarkerFile || hash != x.State.MarkerHash || s.bytes != x.State.Bytes {
				t.Fatal("marker/size mismatch")
			}
		})
	}
	for _, x := range v.Transitions {
		t.Run("transition/"+x.Name, func(t *testing.T) {
			s := referenceCurrentStore(t, v, states[x.Initial].Entries)
			if e := s.audit(); e != nil {
				t.Fatal(e)
			}
			var request currentIntent
			err := json.Unmarshal(x.Request, &request)
			var got CurrentCheckpoint
			var meta currentMetadata
			var changed bool
			if err == nil {
				got, meta, _, _, changed, err = s.stageCheckpoint(x.Index, request, x.Now)
			}
			if x.Expected == "reject" {
				if err == nil {
					t.Fatal("accepted invalid transition")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(got)
			mr, _ := json.Marshal(meta)
			if string(raw) != x.Canonical || !reflect.DeepEqual(got, x.Checkpoint) || changed != (x.Expected == "created") || string(mr) != x.MetaUTF8 {
				t.Fatal("independent transition mismatch")
			}
		})
	}
	for _, x := range v.StorageNegatives {
		t.Run("storage-refusal/"+x.Name, func(t *testing.T) {
			// The independent producer accepts a serialized key/value inventory.
			// LevelDB cannot contain duplicate keys: Batch.Put would silently
			// replace one and erase this fixture-parser refusal witness.
			seen := map[string]bool{}
			for _, entry := range x.Entries {
				if seen[entry.Key] {
					if x.Name != "duplicate-key" {
						t.Fatal("unexpected duplicate fixture key")
					}
					t.Log("duplicate input inventory refused before LevelDB installation; not an on-disk state")
					return
				}
				seen[entry.Key] = true
			}
			s := referenceCurrentStore(t, v, x.Entries)
			var marker currentMarker
			raw := []byte(x.MarkerFile)
			err := ErrCorrupt
			if len(raw) > 0 && raw[len(raw)-1] == '\n' {
				err = strictHosted(raw[:len(raw)-1], &marker, hostedMarkerMax-1)
			}
			if err == nil && !reflect.DeepEqual(marker, s.marker) {
				err = ErrConflict
			}
			if err == nil {
				err = s.audit()
			}
			if err == nil {
				t.Fatal("accepted corrupt reference state")
			}
		})
	}
	for _, x := range v.Raw {
		t.Run("grammar/"+x.Name, func(t *testing.T) {
			raw, e := hex.DecodeString(x.RawHex)
			if e != nil {
				t.Fatal(e)
			}
			var c CurrentCheckpoint
			err := strictHosted(raw, &c, MaxCurrentCheckpointBytes)
			if err == nil {
				err = validateCheckpoint(c, v.Bindings[0], v.Originals[0])
			}
			if (err == nil) != x.Valid {
				t.Fatal("grammar verdict mismatch", err)
			}
		})
	}
}
func TestHostedCurrentAuditRejectsUnknownAndOversizedRows(t *testing.T) {
	v := loadCurrentReference(t)
	s := referenceCurrentStore(t, v, v.States[0].State.Entries)
	if err := s.db.Put([]byte("untrusted"), []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}
	if s.audit() == nil {
		t.Fatal("unknown key")
	}
	s.db.Delete([]byte("untrusted"), nil)
	s.db.Put([]byte("action/"+strings.Repeat("1", 64)), bytes.Repeat([]byte("x"), MaxCurrentCheckpointBytes+1), nil)
	if s.audit() == nil {
		t.Fatal("oversized row")
	}
}
