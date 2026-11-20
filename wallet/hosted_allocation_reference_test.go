// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/taytr-llc/slugwallet/recovery"
)

type allocationRefSnapshot struct {
	Marker allocationMarker   `json:"marker"`
	Meta   allocationMetadata `json:"meta"`
	Rows   []allocationRow    `json:"rows"`
	Head   struct {
		Revision       uint32            `json:"revision"`
		Manifest       recovery.Manifest `json:"manifest"`
		ManifestSHA256 string            `json:"manifest_sha256"`
	} `json:"head"`
}
type allocationReference struct {
	Bindings []struct {
		Binding   AllocationBinding `json:"binding"`
		Canonical string            `json:"canonical_utf8"`
		BindingID string            `json:"binding_id"`
	} `json:"bindings"`
	States []struct {
		Name     string                `json:"name"`
		Snapshot allocationRefSnapshot `json:"snapshot"`
		Bytes    int                   `json:"host_bytes"`
	} `json:"states"`
	StorageNegatives []struct {
		Name     string          `json:"name"`
		Snapshot json.RawMessage `json:"snapshot"`
	} `json:"storage_negatives"`
	Raw []struct {
		Name   string `json:"name"`
		RawHex string `json:"raw_hex"`
		Valid  bool   `json:"valid"`
	} `json:"raw_cases"`
}

func loadAllocationReference(t *testing.T) allocationReference {
	t.Helper()
	raw, e := os.ReadFile("testdata/hosted-allocation/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "221fc42f6848fed27912a43454a1fa9ebe2d4e16b383aad9e294c31316424e6b" {
		t.Fatal("independent allocation corpus changed")
	}
	var result allocationReference
	if e = json.Unmarshal(raw, &result); e != nil {
		t.Fatal(e)
	}
	return result
}
func referenceAllocationStore(t *testing.T, s allocationRefSnapshot) *HostedAllocationInventory {
	t.Helper()
	db, e := leveldb.Open(storage.NewMemStorage(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	batch := new(leveldb.Batch)
	meta, _ := json.Marshal(s.Meta)
	batch.Put([]byte("meta"), meta)
	for _, r := range s.Rows {
		raw, _ := json.Marshal(r)
		batch.Put([]byte("allocation/"+r.Reservation.AllocationID), raw)
	}
	if e = db.Write(batch, nil); e != nil {
		t.Fatal(e)
	}
	id, e := AllocationBindingID(s.Marker.Binding)
	if e != nil {
		t.Fatal(e)
	}
	return &HostedAllocationInventory{db: db, marker: s.Marker, binding: s.Marker.Binding, bindingID: id}
}
func TestHostedAllocationIndependentInventory(t *testing.T) {
	v := loadAllocationReference(t)
	for _, b := range v.Bindings {
		raw, e := json.Marshal(b.Binding)
		if e != nil || string(raw) != b.Canonical {
			t.Fatal("binding bytes", e)
		}
		id, e := AllocationBindingID(b.Binding)
		if e != nil || id != b.BindingID {
			t.Fatal("binding domain", e)
		}
	}
	for _, s := range v.States {
		t.Run(s.Name, func(t *testing.T) {
			i := referenceAllocationStore(t, s.Snapshot)
			if e := i.audit(); e != nil {
				t.Fatal(e)
			}
			if i.bytes != s.Bytes || i.meta != s.Snapshot.Meta {
				t.Fatal("inventory fold/byte accounting mismatch")
			}
			manifest, e := allocationManifest(i.binding, i.meta.Cursors)
			if e != nil || !reflect.DeepEqual(manifest, s.Snapshot.Head.Manifest) {
				t.Fatal("reserved prefix lost", e)
			}
			digest, e := allocationHash("", manifest)
			if e != nil || digest != s.Snapshot.Head.ManifestSHA256 {
				t.Fatal("head digest", e)
			}
		})
	}
	for _, r := range v.Raw {
		t.Run("raw/"+r.Name, func(t *testing.T) {
			raw, e := hex.DecodeString(r.RawHex)
			if e != nil {
				t.Fatal(e)
			}
			var row allocationRow
			e = allocationCanonical(raw, &row, allocationRowMax)
			if e == nil {
				e = validateAllocationRow(row, v.Bindings[0].BindingID)
			}
			if (e == nil) != r.Valid {
				t.Fatalf("raw acceptance = %v, want %v", e == nil, r.Valid)
			}
		})
	}
}
func TestHostedAllocationIndependentHostRefusals(t *testing.T) {
	v := loadAllocationReference(t)
	// These are host invariants; local-wallet and derivation negatives belong
	// to the manager/paired audit and are not relabeled as host-only coverage.
	host := map[string]bool{"meta-revision": true, "head-regression": true, "foreign-row-binding": true, "duplicate-sequence": true, "false-invalid-child": true, "bool-count": true, "clock-regression": true, "unknown-row-field": true}
	for _, s := range v.StorageNegatives {
		if !host[s.Name] {
			continue
		}
		t.Run(s.Name, func(t *testing.T) {
			var raw struct {
				Marker allocationMarker  `json:"marker"`
				Meta   json.RawMessage   `json:"meta"`
				Rows   []json.RawMessage `json:"rows"`
			}
			if e := json.Unmarshal(s.Snapshot, &raw); e != nil {
				t.Fatal(e)
			}
			db, e := leveldb.Open(storage.NewMemStorage(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			compact := func(raw []byte) []byte {
				var b bytes.Buffer
				if e := json.Compact(&b, raw); e != nil {
					t.Fatal(e)
				}
				return b.Bytes()
			}
			batch := new(leveldb.Batch)
			batch.Put([]byte("meta"), compact(raw.Meta))
			for _, row := range raw.Rows {
				var r allocationRow
				if e = json.Unmarshal(row, &r); e != nil {
					t.Fatal(e)
				}
				batch.Put([]byte("allocation/"+r.Reservation.AllocationID), compact(row))
			}
			if e = db.Write(batch, nil); e != nil {
				t.Fatal(e)
			}
			id, e := AllocationBindingID(raw.Marker.Binding)
			if e != nil {
				t.Fatal(e)
			}
			i := &HostedAllocationInventory{db: db, marker: raw.Marker, binding: raw.Marker.Binding, bindingID: id}
			if e = i.audit(); e == nil {
				t.Fatal("accepted independent corrupt host state")
			}
		})
	}
}
