// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type transferAllocationReferenceCase struct {
	Name, Kind, Digest string
	CanonicalUTF8      string `json:"canonical_utf8"`
	Value              json.RawMessage
	Context            struct {
		Binding AllocationBinding2 `json:"binding"`
	}
}
type transferAllocationReference struct {
	Positives, Negatives []transferAllocationReferenceCase
}

func readTransferAllocationReference(t *testing.T) transferAllocationReference {
	t.Helper()
	// Single pinned portable corpus; the workspace deliberately uses its exact
	// sibling module rather than a second mutable copy of the same reference.
	raw, err := os.ReadFile("../../slug/fightercarrier/testdata/reference/wallet-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "8648ac23d5e077df1a4dd1e3b8f07157922e650e92e9eea99c233a6993283495" {
		t.Fatal("independent corpus changed")
	}
	var result transferAllocationReference
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func checkTransferAllocationReference(t *testing.T, c transferAllocationReferenceCase) (any, string, error, bool) {
	t.Helper()
	var raw bytes.Buffer
	if err := json.Compact(&raw, c.Value); err != nil {
		t.Fatal(err)
	}
	var digest string
	switch c.Kind {
	case "binding2":
		var b AllocationBinding2
		err := allocationCanonical2(raw.Bytes(), &b, 8192)
		if err == nil {
			digest, err = AllocationBindingID2(b)
		}
		return b, digest, err, true
	case "request2":
		var r AllocationRequest2
		err := allocationCanonical2(raw.Bytes(), &r, 4096)
		if err == nil {
			digest, err = AllocationRequestDigest2(r, r.ConsumerID)
		}
		return r, digest, err, true
	case "reservation2":
		var r allocationReservationValue2
		err := allocationCanonical2(raw.Bytes(), &r, 8192)
		if err == nil {
			binding, e := AllocationBindingID2(c.Context.Binding)
			err = e
			if err == nil {
				err = validateAllocationReservation2(r, binding)
			}
		}
		if err == nil {
			digest, err = allocationDomain2("reservation", r)
		}
		return r, digest, err, true
	case "allocation_row":
		var r allocationRow2
		err := allocationCanonical2(raw.Bytes(), &r, 8192)
		if err == nil {
			binding, e := AllocationBindingID2(c.Context.Binding)
			err = e
			if err == nil {
				err = validateAllocationRow2(r, binding)
			}
		}
		return r, "", err, true
	case "allocation_marker":
		var m allocationMarker2
		err := allocationCanonical2(raw.Bytes(), &m, 8191)
		if err == nil {
			err = validAllocationBinding2(m.Binding)
		}
		if err == nil && (m.Application != allocationApplication2 || m.Version != 2 || m.InventoryID != m.Binding.InventoryID) {
			err = ErrAllocationInvalid
		}
		return m, "", err, true
	}
	return nil, "", nil, false
}

func TestTransferAllocationIndependentCodecs(t *testing.T) {
	r := readTransferAllocationReference(t)
	count := 0
	for _, c := range r.Positives {
		t.Run(c.Name, func(t *testing.T) {
			v, digest, err, ok := checkTransferAllocationReference(t, c)
			if !ok {
				return
			}
			count++
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(v)
			if err != nil || string(raw) != c.CanonicalUTF8 {
				t.Fatal("independent canonical bytes differ")
			}
			if c.Digest != "" && digest != c.Digest {
				t.Fatal("independent digest differs")
			}
		})
	}
	if count != 34 {
		t.Fatalf("coverage %d, expected34", count)
	}
}

func TestTransferAllocationIndependentRefusals(t *testing.T) {
	r := readTransferAllocationReference(t)
	count, managerCases := 0, 0
	for _, c := range r.Negatives {
		t.Run(c.Name, func(t *testing.T) {
			// False BIP32-invalid children require the concrete manager's bounded
			// derivation proof. A parsed reservation never supplies that capability.
			if c.Kind == "reservation2" {
				managerCases++
				return
			}
			_, _, err, ok := checkTransferAllocationReference(t, c)
			if !ok {
				return
			}
			count++
			if err == nil {
				t.Fatal("accepted independent invalid value")
			}
		})
	}
	if count != 14 || managerCases != 4 {
		t.Fatalf("coverage codec%d manager%d", count, managerCases)
	}
}

func TestTransferAllocationCanonicalBounds(t *testing.T) {
	r := readTransferAllocationReference(t)
	var c transferAllocationReferenceCase
	for _, x := range r.Positives {
		if x.Kind == "request2" {
			c = x
			break
		}
	}
	raw := []byte(c.CanonicalUTF8)
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), '\n'),
		bytes.Replace(raw, []byte("\"version\":2"), []byte("\"version\":2,\"version\":2"), 1),
		bytes.Replace(raw, []byte("\"version\":2"), []byte("\"version\":2.0"), 1),
		bytes.Repeat([]byte(" "), 4097),
	} {
		var got AllocationRequest2
		if allocationCanonical2(bad, &got, 4096) == nil {
			t.Fatal("accepted noncanonical/bounded request")
		}
	}
}
