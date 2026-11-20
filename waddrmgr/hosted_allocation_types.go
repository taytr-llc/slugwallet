// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const HostedAllocationManagerVersion uint32 = 13
const HostedAllocationMaxRecords = 1024
const HostedAllocationMaxBytes = 4 * 1024 * 1024

var (
	ErrHostedAllocationProfile  = errors.New("unsupported hosted allocation profile")
	ErrHostedAllocationInvalid  = errors.New("invalid hosted allocation")
	ErrHostedAllocationCorrupt  = errors.New("corrupt hosted allocation")
	ErrHostedAllocationConflict = errors.New("hosted allocation conflict")
	ErrHostedAllocationCapacity = errors.New("hosted allocation capacity")
	ErrHostedAllocationFrontier = errors.New("hosted allocation frontier")
	hostedAllocationGuardKey    = []byte("hostedallocationguard")
	hostedAllocationMetaKey     = []byte("meta")
	hostedAllocationRecordsKey  = []byte("records")
)

// These are privileged local storage DTOs, not inventory/account capabilities.
type HostedAllocationGuard struct {
	Version               uint32 `json:"version"`
	State                 string `json:"state"`
	InventoryID           string `json:"inventory_id"`
	AuthorityID           string `json:"authority_id"`
	AccountID             string `json:"account_id"`
	WalletOwnerID         string `json:"wallet_owner_id"`
	SourceBindingID       string `json:"source_binding_id"`
	InitialManifestSHA256 string `json:"initial_manifest_sha256"`
	BindingID             string `json:"binding_id"`
}
type HostedAllocationMeta struct {
	Version           uint32    `json:"version"`
	GuardSHA256       string    `json:"guard_sha256"`
	CompletedSequence uint32    `json:"completed_sequence"`
	Cursors           [8]uint32 `json:"cursors"`
}
type HostedAllocationRecord struct {
	Version               uint32    `json:"version"`
	InventoryID           string    `json:"inventory_id"`
	BindingID             string    `json:"binding_id"`
	Sequence              uint32    `json:"sequence"`
	AllocationID          string    `json:"allocation_id"`
	ReservationDigest     string    `json:"reservation_digest"`
	RequestDigest         string    `json:"request_digest"`
	Outcome               string    `json:"outcome"`
	Purpose               uint32    `json:"purpose"`
	Branch                uint32    `json:"branch"`
	StartIndex            uint32    `json:"start_index"`
	EndIndex              uint32    `json:"end_index"`
	SelectedIndex         uint32    `json:"selected_index"`
	InvalidIndices        []uint32  `json:"invalid_indices"`
	Address               string    `json:"address"`
	Script                string    `json:"script"`
	CursorsBefore         [8]uint32 `json:"cursors_before"`
	CursorsAfter          [8]uint32 `json:"cursors_after"`
	WithdrawalBindingID   string    `json:"withdrawal_binding_id"`
	WithdrawalOperationID string    `json:"withdrawal_operation_id"`
	DraftDigest           string    `json:"draft_digest"`
}
type HostedAllocationState struct {
	Guard        HostedAllocationGuard
	Meta         HostedAllocationMeta
	Records      []HostedAllocationRecord
	LogicalBytes uint64
}
type HostedAllocationRange struct {
	Purpose, Branch, StartIndex, EndIndex, SelectedIndex uint32
	InvalidIndices                                       []uint32
	Address, Script                                      string
}
type HostedAllocationPlan struct {
	manager   *Manager
	guard     HostedAllocationGuard
	sequence  uint32
	before    [8]uint32
	candidate HostedAllocationRange
}

func hostedHex(s string, nonzero bool) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s && (!nonzero || !bytes.Equal(b, make([]byte, 32)))
}
func hostedHash(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func hostedDecode(raw []byte, limit int, dst any) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrHostedAllocationCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrHostedAllocationCorrupt
	}
	again, e := json.Marshal(dst)
	if e != nil || !bytes.Equal(raw, again) {
		return ErrHostedAllocationCorrupt
	}
	return nil
}
func validHostedGuard(g HostedAllocationGuard) bool {
	if g.Version != 1 || !hostedHex(g.InventoryID, true) || !hostedHex(g.AuthorityID, true) || !hostedHex(g.AccountID, true) || !hostedHex(g.WalletOwnerID, true) || !hostedHex(g.SourceBindingID, true) || !hostedHex(g.InitialManifestSHA256, false) {
		return false
	}
	return g.State == "locked" && g.BindingID == "" || g.State == "bound" && hostedHex(g.BindingID, false)
}
func HostedAllocationGuardDigest(g HostedAllocationGuard) (string, error) {
	if !validHostedGuard(g) {
		return "", ErrHostedAllocationInvalid
	}
	raw, e := json.Marshal(g)
	if e != nil || len(raw) > 2048 {
		return "", ErrHostedAllocationInvalid
	}
	return hostedHash("SLUG hosted allocation wallet guard\x00v1\x00", raw), nil
}
func validHostedRecord(r HostedAllocationRecord) bool {
	if r.Version != 1 || !hostedHex(r.InventoryID, true) || !hostedHex(r.BindingID, false) || r.Sequence == 0 || r.Sequence > 1024 || !hostedHex(r.AllocationID, true) || !hostedHex(r.ReservationDigest, false) || !hostedHex(r.RequestDigest, false) || (r.Outcome != "consumed" && r.Outcome != "burned") || r.Purpose != 84 || r.Branch > 1 || r.EndIndex > 4096 || r.StartIndex >= r.EndIndex || r.EndIndex-r.StartIndex > 128 || r.SelectedIndex != r.EndIndex-1 || r.InvalidIndices == nil || len(r.InvalidIndices) != int(r.SelectedIndex-r.StartIndex) || len(r.Address) == 0 || len(r.Address) > 90 || len(r.Script) != 44 {
		return false
	}
	b, e := hex.DecodeString(r.Script)
	if e != nil || hex.EncodeToString(b) != r.Script || b[0] != 0 || b[1] != 20 {
		return false
	}
	for i, n := range r.InvalidIndices {
		if n != r.StartIndex+uint32(i) {
			return false
		}
	}
	for i, n := range r.CursorsBefore {
		if n > 4096 || r.CursorsAfter[i] > 4096 || i != 4+int(r.Branch) && n != r.CursorsAfter[i] {
			return false
		}
	}
	if r.CursorsBefore[4+r.Branch] != r.StartIndex || r.CursorsAfter[4+r.Branch] != r.EndIndex {
		return false
	}
	if r.Branch == 0 {
		return r.WithdrawalBindingID == "" && r.WithdrawalOperationID == "" && r.DraftDigest == ""
	}
	return hostedHex(r.WithdrawalBindingID, false) && hostedHex(r.WithdrawalOperationID, true) && (r.Outcome == "burned" && r.DraftDigest == "" || r.Outcome == "consumed" && hostedHex(r.DraftDigest, false))
}
func HostedAllocationRecordDigest(r HostedAllocationRecord) (string, error) {
	if !validHostedRecord(r) {
		return "", ErrHostedAllocationInvalid
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 4096 {
		return "", ErrHostedAllocationCapacity
	}
	return hostedHash("SLUG hosted allocation wallet record\x00v1\x00", raw), nil
}

// Marshal/Parse helpers preserve the exact canonical local-record bytes. They
// validate data only and cannot mint a live allocation plan or inventory proof.
func MarshalHostedAllocationGuard(g HostedAllocationGuard) ([]byte, error) {
	if _, err := HostedAllocationGuardDigest(g); err != nil {
		return nil, err
	}
	return json.Marshal(g)
}
func ParseHostedAllocationGuard(raw []byte) (HostedAllocationGuard, error) {
	var g HostedAllocationGuard
	if hostedDecode(raw, 2048, &g) != nil || !validHostedGuard(g) {
		return HostedAllocationGuard{}, ErrHostedAllocationCorrupt
	}
	return g, nil
}
func MarshalHostedAllocationRecord(r HostedAllocationRecord) ([]byte, error) {
	if _, err := HostedAllocationRecordDigest(r); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
func ParseHostedAllocationRecord(raw []byte) (HostedAllocationRecord, error) {
	var r HostedAllocationRecord
	if hostedDecode(raw, 4096, &r) != nil || !validHostedRecord(r) {
		return HostedAllocationRecord{}, ErrHostedAllocationCorrupt
	}
	return r, nil
}
