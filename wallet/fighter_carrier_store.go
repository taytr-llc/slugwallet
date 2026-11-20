// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

var carrierWalletNamespace = []byte("slug-fighter-carrier-v1")
var purposeExclusionsNamespace = []byte("slug-purpose-exclusions-v1")
var carrierMetaKey = []byte("meta")
var carrierRecordsKey = []byte("records")
var purposeInputsKey = []byte("inputs")

type carrierWalletMeta struct {
	Version         uint32 `json:"version"`
	State           string `json:"state"`
	JournalID       string `json:"journal_id"`
	BindingID       string `json:"binding_id"`
	IdentitySHA256  string `json:"identity_sha256"`
	RecordCount     uint32 `json:"record_count"`
	ActiveRequestID string `json:"active_request_id"`
}
type purposeExclusionMeta struct {
	Version             uint32 `json:"version"`
	ManagerSchema       uint32 `json:"manager_schema"`
	CarrierJournalID    string `json:"carrier_journal_id"`
	WithdrawalJournalID string `json:"withdrawal_journal_id"`
	EntryCount          uint32 `json:"entry_count"`
}
type purposeExclusion struct {
	Version           uint32 `json:"version"`
	OwnerKind         string `json:"owner_kind"`
	RequestID         string `json:"request_id"`
	BindingID         string `json:"binding_id"`
	PreparationDigest string `json:"preparation_digest"`
	State             string `json:"state"`
}
type carrierWalletState struct {
	meta    carrierWalletMeta
	records []fightercarrier.WalletRecord
	bytes   uint64
}

func carrierSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Initialization is always in the same transaction as the fresh manager guard
// or ready12 activation. An established missing namespace is never recreated.
func createCarrierWalletNamespaces(tx walletdb.ReadWriteTx, schema uint32, journal, withdrawal string, pin *fightercarrier.Pin) error {
	if schema != 14 && schema != 15 || !withdrawalHex(journal, 32, true) || schema == 14 && !withdrawalHex(withdrawal, 32, true) || schema == 15 && withdrawal != "" {
		return fightercarrier.ErrInvalid
	}
	if tx.ReadBucket(carrierWalletNamespace) != nil || tx.ReadBucket(purposeExclusionsNamespace) != nil {
		return fightercarrier.ErrConflict
	}
	ns, e := tx.CreateTopLevelBucket(carrierWalletNamespace)
	if e != nil {
		return e
	}
	if _, e = ns.CreateBucket(carrierRecordsKey); e != nil {
		return e
	}
	m := carrierWalletMeta{Version: 1, State: "unbound", JournalID: journal}
	if pin != nil {
		if e = fightercarrier.ValidatePin(*pin); e != nil {
			return e
		}
		if pin.ManagerSchema != schema {
			return fightercarrier.ErrInvalid
		}
		m.State = "ready"
		m.BindingID, e = fightercarrier.BindingID(fightercarrier.Identity{JournalID: journal, Pin: *pin})
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(pin)
		m.IdentitySHA256 = carrierSHA(raw)
	}
	raw, _ := json.Marshal(m)
	if e = ns.Put(carrierMetaKey, raw); e != nil {
		return e
	}
	ns, e = tx.CreateTopLevelBucket(purposeExclusionsNamespace)
	if e != nil {
		return e
	}
	if _, e = ns.CreateBucket(purposeInputsKey); e != nil {
		return e
	}
	raw, _ = json.Marshal(purposeExclusionMeta{Version: 1, ManagerSchema: schema, CarrierJournalID: journal, WithdrawalJournalID: withdrawal})
	return ns.Put(carrierMetaKey, raw)
}
func carrierDecode(raw []byte, cap int, target any) error {
	if len(raw) == 0 || len(raw) > cap {
		return fightercarrier.ErrCorrupt
	}
	// Walk bounded typed containers before decoding any DTO slices.
	walkDecoder := json.NewDecoder(bytes.NewReader(raw))
	walkDecoder.UseNumber()
	tokens, objects := 0, 0
	var walk func(int, string) error
	walk = func(depth int, key string) error {
		if depth > 16 {
			return fightercarrier.ErrCorrupt
		}
		tokens++
		if tokens > 262144 {
			return fightercarrier.ErrCapacity
		}
		token, e := walkDecoder.Token()
		if e != nil {
			return fightercarrier.ErrCorrupt
		}
		switch x := token.(type) {
		case json.Delim:
			switch x {
			case '{':
				objects++
				if objects > 8192 {
					return fightercarrier.ErrCapacity
				}
				seen := map[string]bool{}
				for walkDecoder.More() {
					k, e := walkDecoder.Token()
					s, ok := k.(string)
					if e != nil || !ok || len(s) > 64 || seen[s] {
						return fightercarrier.ErrCorrupt
					}
					seen[s] = true
					if e = walk(depth+1, s); e != nil {
						return e
					}
				}
				end, e := walkDecoder.Token()
				if e != nil || end != json.Delim('}') {
					return fightercarrier.ErrCorrupt
				}
			case '[':
				limit, exact := 0, 0
				switch key {
				case "inputs":
					limit = 16
				case "invalid_indices":
					limit = 127
				case "cursors", "cursors_before", "cursors_after", "activation_cursors":
					limit = 8
					exact = 8
				case "accounts":
					limit = 4
					exact = 4
				default:
					return fightercarrier.ErrCorrupt
				}
				n := 0
				for walkDecoder.More() {
					n++
					if n > limit {
						return fightercarrier.ErrCapacity
					}
					if e = walk(depth+1, ""); e != nil {
						return e
					}
				}
				end, e := walkDecoder.Token()
				if e != nil || end != json.Delim(']') || exact != 0 && n != exact {
					return fightercarrier.ErrCorrupt
				}
			default:
				return fightercarrier.ErrCorrupt
			}
		case string:
			if len(x) > 8192 {
				return fightercarrier.ErrCapacity
			}
			for i := range x {
				if x[i] > 127 {
					return fightercarrier.ErrCorrupt
				}
			}
		case json.Number:
			n, e := strconv.ParseInt(string(x), 10, 64)
			if e != nil || strconv.FormatInt(n, 10) != string(x) {
				return fightercarrier.ErrCorrupt
			}
		case bool:
		case nil:
			if key != "new_funding" && key != "recovery_funding" && key != "restored_allocation" {
				return fightercarrier.ErrCorrupt
			}
		default:
			return fightercarrier.ErrCorrupt
		}
		return nil
	}
	if e := walk(0, ""); e != nil {
		return e
	}
	if _, e := walkDecoder.Token(); e != io.EOF {
		return fightercarrier.ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return fightercarrier.ErrCorrupt
	}
	canonical, e := json.Marshal(target)
	if e != nil || !bytes.Equal(canonical, raw) {
		return fightercarrier.ErrCorrupt
	}
	return nil
}

func carrierOutpoint(txid string, index uint32) (wire.OutPoint, error) {
	h, e := chainhash.NewHashFromStr(txid)
	if e != nil || !withdrawalHex(txid, 32, false) {
		return wire.OutPoint{}, fightercarrier.ErrCorrupt
	}
	return wire.OutPoint{Hash: *h, Index: index}, nil
}
func purposeExclusionValid(v purposeExclusion, schema uint32) bool {
	return v.Version == 1 && (v.OwnerKind == "carrier" || schema == 14 && v.OwnerKind == "withdrawal") && withdrawalHex(v.RequestID, 32, true) && withdrawalHex(v.BindingID, 32, false) && withdrawalHex(v.PreparationDigest, 32, false) && (v.State == "prepared" || v.State == "retained")
}

// This is the exact persisted common exclusion map, not a cache of spendable
// coins. Both purpose owners use it inside their original wallet transaction.
func readPurposeExclusions(ctx context.Context, tx walletdb.ReadTx, schema uint32, journal, withdrawal string) (purposeExclusionMeta, map[string]purposeExclusion, error) {
	var meta purposeExclusionMeta
	out := make(map[string]purposeExclusion)
	if ctx == nil {
		return meta, nil, fightercarrier.ErrInvalid
	}
	ns := tx.ReadBucket(purposeExclusionsNamespace)
	if e := carrierNamespaceShape(ns, purposeInputsKey); e != nil {
		return meta, nil, e
	}
	if carrierDecode(ns.Get(carrierMetaKey), 1024, &meta) != nil || meta.Version != 1 || meta.ManagerSchema != schema || meta.CarrierJournalID != journal || meta.WithdrawalJournalID != withdrawal || meta.EntryCount > 4224 || schema != 14 && schema != 15 || schema == 15 && withdrawal != "" {
		return meta, nil, fightercarrier.ErrCorrupt
	}
	logical := len(purposeExclusionsNamespace) + len(carrierMetaKey) + len(ns.Get(carrierMetaKey)) + len(purposeInputsKey)
	e := ns.NestedReadBucket(purposeInputsKey).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if len(out) >= 4224 || len(k) != 36 || v == nil || len(v) > 512 {
			return fightercarrier.ErrCorrupt
		}
		logical += len(k) + len(v)
		if logical > 4194304 {
			return fightercarrier.ErrCapacity
		}
		var row purposeExclusion
		if carrierDecode(v, 512, &row) != nil || !purposeExclusionValid(row, schema) {
			return fightercarrier.ErrCorrupt
		}
		out[string(k)] = row
		return nil
	})
	if e != nil {
		return meta, nil, e
	}
	if uint32(len(out)) != meta.EntryCount {
		return meta, nil, fightercarrier.ErrCorrupt
	}
	return meta, out, ctx.Err()
}
func auditPurposeExclusions(ctx context.Context, tx walletdb.ReadTx, pin fightercarrier.Pin, journal, withdrawal string) error {
	_, actual, e := readPurposeExclusions(ctx, tx, pin.ManagerSchema, journal, withdrawal)
	if e != nil {
		return e
	}
	var public *fightercarrier.Pin = &pin
	var walletMeta carrierWalletMeta
	carrierNS := tx.ReadBucket(carrierWalletNamespace)
	if carrierNS == nil || carrierDecode(carrierNS.Get(carrierMetaKey), 2048, &walletMeta) != nil {
		return fightercarrier.ErrCorrupt
	}
	if walletMeta.State == "unbound" {
		public = nil
	}
	state, e := readCarrierWalletState(ctx, tx, journal, public)
	if e != nil {
		return e
	}
	expected := make(map[string]purposeExclusion)
	add := func(op wire.OutPoint, row purposeExclusion) error {
		k := string(withdrawalKey(op))
		if _, ok := expected[k]; ok {
			return fightercarrier.ErrCorrupt
		}
		expected[k] = row
		return nil
	}
	for _, r := range state.records {
		if r.State == "abandoned" {
			continue
		}
		status := "prepared"
		if r.State == "retained" || r.State == "complete" {
			status = "retained"
		}
		row := purposeExclusion{1, "carrier", r.RequestID, r.BindingID, r.PreparationDigest, status}
		if r.Preparation.NewFunding != nil {
			for _, in := range r.Preparation.NewFunding.Inputs {
				op, e := carrierOutpoint(in.TxID, in.OutputIndex)
				if e != nil {
					return e
				}
				if e = add(op, row); e != nil {
					return e
				}
			}
		}
		commit := r.CommitTxID
		if r.Preparation.RecoveryFunding != nil {
			commit = r.Preparation.RecoveryFunding.CommitTxID
		}
		if commit != "" {
			op, e := carrierOutpoint(commit, 0)
			if e != nil {
				return e
			}
			if e = add(op, row); e != nil {
				return e
			}
		}
	}
	ns := tx.ReadBucket(withdrawalNamespace)
	if ns != nil {
		if pin.ManagerSchema != 14 {
			return fightercarrier.ErrCorrupt
		}
		var meta withdrawalMeta
		if withdrawalDecode(ns.Get(withdrawalMetaKey), 2048, &meta) != nil || meta.Version != 1 || meta.RecordCount > 128 {
			return fightercarrier.ErrCorrupt
		}
		ops := ns.NestedReadBucket(withdrawalOperations)
		if ops == nil {
			return fightercarrier.ErrCorrupt
		}
		count := uint32(0)
		bytes := 0
		e = ops.ForEach(func(k, v []byte) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			count++
			bytes += len(k) + len(v)
			if count > 128 || bytes > 4194304 || len(k) != 32 || v == nil {
				return fightercarrier.ErrCorrupt
			}
			var r CandidateWithdrawalRecord
			if withdrawalDecode(v, 32768, &r) != nil {
				return fightercarrier.ErrCorrupt
			}
			d, e := CandidateWithdrawalDraftDigest(r.Draft)
			if e != nil || d != r.DraftDigest || r.Draft.OperationID != hex.EncodeToString(k) || r.Draft.BindingID != meta.BindingID {
				return fightercarrier.ErrCorrupt
			}
			if r.State == "abandoned" {
				return nil
			}
			if r.State != "prepared" && r.State != "retained" {
				return fightercarrier.ErrCorrupt
			}
			row := purposeExclusion{1, "withdrawal", r.Draft.OperationID, r.Draft.BindingID, r.DraftDigest, r.State}
			for _, in := range r.Draft.Inputs {
				op, e := withdrawalOutpoint(in)
				if e != nil {
					return e
				}
				if e = add(op, row); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			return e
		}
		if count != meta.RecordCount {
			return fightercarrier.ErrCorrupt
		}
	}
	if len(expected) != len(actual) {
		return fightercarrier.ErrCorrupt
	}
	for k, v := range expected {
		if actual[k] != v {
			return fightercarrier.ErrCorrupt
		}
	}
	return ctx.Err()
}

func putPurposeExclusions(ctx context.Context, tx walletdb.ReadWriteTx, schema uint32, journal, withdrawal string, row purposeExclusion, outpoints []wire.OutPoint) error {
	if !purposeExclusionValid(row, schema) || len(outpoints) == 0 || len(outpoints) > 17 {
		return fightercarrier.ErrInvalid
	}
	meta, existing, e := readPurposeExclusions(ctx, tx, schema, journal, withdrawal)
	if e != nil {
		return e
	}
	seen := make(map[string]bool, len(outpoints))
	for _, op := range outpoints {
		k := string(withdrawalKey(op))
		if seen[k] {
			return fightercarrier.ErrInvalid
		}
		seen[k] = true
		if old, ok := existing[k]; ok {
			if old.OwnerKind != row.OwnerKind || old.RequestID != row.RequestID || old.BindingID != row.BindingID || old.PreparationDigest != row.PreparationDigest || old.State == "retained" && row.State != "retained" {
				return fightercarrier.ErrConflict
			}
		} else {
			if meta.EntryCount >= 4224 {
				return fightercarrier.ErrCapacity
			}
			meta.EntryCount++
		}
	}
	ns := tx.ReadWriteBucket(purposeExclusionsNamespace)
	raw, _ := json.Marshal(row)
	if len(raw) > 512 {
		return fightercarrier.ErrCapacity
	}
	for _, op := range outpoints {
		if e = ns.NestedReadWriteBucket(purposeInputsKey).Put(withdrawalKey(op), raw); e != nil {
			return e
		}
	}
	raw, _ = json.Marshal(meta)
	return ns.Put(carrierMetaKey, raw)
}

// Only concrete owners call this after an exact joined app abandonment lease;
// retained entries can never be released by this helper.
func removePreparedPurposeExclusions(ctx context.Context, tx walletdb.ReadWriteTx, schema uint32, journal, withdrawal, kind, id, binding, digest string) error {
	meta, rows, e := readPurposeExclusions(ctx, tx, schema, journal, withdrawal)
	if e != nil {
		return e
	}
	ns := tx.ReadWriteBucket(purposeExclusionsNamespace)
	for k, row := range rows {
		if row.OwnerKind != kind || row.RequestID != id {
			continue
		}
		if row.BindingID != binding || row.PreparationDigest != digest || row.State != "prepared" {
			return fightercarrier.ErrConflict
		}
		if e = ns.NestedReadWriteBucket(purposeInputsKey).Delete([]byte(k)); e != nil {
			return e
		}
		meta.EntryCount--
	}
	raw, _ := json.Marshal(meta)
	return ns.Put(carrierMetaKey, raw)
}
func carrierNamespaceShape(ns walletdb.ReadBucket, records []byte) error {
	if ns == nil {
		return fightercarrier.ErrCorrupt
	}
	n := 0
	e := ns.ForEach(func(k, v []byte) error {
		n++
		if n > 2 {
			return fightercarrier.ErrCorrupt
		}
		if bytes.Equal(k, carrierMetaKey) && v != nil {
			return nil
		}
		if bytes.Equal(k, records) && v == nil {
			return nil
		}
		return fightercarrier.ErrCorrupt
	})
	if e != nil || n != 2 || ns.NestedReadBucket(records) == nil {
		return fightercarrier.ErrCorrupt
	}
	return nil
}
func readCarrierWalletState(ctx context.Context, tx walletdb.ReadTx, journal string, pin *fightercarrier.Pin) (carrierWalletState, error) {
	var out carrierWalletState
	if ctx == nil {
		return out, fightercarrier.ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	ns := tx.ReadBucket(carrierWalletNamespace)
	if e := carrierNamespaceShape(ns, carrierRecordsKey); e != nil {
		return out, e
	}
	if carrierDecode(ns.Get(carrierMetaKey), 2048, &out.meta) != nil {
		return out, fightercarrier.ErrCorrupt
	}
	m := out.meta
	if m.Version != 1 || m.JournalID != journal || !withdrawalHex(journal, 32, true) || m.RecordCount > 128 {
		return out, fightercarrier.ErrCorrupt
	}
	switch m.State {
	case "unbound":
		if pin != nil || m.BindingID != "" || m.IdentitySHA256 != "" || m.RecordCount != 0 || m.ActiveRequestID != "" {
			return out, fightercarrier.ErrCorrupt
		}
	case "ready":
		if pin == nil {
			return out, fightercarrier.ErrConflict
		}
		binding, e := fightercarrier.BindingID(fightercarrier.Identity{JournalID: journal, Pin: *pin})
		raw, _ := json.Marshal(pin)
		if e != nil || binding != m.BindingID || carrierSHA(raw) != m.IdentitySHA256 {
			return out, fightercarrier.ErrConflict
		}
	default:
		return out, fightercarrier.ErrCorrupt
	}
	out.bytes = uint64(len(carrierWalletNamespace) + len(carrierMetaKey) + len(ns.Get(carrierMetaKey)) + len(carrierRecordsKey))
	e := ns.NestedReadBucket(carrierRecordsKey).ForEach(func(k, v []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if len(out.records) >= 128 || len(k) != 32 || v == nil || len(v) > fightercarrier.MaxWalletRecordBytes {
			return fightercarrier.ErrCorrupt
		}
		out.bytes += uint64(len(k) + len(v))
		if out.bytes > 4194304 {
			return fightercarrier.ErrCapacity
		}
		var r fightercarrier.WalletRecord
		if carrierDecode(v, fightercarrier.MaxWalletRecordBytes, &r) != nil || pin == nil || fightercarrier.ValidateWalletRecord(r, *pin, m.BindingID) != nil || hex.EncodeToString(k) != r.RequestID {
			return fightercarrier.ErrCorrupt
		}
		out.records = append(out.records, r)
		return nil
	})
	if e != nil {
		return out, e
	}
	sort.Slice(out.records, func(i, j int) bool { return out.records[i].Sequence < out.records[j].Sequence })
	active := ""
	for i, r := range out.records {
		if r.Sequence != uint32(i+1) {
			return out, fightercarrier.ErrCorrupt
		}
		if r.State == "prepared" || r.State == "retained" {
			if active != "" {
				return out, fightercarrier.ErrCorrupt
			}
			active = r.RequestID
		}
	}
	if uint32(len(out.records)) != m.RecordCount || active != m.ActiveRequestID {
		return out, fightercarrier.ErrCorrupt
	}
	return out, ctx.Err()
}
