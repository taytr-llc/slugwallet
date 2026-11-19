// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/btcutil/v2/txsort"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/wallet/txauthor"
	"github.com/taytr-llc/slugwallet/wallet/txrules"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

var (
	ErrWithdrawalInvalid        = errors.New("invalid candidate withdrawal")
	ErrWithdrawalProfile        = errors.New("unsupported candidate withdrawal profile")
	ErrWithdrawalBusy           = errors.New("candidate withdrawal busy")
	ErrWithdrawalClosed         = errors.New("candidate withdrawal closed")
	ErrWithdrawalNotFound       = errors.New("candidate withdrawal not found")
	ErrWithdrawalConflict       = errors.New("candidate withdrawal conflict")
	ErrWithdrawalCapacity       = errors.New("candidate withdrawal capacity")
	ErrWithdrawalUnavailable    = errors.New("candidate withdrawal unavailable")
	ErrWithdrawalCorrupt        = errors.New("candidate withdrawal corrupt")
	ErrWithdrawalStorage        = errors.New("candidate withdrawal storage failed")
	ErrWithdrawalOutcomeUnknown = errors.New("candidate withdrawal outcome unknown")
)

const (
	CandidateWithdrawalMaxOperations        = 128
	CandidateWithdrawalMaxInputs            = 16
	CandidateWithdrawalMaxDraftBytes        = 16384
	CandidateWithdrawalMaxRecordBytes       = 32768
	CandidateWithdrawalMaxSignedBytes       = 4096
	CandidateWithdrawalFeeRate        int64 = 1000
	CandidateWithdrawalFeeCeiling     int64 = 100000
)

type CandidateWithdrawalRequest struct {
	Version     uint32 `json:"version"`
	OperationID string `json:"operation_id"`
	Recipient   string `json:"recipient"`
	AmountAtoms int64  `json:"amount_atoms"`
}
type CandidateWithdrawalInput struct {
	TxID        string `json:"txid"`
	OutputIndex uint32 `json:"output_index"`
	Atoms       int64  `json:"atoms"`
	Script      string `json:"script"`
	Branch      uint32 `json:"branch"`
	Index       uint32 `json:"index"`
	BlockHash   string `json:"block_hash"`
	BlockHeight int32  `json:"block_height"`
	Coinbase    bool   `json:"coinbase"`
}
type CandidateWithdrawalChange struct {
	Address     string `json:"address"`
	Script      string `json:"script"`
	Index       uint32 `json:"index"`
	OutputIndex int32  `json:"output_index"`
	Atoms       int64  `json:"atoms"`
}
type CandidateWithdrawalDraft struct {
	Version              uint32                     `json:"version"`
	BindingID            string                     `json:"binding_id"`
	OperationID          string                     `json:"operation_id"`
	Recipient            string                     `json:"recipient"`
	RecipientScript      string                     `json:"recipient_script"`
	AmountAtoms          int64                      `json:"amount_atoms"`
	RecipientOutputIndex uint32                     `json:"recipient_output_index"`
	FeeRateAtomsPerKB    int64                      `json:"fee_rate_atoms_per_kb"`
	FeeCeilingAtoms      int64                      `json:"fee_ceiling_atoms"`
	MinConfirmations     uint32                     `json:"min_confirmations"`
	TipHash              string                     `json:"tip_hash"`
	TipHeight            int32                      `json:"tip_height"`
	TxVersion            int32                      `json:"tx_version"`
	InputSequence        uint32                     `json:"input_sequence"`
	LockTime             uint32                     `json:"lock_time"`
	SighashType          uint32                     `json:"sighash_type"`
	Inputs               []CandidateWithdrawalInput `json:"inputs"`
	TotalInputAtoms      int64                      `json:"total_input_atoms"`
	Change               CandidateWithdrawalChange  `json:"change"`
	FeeAtoms             int64                      `json:"fee_atoms"`
	UnsignedTxHex        string                     `json:"unsigned_tx_hex"`
}
type CandidateWithdrawalRecord struct {
	Version      uint32                   `json:"version"`
	State        string                   `json:"state"`
	DraftDigest  string                   `json:"draft_digest"`
	Draft        CandidateWithdrawalDraft `json:"draft"`
	RetainedTxID string                   `json:"retained_txid"`
}
type CandidateWithdrawalSigned struct {
	Version     uint32 `json:"version"`
	OperationID string `json:"operation_id"`
	DraftDigest string `json:"draft_digest"`
	TxID        string `json:"txid"`
	RawHex      string `json:"raw_hex"`
}

func withdrawalHex(s string, n int, nonzero bool) bool {
	if len(s) != 2*n || s != strings.ToLower(s) {
		return false
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return false
	}
	return !nonzero || !bytes.Equal(b, make([]byte, n))
}
func withdrawalRecipient(s string) ([]byte, error) {
	if len(s) == 0 || len(s) > 90 {
		return nil, ErrWithdrawalInvalid
	}
	for i := range s {
		if s[i] < 33 || s[i] > 126 {
			return nil, ErrWithdrawalInvalid
		}
	}
	a, e := address.DecodeAddress(s, &chaincfg.MainNetParams)
	if e != nil || !a.IsForNet(&chaincfg.MainNetParams) || a.EncodeAddress() != s {
		return nil, ErrWithdrawalInvalid
	}
	switch a.(type) {
	case *address.AddressPubKeyHash, *address.AddressScriptHash, *address.AddressWitnessPubKeyHash, *address.AddressTaproot:
	default:
		return nil, ErrWithdrawalInvalid
	}
	p, e := txscript.PayToAddrScript(a)
	if e != nil || len(p) > 34 {
		return nil, ErrWithdrawalInvalid
	}
	return p, nil
}
func validateWithdrawalRequest(r CandidateWithdrawalRequest) ([]byte, error) {
	if r.Version != 1 || !withdrawalHex(r.OperationID, 32, true) || r.AmountAtoms <= 0 || r.AmountAtoms > int64(btcutil.MaxSatoshi) {
		return nil, ErrWithdrawalInvalid
	}
	p, e := withdrawalRecipient(r.Recipient)
	if e != nil {
		return nil, e
	}
	if txrules.CheckOutput(wire.NewTxOut(r.AmountAtoms, p), txrules.DefaultRelayFeePerKb) != nil {
		return nil, ErrWithdrawalInvalid
	}
	return p, nil
}

// CandidateWithdrawalDraftDigest validates the frozen value grammar before
// hashing. It is not wallet ownership, account authorization or spendability.
func CandidateWithdrawalDraftDigest(d CandidateWithdrawalDraft) (string, error) {
	if _, e := validateWithdrawalDraft(d); e != nil {
		return "", e
	}
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > CandidateWithdrawalMaxDraftBytes {
		return "", ErrWithdrawalInvalid
	}
	h := sha256.New()
	h.Write([]byte("SLUG candidate withdrawal draft\x00v1\x00"))
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(raw)))
	h.Write(n[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validateWithdrawalDraft(d CandidateWithdrawalDraft) (*wire.MsgTx, error) {
	bad := func() (*wire.MsgTx, error) { return nil, ErrWithdrawalInvalid }
	recipient, e := validateWithdrawalRequest(CandidateWithdrawalRequest{1, d.OperationID, d.Recipient, d.AmountAtoms})
	if e != nil || d.Version != 1 || !withdrawalHex(d.BindingID, 32, true) || !withdrawalHex(d.TipHash, 32, true) || d.TipHeight < 0 || d.FeeRateAtomsPerKB != 1000 || d.FeeCeilingAtoms != 100000 || d.MinConfirmations != 1 || d.TxVersion != 1 || d.InputSequence != math.MaxUint32 || d.LockTime != 0 || d.SighashType != 1 || d.RecipientScript != hex.EncodeToString(recipient) || len(d.Inputs) < 1 || len(d.Inputs) > 16 || len(d.UnsignedTxHex) > 2048 {
		return bad()
	}
	if !withdrawalHex(d.UnsignedTxHex, len(d.UnsignedTxHex)/2, false) || len(d.UnsignedTxHex)%2 != 0 {
		return bad()
	}
	raw, _ := hex.DecodeString(d.UnsignedTxHex)
	if !withdrawalFrame(raw, false) {
		return bad()
	}
	tx := wire.NewMsgTx(1)
	reader := bytes.NewReader(raw)
	if tx.DeserializeNoWitness(reader) != nil || reader.Len() != 0 || len(tx.TxIn) != len(d.Inputs) || len(tx.TxOut) < 1 || len(tx.TxOut) > 2 || tx.Version != 1 || tx.LockTime != 0 || !txsort.IsSorted(tx) {
		return bad()
	}
	var canonical bytes.Buffer
	if tx.SerializeNoWitness(&canonical) != nil || !bytes.Equal(raw, canonical.Bytes()) {
		return bad()
	}
	seen := make(map[wire.OutPoint]bool, len(tx.TxIn))
	var total int64
	for i, in := range d.Inputs {
		ti := tx.TxIn[i]
		if !withdrawalHex(in.TxID, 32, false) || !withdrawalHex(in.BlockHash, 32, true) || !withdrawalHex(in.Script, 22, false) || !strings.HasPrefix(in.Script, "0014") || in.Branch > 1 || in.Index >= 4096 || in.BlockHeight < 0 || in.BlockHeight > d.TipHeight || in.Atoms <= 0 || in.Atoms > int64(btcutil.MaxSatoshi)-total || ti.PreviousOutPoint.Hash.String() != in.TxID || ti.PreviousOutPoint.Index != in.OutputIndex || ti.Sequence != math.MaxUint32 || len(ti.SignatureScript) != 0 || len(ti.Witness) != 0 || seen[ti.PreviousOutPoint] {
			return bad()
		}
		if in.Coinbase && int64(d.TipHeight)-int64(in.BlockHeight)+1 < int64(chaincfg.MainNetParams.CoinbaseMaturity) {
			return bad()
		}
		seen[ti.PreviousOutPoint] = true
		total += in.Atoms
	}
	if total != d.TotalInputAtoms || d.FeeAtoms < 1 || d.FeeAtoms > 100000 {
		return bad()
	}
	changeScript, e := withdrawalRecipient(d.Change.Address)
	if e != nil || len(changeScript) != 22 || changeScript[0] != 0 || changeScript[1] != 20 || d.Change.Script != hex.EncodeToString(changeScript) || d.Change.Index >= 4096 {
		return bad()
	}
	role := -1
	var outsum int64
	for i, o := range tx.TxOut {
		if o.Value < 0 || o.Value > int64(btcutil.MaxSatoshi)-outsum || txrules.CheckOutput(o, 1000) != nil {
			return bad()
		}
		outsum += o.Value
		if role < 0 && o.Value == d.AmountAtoms && bytes.Equal(o.PkScript, recipient) {
			role = i
		}
	}
	if role < 0 || uint32(role) != d.RecipientOutputIndex || total-outsum != d.FeeAtoms {
		return bad()
	}
	if len(tx.TxOut) == 1 {
		if d.Change.OutputIndex != -1 || d.Change.Atoms != 0 {
			return bad()
		}
	} else {
		other := 1 - role
		o := tx.TxOut[other]
		if d.Change.OutputIndex != int32(other) || d.Change.Atoms <= 0 || o.Value != d.Change.Atoms || !bytes.Equal(o.PkScript, changeScript) {
			return bad()
		}
	}
	// Reproduce the fixed fee/dust arithmetic over these exact saved inputs,
	// using the already allocated public change script (no wallet mutation).
	credits := make([]wtxmgr.Credit, len(d.Inputs))
	for i, in := range d.Inputs {
		op, _ := withdrawalOutpoint(in)
		script, _ := hex.DecodeString(in.Script)
		credits[i] = wtxmgr.Credit{OutPoint: op, Amount: btcutil.Amount(in.Atoms), PkScript: script}
	}
	funded, err := txauthor.NewUnsignedTransaction([]*wire.TxOut{wire.NewTxOut(d.AmountAtoms, recipient)}, 1000, constantInputSource(credits), &txauthor.ChangeSource{ScriptSize: 22, NewScript: func() ([]byte, error) { return changeScript, nil }})
	if err != nil {
		return bad()
	}
	txsort.InPlaceSort(funded.Tx)
	var fundedBytes bytes.Buffer
	if funded.Tx.SerializeNoWitness(&fundedBytes) != nil || !bytes.Equal(fundedBytes.Bytes(), raw) {
		return bad()
	}
	return tx, nil
}
func withdrawalDecode(raw []byte, limit int, value any) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrWithdrawalCorrupt
	}
	// A bounded token walk limits containers before unmarshalling DTO slices.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func(int, string) error
	walk = func(depth int, key string) error {
		if depth > 7 {
			return ErrWithdrawalCorrupt
		}
		t, e := dec.Token()
		if e != nil {
			return ErrWithdrawalCorrupt
		}
		switch x := t.(type) {
		case json.Delim:
			switch x {
			case '{':
				for dec.More() {
					k, e := dec.Token()
					s, ok := k.(string)
					if e != nil || !ok || len(s) > 64 {
						return ErrWithdrawalCorrupt
					}
					if e = walk(depth+1, s); e != nil {
						return e
					}
				}
				v, e := dec.Token()
				if e != nil || v != json.Delim('}') {
					return ErrWithdrawalCorrupt
				}
			case '[':
				if key != "inputs" {
					return ErrWithdrawalCorrupt
				}
				n := 0
				for dec.More() {
					n++
					if n > 16 {
						return ErrWithdrawalCorrupt
					}
					if e := walk(depth+1, ""); e != nil {
						return e
					}
				}
				v, e := dec.Token()
				if e != nil || v != json.Delim(']') {
					return ErrWithdrawalCorrupt
				}
			default:
				return ErrWithdrawalCorrupt
			}
		case string:
			if len(x) > 8192 {
				return ErrWithdrawalCorrupt
			}
			for i := range x {
				if x[i] > 127 {
					return ErrWithdrawalCorrupt
				}
			}
		case json.Number:
			n, e := strconv.ParseInt(string(x), 10, 64)
			if e != nil || strconv.FormatInt(n, 10) != string(x) {
				return ErrWithdrawalCorrupt
			}
		case bool:
		default:
			return ErrWithdrawalCorrupt
		}
		return nil
	}
	if e := walk(0, ""); e != nil {
		return e
	}
	if _, e := dec.Token(); e != io.EOF {
		return ErrWithdrawalCorrupt
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(value) != nil {
		return ErrWithdrawalCorrupt
	}
	canonical, e := json.Marshal(value)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrWithdrawalCorrupt
	}
	return nil
}
func withdrawalOutpoint(in CandidateWithdrawalInput) (wire.OutPoint, error) {
	h, e := chainhash.NewHashFromStr(in.TxID)
	if e != nil {
		return wire.OutPoint{}, ErrWithdrawalCorrupt
	}
	return wire.OutPoint{Hash: *h, Index: in.OutputIndex}, nil
}
func withdrawalKey(op wire.OutPoint) []byte {
	v := make([]byte, 36)
	copy(v, op.Hash[:])
	binary.LittleEndian.PutUint32(v[32:], op.Index)
	return v
}
