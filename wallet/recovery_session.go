// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"errors"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

// RecoverySourceIdentity is supplied by a separately trusted full-node adapter.
// An adapter must pin this identity again on every new transport. It is not a
// claimant-provided proof or permission to use an unfinalized production chain.
type RecoverySourceIdentity struct {
	Network       uint32
	Genesis       chainhash.Hash
	CSVHeight     int32
	SegwitHeight  int32
	TaprootHeight int32
}

type RecoveryTip struct {
	Height int32
	Hash   chainhash.Hash
}

// RecoveryBlockSource calls must honor cancellation and return owned, bounded
// blocks. The session independently checks returned hashes and merkle binding.
// These methods are read-only; recovery never submits transactions or mines.
type RecoveryBlockSource interface {
	Identity(context.Context) (RecoverySourceIdentity, error)
	BestBlock(context.Context) (RecoveryTip, error)
	BlockHash(context.Context, int32) (chainhash.Hash, error)
	Block(context.Context, chainhash.Hash) (*wire.MsgBlock, error)
}

// RecoveryProgress is public operational state. It contains no mnemonic,
// account keys, addresses, passphrases or private wallet material.
type RecoveryProgress struct {
	Version              uint32 `json:"version"`
	Phase                string `json:"phase"`
	Ready                bool   `json:"ready"`
	Derived              uint64 `json:"derived"`
	Target               uint64 `json:"target"`
	Issued               uint64 `json:"issued"`
	ScannedHeight        int32  `json:"scanned_height"`
	ScannedHash          string `json:"scanned_hash"`
	TargetHeight         int32  `json:"target_height"`
	TargetHash           string `json:"target_hash"`
	RelevantTransactions uint32 `json:"relevant_transactions"`
	OwnedOutputs         uint32 `json:"owned_outputs"`
}

var (
	ErrRecoveryInProgress = waddrmgr.ErrRecoveryInProgress
	ErrRecoveryCapacity   = waddrmgr.ErrRecoveryQuota
	ErrRecoverySource     = errors.New("candidate recovery source rejected")
	ErrRecoveryClosed     = errors.New("candidate recovery session is closed")
	ErrRecoveryPoisoned   = errors.New("candidate recovery write outcome unknown; reopen required")
)
