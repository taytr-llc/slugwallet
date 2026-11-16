//go:build integration && recoveryintegration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectjob"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/registry"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/wallet"
)

type recoveryAdmission struct {
	store         *registry.Store
	node          *node
	context       prospect.Context
	policy        prospectnode.Policy
	publicKey     string
	proof         prospect.Proof
	authorization gymauth.Authorization
	receipt       registry.Record
}

func checkRecoveryGym(t *testing.T, w *wallet.Wallet, fixture recoveryFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := w.GymIdentity(ctx)
	if err != nil {
		t.Fatal("public wallet gym identity:", err)
	}
	manifest := fixture.Export.Manifest
	if identity.Version != 1 || identity.Profile != manifest.Profile ||
		identity.Network != manifest.Network || identity.Genesis != manifest.Genesis ||
		identity.PublicKey != manifest.GymPublicKey || identity.GymID != manifest.GymID {
		t.Fatal("wallet gym identity differs from the independent seed/profile vector")
	}
}

func (admission *recoveryAdmission) checkParent() error {
	var best struct {
		Hash   string `json:"hash"`
		Height uint32 `json:"height"`
	}
	if err := admission.node.rpc.call("getbestblock", nil, &best); err != nil {
		return err
	}
	if best.Hash != admission.context.ParentHash || best.Height != admission.context.ParentHeight {
		return fmt.Errorf("isolated fixture parent changed")
	}
	return nil
}

func (admission *recoveryAdmission) guard(chainContext prospect.Context,
	_ prospect.Proof, _ prospect.Verified) (registry.Eligibility, error) {

	if chainContext != admission.context {
		return registry.Eligibility{}, fmt.Errorf("unexpected fixture policy/context")
	}
	if err := admission.checkParent(); err != nil {
		return registry.Eligibility{}, err
	}
	return registry.Eligibility{
		RuleVersion: registry.EligibilityRuleVersion2, Source: "current-parent",
		Hash: chainContext.ParentHash, Height: chainContext.ParentHeight,
	}, nil
}

// makeRecoveryProof creates one public fixture share, never a submitted block.
// The all-ff prospect threshold deliberately accepts nonce0. Context is an
// assertion by this test authority, not a production target or GBT adapter test.
// Full production Argon2id verification occurs outside every wallet operation.
func makeRecoveryProof(t *testing.T, job prospectjob.Job) prospect.Proof {
	t.Helper()
	commitment, err := prospectjob.CommitmentScript(job)
	if err != nil {
		t.Fatal(err)
	}
	script, err := txscript.NewScriptBuilder().AddInt64(int64(job.Context.ParentHeight) + 1).
		AddData([]byte("PUBLIC-RECOVERY-FIXTURE")).Script()
	if err != nil {
		t.Fatal(err)
	}
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: wire.MaxPrevOutIndex}, script, nil))
	coinbase.AddTxOut(wire.NewTxOut(10e8, []byte{txscript.OP_TRUE}))
	coinbase.AddTxOut(wire.NewTxOut(0, commitment))
	var transaction bytes.Buffer
	if err := coinbase.SerializeNoWitness(&transaction); err != nil {
		t.Fatal(err)
	}
	parent, err := chainhash.NewHashFromStr(job.Context.ParentHash)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := uint32(time.Now().Unix())
	if timestamp < job.Context.MinTimestamp {
		timestamp = job.Context.MinTimestamp
	}
	header := wire.BlockHeader{Version: 0x20000000, PrevBlock: *parent,
		MerkleRoot: coinbase.TxHash(), Timestamp: time.Unix(int64(timestamp), 0),
		Bits: job.Context.ExpectedBits}
	var serialized bytes.Buffer
	if err := header.Serialize(&serialized); err != nil {
		t.Fatal(err)
	}
	proof := prospect.Proof{Version: prospect.Version2, GymID: job.GymID,
		JobID: job.ID, Header: hex.EncodeToString(serialized.Bytes()),
		Coinbase: hex.EncodeToString(transaction.Bytes()), MerkleBranch: []string{}}
	if _, err := prospect.Verify(job.Context, proof); err != nil {
		t.Fatal("production proof verification outside wallet signer:", err)
	}
	return proof
}

func newRecoveryAdmission(t *testing.T, n *node, w *wallet.Wallet,
	fixture recoveryFixture) *recoveryAdmission {

	t.Helper()
	var info struct {
		Blocks        uint32 `json:"blocks"`
		BestBlockHash string `json:"bestblockhash"`
		MedianTime    uint32 `json:"mediantime"`
	}
	n.rpc.must(t, "getblockchaininfo", nil, &info)
	var parent struct {
		Bits string `json:"bits"`
	}
	n.rpc.must(t, "getblockheader", []any{info.BestBlockHash, true}, &parent)
	bits, err := strconv.ParseUint(parent.Bits, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	// The fixed fixture chain is below its first difficulty adjustment. The
	// header bits are a test-authority assertion; no public worker uses them.
	if info.Blocks != 101 {
		t.Fatal("unexpected fixture admission height")
	}
	chainContext := prospect.Context{Version: 1, Network: recoveryNetwork,
		Genesis: genesis, DNAVersion: 1, ProspectTarget: strings.Repeat("f", 64),
		ParentHash: info.BestBlockHash, ParentHeight: info.Blocks,
		ExpectedBits: uint32(bits), MinTimestamp: info.MedianTime + 1,
		MaxTimestamp: uint32(time.Now().Unix()) + 7200}
	store, err := registry.CreateMining(filepath.Join(t.TempDir(), "fixture-authority"),
		chainContext.Network, chainContext.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error("fixture authority close:", err)
		}
	})
	admission := &recoveryAdmission{store: store, node: n, context: chainContext,
		publicKey: fixture.Export.Manifest.GymPublicKey,
		policy: prospectnode.Policy{Version: 1, Network: chainContext.Network,
			Genesis: genesis, DNAVersion: 1, ProspectTarget: chainContext.ProspectTarget}}
	job, err := store.IssueJob(chainContext, admission.publicKey, admission.checkParent)
	if err != nil {
		t.Fatal(err)
	}
	admission.proof = makeRecoveryProof(t, job)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	signer, err := w.ProspectSigner(ctx, admission.policy)
	if err != nil {
		t.Fatal(err)
	}
	admission.authorization, err = signer(ctx, chainContext, admission.proof)
	if err != nil || gymauth.VerifyAuthorization(chainContext, admission.proof, admission.authorization) != nil {
		t.Fatal("automatic wallet admission signing:", err)
	}
	var inserted bool
	admission.receipt, inserted, err = store.RecordJobChecked(admission.proof,
		admission.authorization, admission.guard)
	if err != nil || !inserted || admission.receipt.Verified.GymID != fixture.Export.Manifest.GymID {
		t.Fatal("fixture authority rejected original wallet authorization:", err)
	}
	return admission
}

const recoveryNetwork = 1397511495

func (admission *recoveryAdmission) checkRestored(t *testing.T, w *wallet.Wallet) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	signer, err := w.ProspectSigner(ctx, admission.policy)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := signer(ctx, admission.context, admission.proof)
	if err != nil || authorization != admission.authorization {
		t.Fatal("restored wallet changed deterministic admission authorization:", err)
	}
	replayed, inserted, err := admission.store.RecordJobChecked(admission.proof,
		authorization, func(prospect.Context, prospect.Proof, prospect.Verified) (registry.Eligibility, error) {
			t.Error("historical receipt unnecessarily consulted node eligibility")
			return registry.Eligibility{}, fmt.Errorf("unexpected historical guard")
		})
	if err != nil || inserted || !reflect.DeepEqual(replayed, admission.receipt) {
		t.Fatal("restored signature did not recover immutable original birth/receipt:", err)
	}
	job, err := admission.store.IssueJob(admission.context, admission.publicKey, admission.checkParent)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeRecoveryProof(t, job)
	authorization, err = signer(ctx, admission.context, proof)
	if err != nil || gymauth.VerifyAuthorization(admission.context, proof, authorization) != nil {
		t.Fatal("restored automatic signer failed a fresh issued job:", err)
	}
	receipt, inserted, err := admission.store.RecordJobChecked(proof, authorization, admission.guard)
	if err != nil || !inserted || receipt.Verified.GymID != admission.receipt.Verified.GymID ||
		receipt.Birth == nil || receipt.Birth.BornAtMS != job.IssuedAtMS {
		t.Fatal("restored wallet failed fresh authority admission:", err)
	}
}
