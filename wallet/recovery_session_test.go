//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestRecoverySessionFourScriptsAndSpends(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 0)
	genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	payments := make([]productionprofile.PaymentPublic, 0, 4)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		payments = append(payments, reviewPayment(t, purpose, 0, 0))
	}
	first := reviewFundingBlock(t, genesis, 1, 23, payments...)
	second := reviewFundingBlock(t, first, 2, 24)
	spend := wire.NewMsgTx(2)
	fundingHash := first.Transactions[1].TxHash()
	for i := 0; i < 4; i++ {
		spend.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: fundingHash, Index: uint32(i)}, Sequence: ^uint32(0)})
	}
	change := reviewPayment(t, 84, 1, 0)
	script, err := hex.DecodeString(change.ScriptPubKey)
	if err != nil {
		t.Fatal(err)
	}
	spend.AddTxOut(wire.NewTxOut(50_000_000, script))
	second.Transactions[1] = spend
	a, b := second.Transactions[0].TxHash(), spend.TxHash()
	var pair [64]byte
	copy(pair[:32], a[:])
	copy(pair[32:], b[:])
	second.Header.MerkleRoot = chainhash.DoubleHashH(pair[:])
	source := &reviewRecoverySource{}
	source.set(genesis, first, second)
	for attempts := 0; ; attempts++ {
		if attempts > 100 {
			t.Fatal("did not reach pending spent-history checkpoint")
		}
		p, e := session.Step(context.Background(), source)
		if e != nil {
			t.Fatal(e)
		}
		if p.ScannedHeight == 2 {
			if p.Ready {
				t.Fatal("scan and ready were not separate stages")
			}
			break
		}
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	session, err = loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if err != nil {
		t.Fatal("pending spent-history audit", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	progress := reviewFinishRecovery(t, session, source)
	err = walletdb.View(session.db, func(tx walletdb.ReadTx) error {
		birthday, verified, e := session.manager.BirthdayBlock(tx.ReadBucket(waddrmgrNamespaceKey))
		if e != nil {
			return e
		}
		if !verified || birthday.Height != 0 || birthday.Hash != *chaincfg.MainNetParams.GenesisHash {
			return errors.New("ready recovery lost verified genesis birthday")
		}
		for height, block := range []*wire.MsgBlock{genesis, first, second} {
			hash, e := session.manager.BlockHash(tx.ReadBucket(waddrmgrNamespaceKey), int32(height))
			if e != nil {
				return e
			}
			if *hash != block.BlockHash() {
				return errors.New("ready recovery omitted canonical reorg history")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if progress.RelevantTransactions != 2 || progress.OwnedOutputs != 5 {
		t.Fatalf("history counts: %+v", progress)
	}
	credits := reviewRecoveryCredits(t, session)
	if len(credits) != 1 || int64(credits[0].Amount) != 50_000_000 || !bytes.Equal(credits[0].PkScript, script) {
		t.Fatalf("spend was not reconstructed: %+v", credits)
	}
	for _, purpose := range []uint32{44, 49, 84, 86} {
		if got := reviewRecoveryBranch(t, session, purpose, 0).IssuedNext; got != 1 {
			t.Fatalf("purpose%d issued%d", purpose, got)
		}
	}
	if got := reviewRecoveryBranch(t, session, 84, 1).IssuedNext; got != 1 {
		t.Fatalf("change issuance %d", got)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := loader.OpenExistingWallet(retainedPubPass, false)
	if err != nil {
		t.Fatal(err)
	}
	defer loader.UnloadWallet()
	if !opened.Manager.ResumableRecovery() {
		t.Fatal("ready schema changed")
	}
}

type recoveryBlockingIdentity struct{ entered chan struct{} }

func (b *recoveryBlockingIdentity) Identity(ctx context.Context) (RecoverySourceIdentity, error) {
	close(b.entered)
	<-ctx.Done()
	return RecoverySourceIdentity{}, ctx.Err()
}
func (*recoveryBlockingIdentity) BestBlock(context.Context) (RecoveryTip, error) {
	panic("unexpected source read")
}
func (*recoveryBlockingIdentity) BlockHash(context.Context, int32) (chainhash.Hash, error) {
	panic("unexpected source read")
}
func (*recoveryBlockingIdentity) Block(context.Context, chainhash.Hash) (*wire.MsgBlock, error) {
	panic("unexpected source read")
}

func TestRecoverySessionCloseCancelsAndJoins(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 0)
	before, err := session.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = session.Step(canceled, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, err := session.Status(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled call changed durable progress", err)
	}
	for i := 0; i < 3; i++ {
		p, e := session.Step(context.Background(), nil)
		if e != nil {
			t.Fatal(e)
		}
		if p.Phase == "scanning" {
			break
		}
	}
	blocked := &recoveryBlockingIdentity{entered: make(chan struct{})}
	finished := make(chan error, 1)
	go func() { _, e := session.Step(context.Background(), blocked); finished <- e }()
	<-blocked.entered
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	select {
	case e := <-finished:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("source operation not canceled")
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not join")
	}
	if _, e := session.Status(context.Background()); !errors.Is(e, ErrRecoveryClosed) {
		t.Fatal(e)
	}
	resumed, e := loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if e != nil {
		t.Fatal(e)
	}
	defer resumed.Close()
	if _, e = resumed.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestRecoveryTypedBlockBoundsAndOwnership(t *testing.T) {
	original := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	owned, err := ownRecoveryBlock(original)
	if err != nil {
		t.Fatal(err)
	}
	original.Transactions[0].TxOut[0].PkScript[0] ^= 1
	if bytes.Equal(original.Transactions[0].TxOut[0].PkScript, owned.Transactions[0].TxOut[0].PkScript) {
		t.Fatal("source block aliases session bytes")
	}
	cases := []*wire.MsgBlock{nil, {}, {Transactions: []*wire.MsgTx{nil}}, {Transactions: []*wire.MsgTx{{TxIn: []*wire.TxIn{nil}, TxOut: []*wire.TxOut{{}}}}}, {Transactions: []*wire.MsgTx{{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{nil}}}}}
	for _, block := range cases {
		if _, e := ownRecoveryBlock(block); !errors.Is(e, ErrRecoverySource) {
			t.Fatal("malformed typed block accepted", e)
		}
	}
}

func TestRecoveryCanceledCommitPoisonsAndRollsBack(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 0)
	before, err := session.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	original := session.update
	session.update = func(fn func(walletdb.ReadWriteTx) error) error {
		return original(func(tx walletdb.ReadWriteTx) error {
			if err := fn(tx); err != nil {
				return err
			}
			cancel()
			return ctx.Err()
		})
	}
	if _, err = session.Step(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = session.Status(context.Background()); !errors.Is(err, ErrRecoveryPoisoned) {
		t.Fatal("write failure did not require reopen", err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	after, err := resumed.Status(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled transaction advanced progress", err)
	}
	var state waddrmgr.RecoveryState
	err = walletdb.View(resumed.db, func(tx walletdb.ReadTx) error {
		var e error
		state, e = resumed.manager.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	})
	if err != nil || state.AddressCount != 0 {
		t.Fatal("canceled chunk retained address rows", err)
	}
}

type recoveryWrongIdentity struct {
	RecoveryBlockSource
	identity RecoverySourceIdentity
}

func (s recoveryWrongIdentity) Identity(context.Context) (RecoverySourceIdentity, error) {
	return s.identity, nil
}

func TestRecoverySourceIdentityAndMerkleBinding(t *testing.T) {
	_, session := reviewBeginRecovery(t, 0)
	genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	block := reviewFundingBlock(t, genesis, 1, 27, reviewPayment(t, 84, 0, 0))
	// A source can return bytes whose own header hash is correct while the body
	// does not belong to that header. Merkle validation must reject this case.
	block.Header.MerkleRoot[0] ^= 1
	source := &reviewRecoverySource{}
	source.set(genesis, block)
	for {
		p, e := session.Step(context.Background(), source)
		if e != nil {
			t.Fatal(e)
		}
		if p.Phase == "scanning" {
			break
		}
	}
	baseline, err := session.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := source.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"network", "genesis", "csv", "segwit", "taproot"} {
		bad := identity
		switch field {
		case "network":
			bad.Network++
		case "genesis":
			bad.Genesis[0] ^= 1
		case "csv":
			bad.CSVHeight--
		case "segwit":
			bad.SegwitHeight--
		case "taproot":
			bad.TaprootHeight--
		}
		if _, e := session.Step(context.Background(), recoveryWrongIdentity{source, bad}); !errors.Is(e, ErrRecoverySource) {
			t.Fatalf("%s accepted: %v", field, e)
		}
		after, e := session.Status(context.Background())
		if e != nil || !reflect.DeepEqual(baseline, after) {
			t.Fatal("foreign identity changed durable state", e)
		}
	}
	p, err := session.Step(context.Background(), source)
	if err != nil || p.ScannedHeight != 0 {
		t.Fatal("genesis scan", p, err)
	}
	if _, err = session.Step(context.Background(), source); !errors.Is(err, ErrRecoverySource) {
		t.Fatal("unbound transaction body accepted", err)
	}
	p, err = session.Status(context.Background())
	if err != nil || p.ScannedHeight != 0 || p.RelevantTransactions != 0 {
		t.Fatal("invalid body changed ledger", p, err)
	}
	tooLarge := reviewCopyBlock(genesis)
	tooLarge.Transactions[0].TxIn[0].SignatureScript = make([]byte, wire.MaxBlockPayload)
	if _, err = ownRecoveryBlock(tooLarge); !errors.Is(err, ErrRecoverySource) {
		t.Fatal("oversized typed block accepted", err)
	}
}
