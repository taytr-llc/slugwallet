//go:build !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

// This source is a synthetic trusted-node fixture, not a claim that its UTXOs
// are valid on a real chain. Header hashes use normal production Argon2. The
// separate real-node acceptance gate supplies full consensus/spend evidence.
type reviewRecoverySource struct {
	mu          sync.Mutex
	chain       []*wire.MsgBlock
	hashes      []chainhash.Hash
	blocks      map[chainhash.Hash]*wire.MsgBlock
	beforeBlock func(chainhash.Hash)
	beforeHash  func(int32)
}

func reviewCopyBlock(block *wire.MsgBlock) *wire.MsgBlock {
	var encoded bytes.Buffer
	if err := block.Serialize(&encoded); err != nil {
		panic(err)
	}
	var owned wire.MsgBlock
	if err := owned.Deserialize(bytes.NewReader(encoded.Bytes())); err != nil {
		panic(err)
	}
	return &owned
}

func (source *reviewRecoverySource) set(blocks ...*wire.MsgBlock) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.chain = append([]*wire.MsgBlock(nil), blocks...)
	source.hashes = nil
	if source.blocks == nil {
		source.blocks = make(map[chainhash.Hash]*wire.MsgBlock)
	}
	for _, block := range blocks {
		hash := block.BlockHash()
		source.hashes = append(source.hashes, hash)
		source.blocks[hash] = reviewCopyBlock(block)
	}
}

func (source *reviewRecoverySource) Identity(ctx context.Context) (RecoverySourceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return RecoverySourceIdentity{}, err
	}
	return RecoverySourceIdentity{Network: uint32(chaincfg.MainNetParams.Net), Genesis: *chaincfg.MainNetParams.GenesisHash, CSVHeight: 62, SegwitHeight: 62, TaprootHeight: 62}, nil
}
func (source *reviewRecoverySource) BestBlock(ctx context.Context) (RecoveryTip, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryTip{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return RecoveryTip{Height: int32(len(source.hashes) - 1), Hash: source.hashes[len(source.hashes)-1]}, nil
}
func (source *reviewRecoverySource) BlockHash(ctx context.Context, height int32) (chainhash.Hash, error) {
	if err := ctx.Err(); err != nil {
		return chainhash.Hash{}, err
	}
	if source.beforeHash != nil {
		source.beforeHash(height)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if height < 0 || int(height) >= len(source.hashes) {
		return chainhash.Hash{}, errors.New("fixture height absent")
	}
	return source.hashes[height], nil
}
func (source *reviewRecoverySource) Block(ctx context.Context, hash chainhash.Hash) (*wire.MsgBlock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source.beforeBlock != nil {
		source.beforeBlock(hash)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	block := source.blocks[hash]
	if block == nil {
		return nil, errors.New("fixture block absent")
	}
	return reviewCopyBlock(block), nil
}

func reviewPayment(t *testing.T, purpose, branch, index uint32) productionprofile.PaymentPublic {
	t.Helper()
	for _, name := range []string{"candidate_v1.json", "recovery_indices_v1.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "productionprofile", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var corpus struct {
			Cases []struct {
				Name     string                            `json:"name"`
				Payments []productionprofile.PaymentPublic `json:"payments"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &corpus); err != nil {
			t.Fatal(err)
		}
		for _, fixture := range corpus.Cases {
			if fixture.Name != productionprofile.CandidateZero256 {
				continue
			}
			for _, payment := range fixture.Payments {
				if payment.Purpose == purpose && payment.Branch == branch && payment.Index == index {
					return payment
				}
			}
		}
	}
	t.Fatalf("missing independent payment %d/%d/%d", purpose, branch, index)
	return productionprofile.PaymentPublic{}
}

func reviewFundingBlock(t *testing.T, parent *wire.MsgBlock, height int32, marker byte, outputs ...productionprofile.PaymentPublic) *wire.MsgBlock {
	t.Helper()
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}, SignatureScript: []byte{1, byte(height), marker}, Sequence: ^uint32(0)})
	coinbase.AddTxOut(wire.NewTxOut(10e8, []byte{0x51}))
	funding := wire.NewMsgTx(2)
	funding.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{marker, byte(height)}, Index: 0}, Sequence: ^uint32(0)})
	for i, output := range outputs {
		script, err := hex.DecodeString(output.ScriptPubKey)
		if err != nil {
			t.Fatal(err)
		}
		funding.AddTxOut(wire.NewTxOut(int64(marker)*1e6+int64(i), script))
	}
	if len(outputs) == 0 {
		funding.AddTxOut(wire.NewTxOut(1, []byte{0x51}))
	}
	left, right := coinbase.TxHash(), funding.TxHash()
	pair := append(append([]byte(nil), left[:]...), right[:]...)
	block := &wire.MsgBlock{Header: wire.BlockHeader{Version: 0x20000000, PrevBlock: parent.BlockHash(), MerkleRoot: chainhash.DoubleHashH(pair), Timestamp: time.Unix(1700000000+int64(height), 0), Bits: 0x207fffff, Nonce: uint32(marker)}, Transactions: []*wire.MsgTx{coinbase, funding}}
	return block
}

func reviewRecoveryExport(t *testing.T, floor uint32) productionprofile.Export {
	t.Helper()
	vector := candidateVectors(t)[0].Export
	for i := range vector.Manifest.Accounts {
		vector.Manifest.Accounts[i].NextExternal = 0
		vector.Manifest.Accounts[i].NextInternal = 0
		if vector.Manifest.Accounts[i].Purpose == 84 {
			vector.Manifest.Accounts[i].NextExternal = floor
		}
	}
	return vector
}

func reviewRecoveryLoader(dir string) *Loader {
	return NewLoader(&chaincfg.MainNetParams, dir, true, time.Second, 20)
}

func reviewBeginRecovery(t *testing.T, floor uint32) (*Loader, *RecoverySession) {
	t.Helper()
	loader := reviewRecoveryLoader(t.TempDir())
	session, err := loader.BeginCandidateRecovery(context.Background(), retainedPubPass, retainedPrivPass, reviewRecoveryExport(t, floor))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return loader, session
}

func reviewFinishRecovery(t *testing.T, session *RecoverySession, source RecoveryBlockSource) RecoveryProgress {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for attempts := 0; attempts < 1000; attempts++ {
		progress, err := session.Step(ctx, source)
		if err != nil {
			t.Fatalf("recovery step%d: %v", attempts, err)
		}
		if progress.Ready {
			return progress
		}
	}
	t.Fatal("bounded recovery did not complete")
	return RecoveryProgress{}
}

func reviewRecoveryCredits(t *testing.T, session *RecoverySession) []wtxmgr.Credit {
	t.Helper()
	var credits []wtxmgr.Credit
	err := walletdb.View(session.db, func(tx walletdb.ReadTx) error {
		var err error
		credits, err = session.txStore.UnspentOutputs(tx.ReadBucket(wtxmgrNamespaceKey))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return credits
}

func reviewRecoveryBranch(t *testing.T, session *RecoverySession, purpose, branch uint32) waddrmgr.RecoveryBranch {
	t.Helper()
	var state waddrmgr.RecoveryState
	err := walletdb.View(session.db, func(tx walletdb.ReadTx) error {
		var err error
		state, err = session.manager.CandidateRecoveryState(tx.ReadBucket(waddrmgrNamespaceKey))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range state.Branches {
		if candidate.Scope.Purpose == purpose && candidate.Branch == branch {
			return candidate
		}
	}
	t.Fatal("missing recovery branch")
	return waddrmgr.RecoveryBranch{}
}

func TestRecoveryReviewHighLookaheadReplaysEarlierCredit(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 4097)
	genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	higher := reviewPayment(t, 84, 0, 4128)
	lower := reviewPayment(t, 84, 0, 4116)
	first := reviewFundingBlock(t, genesis, 1, 17, higher)
	second := reviewFundingBlock(t, first, 2, 23, lower)
	source := &reviewRecoverySource{}
	source.set(genesis, first, second)
	ready := reviewFinishRecovery(t, session, source)
	if ready.RelevantTransactions != 2 || ready.OwnedOutputs != 2 || ready.ScannedHeight != 2 || ready.ScannedHash != second.BlockHash().String() {
		t.Fatalf("recovery omitted an earlier newly covered credit: %#v", ready)
	}
	branch := reviewRecoveryBranch(t, session, 84, 0)
	if branch.ImportedNext != 4097 || branch.IssuedNext != 4129 || branch.TargetNext != 4149 || branch.DerivedNext != 4149 {
		t.Fatalf("issued/discovered/lookahead cursors mixed: %#v", branch)
	}
	credits := reviewRecoveryCredits(t, session)
	if len(credits) != 2 {
		t.Fatalf("got%d credits", len(credits))
	}
	var total int64
	for _, credit := range credits {
		total += int64(credit.Amount)
	}
	if total != 40e6 {
		t.Fatalf("credit amounts changed or duplicated: %d", total)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := loader.OpenExistingWallet(retainedPubPass, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loader.UnloadWallet() })
	retainedUnlock(t, opened, retainedPrivPass)
	exported, err := opened.ExportCandidateRecovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := reviewRecoveryExport(t, 4129)
	if !reflect.DeepEqual(exported, want) {
		t.Fatal("ready export lost identity/cursors or exported unused lookahead")
	}
}

func TestRecoveryReviewReorgBoundaries(t *testing.T) {
	for _, boundary := range []string{"during-fetch", "before-scan-commit", "before-ready"} {
		t.Run(boundary, func(t *testing.T) {
			_, session := reviewBeginRecovery(t, 0)
			genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
			payment := reviewPayment(t, 84, 0, 0)
			old := reviewFundingBlock(t, genesis, 1, 17, payment)
			replacement := reviewFundingBlock(t, genesis, 1, 31, payment)
			source := &reviewRecoverySource{}
			source.set(genesis, old)
			fired := false
			fetchedOld := false
			flip := func() {
				if !fired {
					fired = true
					source.set(genesis, replacement)
				}
			}
			source.beforeBlock = func(hash chainhash.Hash) {
				if hash == old.BlockHash() {
					fetchedOld = true
					if boundary == "during-fetch" {
						flip()
					}
				}
			}
			if boundary != "during-fetch" {
				session.checkpoint = func(stage string) {
					if stage == boundary && fetchedOld {
						flip()
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var ready RecoveryProgress
			for step := 0; step < 100; step++ {
				progress, err := session.Step(ctx, source)
				if err != nil && !errors.Is(err, ErrRecoverySource) {
					t.Fatal(err)
				}
				if progress.Ready {
					ready = progress
					break
				}
			}
			if !fired || !ready.Ready || ready.ScannedHash != replacement.BlockHash().String() {
				t.Fatalf("reorg boundary was skipped or old branch became ready: fired=%v progress=%#v", fired, ready)
			}
			credits := reviewRecoveryCredits(t, session)
			if len(credits) != 1 || int64(credits[0].Amount) != 31e6 {
				t.Fatal("reorg retained or duplicated old-branch credits")
			}
		})
	}
}

func TestRecoveryReviewReopenAfterReorgKeepsIssuedFloor(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 6)
	genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
	old := reviewFundingBlock(t, genesis, 1, 17, reviewPayment(t, 84, 0, 25))
	replacement := reviewFundingBlock(t, genesis, 1, 31, reviewPayment(t, 84, 0, 0))
	source := &reviewRecoverySource{}
	source.set(genesis, old)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := false
	session.checkpoint = func(stage string) {
		if (stage == "expanded" || stage == "scanned") && len(reviewRecoveryCredits(t, session)) != 0 {
			stopped = true
			cancel()
		}
	}
	for step := 0; step < 30 && !stopped; step++ {
		progress, err := session.Step(ctx, source)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if progress.Ready {
			t.Fatal("test failed to stop before ready")
		}
	}
	if !stopped {
		t.Fatal("no committed credit checkpoint reached")
	}
	before := reviewRecoveryBranch(t, session, 84, 0)
	if before.IssuedNext != 26 {
		t.Fatalf("discovery not committed before interruption: %#v", before)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	session, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	source.set(genesis, replacement)
	ready := reviewFinishRecovery(t, session, source)
	after := reviewRecoveryBranch(t, session, 84, 0)
	if !ready.Ready || after.IssuedNext != 26 || after.ImportedNext != 6 {
		t.Fatal("reorg reused an already exposed/discovered index")
	}
	credits := reviewRecoveryCredits(t, session)
	if len(credits) != 1 || int64(credits[0].Amount) != 31e6 {
		t.Fatal("reopen retained stale branch funds")
	}
}

func TestRecoveryReviewCommittedWriteErrorRequiresReopen(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 0)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	real := session.update
	injected := errors.New("public test: lost write acknowledgement")
	session.update = func(fn func(walletdb.ReadWriteTx) error) error {
		if err := real(fn); err != nil {
			return err
		}
		return injected
	}
	progress, err := session.Step(context.Background(), source)
	if err == nil || progress.Ready {
		t.Fatal("uncertain committed write returned ready success")
	}
	if _, err := session.Step(context.Background(), source); !errors.Is(err, ErrRecoveryPoisoned) {
		t.Fatalf("uncertain handle remained usable: %v", err)
	}
	if err := session.Close(); err != nil && !errors.Is(err, ErrRecoveryPoisoned) {
		t.Fatal(err)
	}
	session, err = loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	ready := reviewFinishRecovery(t, session, source)
	if !ready.Ready || ready.Derived != 160 || ready.Issued != 0 {
		t.Fatalf("reopen did not reconcile exact derived/issued state: %#v", ready)
	}
}

func TestRecoveryReviewLostReadyAcknowledgement(t *testing.T) {
	loader, session := reviewBeginRecovery(t, 0)
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	real := session.update
	injected := errors.New("public test: ready commit acknowledgement lost")
	session.update = func(fn func(walletdb.ReadWriteTx) error) error {
		if err := real(fn); err != nil {
			return err
		}
		var ready bool
		if err := walletdb.View(session.db, func(tx walletdb.ReadTx) error {
			progress, err := session.status(tx)
			ready = progress.Ready
			return err
		}); err != nil {
			return err
		}
		if ready {
			return injected
		}
		return nil
	}
	fired := false
	for i := 0; i < 10; i++ {
		progress, err := session.Step(context.Background(), source)
		if errors.Is(err, injected) {
			fired = true
			break
		}
		if err != nil || progress.Ready {
			t.Fatal("ready acknowledged despite injected commit uncertainty", err)
		}
	}
	if !fired {
		t.Fatal("did not reach ready commit")
	}
	if _, err := session.Status(context.Background()); !errors.Is(err, ErrRecoveryPoisoned) {
		t.Fatalf("ambiguous ready handle remained usable: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	progress, err := resumed.Status(context.Background())
	if err != nil || !progress.Ready || progress.ScannedHeight != 0 || progress.ScannedHash != chaincfg.MainNetParams.GenesisHash.String() || progress.Derived != 160 || progress.Issued != 0 {
		t.Fatalf("ready commit did not reconcile atomically: %#v %v", progress, err)
	}
}

func TestRecoveryReviewMissingAndMixedMarkersFailClosed(t *testing.T) {
	for _, mutation := range []string{"missing-manager-progress", "schema10-with-progress11", "derived-count-without-addresses", "issued-below-imported"} {
		t.Run(mutation, func(t *testing.T) {
			loader, session := reviewBeginRecovery(t, 6)
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := walletdb.Open("bdb", filepath.Join(loader.dbDirPath, WalletDBName), true, time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				main := tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket([]byte("main"))
				raw := append([]byte(nil), main.Get([]byte("slug-candidate-progress"))...)
				if len(raw) != 236 {
					return errors.New("unexpected schema11 progress encoding")
				}
				switch mutation {
				case "missing-manager-progress":
					return main.Delete([]byte("slug-candidate-progress"))
				case "schema10-with-progress11":
					var version [4]byte
					binary.LittleEndian.PutUint32(version[:], 10)
					return main.Put([]byte("mgrver"), version[:])
				case "derived-count-without-addresses":
					binary.LittleEndian.PutUint32(raw[8:], 1)
				case "issued-below-imported":
					// Native84 external is the fifth canonical branch row.
					binary.LittleEndian.PutUint32(raw[12+4*28+4*4:], 5)
				}
				return main.Put([]byte("slug-candidate-progress"), raw)
			})
			closeErr := db.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			if opened, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass); err == nil || opened != nil {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatal("corrupt recovery state recreated or accepted")
			}
			if opened, err := loader.OpenExistingWallet(retainedPubPass, false); err == nil || opened != nil {
				if opened != nil {
					_ = loader.UnloadWallet()
				}
				t.Fatal("corrupt pending state bypassed ordinary Wallet open gate")
			}
		})
	}
}

func reviewMutateRecoveryDB(t *testing.T, loader *Loader, mutate func(walletdb.ReadWriteTx) error) {
	t.Helper()
	db, err := walletdb.Open("bdb", filepath.Join(loader.dbDirPath, WalletDBName), true, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := walletdb.Update(db, mutate); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryReviewScriptIndexCorruptionFailsClosed(t *testing.T) {
	for _, mutation := range []string{"missing-script", "wrong-derived-index", "missing-scanner-progress", "premature-scanning"} {
		t.Run(mutation, func(t *testing.T) {
			loader, session := reviewBeginRecovery(t, 0)
			progress, err := session.Step(context.Background(), nil)
			if err != nil || progress.Derived != 128 {
				t.Fatal("offline derivation setup", err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			reviewMutateRecoveryDB(t, loader, func(tx walletdb.ReadWriteTx) error {
				bucket := tx.ReadWriteBucket(recoveryScanBucket)
				if mutation == "premature-scanning" {
					progress, err := readRecoveryScan(bucket)
					if err != nil {
						return err
					}
					progress.Phase = "scanning"
					raw, err := json.Marshal(progress)
					if err != nil {
						return err
					}
					return bucket.Put(recoveryScanMeta, raw)
				}
				if mutation == "missing-scanner-progress" {
					return bucket.Delete(recoveryScanMeta)
				}
				scripts := bucket.NestedReadWriteBucket(recoveryScripts)
				key, value := scripts.ReadCursor().First()
				if key == nil || value == nil {
					return errors.New("missing test script")
				}
				ownedKey := append([]byte(nil), key...)
				if mutation == "missing-script" {
					return scripts.Delete(ownedKey)
				}
				var row recoveryScript
				if err := json.Unmarshal(value, &row); err != nil {
					return err
				}
				row.Index++
				encoded, err := json.Marshal(row)
				if err != nil {
					return err
				}
				return scripts.Put(ownedKey, encoded)
			})
			if recovered, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass); err == nil || recovered != nil {
				if recovered != nil {
					_ = recovered.Close()
				}
				t.Fatal("scanner index corruption accepted")
			}
		})
	}
}

func TestRecoveryReviewMissingLedgerCannotComplete(t *testing.T) {
	for _, corruption := range []string{"missing-ledger", "missing-unspent-index", "missing-balance", "zero-balance", "false-spent-credit", "checkpoint-time-overflow", "checkpoint-time-mismatch"} {
		t.Run(corruption, func(t *testing.T) {
			loader, session := reviewBeginRecovery(t, 0)
			genesis := reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock)
			funded := reviewFundingBlock(t, genesis, 1, 17, reviewPayment(t, 84, 0, 0))
			source := &reviewRecoverySource{}
			source.set(genesis, funded)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			committedCredit := false
			session.checkpoint = func(stage string) {
				if stage == "scanned" && len(reviewRecoveryCredits(t, session)) == 1 {
					committedCredit = true
					cancel()
				}
			}
			for step := 0; step < 20 && !committedCredit; step++ {
				progress, err := session.Step(ctx, source)
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if progress.Ready {
					t.Fatal("corruption setup unexpectedly ready")
				}
			}
			if !committedCredit {
				t.Fatal("missing durable pending credit")
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			reviewMutateRecoveryDB(t, loader, func(tx walletdb.ReadWriteTx) error {
				// Leave the coherent scanner checkpoint and all three indices intact.
				// An index-only audit would then silently skip already-scanned funds.
				if corruption == "checkpoint-time-overflow" || corruption == "checkpoint-time-mismatch" {
					bucket := tx.ReadWriteBucket(recoveryScanBucket)
					progress, err := readRecoveryScan(bucket)
					if err != nil {
						return err
					}
					progress.Time++
					if corruption == "checkpoint-time-overflow" {
						progress.Time = int64(^uint32(0)) + 1
					}
					raw, err := json.Marshal(progress)
					if err != nil {
						return err
					}
					return bucket.Put(recoveryScanMeta, raw)
				}
				ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
				switch corruption {
				case "missing-balance":
					return ns.Delete([]byte("bal"))
				case "zero-balance":
					return ns.Put([]byte("bal"), make([]byte, 8))
				case "false-spent-credit":
					credits := ns.NestedReadWriteBucket([]byte("c"))
					key, value := credits.ReadCursor().First()
					if len(key) != 72 || len(value) != 9 {
						return errors.New("expected one ordinary unspent credit fixture")
					}
					value = append([]byte(nil), value...)
					value[8] |= 1
					return credits.Put(key, value)
				}
				if corruption == "missing-unspent-index" {
					// The documented wtxmgr unspent bucket is distinct from credit
					// metadata. Losing it must not turn retained funds invisible.
					if err := ns.DeleteNestedBucket([]byte("u")); err != nil {
						return err
					}
					_, err := ns.CreateBucket([]byte("u"))
					return err
				}
				if err := tx.DeleteTopLevelBucket(wtxmgrNamespaceKey); err != nil {
					return err
				}
				ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
				if err != nil {
					return err
				}
				return wtxmgr.Create(ns)
			})
			if recovered, err := loader.OpenCandidateRecovery(context.Background(), retainedPubPass); err == nil || recovered != nil {
				if recovered != nil {
					_ = recovered.Close()
				}
				t.Fatal("pending scanner accepted missing recovered transaction ledger")
			}
		})
	}
}
