//go:build integration && recoveryintegration && activationintegration && !slugtestpow

// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/blockchain"
	"github.com/taytr-llc/slug/btcutil/v2"
	"github.com/taytr-llc/slug/prospectjob"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/prospectwork"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
)

func TestWalletActivatedRecoveryNormalPoW(t *testing.T) {
	for _, funding := range []struct {
		name    string
		purpose uint32
	}{{"legacy", 44}, {"nested_witness", 49}, {"native_witness", 84}, {"taproot", 86}} {
		if !t.Run(funding.name, func(t *testing.T) {
			hooks := recoveryGateHooks{activation: assertActivationBoundary, spends: assertActivatedSpends}
			if funding.purpose == 84 {
				// One real witness transaction additionally traverses the complete
				// production template/builder/proposal/submission path.
				hooks.firstConfirmation = confirmWitnessTemplate
			}
			runWalletRecoveryNormalPoW(t, funding.purpose, hooks)
		}) {
			return
		}
	}
}

func assertActivationBoundary(t *testing.T, n *node, height int32) {
	t.Helper()
	var info struct {
		Blocks int32 `json:"blocks"`
		BIP9   map[string]struct {
			Status             string `json:"status"`
			AlwaysActiveHeight uint32 `json:"always_active_height"`
		} `json:"bip9_softforks"`
		Buried []struct {
			ID     string `json:"id"`
			Reject struct {
				Status bool `json:"status"`
			} `json:"reject"`
		} `json:"softforks"`
	}
	n.rpc.must(t, "getblockchaininfo", nil, &info)
	if info.Blocks != height || height < 60 || height > 62 {
		t.Fatal("unexpected activation observation height")
	}
	// BIP9 status describes the NEXT candidate. Buried reject.status instead
	// describes the current tip height; deliberately test their asymmetry.
	for _, name := range []string{"csv", "segwit", "taproot"} {
		state, ok := info.BIP9[name]
		if !ok || state.AlwaysActiveHeight != 62 || (state.Status == "active") != (height >= 61) {
			t.Fatalf("%s next-block activation at tip%d: %+v", name, height, state)
		}
	}
	for _, name := range []string{"bip34", "bip65", "bip66"} {
		found := false
		for _, state := range info.Buried {
			if state.ID == name {
				found = true
				if state.Reject.Status != (height >= 62) {
					t.Fatalf("%s current-tip activation at%d", name, height)
				}
			}
		}
		if !found {
			t.Fatalf("missing buried deployment %s", name)
		}
	}
	t.Logf("real node activation boundary checked at tip%d (candidate%d)", height, height+1)
}

func assertActivatedSpends(t *testing.T, purpose uint32, first, second *wire.MsgTx) {
	t.Helper()
	if len(first.TxIn) != 1 || len(second.TxIn) != 2 || len(first.TxOut) != 2 || len(second.TxOut) != 2 {
		t.Fatal("unexpected funded-input/change shape")
	}
	input := first.TxIn[0]
	switch purpose {
	case 44:
		if len(input.Witness) != 0 || len(input.SignatureScript) == 0 {
			t.Fatal("legacy funding did not produce a legacy input")
		}
	case 49:
		if len(input.Witness) != 2 || len(input.SignatureScript) != 23 ||
			!bytes.Equal(input.SignatureScript[:3], []byte{22, 0, 20}) {
			t.Fatal("nested-witness funding did not spend its redeem program")
		}
	case 84:
		if len(input.Witness) != 2 || len(input.SignatureScript) != 0 {
			t.Fatal("native-witness funding did not produce a witness input")
		}
	case 86:
		if len(input.Witness) != 1 || len(input.SignatureScript) != 0 ||
			(len(input.Witness[0]) != 64 && len(input.Witness[0]) != 65) {
			t.Fatal("taproot funding did not produce a key-path Schnorr input")
		}
	default:
		t.Fatal("unsupported fixture funding scope")
	}
	if first.HasWitness() != (purpose != 44) || second.HasWitness() != (purpose != 44) {
		t.Fatal("unexpected witness state for funded/restored inputs")
	}
	// The RPC deliberately uses legacy change. Both outputs here are P2PKH:
	// the independently known external sink and the wallet's own change.
	for _, transaction := range []*wire.MsgTx{first, second} {
		if transaction.LockTime != 61 {
			t.Fatal("activated RPC spend lacks the height62 finality floor")
		}
		for _, input := range transaction.TxIn {
			if input.Sequence != wire.MaxTxInSequenceNum-1 {
				t.Fatal("activated RPC spend changed its nonfinal sequence policy")
			}
		}
		for _, output := range transaction.TxOut {
			if !txscript.IsPayToPubKeyHash(output.PkScript) {
				t.Fatal("RPC silently changed its explicit legacy change policy")
			}
		}
	}
	firstHash := first.TxHash()
	for _, spent := range second.TxIn {
		if spent.PreviousOutPoint.Hash == firstHash && len(spent.Witness) != 0 {
			t.Fatal("recovered legacy change unexpectedly required a witness")
		}
	}
}

// startTemplatePeer is a second disposable normal node, listening exclusively
// on loopback. It gives GBT a real peer without a public connection or mock node.
func startTemplatePeer(t *testing.T, binary, payout string) (*node, string) {
	t.Helper()
	directory := t.TempDir()
	rpcPort, peerPort := freePort(t), freePort(t)
	for peerPort == rpcPort {
		peerPort = freePort(t)
	}
	peerAddress := fmt.Sprintf("127.0.0.1:%d", peerPort)
	config := fmt.Sprintf("rpcuser=fixture\nrpcpass=%s\nnotls=1\nrpclisten=127.0.0.1:%d\nlisten=%s\nnodnsseed=1\nconnect=127.0.0.1:0\ndatadir=%s\nlogdir=%s\nminingaddr=%s\nmaxpeers=2\n", fixturePass, rpcPort, peerAddress, filepath.Join(directory, "chain"), filepath.Join(directory, "logs"), payout)
	configPath := filepath.Join(directory, "slug.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "node.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "--configfile="+configPath)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	peer := &node{rpc: newRPC(fmt.Sprintf("http://127.0.0.1:%d", rpcPort)), cmd: command, done: make(chan error, 1)}
	go func() { peer.done <- command.Wait(); log.Close() }()
	t.Cleanup(func() {
		peer.once.Do(func() {
			_ = peer.rpc.call("stop", nil, nil)
			select {
			case err := <-peer.done:
				if err != nil {
					t.Errorf("template peer shutdown: %v", err)
				}
			case <-time.After(20 * time.Second):
				_ = command.Process.Kill()
				<-peer.done
				t.Error("template peer needed forced shutdown")
			}
			peer.rpc.client.CloseIdleConnections()
		})
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		var magic uint32
		if peer.rpc.call("getcurrentnet", nil, &magic) == nil {
			if magic != recoveryNetwork {
				t.Fatal("template peer wrong network")
			}
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logPath)
			t.Fatalf("template peer startup: %s", log)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var first string
	peer.rpc.must(t, "getblockhash", []any{0}, &first)
	if first != genesis {
		t.Fatal("template peer wrong genesis")
	}
	return peer, peerAddress
}

func confirmWitnessTemplate(t *testing.T, n *node, wallet *session, height *int32,
	payout, transactionID string) {

	t.Helper()
	peer, peerAddress := startTemplatePeer(t, os.Getenv("SLUG_WALLET_NODE"), payout)
	n.rpc.must(t, "addnode", []any{peerAddress, "add"}, nil)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		var peers []json.RawMessage
		var peerHeight int32
		if n.rpc.call("getpeerinfo", nil, &peers) == nil && len(peers) == 1 &&
			peer.rpc.call("getblockcount", nil, &peerHeight) == nil && peerHeight == *height {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated template peer did not synchronize")
		}
		time.Sleep(100 * time.Millisecond)
	}
	client, err := prospectnode.NewClient(prospectnode.RPCConfig{
		Version: 1, URL: n.rpc.url, Username: "fixture", Password: fixturePass,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	policy := prospectnode.Policy{Version: 1, Network: recoveryNetwork,
		Genesis: genesis, DNAVersion: 1, ProspectTarget: strings.Repeat("f", 64)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	template, err := client.ResolveTemplate(ctx, policy)
	if err != nil {
		t.Fatal("activated witness template:", err)
	}
	if template.Context.ParentHeight != uint32(*height) || template.Block.DefaultWitnessCommitment == "" {
		t.Fatal("template omitted witness commitment or used unexpected parent")
	}
	transactionBytes, err := hex.DecodeString(history(t, wallet, transactionID)["hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, transaction := range template.Block.Transactions {
		decoded, err := hex.DecodeString(transaction.Data)
		if err != nil {
			t.Fatal(err)
		}
		var tx wire.MsgTx
		if tx.Deserialize(bytes.NewReader(decoded)) != nil {
			t.Fatal("invalid template transaction")
		}
		if tx.TxHash().String() == transactionID {
			found = true
			if !tx.HasWitness() || !bytes.Equal(decoded, transactionBytes) {
				t.Fatal("GBT did not preserve the complete real witness transaction")
			}
		}
	}
	if !found {
		t.Fatal("actual witness spend missing from template")
	}
	identity, err := wallet.wallet.GymIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	job, err := prospectjob.New(template.Context, identity.PublicKey, strings.Repeat("42", 32), time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := prospectwork.Build(job, template, payout, 0)
	if err != nil {
		t.Fatal("payable witness candidate:", err)
	}
	if err := client.Proposal(ctx, template.Context, candidate.BlockHex); err != nil {
		t.Fatal("unmined witness candidate proposal:", err)
	}
	raw, err := hex.DecodeString(candidate.BlockHex)
	if err != nil {
		t.Fatal(err)
	}
	var block wire.MsgBlock
	if block.Deserialize(bytes.NewReader(raw)) != nil || len(block.Transactions) != len(template.Block.Transactions)+1 {
		t.Fatal("candidate changed transaction count")
	}
	if err := blockchain.ValidateWitnessCommitment(btcutil.NewBlock(&block)); err != nil {
		t.Fatal("candidate witness commitment:", err)
	}
	found = false
	for _, tx := range block.Transactions[1:] {
		if tx.TxHash().String() == transactionID {
			var encoded bytes.Buffer
			if tx.Serialize(&encoded) != nil || !bytes.Equal(encoded.Bytes(), transactionBytes) {
				t.Fatal("candidate did not preserve full witness transaction bytes")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("candidate dropped actual witness transaction")
	}
	target := blockchain.CompactToBig(block.Header.Bits)
	var workHash string
	for nonce := uint32(0); nonce < 512; nonce++ {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		block.Header.Nonce = nonce
		hash := block.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			workHash = hash.String()
			break
		}
	}
	if workHash == "" {
		t.Fatal("bounded normal-PoW fixture scan exhausted")
	}
	var serialized, header bytes.Buffer
	if block.Serialize(&serialized) != nil || block.Header.Serialize(&header) != nil {
		t.Fatal("mined candidate serialization")
	}
	mined := hex.EncodeToString(serialized.Bytes())
	if err := client.Proposal(ctx, template.Context, mined); err != nil {
		t.Fatal("mined witness candidate proposal:", err)
	}
	if err := client.SubmitBlock(ctx, template.Context, mined); err != nil {
		t.Fatal("isolated witness block submission:", err)
	}
	proof := candidate.Proof
	proof.Header = hex.EncodeToString(header.Bytes())
	if err := client.CanonicalBlock(ctx, template.Context, proof, workHash); err != nil {
		t.Fatal("witness block was not observed canonical:", err)
	}
	*height++
	waitSync(t, wallet, *height)
	t.Logf("actual witness tx preserved through ResolveTemplate, Build, Proposal and accepted normal block%s at height%d (nonce%d)", workHash, *height, block.Header.Nonce)
}
