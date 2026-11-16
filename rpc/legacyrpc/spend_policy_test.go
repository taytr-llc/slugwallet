package legacyrpc

import (
	"errors"
	"reflect"
	"testing"

	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

type spendNode struct {
	chain.Interface
	height int32
	hash   chainhash.Hash
	info   *btcjson.GetBlockChainInfoResult
	err    error
}

func (n *spendNode) GetBestBlock() (*chainhash.Hash, int32, error) { return &n.hash, n.height, n.err }
func (n *spendNode) GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error) {
	return n.info, n.err
}
func phaseSpendNode(height int32) *spendNode {
	hash := chainhash.Hash{1}
	status := "failed"
	if height+1 >= chaincfg.PhaseAActivationHeight {
		status = "active"
	}
	return &spendNode{height: height, hash: hash, info: &btcjson.GetBlockChainInfoResult{Chain: chaincfg.MainNetParams.Name, Blocks: height, BestBlockHash: hash.String(), SoftForks: &btcjson.SoftForks{Bip9SoftForks: map[string]*btcjson.Bip9SoftForkDescription{
		"segwit": {Status: status, AlwaysActiveHeight: chaincfg.PhaseAActivationHeight}, "taproot": {Status: status, AlwaysActiveHeight: chaincfg.PhaseAActivationHeight},
	}}}}
}
func TestRPCSpendActivationBoundaryAndUpgrade(t *testing.T) {
	for _, height := range []int32{60, 61, 62} {
		n := phaseSpendNode(height)
		state, err := rpcSpendActivation(&chaincfg.MainNetParams, n)
		if err != nil {
			t.Fatal(err)
		}
		active := height >= 61
		if state.segwit != active || state.taproot != active {
			t.Fatalf("tip%d wrong next-block activation", height)
		}
		if active && state.minimumHeight != 62 {
			t.Fatal("activation finality floor missing")
		}
	}
	for _, mutation := range []struct {
		name   string
		change func(*spendNode)
	}{
		{"old-node", func(n *spendNode) { n.info.Bip9SoftForks["segwit"].AlwaysActiveHeight = 0 }},
		{"wrong-height", func(n *spendNode) { n.info.Bip9SoftForks["taproot"].AlwaysActiveHeight = 63 }},
		{"incorrect-active", func(n *spendNode) { n.info.Bip9SoftForks["taproot"].Status = "failed" }},
		{"early-active", func(n *spendNode) { n.height = 60; n.info.Blocks = 60 }},
		{"tip-advance", func(n *spendNode) { n.height++ }},
		{"tip-reorg", func(n *spendNode) { n.hash[0]++ }},
		{"wrong-chain", func(n *spendNode) { n.info.Chain = "main" }},
		{"rpc-failure", func(n *spendNode) { n.err = errors.New("fixture unavailable") }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			n := phaseSpendNode(61)
			mutation.change(n)
			if state, err := rpcSpendActivation(&chaincfg.MainNetParams, n); err == nil || state != (spendActivation{}) {
				t.Fatal("inconsistent/unupgraded node accepted", err)
			}
		})
	}
}
func TestRPCSpendOtherNetworkUsesReportedState(t *testing.T) {
	n := phaseSpendNode(1000)
	n.info.SoftForks.Bip9SoftForks["segwit"].Status = "started"
	n.info.SoftForks.Bip9SoftForks["taproot"].Status = "started"
	state, err := rpcSpendActivation(&chaincfg.TestNet3Params, n)
	if err != nil || state.segwit || state.taproot || state.minimumHeight != 0 {
		t.Fatal("Phase-A height leaked to testnetwork", err)
	}
	n.info.Bip9SoftForks["segwit"].Status = "active"
	state, err = rpcSpendActivation(&chaincfg.TestNet3Params, n)
	if err != nil || !state.segwit || state.taproot || state.minimumHeight != 0 {
		t.Fatal("reported testnetwork state ignored", err)
	}
	delete(n.info.Bip9SoftForks, "taproot")
	if _, err := rpcSpendActivation(&chaincfg.TestNet3Params, n); err == nil {
		t.Fatal("unknown deployment guessed active")
	}
}
func TestRPCSpendDefaultAndNamedScopes(t *testing.T) {
	active := spendActivation{segwit: true, taproot: true, minimumHeight: 62}
	want := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044, waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScopeBIP0086}
	if got := rpcSpendScopes(0, active); !reflect.DeepEqual(got, want) {
		t.Fatalf("default scopes %v", got)
	}
	for _, account := range []uint32{1, waddrmgr.ImportedAddrAccount} {
		if got := rpcSpendScopes(account, active); !reflect.DeepEqual(got, want[:1]) {
			t.Fatal("named/imported account crossed scope", got)
		}
	}
	if got := rpcSpendScopes(0, spendActivation{}); !reflect.DeepEqual(got, want[:1]) {
		t.Fatal("preactivation selected witness scope")
	}
	if got := rpcSpendScopes(0, spendActivation{segwit: true}); !reflect.DeepEqual(got, want[:3]) {
		t.Fatal("taproot selected before its activation")
	}
}
func TestRPCSpendRejectsPrematureWitnessRecipients(t *testing.T) {
	native := append([]byte{0x00, 0x14}, make([]byte, 20)...)
	taproot := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	p2sh := append(append([]byte{0xa9, 0x14}, make([]byte, 20)...), 0x87)
	for _, script := range [][]byte{native, taproot, p2sh} {
		if _, err := rpcSpendOptions(0, []*wire.TxOut{{Value: 10000, PkScript: script}}, spendActivation{}); err == nil {
			t.Fatal("preactivation witness recipient accepted")
		}
	}
	if _, err := rpcSpendOptions(0, []*wire.TxOut{{Value: 10000, PkScript: taproot}}, spendActivation{segwit: true}); err == nil {
		t.Fatal("taproot recipient accepted before taproot")
	}
	if _, err := rpcSpendOptions(0, []*wire.TxOut{{Value: 10000, PkScript: native}}, spendActivation{segwit: true}); err != nil {
		t.Fatal("active witness recipient rejected", err)
	}
}
