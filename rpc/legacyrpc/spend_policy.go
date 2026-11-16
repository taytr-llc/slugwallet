package legacyrpc

import (
	"errors"

	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/wallet"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

type spendActivation struct {
	segwit, taproot bool
	// Phase-A fixed activation height; zero on voting/test networks.
	minimumHeight uint32
}

func rpcSpendActivation(params *chaincfg.Params, backend chain.Interface) (spendActivation, error) {
	var state spendActivation
	if params == nil || backend == nil {
		return state, errors.New("blockchain RPC is inactive")
	}
	reader, ok := backend.(interface {
		GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error)
	})
	if !ok {
		return state, errors.New("backend cannot report spend activation")
	}
	info, err := reader.GetBlockChainInfo()
	if err != nil || info == nil {
		return state, errors.New("cannot determine spend activation")
	}
	// Only the pinned Phase-A identity uses a fixed-height interpretation.
	// Require the node to report the matching overrides too: network/genesis
	// alone do not distinguish an upgraded node from its older software.
	if params.Net == chaincfg.MainNetParams.Net && params.GenesisHash != nil && params.GenesisHash.IsEqual(chaincfg.MainNetParams.GenesisHash) {
		hash, height, err := backend.GetBestBlock()
		if err != nil {
			return state, errors.New("cannot determine current spend activation")
		}
		if hash == nil || height < 0 || info.Chain != params.Name || info.Blocks != height || info.BestBlockHash != hash.String() {
			return state, errors.New("node tip changed or is invalid during spend activation check")
		}
		if info.SoftForks == nil {
			return state, errors.New("node does not report Phase-A activation overrides")
		}
		segwit := params.Deployments[chaincfg.DeploymentSegwit].EffectiveAlwaysActiveHeight()
		taproot := params.Deployments[chaincfg.DeploymentTaproot].EffectiveAlwaysActiveHeight()
		next := uint64(height) + 1
		check := func(name string, activation uint32) (bool, error) {
			deployment := info.Bip9SoftForks[name]
			if deployment == nil || deployment.AlwaysActiveHeight != activation {
				return false, errors.New("node does not match Phase-A activation rules")
			}
			expected := next >= uint64(activation)
			switch deployment.Status {
			case "defined", "started", "locked_in", "active", "failed":
			default:
				return false, errors.New("invalid spend activation state")
			}
			if (deployment.Status == "active") != expected {
				return false, errors.New("node reports inconsistent spend activation")
			}
			return expected, nil
		}
		state.segwit, err = check("segwit", segwit)
		if err != nil {
			return spendActivation{}, err
		}
		state.taproot, err = check("taproot", taproot)
		if err != nil {
			return spendActivation{}, err
		}
		state.taproot = state.taproot && state.segwit
		if state.segwit {
			state.minimumHeight = segwit
		}
		if state.taproot && taproot > state.minimumHeight {
			state.minimumHeight = taproot
		}
		return state, nil
	}
	active := func(name string) (bool, error) {
		if info.SoftForks != nil {
			if deployment, ok := info.Bip9SoftForks[name]; ok && deployment != nil {
				switch deployment.Status {
				case "active":
					return true, nil
				case "defined", "started", "locked_in", "failed":
					return false, nil
				default:
					return false, errors.New("invalid spend activation state")
				}
			}
		}
		if info.UnifiedSoftForks != nil {
			if deployment, ok := info.UnifiedSoftForks.SoftForks[name]; ok && deployment != nil {
				return deployment.Active, nil
			}
		}
		return false, errors.New("missing spend activation state")
	}
	state.segwit, err = active("segwit")
	if err != nil {
		return spendActivation{}, err
	}
	state.taproot, err = active("taproot")
	if err != nil {
		return spendActivation{}, err
	}
	state.taproot = state.taproot && state.segwit
	return state, nil
}

func rpcSpendScopes(account uint32, state spendActivation) []waddrmgr.KeyScope {
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	// RPC account names are resolved in44. Expand only account0, never a
	// same-numbered named/imported account in another derivation scope.
	if account == waddrmgr.DefaultAccountNum {
		if state.segwit {
			scopes = append(scopes, waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0084)
		}
		if state.taproot {
			scopes = append(scopes, waddrmgr.KeyScopeBIP0086)
		}
	}
	return scopes
}

func rpcSpendOptions(account uint32, outputs []*wire.TxOut, state spendActivation) ([]wallet.TxCreateOption, error) {
	for _, out := range outputs {
		if txscript.IsPayToTaproot(out.PkScript) {
			if !state.taproot {
				return nil, errors.New("taproot payments are not active for the next block")
			}
		} else if txscript.IsWitnessProgram(out.PkScript) || txscript.IsPayToScriptHash(out.PkScript) {
			if !state.segwit {
				return nil, errors.New("witness payments are not active for the next block")
			}
		}
	}
	scopes := rpcSpendScopes(account, state)
	options := []wallet.TxCreateOption{
		wallet.WithCoinSelectionScopes(scopes...),
		wallet.WithCustomChangeScope(&waddrmgr.KeyScopeBIP0044),
		wallet.WithUtxoFilter(func(credit wtxmgr.Credit) bool {
			if txscript.IsPayToTaproot(credit.PkScript) {
				return state.taproot
			}
			// The author's supported P2SH input is nested P2WPKH.
			if txscript.IsWitnessProgram(credit.PkScript) || txscript.IsPayToScriptHash(credit.PkScript) {
				return state.segwit
			}
			return true
		}),
	}
	// Apply the activation floor to all active Phase-A RPC spends: a named or
	// imported account may also hold witness coins, and opaque P2SH recipients
	// may use a witness redeem script. A reorg must not move these before the
	// fixed activation boundary. Preactivation legacy spends have no floor.
	if state.minimumHeight != 0 {
		options = append(options, wallet.WithMinBlockHeight(state.minimumHeight))
	}
	return options, nil
}
