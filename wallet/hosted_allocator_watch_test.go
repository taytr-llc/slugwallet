// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/rpcclient"
	"github.com/taytr-llc/slugwallet/chain"
)

// Match the desktop ownership shape: only readiness is wrapped; the same
// concrete RPC client remains responsible for watch and joined shutdown.
type allocationWatchReadinessWrapper struct{ *chain.RPCClient }

func (*allocationWatchReadinessWrapper) IsCurrent() bool { return true }

type allocationWatchUnsupported struct{ chain.Interface }

func TestHostedAllocationWatchConcreteOwner(t *testing.T) {
	backend := &chain.RPCClient{}
	wrapped := &allocationWatchReadinessWrapper{RPCClient: backend}
	var absent *chain.RPCClient
	for _, test := range []struct {
		name string
		in   chain.Interface
		want *chain.RPCClient
	}{
		{"direct", backend, backend},
		{"promoted-readiness-wrapper", wrapped, backend},
		{"nil-interface", nil, nil},
		{"nil-concrete", absent, nil},
		{"nil-promoted-backend", &allocationWatchReadinessWrapper{}, nil},
		{"unsupported", &allocationWatchUnsupported{}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := allocationWatchClient(test.in); got != test.want {
				t.Fatal("watch did not retain the exact installed concrete backend")
			}
		})
	}
}

func TestHostedAllocationWatchUnavailableBackend(t *testing.T) {
	// Construction disables connection-on-new. No socket or node is started.
	backend, err := chain.NewRPCClient(&chaincfg.MainNetParams, "127.0.0.1:1", "fixture", "fixture", nil, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		backend.Stop()
		backend.WaitForShutdown()
	})
	encoded, err := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	var absent *chain.RPCClient
	for _, test := range []struct {
		name      string
		in        chain.Interface
		attempted bool
	}{
		{"no-client", nil, false},
		{"unsupported", &allocationWatchUnsupported{}, false},
		{"nil-concrete", absent, false},
		{"nil-promoted-backend", &allocationWatchReadinessWrapper{}, false},
		{"nil-rpc-client", &chain.RPCClient{}, false},
		// Disconnected is false before the first connection. The actual send
		// must refuse ErrClientNotConnected and poison the attempted watch.
		{"unstarted-direct", backend, true},
		{"unstarted-promoted", &allocationWatchReadinessWrapper{RPCClient: backend}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := &Wallet{chainParams: &chaincfg.MainNetParams, chainClient: test.in}
			a := &HostedAllocator{wallet: w}
			err := a.watch(context.Background(), encoded.EncodeAddress())
			if !errors.Is(err, ErrAllocationUnavailable) {
				t.Fatal("unavailable concrete watch accepted", err)
			}
			if test.attempted && !errors.Is(err, rpcclient.ErrClientNotConnected) {
				t.Fatal("unstarted client did not report the concrete send failure", err)
			}
			if a.poisoned.Load() != test.attempted {
				t.Fatal("watch poisoning did not distinguish pre-RPC refusal from attempted RPC")
			}
			if w.chainClient != test.in {
				t.Fatal("watch replaced the installed owner")
			}
		})
	}
}
