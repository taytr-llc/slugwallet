// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package legacyrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcjson"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/chain"
	"github.com/taytr-llc/slugwallet/productionprofile"
	"github.com/taytr-llc/slugwallet/wallet"
	_ "github.com/taytr-llc/slugwallet/walletdb/bdb"
)

// This notification sink lets the actual RPC handlers commit real wallet
// addresses without pretending to perform chain synchronization or spending.
// Funded normal-PoW integration separately exercises those behaviors.
type addressNotificationSink struct{ chain.Interface }

func (*addressNotificationSink) NotifyReceived([]address.Address) error { return nil }
func (*addressNotificationSink) Notifications() <-chan interface{}      { return nil }
func (*addressNotificationSink) Stop()                                  {}
func (*addressNotificationSink) WaitForShutdown()                       {}

func rpcProfileExpectations(t *testing.T, candidate bool) map[string]string {
	t.Helper()
	file := "../../recovery/testdata/recovery_v1.json"
	name := "zero256"
	if candidate {
		file = "../../productionprofile/testdata/candidate_v1.json"
		name = productionprofile.CandidateZero256
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string                            `json:"name"`
			Payments  []productionprofile.PaymentPublic `json:"payments"`
			Addresses []struct {
				Path    string `json:"path"`
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, vector := range corpus.Cases {
		if vector.Name != name {
			continue
		}
		for _, p := range vector.Payments {
			result[p.Path] = p.Address
		}
		for _, p := range vector.Addresses {
			result[p.Path] = p.Address
		}
	}
	if len(result) == 0 {
		t.Fatal("missing independent public fixture")
	}
	return result
}

func TestCandidateRPCAddressDefaultsPreserveV1(t *testing.T) {
	if wire.TestPoW {
		t.Skip("candidate and v1 wallet constructors require normal PoW")
	}
	for _, candidate := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate=%v", candidate), func(t *testing.T) {
			pubPass := []byte("RPC public fixture password")
			privPass := []byte("RPC private fixture password")
			loader := wallet.NewLoader(&chaincfg.MainNetParams, t.TempDir(), true, time.Second, 20)
			t.Cleanup(func() {
				if _, loaded := loader.LoadedWallet(); loaded {
					if err := loader.UnloadWallet(); err != nil {
						t.Error(err)
					}
				}
			})
			var w *wallet.Wallet
			var err error
			if candidate {
				w, err = loader.CreateCandidateFixtureWallet(pubPass, privPass, productionprofile.CandidateZero256)
			} else {
				// This all-zero entropy is the explicitly published v1 fixture.
				w, err = loader.CreateNewRecoveryWallet(pubPass, privPass, [32]byte{}, time.Unix(0, 0))
			}
			if err != nil {
				t.Fatal(err)
			}
			w.SynchronizeRPC(&addressNotificationSink{})
			want := rpcProfileExpectations(t, candidate)
			coin, defaultPurpose := uint32(0), uint32(44)
			if candidate {
				coin, defaultPurpose = productionprofile.CandidateCoinType, 84
			}
			check := func(got any, err error, purpose, branch uint32) {
				t.Helper()
				path := fmt.Sprintf("m/%d'/%d'/0'/%d/0", purpose, coin, branch)
				if expected := want[path]; expected == "" || err != nil || got != expected {
					t.Fatalf("RPC address differs from independent %s vector: %v", path, err)
				}
			}
			got, err := getNewAddress(&btcjson.GetNewAddressCmd{}, w)
			check(got, err, defaultPurpose, 0)
			got, err = getAccountAddress(&btcjson.GetAccountAddressCmd{Account: defaultAccountName}, w)
			check(got, err, defaultPurpose, 0)
			got, err = getRawChangeAddress(&btcjson.GetRawChangeAddressCmd{}, w)
			check(got, err, defaultPurpose, 1)
			type addressOption struct {
				name    string
				purpose uint32
			}
			options := []addressOption{{"p2sh-segwit", 49}}
			if candidate {
				options = append(options, addressOption{"legacy", 44}, addressOption{"bech32m", 86})
			} else {
				options = append(options, addressOption{"bech32", 84})
			}
			for _, option := range options {
				kind := option.name
				got, err = getNewAddress(&btcjson.GetNewAddressCmd{AddressType: &kind}, w)
				check(got, err, option.purpose, 0)
				got, err = getRawChangeAddress(&btcjson.GetRawChangeAddressCmd{AddressType: &kind}, w)
				check(got, err, option.purpose, 1)
			}
			if !candidate {
				kind := "bech32m"
				if got, err := getNewAddress(&btcjson.GetNewAddressCmd{AddressType: &kind}, w); err == nil || got != nil {
					t.Fatal("candidate RPC extension changed v1 behavior")
				}
				return
			}
			if err := w.Unlock(privPass, nil); err != nil {
				t.Fatal(err)
			}
			before, err := w.ExportCandidateRecovery(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			kind := "unsupported"
			if got, err := getNewAddress(&btcjson.GetNewAddressCmd{AddressType: &kind}, w); err == nil || got != nil {
				t.Fatal("unknown address type accepted")
			}
			if err := loader.UnloadWallet(); err != nil {
				t.Fatal(err)
			}
			w, err = loader.OpenExistingWallet(pubPass, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Unlock(privPass, nil); err != nil {
				t.Fatal(err)
			}
			after, err := w.ExportCandidateRecovery(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("RPC allocation cursors did not survive reopen unchanged", err)
			}
		})
	}
}
