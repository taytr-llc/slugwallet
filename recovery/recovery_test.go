// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
)

type fixture struct {
	Name      string                                                    `json:"name"`
	Entropy   string                                                    `json:"entropy"`
	Seed      string                                                    `json:"seed"`
	Export    Export                                                    `json:"export"`
	Addresses []struct{ Path, PublicKey, Address, ScriptPubKey string } `json:"-"`
}

func fixtures(t *testing.T) []fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []fixture `json:"cases"`
	}
	if json.Unmarshal(raw, &f) != nil || len(f.Cases) != 3 {
		t.Fatal("invalid fixture")
	}
	return f.Cases
}
func fixtureEntropy(t *testing.T, f fixture) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(f.Entropy)
	if err != nil || len(raw) != 32 {
		t.Fatal("bad fixture entropy")
	}
	var e [32]byte
	copy(e[:], raw)
	return e
}

func TestIndependentRecoveryFixtures(t *testing.T) {
	for _, f := range fixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			entropy := fixtureEntropy(t, f)
			if got := Mnemonic(entropy); got != f.Export.Mnemonic {
				t.Fatal("independent mnemonic mismatch")
			}
			parsed, err := Entropy(f.Export.Mnemonic)
			if err != nil || parsed != entropy {
				t.Fatal("entropy roundtrip", err)
			}
			seed, err := Seed(f.Export.Mnemonic)
			if err != nil || hex.EncodeToString(seed[:]) != f.Seed {
				t.Fatal("independent seed mismatch", err)
			}
			if SeedFromEntropy(entropy) != seed {
				t.Fatal("entropy seed mismatch")
			}
			got, err := NewExport(entropy, f.Export.Manifest.Accounts)
			if err != nil || !reflect.DeepEqual(got, f.Export) {
				t.Fatal("independent full export mismatch", err)
			}
			encoded, err := MarshalExport(got)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ParseExport(encoded)
			if err != nil || !reflect.DeepEqual(decoded, got) {
				t.Fatal("export codec roundtrip", err)
			}
			encoded, err = MarshalManifest(got.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			m, err := ParseManifest(encoded)
			if err != nil || !reflect.DeepEqual(m, got.Manifest) {
				t.Fatal("manifest codec roundtrip", err)
			}
		})
	}
}

func TestPinnedWordlist(t *testing.T) {
	raw, err := os.ReadFile("testdata/oracle/sources/english.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != englishWords {
		t.Fatal("embedded wordlist differs from pinned primary source")
	}
}

func TestOfficialEnglishPhraseVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/oracle/sources/mnemonic-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string][][]string
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("invalid official vectors")
	}
	supported := 0
	for _, row := range vectors["english"] {
		raw, _ := hex.DecodeString(row[0])
		if len(raw) != 32 {
			if _, err := Entropy(row[1]); err == nil {
				t.Fatal("non24-word official vector accepted by fixed profile")
			}
			continue
		}
		supported++
		var entropy [32]byte
		copy(entropy[:], raw)
		if Mnemonic(entropy) != row[1] {
			t.Fatal("official mnemonic mismatch")
		}
		if got, err := Entropy(row[1]); err != nil || got != entropy {
			t.Fatal("official entropy mismatch", err)
		}
	}
	if supported != 8 {
		t.Fatal("unexpected official256bit vector count", supported)
	}
}

func TestPhrasePolicy(t *testing.T) {
	valid := fixtures(t)[0].Export.Mnemonic
	split := strings.Split(valid, " ")
	split[23] = words[wordIndexes[split[23]]^1]
	for _, phrase := range []string{"", strings.ToUpper(valid), " " + valid, valid + " ", strings.Replace(valid, " ", "  ", 1), strings.Replace(valid, " ", "\t", 1), strings.Replace(valid, " ", "\u00a0", 1), strings.Join(split, " "), strings.Repeat("x", MaxPhraseSize+1)} {
		if entropy, err := Entropy(phrase); err == nil || entropy != [32]byte{} {
			t.Fatal("invalid phrase returned entropy")
		}
		if seed, err := Seed(phrase); err == nil || seed != [64]byte{} {
			t.Fatal("invalid phrase returned seed")
		}
	}
}

func TestManifestBoundaryAndOwnership(t *testing.T) {
	f := fixtures(t)[0]
	entropy := fixtureEntropy(t, f)
	accounts := DefaultAccounts()
	accounts[0].NextExternal = MaxBranchIndex
	accounts[3].NextInternal = MaxBranchIndex
	m, err := ManifestFor(entropy, accounts)
	if err != nil {
		t.Fatal(err)
	}
	accounts[0].NextExternal = MaxBranchIndex + 1
	if m.Accounts[0].NextExternal != MaxBranchIndex {
		t.Fatal("manifest aliases input inventory")
	}
	if _, err := ManifestFor(entropy, accounts); err == nil {
		t.Fatal("cursor overflow accepted")
	}
	defaults := DefaultAccounts()
	defaults[0].Purpose = 999
	if DefaultAccounts()[0].Purpose != 44 {
		t.Fatal("mutable global default accounts")
	}
	path := GymPathIndices()
	path[0] = 0
	if GymPathIndices()[0] != 0xd34c5547 {
		t.Fatal("mutable gym path")
	}
	mutations := []func(*Manifest){
		func(m *Manifest) { m.Version++ }, func(m *Manifest) { m.Profile += "x" }, func(m *Manifest) { m.Network++ }, func(m *Manifest) { m.Genesis = strings.Repeat("0", 64) }, func(m *Manifest) { m.Derivation = "legacy" }, func(m *Manifest) { m.ScanFromHeight = 1 }, func(m *Manifest) { m.RootPublicKey = "invalid" }, func(m *Manifest) { m.GymPath = "m/0'" }, func(m *Manifest) { m.GymPublicKey = strings.ToUpper(m.GymPublicKey) }, func(m *Manifest) { m.GymID = strings.Repeat("0", 64) }, func(m *Manifest) { m.Accounts = m.Accounts[:3] }, func(m *Manifest) { m.Accounts[0].Account = 1 }, func(m *Manifest) { m.Accounts[0].Coin = 1 }, func(m *Manifest) { m.Accounts[1].InternalType = "p2sh-p2wpkh" }, func(m *Manifest) { m.Accounts[0], m.Accounts[1] = m.Accounts[1], m.Accounts[0] }, func(m *Manifest) { m.Accounts[0].NextInternal = MaxBranchIndex + 1 },
	}
	for _, mutate := range mutations {
		candidate := f.Export.Manifest
		candidate.Accounts = append([]Account(nil), candidate.Accounts...)
		mutate(&candidate)
		if ValidateManifest(candidate) == nil {
			t.Fatal("invalid typed manifest accepted")
		}
	}
	other := fixtures(t)[1].Export.Manifest
	if ValidateManifest(other) != nil {
		t.Fatal("second valid manifest rejected")
	}
	if ValidateEntropyManifest(entropy, other) == nil {
		t.Fatal("phrase identity swap accepted")
	}
	invalid := f.Export
	invalid.Manifest = other
	if _, err := MarshalExport(invalid); err == nil {
		t.Fatal("swapped identities exported")
	}
}

func TestRootPublicIdentityRestrictions(t *testing.T) {
	f := fixtures(t)[0]
	seed := SeedFromEntropy(fixtureEntropy(t, f))
	key, err := hdkeychain.NewMaster(seed[:], profileParams())
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	m := f.Export.Manifest
	m.RootPublicKey = key.String()
	if ValidateManifest(m) == nil {
		t.Fatal("private root accepted as public metadata")
	}
	child, err := key.Derive(0)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Zero()
	pub, err := child.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Zero()
	m.RootPublicKey = pub.String()
	if ValidateManifest(m) == nil {
		t.Fatal("nonroot extended key accepted")
	}
	m.RootPublicKey = strings.Repeat("a", 129)
	if ValidateManifest(m) == nil {
		t.Fatal("oversized root accepted")
	}
}

func TestStrictRecoveryJSON(t *testing.T) {
	f := fixtures(t)[0]
	raw, err := MarshalExport(f.Export)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	replacements := [][2]string{
		{`"version":1`, `"version":1,"version":1`}, {`"version":1`, `"Version":1`}, {`"version":1`, `"version":1.0`}, {`"version":1`, `"version":null`},
		{`"profile":`, `"unexpected":0,"profile":`}, {`"gym_path":`, `"gym_path":"m/0'","gym_path":`}, {`"coin":0`, `"coin":0,"coin":0`}, {`"next_external":0`, `"next_external":-1`}, {`"next_external":0`, `"next_external":4294967296`}, {`"accounts":[`, `"accounts":[null,`},
	}
	invalid := []string{"", valid + "{}", "null", "[]", strings.Repeat(" ", MaxExportSize+1), strings.Replace(valid, `"version":1,`, "", 1)}
	for _, pair := range replacements {
		mutated := strings.Replace(valid, pair[0], pair[1], 1)
		if mutated == valid {
			t.Fatal("bad test mutation")
		}
		invalid = append(invalid, mutated)
	}
	for _, data := range invalid {
		got, err := ParseExport([]byte(data))
		if err == nil || !reflect.DeepEqual(got, Export{}) {
			t.Fatal("invalid JSON returned export")
		}
		if strings.Contains(err.Error(), f.Export.Mnemonic) {
			t.Fatal("error exposed phrase")
		}
	}
	// Extra BIP39 passphrases are not a supported field or implicit wallet password.
	invalidPass := strings.Replace(valid, `"mnemonic":`, `"passphrase":"TREZOR","mnemonic":`, 1)
	if _, err := ParseExport([]byte(invalidPass)); err == nil {
		t.Fatal("additional passphrase accepted")
	}
}

func TestIndependentPaymentAddresses(t *testing.T) {
	raw, err := os.ReadFile("testdata/recovery_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Cases []struct {
			Seed      string `json:"seed"`
			Addresses []struct {
				Path      string `json:"path"`
				PublicKey string `json:"public_key"`
				Address   string `json:"address"`
				Script    string `json:"script_pub_key"`
			} `json:"addresses"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &data) != nil {
		t.Fatal("invalid fixture")
	}
	for _, f := range data.Cases {
		seed, _ := hex.DecodeString(f.Seed)
		for _, a := range f.Addresses {
			// Compare source-independent encodings through ordinary address/script APIs.
			decoded, err := address.DecodeAddress(a.Address, &chaincfg.MainNetParams)
			if err != nil {
				t.Fatal(err)
			}
			script, err := txscript.PayToAddrScript(decoded)
			if err != nil || hex.EncodeToString(script) != a.Script {
				t.Fatal("independent script mismatch", err)
			}
			key, err := hdkeychain.NewMaster(seed, profileParams())
			if err != nil {
				t.Fatal(err)
			}
			for _, component := range strings.Split(a.Path, "/")[1:] {
				var value uint32
				hardened := strings.HasSuffix(component, "'")
				component = strings.TrimSuffix(component, "'")
				for _, digit := range component {
					value = value*10 + uint32(digit-'0')
				}
				if hardened {
					value += hdkeychain.HardenedKeyStart
				}
				next, err := key.Derive(value)
				key.Zero()
				if err != nil {
					t.Fatal(err)
				}
				key = next
			}
			pub, err := key.ECPubKey()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub.SerializeCompressed(), mustHex(t, a.PublicKey)) {
				t.Fatal("independent payment public key mismatch")
			}
			if strings.HasPrefix(a.Path, "m/86'") {
				tapScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(pub))
				if err != nil || hex.EncodeToString(tapScript) != a.Script {
					t.Fatal("independent taproot output mismatch", err)
				}
			}
			key.Zero()
		}
	}
}
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
