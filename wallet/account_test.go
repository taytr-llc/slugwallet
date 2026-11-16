package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

type accountSigningVector struct {
	Name          string                         `json:"name"`
	FixtureName   string                         `json:"fixture_name"`
	Challenge     gymaccount.EnrollmentChallenge `json:"challenge"`
	Authorization gymaccount.Authorization       `json:"authorization"`
}

func accountSigningVectors(t *testing.T) []accountSigningVector {
	t.Helper()
	data, err := os.ReadFile("../../slug/gymaccount/testdata/enrollment_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FixtureOnly bool                   `json:"fixture_only"`
		Cases       []accountSigningVector `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || !fixture.FixtureOnly || len(fixture.Cases) != 4 {
		t.Fatal("invalid independent public account vectors", err)
	}
	return fixture.Cases
}

func assertAccountSignature(t *testing.T, w *Wallet, v accountSigningVector) {
	t.Helper()
	got, err := w.SignAccountChallenge(context.Background(), v.Challenge.AuthorityID, v.Challenge)
	if err != nil || got != v.Authorization {
		t.Fatal("account signature differs from independent fixture", err)
	}
	if err := gymaccount.VerifyAuthorization(v.Challenge, got); err != nil {
		t.Fatal(err)
	}
}

func TestAccountChallengeRetainedRekeyRestore(t *testing.T) {
	if wire.TestPoW {
		t.Skip("normal-chain account profile")
	}
	vectors := accountSigningVectors(t)
	for _, name := range []string{"zero256", "incrementing256"} {
		t.Run(name, func(t *testing.T) {
			f := retainedRecoveryFixture(t, name)
			l := retainedLoader(t)
			w := retainedCreate(t, l, f)
			var enroll, recoverVector accountSigningVector
			for _, v := range vectors {
				if v.FixtureName == name {
					if v.Challenge.Action == "enroll" {
						enroll = v
					} else {
						recoverVector = v
					}
				}
			}
			if got, err := w.SignAccountChallenge(context.Background(), enroll.Challenge.AuthorityID, enroll.Challenge); err == nil || got != (gymaccount.Authorization{}) {
				t.Fatal("locked wallet signed")
			}
			retainedUnlock(t, w, retainedPrivPass)
			assertAccountSignature(t, w, enroll)
			wrong := enroll.Challenge
			wrong.AuthorityID = strings.Repeat("00", 32)
			if got, err := w.SignAccountChallenge(context.Background(), enroll.Challenge.AuthorityID, wrong); err == nil || got != (gymaccount.Authorization{}) {
				t.Fatal("untrusted authority signed")
			}
			for _, other := range vectors {
				if other.FixtureName != name {
					if got, err := w.SignAccountChallenge(context.Background(), other.Challenge.AuthorityID, other.Challenge); err == nil || got != (gymaccount.Authorization{}) {
						t.Fatal("other wallet identity signed")
					}
					break
				}
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := w.SignAccountChallenge(canceled, enroll.Challenge.AuthorityID, enroll.Challenge); !errors.Is(err, context.Canceled) || got != (gymaccount.Authorization{}) {
				t.Fatal("canceled signing released authorization", err)
			}
			want := f.Export
			want.Manifest.Accounts = recovery.DefaultAccounts()
			// This uses the existing serialized wallet password API outside any
			// unlock lease. Login reset credentials are separate from this key.
			newPass := []byte("rotated account fixture password")
			if err := w.ChangePrivatePassphrase(retainedPrivPass, newPass); err != nil {
				t.Fatal(err)
			}
			if err := l.UnloadWallet(); err != nil {
				t.Fatal(err)
			}
			w.Manager.Close()
			w, err := l.OpenExistingWallet(retainedPubPass, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Unlock(retainedPrivPass, nil); err == nil {
				t.Fatal("old private password still unlocks")
			}
			retainedUnlock(t, w, newPass)
			assertAccountSignature(t, w, recoverVector)
			bundle, err := w.ExportRecovery(context.Background())
			if err != nil || !reflect.DeepEqual(bundle, want) {
				t.Fatal("password rotation changed retained recovery", err)
			}
			if err := l.UnloadWallet(); err != nil {
				t.Fatal(err)
			}
			w.Manager.Close()
			if got, err := w.SignAccountChallenge(context.Background(), recoverVector.Challenge.AuthorityID, recoverVector.Challenge); err == nil || got != (gymaccount.Authorization{}) {
				t.Fatal("stopped wallet signed")
			}
			fresh := retainedLoader(t)
			restored, err := fresh.RestoreRecoveryWallet(retainedPubPass, []byte("different restore fixture password"), bundle)
			if err != nil {
				t.Fatal(err)
			}
			retainedUnlock(t, restored, []byte("different restore fixture password"))
			assertAccountSignature(t, restored, recoverVector)
		})
	}
}

func TestAccountChallengeRejectsOtherRecoveryProfile(t *testing.T) {
	f := retainedRecoveryFixture(t, "official-leading-zero-account")
	l := retainedLoader(t)
	w := retainedCreate(t, l, f)
	retainedUnlock(t, w, retainedPrivPass)
	c := accountSigningVectors(t)[0].Challenge
	c.RootPublicKey, c.GymPublicKey, c.GymID = f.Export.Manifest.RootPublicKey, f.Export.Manifest.GymPublicKey, f.Export.Manifest.GymID
	if got, err := w.SignAccountChallenge(context.Background(), c.AuthorityID, c); err == nil || got != (gymaccount.Authorization{}) {
		t.Fatal("non-account fixture signed")
	}
}

func TestAccountChallengeCheapProfileRefusal(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("cheap-profile refusal")
	}
	// The refusal must happen before accessing any manager or retained secrets.
	var w Wallet
	c := accountSigningVectors(t)[0].Challenge
	if got, err := w.SignAccountChallenge(context.Background(), c.AuthorityID, c); err == nil || got != (gymaccount.Authorization{}) {
		t.Fatal("cheap profile signed")
	}
}
