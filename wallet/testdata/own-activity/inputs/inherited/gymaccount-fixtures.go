// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package gymaccount

import "errors"

// FixtureIdentity returns only public identities independently derived by
// recovery/testdata/reference_recovery.py in the paired wallet repository.
// These two published fixtures are not secret or suitable for real funds.
func FixtureIdentity(name string) (Identity, error) {
	switch name {
	case "zero256":
		return Identity{Network: FixtureNetwork, Genesis: FixtureGenesis, Profile: FixtureProfile, RootPublicKey: "JgduaQiYjRcnjcD9t1MfTP1qo8eWaAWPQtS9nChXwtAeyTsoEGVZ8SjVqa5qxxvvKqX8tqC77wMSjaMHXNY8JSYEASdzX6PT31ktXqKPJvkhyy31", GymPublicKey: "03ec7488667fd544b4a1de8fb0ae03730c9a2dc346c652cbaa59a077dbeddca519", GymID: "a227587d837507dbcb5f9d781967339d816070fb7bd574931c690ba6937b88e5"}, nil
	case "incrementing256":
		return Identity{Network: FixtureNetwork, Genesis: FixtureGenesis, Profile: FixtureProfile, RootPublicKey: "JgduaQiYjRcnjcD9syNDf4x3txTZkg8HpvTKZtposTTw7bTLpRzvd7ibV3buRixMEqAwVAyreX36pAw5DxLXwG5gW6EGNWeRcJfJitkx2kCJ54pC", GymPublicKey: "033de5e2e3d5ad06f616572fcb3d61f089ce1105ef486debf308027b3b663d6d92", GymID: "28452fc8a478d28f284dfe671cfc57e7cabeca08ea953aef371f5674d3f4c510"}, nil
	default:
		return Identity{}, errors.New("unknown public account fixture")
	}
}
