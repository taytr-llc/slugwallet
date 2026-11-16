#!/bin/sh
# Published fixture only; never uses a real wallet, key, or public peer.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
: "${SLUG_WALLET_NODE:?Set SLUG_WALLET_NODE to an explicit normal-PoW slugd executable}"
export SLUG_WALLET_NODE
export GOFLAGS=
python3 recovery/testdata/reference_recovery.py --check
python3 integration/testdata/reference_recovery_highwater.py --check
go test -tags=integration,recoveryintegration -run '^TestWalletRecoveryNormalPoW$' -count=1 -timeout=15m -v ./integration
