#!/bin/sh
# Published fixtures, normal PoW and disposable loopback nodes only.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
: "${SLUG_WALLET_NODE:?Set SLUG_WALLET_NODE to an explicit activation-62 normal-PoW slugd executable}"
export SLUG_WALLET_NODE
export GOFLAGS=
python3 recovery/testdata/reference_recovery.py --check
python3 integration/testdata/reference_recovery_highwater.py --check
go test -tags=integration,recoveryintegration,activationintegration -run '^TestWalletActivatedRecoveryNormalPoW$' -count=1 -timeout=20m -v ./integration
