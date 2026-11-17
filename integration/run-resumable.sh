#!/bin/sh
# Published candidate fixtures only; disposable loopback normal-PoW chain.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
: "${SLUG_WALLET_NODE:?Set an explicit activation-62 normal-PoW slugd binary}"
export SLUG_WALLET_NODE
export GOFLAGS=
python3 productionprofile/testdata/reference_recovery_indices.py --check
go test -tags=integration,recoveryintegration,candidateintegration,resumablerecoveryintegration -run '^TestResumableRecoveryNormalPoW$' -count=1 -timeout=20m -v ./integration
