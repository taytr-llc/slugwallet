#!/bin/sh
# Public fixture only. No real wallet/key paths are accepted or accessed.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
: "${SLUG_WALLET_NODE:?Set SLUG_WALLET_NODE to an explicit normal-PoW slugd executable}"
export SLUG_WALLET_NODE
export GOFLAGS=
python3 integration/testdata/reference_addresses.py --check
go test -tags=integration -count=1 -timeout=15m -v ./integration
