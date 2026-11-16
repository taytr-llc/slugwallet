#!/bin/sh
# Public candidate fixtures only; normal PoW on disposable loopback nodes.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
: "${SLUG_WALLET_NODE:?Set SLUG_WALLET_NODE to an explicit activation-62 normal-PoW slugd executable}"
export SLUG_WALLET_NODE
export GOFLAGS=
python3 productionprofile/testdata/reference_profile.py --check
go test -tags=integration,recoveryintegration,candidateintegration -run '^TestCandidateProfileNormalPoW$' -count=1 -timeout=15m -v ./integration
