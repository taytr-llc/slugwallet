#!/bin/bash
# Keep the six runtime modules consistent with the paired local SLUG checkout.
set -euo pipefail
cd "$(dirname "$0")/.."
for module in . wallet/txauthor wallet/txrules wallet/txsizes walletdb wtxmgr; do
    (cd "$module" && GOWORK=off go mod tidy)
done
