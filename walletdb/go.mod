module github.com/taytr-llc/slugwallet/walletdb

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/davecgh/go-spew v1.1.1
	go.etcd.io/bbolt v1.3.11
)

require (
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
)

go 1.27.3

// Resolve the unpublished SLUG fork modules from these sibling checkouts.
replace (
	github.com/taytr-llc/slug => ../../slug
	github.com/taytr-llc/slug/address/v2 => ../../slug/address
	github.com/taytr-llc/slug/btcec/v2 => ../../slug/btcec
	github.com/taytr-llc/slug/btcutil/v2 => ../../slug/btcutil
	github.com/taytr-llc/slug/chaincfg/v2 => ../../slug/chaincfg
	github.com/taytr-llc/slug/chainhash/v2 => ../../slug/chainhash
	github.com/taytr-llc/slug/psbt/v2 => ../../slug/psbt
	github.com/taytr-llc/slug/txscript/v2 => ../../slug/txscript
	github.com/taytr-llc/slug/v2transport => ../../slug/v2transport
	github.com/taytr-llc/slug/wire/v2 => ../../slug/wire
	github.com/taytr-llc/slugwallet => ..
	github.com/taytr-llc/slugwallet/wallet/txauthor => ../wallet/txauthor
	github.com/taytr-llc/slugwallet/wallet/txrules => ../wallet/txrules
	github.com/taytr-llc/slugwallet/wallet/txsizes => ../wallet/txsizes
	github.com/taytr-llc/slugwallet/wtxmgr => ../wtxmgr
)
