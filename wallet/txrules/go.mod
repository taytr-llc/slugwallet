module github.com/taytr-llc/slugwallet/wallet/txrules

require (
	github.com/taytr-llc/slug v0.27.0
	github.com/taytr-llc/slug/btcutil/v2 v2.0.2
	github.com/taytr-llc/slug/txscript/v2 v2.0.1
	github.com/taytr-llc/slug/wire/v2 v2.0.2
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/taytr-llc/slug/address/v2 v2.0.1 // indirect
	github.com/taytr-llc/slug/btcec/v2 v2.5.1 // indirect
	github.com/taytr-llc/slug/chaincfg/v2 v2.0.0 // indirect
	github.com/taytr-llc/slug/chainhash/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

go 1.27.3

// Resolve the unpublished SLUG fork modules from these sibling checkouts.
replace (
	github.com/taytr-llc/slug => ../../../slug
	github.com/taytr-llc/slug/address/v2 => ../../../slug/address
	github.com/taytr-llc/slug/btcec/v2 => ../../../slug/btcec
	github.com/taytr-llc/slug/btcutil/v2 => ../../../slug/btcutil
	github.com/taytr-llc/slug/chaincfg/v2 => ../../../slug/chaincfg
	github.com/taytr-llc/slug/chainhash/v2 => ../../../slug/chainhash
	github.com/taytr-llc/slug/psbt/v2 => ../../../slug/psbt
	github.com/taytr-llc/slug/txscript/v2 => ../../../slug/txscript
	github.com/taytr-llc/slug/v2transport => ../../../slug/v2transport
	github.com/taytr-llc/slug/wire/v2 => ../../../slug/wire
	github.com/taytr-llc/slugwallet => ../..
	github.com/taytr-llc/slugwallet/wallet/txauthor => ../txauthor
	github.com/taytr-llc/slugwallet/wallet/txsizes => ../txsizes
	github.com/taytr-llc/slugwallet/walletdb => ../../walletdb
	github.com/taytr-llc/slugwallet/wtxmgr => ../../wtxmgr
)
