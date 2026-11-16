module github.com/taytr-llc/slugwallet

require (
	github.com/btcsuite/btclog v1.0.0
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/golang/protobuf v1.5.4
	github.com/gorilla/websocket v1.5.3
	github.com/jessevdk/go-flags v1.6.1
	github.com/jrick/logrotate v1.1.2
	github.com/lightninglabs/neutrino/cache v1.1.4
	github.com/lightningnetwork/lnd/fn/v2 v2.0.8
	github.com/stretchr/testify v1.12.1
	github.com/taytr-llc/slug v0.27.0
	github.com/taytr-llc/slug/address/v2 v2.0.1
	github.com/taytr-llc/slug/btcec/v2 v2.5.1
	github.com/taytr-llc/slug/btcutil/v2 v2.0.2
	github.com/taytr-llc/slug/chaincfg/v2 v2.0.0
	github.com/taytr-llc/slug/chainhash/v2 v2.0.0
	github.com/taytr-llc/slug/psbt/v2 v2.0.0
	github.com/taytr-llc/slug/txscript/v2 v2.0.1
	github.com/taytr-llc/slug/wire/v2 v2.0.2
	github.com/taytr-llc/slugwallet/wallet/txauthor v1.4.0
	github.com/taytr-llc/slugwallet/wallet/txrules v1.3.0
	github.com/taytr-llc/slugwallet/wallet/txsizes v1.3.0
	github.com/taytr-llc/slugwallet/walletdb v1.6.0
	github.com/taytr-llc/slugwallet/wtxmgr v1.6.1-0.20261020132555-16cfb4483d1f
	golang.org/x/crypto v0.57.0
	golang.org/x/exp v0.0.0-20250811191247-51f88131bc50
	golang.org/x/net v0.60.0
	golang.org/x/sync v0.23.0
	golang.org/x/term v0.46.0
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/lightningnetwork/lnd/clock v1.0.1 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
)

// If you change this please run `make lint` to see where else it needs to be
// updated as well.
go 1.27.3

// Resolve the unpublished SLUG fork modules from these sibling checkouts.
replace (
	github.com/taytr-llc/slug => ../slug
	github.com/taytr-llc/slug/address/v2 => ../slug/address
	github.com/taytr-llc/slug/btcec/v2 => ../slug/btcec
	github.com/taytr-llc/slug/btcutil/v2 => ../slug/btcutil
	github.com/taytr-llc/slug/chaincfg/v2 => ../slug/chaincfg
	github.com/taytr-llc/slug/chainhash/v2 => ../slug/chainhash
	github.com/taytr-llc/slug/psbt/v2 => ../slug/psbt
	github.com/taytr-llc/slug/txscript/v2 => ../slug/txscript
	github.com/taytr-llc/slug/v2transport => ../slug/v2transport
	github.com/taytr-llc/slug/wire/v2 => ../slug/wire
	github.com/taytr-llc/slugwallet/wallet/txauthor => ./wallet/txauthor
	github.com/taytr-llc/slugwallet/wallet/txrules => ./wallet/txrules
	github.com/taytr-llc/slugwallet/wallet/txsizes => ./wallet/txsizes
	github.com/taytr-llc/slugwallet/walletdb => ./walletdb
	github.com/taytr-llc/slugwallet/wtxmgr => ./wtxmgr
)
