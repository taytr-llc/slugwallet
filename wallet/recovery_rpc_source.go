// Copyright (c) 2026 The SLUG developers. ISC license.

package wallet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
)

const recoveryRPCSmallLimit int64 = 64 * 1024
const recoveryRPCBlockLimit int64 = 2*wire.MaxBlockPayload + 4096
const recoveryRPCDeadline = 30 * time.Second

// RecoveryRPCConfig names a separately trusted, read-only full-node source.
// Plaintext is restricted to literal loopback. TLS uses normal hostname and CA
// verification; no certificate bypass, proxy or redirect option is provided.
type RecoveryRPCConfig struct {
	URL           string `json:"-"`
	Username      string `json:"-"`
	Password      string `json:"-"`
	CACertificate []byte `json:"-"`
}

func (RecoveryRPCConfig) String() string   { return "RecoveryRPCConfig{redacted}" }
func (RecoveryRPCConfig) GoString() string { return "RecoveryRPCConfig{redacted}" }

// RecoveryRPCSource opens one bounded WebSocket for each public method. It
// checks the chain identity and activation rules on that exact connection
// before requesting data. There is no implicit reconnect onto an unchecked
// transport. Calls are serialized; cancellation closes the actual connection.
type RecoveryRPCSource struct {
	url       string
	header    http.Header
	dialer    websocket.Dialer
	identity  RecoverySourceIdentity
	gate      chan struct{}
	life      context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeDone chan struct{}
}

var _ RecoveryBlockSource = (*RecoveryRPCSource)(nil)

func NewRecoveryRPCSource(config RecoveryRPCConfig) (*RecoveryRPCSource, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "/ws" || u.RawPath != "" || (u.Scheme != "ws" && u.Scheme != "wss") || wire.TestPoW {
		return nil, ErrRecoverySource
	}
	if len(config.URL) > 2048 || len(config.Username) == 0 || len(config.Username) > 256 || len(config.Password) == 0 || len(config.Password) > 4096 || strings.Contains(config.Username, ":") || len(config.CACertificate) > 1<<20 {
		return nil, ErrRecoverySource
	}
	if u.Scheme == "ws" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() || len(config.CACertificate) != 0 {
			return nil, ErrRecoverySource
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(config.CACertificate) != 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(append([]byte(nil), config.CACertificate...)) {
			return nil, ErrRecoverySource
		}
		tlsConfig.RootCAs = pool
	}
	life, cancel := context.WithCancel(context.Background())
	s := &RecoveryRPCSource{
		url: config.URL, header: make(http.Header),
		dialer:   websocket.Dialer{Proxy: nil, HandshakeTimeout: recoveryRPCDeadline, TLSClientConfig: tlsConfig, EnableCompression: false},
		identity: RecoverySourceIdentity{Network: uint32(chaincfg.MainNetParams.Net), Genesis: *chaincfg.MainNetParams.GenesisHash, CSVHeight: 62, SegwitHeight: 62, TaprootHeight: 62},
		gate:     make(chan struct{}, 1), life: life, cancel: cancel, closeDone: make(chan struct{}),
	}
	s.header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password)))
	s.gate <- struct{}{}
	return s, nil
}

func recoverySourceError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrRecoverySource
	}
	return nil
}

type recoveryRPCConnection struct {
	conn *websocket.Conn
	id   uint64
}

// Bound the TLS/HTTP upgrade read before WebSocket frame limits take effect.
// After DialContext returns, the owned WebSocket applies its per-message limit.
type recoveryHandshakeConn struct {
	net.Conn
	guard     atomic.Bool
	remaining int64
}

func (c *recoveryHandshakeConn) Read(p []byte) (int, error) {
	if !c.guard.Load() {
		return c.Conn.Read(p)
	}
	if c.remaining <= 0 {
		return 0, ErrRecoverySource
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

type recoveryRPCResponse struct {
	JSONRPC string
	ID      string
	Result  json.RawMessage
	Error   json.RawMessage
}

func decodeRecoveryRPCResponse(raw []byte) (recoveryRPCResponse, error) {
	var response recoveryRPCResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return response, ErrRecoverySource
	}
	seen := make(map[string]bool, 4)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return response, ErrRecoverySource
		}
		seen[key] = true
		switch key {
		case "jsonrpc":
			err = decoder.Decode(&response.JSONRPC)
		case "id":
			err = decoder.Decode(&response.ID)
		case "result":
			err = decoder.Decode(&response.Result)
		case "error":
			err = decoder.Decode(&response.Error)
		default:
			return response, ErrRecoverySource
		}
		if err != nil {
			return response, ErrRecoverySource
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return response, ErrRecoverySource
	}
	if _, err = decoder.Token(); err != io.EOF {
		return response, ErrRecoverySource
	}
	return response, nil
}

func (c *recoveryRPCConnection) call(method string, params []any, limit int64, out any) error {
	c.id++
	id := "slug-recovery-" + strconv.FormatUint(c.id, 10)
	request := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"1.0", id, method, params}
	c.conn.SetReadLimit(limit)
	if err := c.conn.WriteJSON(request); err != nil {
		return ErrRecoverySource
	}
	kind, raw, err := c.conn.ReadMessage()
	if err != nil || kind != websocket.TextMessage || int64(len(raw)) > limit {
		return ErrRecoverySource
	}
	response, err := decodeRecoveryRPCResponse(raw)
	if err != nil || response.ID != id || (response.JSONRPC != "" && response.JSONRPC != "1.0" && response.JSONRPC != "2.0") || len(response.Result) == 0 || bytes.Equal(response.Result, []byte("null")) || (len(response.Error) != 0 && !bytes.Equal(response.Error, []byte("null"))) {
		return ErrRecoverySource
	}
	// Never return server errors, request bodies or credential-bearing URLs.
	if json.Unmarshal(response.Result, out) != nil {
		return ErrRecoverySource
	}
	return nil
}

func recoverySourceHash(text string) (chainhash.Hash, error) {
	if len(text) != 64 || strings.ToLower(text) != text {
		return chainhash.Hash{}, ErrRecoverySource
	}
	hash, err := chainhash.NewHashFromStr(text)
	if err != nil {
		return chainhash.Hash{}, ErrRecoverySource
	}
	return *hash, nil
}

func (c *recoveryRPCConnection) identity() (RecoverySourceIdentity, error) {
	var identity RecoverySourceIdentity
	if err := c.call("getcurrentnet", []any{}, recoveryRPCSmallLimit, &identity.Network); err != nil {
		return identity, err
	}
	var genesis string
	if err := c.call("getblockhash", []any{0}, recoveryRPCSmallLimit, &genesis); err != nil {
		return identity, err
	}
	var err error
	identity.Genesis, err = recoverySourceHash(genesis)
	if err != nil {
		return identity, err
	}
	var chainInfo struct {
		Forks map[string]struct {
			Height *int32 `json:"always_active_height"`
		} `json:"bip9_softforks"`
	}
	if err := c.call("getblockchaininfo", []any{}, recoveryRPCSmallLimit, &chainInfo); err != nil {
		return identity, err
	}
	csv, segwit, taproot := chainInfo.Forks["csv"].Height, chainInfo.Forks["segwit"].Height, chainInfo.Forks["taproot"].Height
	if csv == nil || segwit == nil || taproot == nil {
		return identity, ErrRecoverySource
	}
	identity.CSVHeight, identity.SegwitHeight, identity.TaprootHeight = *csv, *segwit, *taproot
	return identity, nil
}

func (s *RecoveryRPCSource) withConnection(ctx context.Context, fn func(*recoveryRPCConnection, RecoverySourceIdentity) error) error {
	if ctx == nil || s == nil {
		return ErrRecoverySource
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.life.Done():
		return ErrRecoveryClosed
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.life.Err() != nil {
		return ErrRecoveryClosed
	}
	operation, cancel := context.WithTimeout(ctx, recoveryRPCDeadline)
	defer cancel()
	stopLifetime := context.AfterFunc(s.life, cancel)
	defer stopLifetime()
	dialer := s.dialer
	var transport *recoveryHandshakeConn
	var stopSocket func() bool
	closed := make(chan struct{})
	defer func() {
		if stopSocket != nil && !stopSocket() {
			<-closed
		}
	}()
	dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if transport != nil {
			return nil, ErrRecoverySource
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		transport = &recoveryHandshakeConn{Conn: conn, remaining: recoveryRPCSmallLimit}
		transport.guard.Store(true)
		// Gorilla's HTTP upgrade read is not canceled by DialContext once
		// TCP connects. Own cancellation from this point through all TLS,
		// upgrade and WebSocket reads, closing the actual underlying socket.
		stopSocket = context.AfterFunc(operation, func() { conn.Close(); close(closed) })
		return transport, nil
	}
	conn, response, err := dialer.DialContext(operation, s.url, s.header)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		if s.life.Err() != nil {
			return ErrRecoveryClosed
		}
		return recoverySourceError(operation, err)
	}
	transport.guard.Store(false)
	defer conn.Close()
	deadline, _ := operation.Deadline()
	if err := errors.Join(conn.SetReadDeadline(deadline), conn.SetWriteDeadline(deadline)); err != nil {
		return ErrRecoverySource
	}
	client := &recoveryRPCConnection{conn: conn}
	identity, err := client.identity()
	if err == nil && identity != s.identity {
		err = ErrRecoverySource
	}
	if err == nil {
		err = fn(client, identity)
	}
	if s.life.Err() != nil {
		return ErrRecoveryClosed
	}
	return recoverySourceError(operation, err)
}

func (s *RecoveryRPCSource) Identity(ctx context.Context) (RecoverySourceIdentity, error) {
	var result RecoverySourceIdentity
	err := s.withConnection(ctx, func(_ *recoveryRPCConnection, identity RecoverySourceIdentity) error { result = identity; return nil })
	if err != nil {
		return RecoverySourceIdentity{}, err
	}
	return result, nil
}

func (s *RecoveryRPCSource) BestBlock(ctx context.Context) (RecoveryTip, error) {
	var result RecoveryTip
	err := s.withConnection(ctx, func(c *recoveryRPCConnection, _ RecoverySourceIdentity) error {
		var tip struct {
			Height *int32 `json:"height"`
			Hash   string `json:"hash"`
		}
		if err := c.call("getbestblock", []any{}, recoveryRPCSmallLimit, &tip); err != nil || tip.Height == nil || *tip.Height < 0 {
			return ErrRecoverySource
		}
		hash, err := recoverySourceHash(tip.Hash)
		result = RecoveryTip{Height: *tip.Height, Hash: hash}
		return err
	})
	if err != nil {
		return RecoveryTip{}, err
	}
	return result, nil
}

func (s *RecoveryRPCSource) BlockHash(ctx context.Context, height int32) (chainhash.Hash, error) {
	var result chainhash.Hash
	if height < 0 {
		return result, ErrRecoverySource
	}
	err := s.withConnection(ctx, func(c *recoveryRPCConnection, _ RecoverySourceIdentity) error {
		var text string
		if err := c.call("getblockhash", []any{height}, recoveryRPCSmallLimit, &text); err != nil {
			return err
		}
		var err error
		result, err = recoverySourceHash(text)
		return err
	})
	if err != nil {
		return chainhash.Hash{}, err
	}
	return result, nil
}

func (s *RecoveryRPCSource) Block(ctx context.Context, hash chainhash.Hash) (*wire.MsgBlock, error) {
	var result *wire.MsgBlock
	err := s.withConnection(ctx, func(c *recoveryRPCConnection, _ RecoverySourceIdentity) error {
		var encoded string
		if err := c.call("getblock", []any{hash.String(), 0}, recoveryRPCBlockLimit, &encoded); err != nil {
			return err
		}
		if len(encoded) > 2*wire.MaxBlockPayload || len(encoded)%2 != 0 {
			return ErrRecoverySource
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return ErrRecoverySource
		}
		reader := bytes.NewReader(raw)
		block := new(wire.MsgBlock)
		if block.Deserialize(reader) != nil || reader.Len() != 0 {
			return ErrRecoverySource
		}
		result = block // Session verifies hash, merkle root and canonical binding.
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *RecoveryRPCSource) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.gate
		s.gate <- struct{}{}
		close(s.closeDone)
	})
	<-s.closeDone
	return nil
}
