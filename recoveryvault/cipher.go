// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"math"
	"time"
)

const providerTimeout = 30 * time.Second

func providerContext(ctx context.Context, wrapper KeyWrapper, expectedID string) (context.Context, context.CancelFunc, error) {
	if ctx == nil || wrapper == nil || !validReference(expectedID) || wrapper.ID() != expectedID {
		return nil, nil, ErrEnvelope
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	child, cancel := context.WithTimeout(ctx, providerTimeout)
	return child, cancel, nil
}

func providerError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrEnvelope
}

func sealEnvelope(ctx context.Context, wrapper KeyWrapper, binding Binding, purpose Purpose,
	contentRevision uint64, manifestHash string, payload []byte, keyRef string,
	random io.Reader) (Envelope, error) {

	var empty Envelope
	if len(payload) == 0 || len(payload) > MaxPayloadSize || random == nil || wrapper == nil || !validReference(keyRef) {
		return empty, ErrEnvelope
	}
	aad, err := contentAAD(binding, purpose, contentRevision, manifestHash)
	if err != nil {
		return empty, err
	}
	ctx, cancel, err := providerContext(ctx, wrapper, wrapper.ID())
	if err != nil {
		return empty, err
	}
	defer cancel()
	// Own bounded plaintext before any provider call. Clearing these explicit
	// buffers is best-effort; Go and its AES implementation can retain copies.
	plaintext := append([]byte(nil), payload...)
	defer clear(plaintext)
	var dek [32]byte
	defer clear(dek[:])
	var nonce [12]byte
	if _, err = io.ReadFull(random, dek[:]); err != nil {
		return empty, ErrEnvelope
	}
	if _, err = io.ReadFull(random, nonce[:]); err != nil {
		return empty, ErrEnvelope
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return empty, ErrEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return empty, ErrEnvelope
	}
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	e := Envelope{Version: Version1, Binding: binding, Purpose: purpose, ContentRevision: contentRevision,
		ManifestHash: manifestHash, Nonce: hex.EncodeToString(nonce[:]), Ciphertext: hex.EncodeToString(ciphertext),
		WrapperID: wrapper.ID(), KeyRef: keyRef, WrapRevision: 1}
	wrapAAD, err := wrappingAAD(e)
	if err != nil {
		return empty, err
	}
	wrapped, err := wrapper.Wrap(ctx, keyRef, dek, append([]byte(nil), wrapAAD...))
	if err != nil || len(wrapped) == 0 || len(wrapped) > MaxWrappedKeySize {
		return empty, providerError(ctx)
	}
	e.WrappedKey = hex.EncodeToString(wrapped)
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	// A returned provider blob must recover this exact data key. A malformed
	// success is not retained as a supposedly recoverable envelope.
	confirmed, err := unwrapKey(ctx, wrapper, e)
	defer clear(confirmed[:])
	if err != nil {
		return empty, err
	}
	if subtle.ConstantTimeCompare(dek[:], confirmed[:]) != 1 {
		return empty, ErrEnvelope
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return e, nil
}

func unwrapKey(ctx context.Context, wrapper KeyWrapper, e Envelope) ([32]byte, error) {
	var empty [32]byte
	if validateEnvelope(e) != nil || wrapper == nil || wrapper.ID() != e.WrapperID {
		return empty, ErrEnvelope
	}
	aad, err := wrappingAAD(e)
	if err != nil {
		return empty, err
	}
	blob, _ := hex.DecodeString(e.WrappedKey)
	key, err := wrapper.Unwrap(ctx, e.KeyRef, blob, aad)
	if err != nil {
		clear(key[:])
		return empty, providerError(ctx)
	}
	if err := ctx.Err(); err != nil {
		clear(key[:])
		return empty, err
	}
	return key, nil
}

// openEnvelope is deliberately private. Its caller first authorizes a narrow
// capability, then reauthorizes the original session after provider preparation
// and before a protected effect. Callers clear the returned owned buffer.
func openEnvelope(ctx context.Context, wrapper KeyWrapper, e Envelope) ([]byte, error) {
	if validateEnvelope(e) != nil {
		return nil, ErrEnvelope
	}
	ctx, cancel, err := providerContext(ctx, wrapper, e.WrapperID)
	if err != nil {
		return nil, err
	}
	defer cancel()
	dek, err := unwrapKey(ctx, wrapper, e)
	defer clear(dek[:])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return nil, ErrEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEnvelope
	}
	aad, err := contentAAD(e.Binding, e.Purpose, e.ContentRevision, e.ManifestHash)
	if err != nil {
		return nil, err
	}
	nonce, _ := hex.DecodeString(e.Nonce)
	ciphertext, _ := hex.DecodeString(e.Ciphertext)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrEnvelope
	}
	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func rewrapEnvelope(ctx context.Context, wrapper KeyWrapper, e Envelope,
	targetKeyRef string, nextRevision uint64) (Envelope, error) {

	var empty Envelope
	if validateEnvelope(e) != nil || !validReference(targetKeyRef) || e.WrapRevision == math.MaxUint64 || nextRevision != e.WrapRevision+1 {
		return empty, ErrEnvelope
	}
	ctx, cancel, err := providerContext(ctx, wrapper, e.WrapperID)
	if err != nil {
		return empty, err
	}
	defer cancel()
	dek, err := unwrapKey(ctx, wrapper, e)
	defer clear(dek[:])
	if err != nil {
		return empty, err
	}
	result := e
	result.KeyRef = targetKeyRef
	result.WrapRevision = nextRevision
	result.WrappedKey = ""
	aad, err := wrappingAAD(result)
	if err != nil {
		return empty, err
	}
	wrapped, err := wrapper.Wrap(ctx, targetKeyRef, dek, append([]byte(nil), aad...))
	if err != nil || len(wrapped) == 0 || len(wrapped) > MaxWrappedKeySize {
		return empty, providerError(ctx)
	}
	result.WrappedKey = hex.EncodeToString(wrapped)
	confirmed, err := unwrapKey(ctx, wrapper, result)
	defer clear(confirmed[:])
	if err != nil {
		return empty, err
	}
	if subtle.ConstantTimeCompare(dek[:], confirmed[:]) != 1 {
		return empty, ErrEnvelope
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return result, nil
}
