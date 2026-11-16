// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recovery

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// englishWords is the pinned BIP39 English wordlist; see testdata/README.md.
//
//go:embed english.txt
var englishWords string
var words = strings.Fields(englishWords)
var wordIndexes = func() map[string]uint16 {
	if len(words) != 2048 {
		panic("invalid embedded BIP39 wordlist")
	}
	result := make(map[string]uint16, 2048)
	for i, word := range words {
		if _, exists := result[word]; exists {
			panic("duplicate embedded BIP39 word")
		}
		result[word] = uint16(i)
	}
	return result
}()

// Mnemonic encodes exactly 256 bits as the approved 24-word English phrase.
func Mnemonic(entropy [32]byte) string {
	defer clear(entropy[:])
	checksum := sha256.Sum256(entropy[:])
	var bits [33]byte
	copy(bits[:32], entropy[:])
	bits[32] = checksum[0]
	result := make([]string, 24)
	for i := range result {
		var index uint16
		for j := 0; j < 11; j++ {
			offset := i*11 + j
			index = (index << 1) | uint16((bits[offset/8]>>uint(7-offset%8))&1)
		}
		result[i] = words[index]
	}
	clear(bits[:])
	return strings.Join(result, " ")
}

// Entropy validates canonical spelling, spacing, word count and checksum.
// UI normalization, if added later, must happen explicitly before this codec.
func Entropy(phrase string) ([32]byte, error) {
	var entropy [32]byte
	if len(phrase) > MaxPhraseSize {
		return entropy, errors.New("invalid recovery phrase")
	}
	split := strings.Split(phrase, " ")
	if len(split) != 24 {
		return entropy, errors.New("recovery phrase must contain 24 canonical English words")
	}
	var bits [33]byte
	defer clear(bits[:])
	for i, word := range split {
		index, ok := wordIndexes[word]
		if !ok {
			return entropy, errors.New("invalid recovery phrase word or spacing")
		}
		for j := 0; j < 11; j++ {
			offset := i*11 + j
			bits[offset/8] |= byte((index>>uint(10-j))&1) << uint(7-offset%8)
		}
	}
	copy(entropy[:], bits[:32])
	checksum := sha256.Sum256(entropy[:])
	if bits[32] != checksum[0] {
		clear(entropy[:])
		return entropy, errors.New("invalid recovery phrase checksum")
	}
	return entropy, nil
}

// Seed validates the fixed phrase profile and derives its standard BIP39 seed.
// The additional BIP39 passphrase is always empty, unrelated to wallet unlock.
func Seed(phrase string) ([64]byte, error) {
	entropy, err := Entropy(phrase)
	clear(entropy[:])
	if err != nil {
		return [64]byte{}, err
	}
	return phraseSeed(phrase), nil
}

// SeedFromEntropy derives a standard BIP39 seed for the fixed profile.
func SeedFromEntropy(entropy [32]byte) [64]byte {
	defer clear(entropy[:])
	return phraseSeed(Mnemonic(entropy))
}

func phraseSeed(phrase string) [64]byte {
	// Canonical English words and an empty passphrase are already NFKD.
	var result [64]byte
	password := []byte(phrase)
	defer clear(password)
	derived := pbkdf2.Key(password, []byte("mnemonic"), 2048, 64, sha512.New)
	copy(result[:], derived)
	clear(derived)
	return result
}
