// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/mr-tron/base58"
)

func publicKeyFromDID(did string) (ed25519.PublicKey, error) {
	const prefix = "did:key:z"
	if len(did) <= len(prefix) || did[:len(prefix)] != prefix {
		return nil, fmt.Errorf("invalid did:key: %s", did)
	}
	decoded, err := base58.Decode(did[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}
	if len(decoded) < 2 {
		return nil, fmt.Errorf("did:key payload too short")
	}
	val, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, fmt.Errorf("did:key: invalid varint prefix")
	}
	if val != 0xed {
		return nil, fmt.Errorf("did:key: unsupported key type (expected ed25519 0xed, got 0x%x)", val)
	}
	keyBytes := decoded[n:]
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("did:key: invalid Ed25519 key length: %d", len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}
