// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/mr-tron/base58"
	sealchain "github.com/pmonday/sealchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testIdentity struct {
	did     string
	privKey ed25519.PrivateKey
}

func (id *testIdentity) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(id.privKey, msg), nil
}

func newTestIdentity(t *testing.T) *testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	buf := make([]byte, binary.MaxVarintLen64+len(pub))
	n := binary.PutUvarint(buf, 0xed)
	copy(buf[n:], pub)
	did := "did:key:z" + base58.Encode(buf[:n+len(pub)])
	return &testIdentity{did: did, privKey: priv}
}

func TestAppendSetsFoundationFields(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventVaultCreated,
		Domain: sealchain.DomainEntry{"vault": "team-green"},
	}, id.did, id))

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventDocumentAccessed,
		Domain: sealchain.DomainEntry{"vault": "team-green", "document": "design-v7"},
	}, id.did, id))

	entries, err := log.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, uint64(1), entries[0].Foundation.Seq)
	assert.Equal(t, "genesis", entries[0].Foundation.PrevHash)
	assert.Equal(t, id.did, entries[0].Foundation.ActorDID)
	assert.NotEmpty(t, entries[0].Foundation.Timestamp)
	assert.NotEmpty(t, entries[0].Foundation.Signature)
	assert.Equal(t, sealchain.EventVaultCreated, entries[0].Event)

	assert.Equal(t, uint64(2), entries[1].Foundation.Seq)
	assert.Contains(t, entries[1].Foundation.PrevHash, "sha256:")
}

func TestAppendWithNilDomain(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))

	require.NoError(t, log.Append(sealchain.Entry{
		Event: sealchain.EventVaultCreated,
	}, id.did, id))

	entries, err := log.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].Domain)
}
