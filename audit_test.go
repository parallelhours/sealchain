// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
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

func TestEmptyLogVerifies(t *testing.T) {
	dir := t.TempDir()
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))
	assert.NoError(t, log.Verify())
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	logPath := filepath.Join(dir, "audit.log")
	log := sealchain.NewLog(logPath)

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventVaultCreated,
		Domain: sealchain.DomainEntry{"vault": "v"},
	}, id.did, id))
	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventDocumentAccessed,
		Domain: sealchain.DomainEntry{"vault": "v", "document": "d"},
	}, id.did, id))

	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	newline := bytes.IndexByte(raw, '\n')
	require.Greater(t, newline, 0)
	tampered := append(
		[]byte(`{"foundation":{"seq":1,"prev_hash":"tampered","actor_did":"`+id.did+`","timestamp":"2026-01-01T00:00:00Z","signature":""},"event":"VAULT_CREATED","domain":{"vault":"v"}}`+"\n"),
		raw[newline+1:]...,
	)
	require.NoError(t, os.WriteFile(logPath, tampered, 0600))

	assert.Error(t, log.Verify(), "tampered log should fail verification")
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	other := newTestIdentity(t)
	logPath := filepath.Join(dir, "audit.log")
	log := sealchain.NewLog(logPath)

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventVaultCreated,
		Domain: sealchain.DomainEntry{"vault": "v"},
	}, id.did, id))

	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	var e sealchain.Entry
	require.NoError(t, json.Unmarshal(bytes.TrimRight(raw, "\n"), &e))
	e.Foundation.Signature = ""
	body, err := json.Marshal(e)
	require.NoError(t, err)
	sig, err := other.Sign(body)
	require.NoError(t, err)
	e.Foundation.Signature = base64.StdEncoding.EncodeToString(sig)
	forged, err := json.Marshal(e)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(logPath, append(forged, '\n'), 0600))

	assert.Error(t, log.Verify(), "forged signature should be rejected")
}
