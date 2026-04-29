// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package sealchain_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mr-tron/base58"
	sealchain "github.com/parallelhours/sealchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	evtVaultCreated      sealchain.EventType = "VAULT_CREATED"
	evtDocumentStored    sealchain.EventType = "DOCUMENT_STORED"
	evtDocumentAccessed  sealchain.EventType = "DOCUMENT_ACCESSED"
	evtDocumentExtracted sealchain.EventType = "DOCUMENT_EXTRACTED"
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
		Event:  evtVaultCreated,
		Domain: sealchain.DomainEntry{"vault": "team-green"},
	}, id.did, id))

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  evtDocumentAccessed,
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
	assert.Equal(t, evtVaultCreated, entries[0].Event)

	assert.Equal(t, uint64(2), entries[1].Foundation.Seq)
	assert.Contains(t, entries[1].Foundation.PrevHash, "sha256:")
}

func TestAppendWithNilDomain(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))

	require.NoError(t, log.Append(sealchain.Entry{
		Event: evtVaultCreated,
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
		Event:  evtVaultCreated,
		Domain: sealchain.DomainEntry{"vault": "v"},
	}, id.did, id))
	require.NoError(t, log.Append(sealchain.Entry{
		Event:  evtDocumentAccessed,
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
		Event:  evtVaultCreated,
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

func TestVerifyDetectsDomainTampering(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	logPath := filepath.Join(dir, "audit.log")
	log := sealchain.NewLog(logPath)

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  evtDocumentExtracted,
		Domain: sealchain.DomainEntry{"vault": "pharma-trial-007", "document": "protocol.pdf"},
	}, id.did, id))

	entries, err := log.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	err = log.Verify()
	assert.NoError(t, err, "freshly created log should verify")
}

func TestVerifySignatureRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))

	require.NoError(t, log.Append(sealchain.Entry{
		Event:  evtDocumentStored,
		Domain: sealchain.DomainEntry{"vault": "test-vault", "document": "test-doc"},
	}, id.did, id))

	entries, err := log.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]

	sigBytes, err := base64.StdEncoding.DecodeString(e.Foundation.Signature)
	require.NoError(t, err)

	signingEntry := e
	signingEntry.Foundation.Signature = ""
	body, err := json.Marshal(signingEntry)
	require.NoError(t, err)

	verified := ed25519.Verify(id.privKey.Public().(ed25519.PublicKey), body, sigBytes)
	assert.True(t, verified, "signature should verify")

	err = log.Verify()
	assert.NoError(t, err, "log.Verify should pass")
}

func TestRotationEventTypes(t *testing.T) {
	assert.Equal(t, sealchain.EventType("log.terminus"), sealchain.EventLogTerminus)
	assert.Equal(t, sealchain.EventType("log.genesis"), sealchain.EventLogGenesis)
}

func TestRotationReasons(t *testing.T) {
	reasons := []struct {
		got  sealchain.RotationReason
		want string
	}{
		{sealchain.RotationSize, "size_threshold"},
		{sealchain.RotationTime, "time_threshold"},
		{sealchain.RotationManual, "manual"},
	}
	for _, r := range reasons {
		assert.Equal(t, r.want, string(r.got))
	}
}

func TestFoundationRotationFields(t *testing.T) {
	f := sealchain.Foundation{
		Seq:       1,
		PrevHash:  "genesis",
		ActorDID:  "did:key:z123",
		Timestamp: "2026-04-29T00:00:00Z",
		Signature: "sig",
		LogRole:   "genesis",
		LogRef:    "audit-log.001.jsonl",
	}
	// Marshal and check omitempty works
	data, err := json.Marshal(f)
	require.NoError(t, err)
	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)
	assert.Equal(t, "genesis", m["log_role"])
	assert.Equal(t, "audit-log.001.jsonl", m["log_ref"])

	// Test omitempty when fields are empty
	f2 := sealchain.Foundation{Seq: 1}
	data2, err := json.Marshal(f2)
	require.NoError(t, err)
	var m2 map[string]interface{}
	err = json.Unmarshal(data2, &m2)
	require.NoError(t, err)
	_, ok := m2["log_role"]
	assert.False(t, ok, "log_role should be omitted when empty")
	_, ok = m2["log_ref"]
	assert.False(t, ok, "log_ref should be omitted when empty")
}

func TestAppendConcurrentGoroutinesSafe(t *testing.T) {
	dir := t.TempDir()
	id := newTestIdentity(t)
	log := sealchain.NewLog(filepath.Join(dir, "audit.log"))

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, log.Append(sealchain.Entry{
				Event:  evtDocumentAccessed,
				Domain: sealchain.DomainEntry{"vault": "v", "document": "d"},
			}, id.did, id))
		}()
	}
	wg.Wait()

	entries, err := log.Entries()
	require.NoError(t, err)
	assert.Len(t, entries, n)
	assert.NoError(t, log.Verify())
}

func TestDefaultRotatePath(t *testing.T) {
	// Create temp dir with existing rotated logs
	dir := t.TempDir()
	os.Create(filepath.Join(dir, "audit-log.001.jsonl"))
	os.Create(filepath.Join(dir, "audit-log.002.jsonl"))

	tests := []struct {
		currentPath string
		want        string
	}{
		{filepath.Join(dir, "audit-log.jsonl"), filepath.Join(dir, "audit-log.003.jsonl")},
		{filepath.Join(dir, "other-log.jsonl"), filepath.Join(dir, "other-log.001.jsonl")},
	}
	for _, tt := range tests {
		got, err := sealchain.DefaultRotatePath(tt.currentPath)
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func TestLogFingerprint(t *testing.T) {
	dir := t.TempDir()
	log := sealchain.NewLog(filepath.Join(dir, "audit-log.jsonl"))
	id := newTestIdentity(t)

	// Append a test entry
	err := log.Append(sealchain.Entry{
		Event:  sealchain.EventType("test.event"),
		Domain: sealchain.DomainEntry{"key": "val"},
	}, id.did, id)
	require.NoError(t, err)

	fp, err := log.Fingerprint()
	require.NoError(t, err)

	// Verify format is sha256:hex
	assert.True(t, strings.HasPrefix(fp, "sha256:"))

	// Manually compute expected hash
	data, err := os.ReadFile(log.Path())
	require.NoError(t, err)
	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	assert.Equal(t, expected, fp)
}

func TestLogRotate(t *testing.T) {
	dir := t.TempDir()
	// First log is audit-log.000.jsonl (true genesis)
	logPath := filepath.Join(dir, "audit-log.000.jsonl")
	log := sealchain.NewLog(logPath)
	id := newTestIdentity(t)

	// Append a normal entry first
	err := log.Append(sealchain.Entry{
		Event:  sealchain.EventType("test.event"),
		Domain: sealchain.DomainEntry{"key": "val"},
	}, id.did, id)
	require.NoError(t, err)

	// Get fingerprint before rotation
	fpBefore, err := log.Fingerprint()
	require.NoError(t, err)

	// Perform rotation
	newLog, err := log.Rotate(sealchain.RotationManual, id.did, id)
	require.NoError(t, err)
	require.NotNil(t, newLog)

	// Check old log (audit-log.000.jsonl) has terminus
	assert.True(t, log.IsTerminus(), "Old log should have terminus as last entry")

	// Check new log (audit-log.001.jsonl) has genesis
	assert.True(t, newLog.IsGenesis(), "New log should have genesis as first entry")

	// Check fingerprint consistency
	entries, err := log.Entries()
	require.NoError(t, err)
	terminusFP := entries[len(entries)-1].Domain.Fields()["previous_fingerprint"].(string)

	newEntries, err := newLog.Entries()
	require.NoError(t, err)
	genesisFP := newEntries[0].Domain.Fields()["previous_fingerprint"].(string)

	assert.Equal(t, fpBefore, terminusFP, "Terminus fingerprint should match log fingerprint")
	assert.Equal(t, fpBefore, genesisFP, "Genesis fingerprint should match log fingerprint")

	// Check LogRef fields
	assert.Equal(t, filepath.Join(dir, "audit-log.001.jsonl"), entries[len(entries)-1].Foundation.LogRef)
	assert.Equal(t, logPath, newEntries[0].Foundation.LogRef)
}

func TestLogRotateTwice(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit-log.000.jsonl")
	log := sealchain.NewLog(logPath)
	id := newTestIdentity(t)

	// First generation: append entries and rotate
	require.NoError(t, log.Append(sealchain.Entry{
		Event:  sealchain.EventType("test.event.1"),
		Domain: sealchain.DomainEntry{"gen": "0"},
	}, id.did, id))
	fp0, err := log.Fingerprint()
	require.NoError(t, err)

	newLog1, err := log.Rotate(sealchain.RotationManual, id.did, id)
	require.NoError(t, err)
	require.NotNil(t, newLog1)
	assert.True(t, log.IsTerminus())
	assert.True(t, newLog1.IsGenesis())

	// Second generation: append entries and rotate again
	require.NoError(t, newLog1.Append(sealchain.Entry{
		Event:  sealchain.EventType("test.event.2"),
		Domain: sealchain.DomainEntry{"gen": "1"},
	}, id.did, id))
	fp1, err := newLog1.Fingerprint()
	require.NoError(t, err)

	newLog2, err := newLog1.Rotate(sealchain.RotationManual, id.did, id)
	require.NoError(t, err)
	require.NotNil(t, newLog2)
	assert.True(t, newLog1.IsTerminus())
	assert.True(t, newLog2.IsGenesis())

	// Verify the chain across all three logs
	assert.Equal(t, filepath.Join(dir, "audit-log.001.jsonl"), newLog1.Path())
	assert.Equal(t, filepath.Join(dir, "audit-log.002.jsonl"), newLog2.Path())

	// Check fingerprints propagate correctly
	entries0, _ := log.Entries()
	entries1, _ := newLog1.Entries()
	assert.Equal(t, fp0, entries0[len(entries0)-1].Domain.Fields()["previous_fingerprint"])
	assert.Equal(t, fp0, entries1[0].Domain.Fields()["previous_fingerprint"])

	entries1After, _ := newLog1.Entries()
	fp1Actual := entries1After[len(entries1After)-1].Domain.Fields()["previous_fingerprint"]
	entries2, _ := newLog2.Entries()
	assert.Equal(t, fp1, fp1Actual)
	assert.Equal(t, fp1, entries2[0].Domain.Fields()["previous_fingerprint"])

	// Verify full chain
	assert.NoError(t, sealchain.VerifyChain(dir, "audit-log"))
}
