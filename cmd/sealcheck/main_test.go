// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-tron/base58"
	sealchain "github.com/parallelhours/sealchain"
)

type testID struct {
	did     string
	privKey ed25519.PrivateKey
}

func (id *testID) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(id.privKey, msg), nil
}

func makeID(t *testing.T) *testID {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, binary.MaxVarintLen64+len(pub))
	n := binary.PutUvarint(buf, 0xed)
	copy(buf[n:], pub)
	did := "did:key:z" + base58.Encode(buf[:n+len(pub)])
	return &testID{did: did, privKey: priv}
}

func TestRunVerifyOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	id := makeID(t)
	l := sealchain.NewLog(path)
	if err := l.Append(sealchain.Entry{Event: "TEST"}, id.did, id); err != nil {
		t.Fatal(err)
	}

	code := run([]string{"verify", path})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestRunVerifyEmptyLog(t *testing.T) {
	// A non-existent file is a valid empty log (exit 0)
	dir := t.TempDir()
	code := run([]string{"verify", filepath.Join(dir, "nonexistent.log")})
	if code != 0 {
		t.Fatalf("expected exit 0 for empty log, got %d", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	code := run([]string{})
	if code != 2 {
		t.Fatalf("expected exit 2 (usage error), got %d", code)
	}
}

func TestRunMissingPath(t *testing.T) {
	code := run([]string{"verify"})
	if code != 2 {
		t.Fatalf("expected exit 2 (usage error), got %d", code)
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	code := run([]string{"explode"})
	if code != 2 {
		t.Fatalf("expected exit 2 (usage error), got %d", code)
	}
}

func TestRunTamperedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	id := makeID(t)
	l := sealchain.NewLog(path)
	if err := l.Append(sealchain.Entry{Event: "TEST"}, id.did, id); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(sealchain.Entry{Event: "TEST2"}, id.did, id); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newline := bytes.IndexByte(raw, '\n')
	tampered := append(
		[]byte(`{"foundation":{"seq":1,"prev_hash":"tampered","actor_did":"`+id.did+`","timestamp":"2026-01-01T00:00:00Z","signature":""},"event":"TEST"}`+"\n"),
		raw[newline+1:]...,
	)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}

	code := run([]string{"verify", path})
	if code != 1 {
		t.Fatalf("expected exit 1 (tampered), got %d", code)
	}
}

func TestRunVerifyChain(t *testing.T) {
	dir := t.TempDir()
	// Use audit-log.000.jsonl to match the baseName.NNN.jsonl pattern expected by VerifyChain
	logPath := filepath.Join(dir, "audit-log.000.jsonl")
	l := sealchain.NewLog(logPath)
	id := makeID(t)

	err := l.Append(sealchain.Entry{
		Event:  sealchain.EventType("test"),
		Domain: sealchain.DomainEntry{"key": "val"},
	}, id.did, id)
	if err != nil {
		t.Fatal(err)
	}

	newLog, err := l.Rotate(sealchain.RotationManual, id.did, id)
	if err != nil {
		t.Fatal(err)
	}
	if newLog == nil {
		t.Fatal("expected new log after rotation")
	}

	err = newLog.Append(sealchain.Entry{
		Event:  sealchain.EventType("test2"),
		Domain: sealchain.DomainEntry{"key2": "val2"},
	}, id.did, id)
	if err != nil {
		t.Fatal(err)
	}

	code := run([]string{"verify-chain", dir, "audit-log"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}
