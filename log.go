// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Log struct {
	path string
	mu   sync.RWMutex
}

func NewLog(path string) *Log {
	return &Log{path: path}
}

func (l *Log) Append(e Entry, did string, s Signer) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	rawLines, err := l.readRawLines()
	if err != nil {
		return err
	}

	e.Foundation.ActorDID = did
	e.Foundation.Seq = uint64(len(rawLines) + 1)
	e.Foundation.Timestamp = time.Now().UTC().Format(time.RFC3339)

	if len(rawLines) == 0 {
		e.Foundation.PrevHash = "genesis"
	} else {
		sum := sha256.Sum256(rawLines[len(rawLines)-1])
		e.Foundation.PrevHash = fmt.Sprintf("sha256:%x", sum)
	}

	e.Foundation.Signature = ""
	body, err := jsonMarshalForSign(e)
	if err != nil {
		return fmt.Errorf("marshal entry body: %w", err)
	}
	sig, err := s.Sign(body)
	if err != nil {
		return fmt.Errorf("sign entry: %w", err)
	}
	e.Foundation.Signature = base64.StdEncoding.EncodeToString(sig)

	line, err := jsonMarshalForSign(e)
	if err != nil {
		return fmt.Errorf("marshal signed entry: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		return fmt.Errorf("write log entry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync log: %w", err)
	}
	return nil
}

func (l *Log) Entries() ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	lines, err := l.readRawLines()
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(lines))
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("parse log entry %d: %w", i+1, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (l *Log) Verify() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	lines, err := l.readRawLines()
	if err != nil {
		return err
	}
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("entry %d: parse error: %w", i+1, err)
		}
		if e.Foundation.Seq != uint64(i+1) {
			return fmt.Errorf("entry %d: sequence gap (expected %d, got %d)", i+1, i+1, e.Foundation.Seq)
		}
		if i == 0 {
			if e.Foundation.PrevHash != "genesis" {
				return fmt.Errorf("entry 1: expected prev_hash \"genesis\", got %q", e.Foundation.PrevHash)
			}
		} else {
			sum := sha256.Sum256(lines[i-1])
			expected := fmt.Sprintf("sha256:%x", sum)
			if e.Foundation.PrevHash != expected {
				return fmt.Errorf("entry %d: hash chain broken (expected %s, got %s)", i+1, expected, e.Foundation.PrevHash)
			}
		}

		pub, err := publicKeyFromDID(e.Foundation.ActorDID)
		if err != nil {
			return fmt.Errorf("entry %d: resolve actor DID %s: %w", i+1, e.Foundation.ActorDID, err)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(e.Foundation.Signature)
		if err != nil {
			return fmt.Errorf("entry %d: decode signature: %w", i+1, err)
		}
		signingEntry := e
		signingEntry.Foundation.Signature = ""
		signingBody, err := jsonMarshalForSign(signingEntry)
		if err != nil {
			return fmt.Errorf("entry %d: marshal signing body: %w", i+1, err)
		}
		if !ed25519.Verify(pub, signingBody, sigBytes) {
			return fmt.Errorf("entry %d: signature verification failed for actor %s", i+1, e.Foundation.ActorDID)
		}
	}
	return nil
}

func jsonMarshalForSign(v any) ([]byte, error) {
	return MarshalForSign(v)
}

func MarshalForSign(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	result := buf.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result, nil
}

func (l *Log) readRawLines() ([][]byte, error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		b := scanner.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
