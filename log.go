// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Log struct {
	path string
	mu   sync.RWMutex
}

// DefaultRotatePath returns the next rotated log path for the given current path.
// Rotated logs use zero-padded sequence numbers: audit-log.001.jsonl, audit-log.002.jsonl, etc.
func DefaultRotatePath(currentPath string) (string, error) {
	dir := filepath.Dir(currentPath)
	base := filepath.Base(currentPath)
	ext := filepath.Ext(base)
	nameNoExt := base[:len(base)-len(ext)]

	// Extract base name and current sequence number.
	// nameNoExt may be "audit-log.000" (with seq) or "audit-log" (without).
	baseName := nameNoExt
	currentSeq := 0

	if idx := strings.LastIndex(nameNoExt, "."); idx >= 0 {
		seqPart := nameNoExt[idx+1:]
		if _, err := fmt.Sscanf(seqPart, "%d", &currentSeq); err == nil {
			baseName = nameNoExt[:idx]
		}
	}

	pattern := filepath.Join(dir, baseName+".*"+ext)
	existing, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("glob failed: %w", err)
	}

	nextSeq := currentSeq + 1
	for _, f := range existing {
		fbase := filepath.Base(f)
		prefix := baseName + "."
		if !strings.HasPrefix(fbase, prefix) {
			continue
		}
		afterPrefix := fbase[len(prefix):]
		if !strings.HasSuffix(afterPrefix, ext) {
			continue
		}
		seqPart := afterPrefix[:len(afterPrefix)-len(ext)]
		var seq int
		if _, err := fmt.Sscanf(seqPart, "%d", &seq); err == nil {
			if seq >= nextSeq {
				nextSeq = seq + 1
			}
		}
	}

	return filepath.Join(dir, fmt.Sprintf("%s.%03d%s", baseName, nextSeq, ext)), nil
}

// defaultRotatePath is the unexported version for internal use.
func defaultRotatePath(currentPath string) (string, error) {
	return DefaultRotatePath(currentPath)
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

// Path returns the file path of the log.
func (l *Log) Path() string {
	return l.path
}

// Fingerprint returns the SHA-256 hash of the entire log file.
func (l *Log) Fingerprint() (string, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return "", fmt.Errorf("read log: %w", err)
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// IsTerminus returns true if the last entry is a terminus entry.
func (l *Log) IsTerminus() bool {
	entries, err := l.Entries()
	if err != nil || len(entries) == 0 {
		return false
	}
	return entries[len(entries)-1].Event == EventLogTerminus
}

// IsGenesis returns true if the first entry is a genesis entry.
func (l *Log) IsGenesis() bool {
	entries, err := l.Entries()
	if err != nil || len(entries) == 0 {
		return false
	}
	return entries[0].Event == EventLogGenesis
}

// Rotate performs atomic log rotation.
// It writes a terminus entry to the current log, then creates a new log
// at the NEXT sequence number with a genesis entry.
// Returns the new Log instance (next generation).
func (l *Log) Rotate(reason RotationReason, did string, s Signer) (*Log, error) {
	l.mu.Lock()

	// Compute fingerprint of current log (before terminus)
	fp, err := l.Fingerprint()
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("fingerprint failed: %w", err)
	}

	// Generate NEW log path (next sequence)
	newPath, err := defaultRotatePath(l.path)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("rotate path failed: %w", err)
	}

	// Read raw lines to compute Seq and PrevHash for terminus
	rawLines, err := l.readRawLines()
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("read raw lines: %w", err)
	}

	// Create terminus entry
	// Terminus LogRef points to the NEW log (next generation)
	terminus := Entry{
		Event: EventLogTerminus,
		Foundation: Foundation{
			ActorDID:  did,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			LogRole:   "terminus",
			LogRef:    newPath,
		},
		Domain: DomainEntry{
			"next_log":             newPath,
			"previous_fingerprint": fp,
			"rotation_reason":      string(reason),
		},
	}

	terminus.Foundation.Seq = uint64(len(rawLines) + 1)
	if len(rawLines) == 0 {
		terminus.Foundation.PrevHash = "genesis"
	} else {
		sum := sha256.Sum256(rawLines[len(rawLines)-1])
		terminus.Foundation.PrevHash = fmt.Sprintf("sha256:%x", sum)
	}

	// Sign terminus
	terminus.Foundation.Signature = ""
	body, err := jsonMarshalForSign(terminus)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("marshal terminus: %w", err)
	}
	sig, err := s.Sign(body)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("sign terminus: %w", err)
	}
	terminus.Foundation.Signature = base64.StdEncoding.EncodeToString(sig)

	// Marshal terminus line
	line, err := jsonMarshalForSign(terminus)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("marshal terminus line: %w", err)
	}

	// Append terminus to OLD log (current)
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("open log for terminus: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		f.Close()
		l.mu.Unlock()
		return nil, fmt.Errorf("write terminus: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		l.mu.Unlock()
		return nil, fmt.Errorf("sync terminus: %w", err)
	}
	f.Close()
	l.mu.Unlock()

	// Create NEW log at next sequence with genesis entry
	newLog := NewLog(newPath)

	genesis := Entry{
		Event: EventLogGenesis,
		Foundation: Foundation{
			ActorDID:  did,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			LogRole:   "genesis",
			LogRef:    l.path, // Points back to OLD log
		},
		Domain: DomainEntry{
			"previous_log":         l.path,
			"previous_fingerprint": fp,
			"terminus_seq":         terminus.Foundation.Seq,
		},
	}

	if err := newLog.Append(genesis, did, s); err != nil {
		return nil, fmt.Errorf("append genesis: %w", err)
	}

	return newLog, nil
}

// VerifyChain validates the cross-log rotation integrity.
// All logs use the naming pattern: baseName.NNN.jsonl (e.g., audit-log.000.jsonl)
// Logs are ordered by generation number and verified in sequence.
func VerifyChain(logDir string, baseName string) error {
	// Discover all logs (000, 001, 002, etc.)
	pattern := filepath.Join(logDir, baseName+".*.jsonl")
	logs, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob logs: %w", err)
	}
	if len(logs) < 2 {
		return fmt.Errorf("need at least 2 logs to verify chain, found %d", len(logs))
	}
	sort.Strings(logs)

	// Verify each consecutive pair (old -> new)
	for i := 0; i < len(logs)-1; i++ {
		oldLog := NewLog(logs[i])   // e.g., audit-log.002.jsonl
		newLog := NewLog(logs[i+1]) // e.g., audit-log.003.jsonl

		// 1. Verify old log internally (ends with terminus)
		if err := oldLog.Verify(); err != nil {
			return fmt.Errorf("old log %s: %w", logs[i], err)
		}

		// 2. Verify new log internally (starts with genesis)
		if err := newLog.Verify(); err != nil {
			return fmt.Errorf("new log %s: %w", logs[i+1], err)
		}

		// 3. Check terminus exists in old log
		oldEntries, err := oldLog.Entries()
		if err != nil {
			return fmt.Errorf("read old log entries: %w", err)
		}
		if len(oldEntries) == 0 || oldEntries[len(oldEntries)-1].Event != EventLogTerminus {
			return fmt.Errorf("last entry of %s is not a terminus", logs[i])
		}

		// 4. Check genesis exists in new log
		newEntries, err := newLog.Entries()
		if err != nil {
			return fmt.Errorf("read new log entries: %w", err)
		}
		if len(newEntries) == 0 || newEntries[0].Event != EventLogGenesis {
			return fmt.Errorf("first entry of %s is not a genesis", logs[i+1])
		}

		// 5. Verify fingerprint: recompute old log hash (without terminus)
		oldBytes, err := os.ReadFile(logs[i])
		if err != nil {
			return fmt.Errorf("read old log file: %w", err)
		}
		// File format: each line ends with \n, file ends with \n after last line.
		// Find the last two newlines to extract content before the terminus line.
		// oldBytes = "line1\nline2\n...\nterminus\n"
		lastNewline := bytes.LastIndex(oldBytes, []byte("\n"))
		if lastNewline < 0 {
			return fmt.Errorf("invalid log file format: no newline found")
		}
		// Find the newline before the terminus line
		beforeTerminus := oldBytes[:lastNewline] // everything up to last newline
		secondLastNewline := bytes.LastIndex(beforeTerminus, []byte("\n"))
		var withoutTerminus []byte
		if secondLastNewline < 0 {
			// Only terminus line exists (file was empty before rotation)
			withoutTerminus = []byte{}
		} else {
			withoutTerminus = oldBytes[:secondLastNewline+1] // include the newline after second-to-last line
		}
		expectedFP := fmt.Sprintf("sha256:%x", sha256.Sum256(withoutTerminus))

		// Check fingerprint in BOTH terminus and genesis
		terminusFP, ok := oldEntries[len(oldEntries)-1].Domain.Fields()["previous_fingerprint"].(string)
		if !ok {
			return fmt.Errorf("terminus missing previous_fingerprint")
		}
		genesisFP, ok := newEntries[0].Domain.Fields()["previous_fingerprint"].(string)
		if !ok {
			return fmt.Errorf("genesis missing previous_fingerprint")
		}

		if terminusFP != expectedFP {
			return fmt.Errorf("terminus fingerprint mismatch in %s", logs[i])
		}
		if genesisFP != expectedFP {
			return fmt.Errorf("genesis fingerprint mismatch in %s", logs[i+1])
		}

		// 6. Cross-check: terminus and genesis should have same fingerprint
		if terminusFP != genesisFP {
			return fmt.Errorf("fingerprint mismatch between terminus and genesis")
		}

		// 7. Verify log path references in Foundation.LogRef
		// Terminus LogRef should point to the NEW log (next generation)
		if oldEntries[len(oldEntries)-1].Foundation.LogRef != logs[i+1] {
			return fmt.Errorf("terminus LogRef doesn't match new log")
		}
		// Genesis LogRef should point to the OLD log (previous generation)
		if newEntries[0].Foundation.LogRef != logs[i] {
			return fmt.Errorf("genesis LogRef doesn't match old log")
		}
	}
	return nil
}
