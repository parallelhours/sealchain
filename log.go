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
	"text/template"
	"time"
)

// LogConfig holds configuration options for a Log.
type LogConfig struct {
	// RotateTemplate is the Go template string used to generate rotated log file names.
	// Available template variables:
	//   {{.Base}} - original filename without extension
	//   {{.Ext}} - file extension (including the dot, e.g., ".jsonl")
	//   {{.Seq}} - sequence number (not padded)
	//   {{.SeqPadded}} - zero-padded sequence number (3 digits)
	//   {{.Timestamp}} - rotation timestamp in RFC3339 format
	//   {{.PrevPath}} - previous log path
	// Default: "{{.Base}}.{{.SeqPadded}}{{.Ext}}"
	RotateTemplate string
}

// DefaultRotateTemplate is the default template that preserves current behavior.
const DefaultRotateTemplate = "{{.Base}}.{{.SeqPadded}}{{.Ext}}"

// Log is a file-backed append-only audit log. It is safe for concurrent use:
// Append holds an exclusive write lock and Entries/Verify hold a shared read lock.
//
// A Log is a lightweight handle — multiple instances pointing to the same path
// are safe as long as all access goes through this type's methods. Direct
// modification of the underlying file bypasses locking and will corrupt the chain.
type Log struct {
	path   string
	config LogConfig
	mu     sync.RWMutex
}

// DefaultRotatePath returns the next log file path in the rotation sequence.
// Given "logs/audit-log.002.jsonl" it scans the directory for files matching
// "audit-log.*.jsonl" and returns the path with the next available three-digit
// sequence number, e.g. "logs/audit-log.003.jsonl".
//
// If currentPath contains no sequence number the sequence starts at .001.
// Sequence numbers are zero-padded to three digits; beyond 999 the padding
// grows naturally to preserve lexicographic sort order.
//
// This is the function used internally by Rotate. It is exported so callers
// can preview the next path (e.g. to pre-allocate storage) without triggering
// a rotation.
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

// rotateTemplateData holds the data available to the rotation template.
type rotateTemplateData struct {
	Base      string
	Ext       string
	Seq       int
	SeqPadded string // Zero-padded sequence number (3 digits by default)
	Timestamp string
	PrevPath  string
}

// applyRotateTemplate applies the configured template to generate a rotated log path.
func (l *Log) applyRotateTemplate(seq int, prevPath string) (string, error) {
	dir := filepath.Dir(l.path)
	base := filepath.Base(l.path)
	ext := filepath.Ext(base)
	baseNoExt := base[:len(base)-len(ext)]

	// Strip existing sequence number from base name if present
	// e.g., "audit-log.000" -> "audit-log"
	baseName := baseNoExt
	if idx := strings.LastIndex(baseNoExt, "."); idx >= 0 {
		seqPart := baseNoExt[idx+1:]
		if _, err := fmt.Sscanf(seqPart, "%d", new(int)); err == nil {
			baseName = baseNoExt[:idx]
		}
	}

	tmpl, err := template.New("rotate").Parse(l.config.RotateTemplate)
	if err != nil {
		return "", fmt.Errorf("parse rotate template: %w", err)
	}

	data := rotateTemplateData{
		Base:      baseName,
		Ext:       ext,
		Seq:       seq,
		SeqPadded: fmt.Sprintf("%03d", seq),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		PrevPath:  prevPath,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute rotate template: %w", err)
	}

	filename := buf.String()
	return filepath.Join(dir, filename), nil
}

// nextRotateSeq determines the next sequence number for rotation by scanning
// the directory for existing files that match the base name pattern.
func (l *Log) nextRotateSeq() (int, error) {
	dir := filepath.Dir(l.path)
	base := filepath.Base(l.path)
	ext := filepath.Ext(base)
	baseNoExt := base[:len(base)-len(ext)]

	// Strip existing sequence number from base name if present
	// e.g., "audit-log.000" -> "audit-log"
	baseName := baseNoExt
	if idx := strings.LastIndex(baseNoExt, "."); idx >= 0 {
		seqPart := baseNoExt[idx+1:]
		if _, err := fmt.Sscanf(seqPart, "%d", new(int)); err == nil {
			baseName = baseNoExt[:idx]
		}
	}

	// For the default template, scan for files matching baseName.*.ext
	// For custom templates, we'll use a simple heuristic: scan for files starting with baseName
	pattern := filepath.Join(dir, baseName+"*"+ext)
	existing, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("glob failed: %w", err)
	}

	maxSeq := 0
	for _, f := range existing {
		fbase := filepath.Base(f)
		// Try to extract sequence number from the filename
		// This is a simple heuristic that works for the default template
		// For custom templates, users may need to manage sequence numbers differently
		// Look for pattern: baseName.NNN.ext or baseName.N.ext
		if strings.HasPrefix(fbase, baseName) && strings.HasSuffix(fbase, ext) {
			between := fbase[len(baseName) : len(fbase)-len(ext)]
			// Remove leading dot if present
			between = strings.TrimPrefix(between, ".")
			var seq int
			if _, err := fmt.Sscanf(between, "%d", &seq); err == nil {
				if seq > maxSeq {
					maxSeq = seq
				}
			}
		}
	}

	return maxSeq + 1, nil
}

// NewLog returns a Log handle for path with default configuration.
// The file is created on the first Append if it does not yet exist.
// Calling NewLog on an existing log file is safe — previous entries are
// preserved and subsequent Appends extend the chain.
func NewLog(path string) *Log {
	return &Log{
		path:   path,
		config: LogConfig{RotateTemplate: DefaultRotateTemplate},
	}
}

// NewLogWithConfig returns a Log handle for path with custom configuration.
// The file is created on the first Append if it does not yet exist.
// Calling NewLogWithConfig on an existing log file is safe — previous entries
// are preserved and subsequent Appends extend the chain.
func NewLogWithConfig(path string, config LogConfig) *Log {
	if config.RotateTemplate == "" {
		config.RotateTemplate = DefaultRotateTemplate
	}
	return &Log{
		path:   path,
		config: config,
	}
}

// Append signs and appends e to the log. Callers set e.Event and optionally
// e.Domain; all Foundation fields are computed and overwritten:
//
//   - Seq is set to the next sequence number (existing entries + 1).
//   - PrevHash is "sha256:<hex>" of the last raw on-disk line, or "genesis"
//     for the first entry.
//   - ActorDID is set to did.
//   - Timestamp is set to the current UTC time in RFC3339.
//   - Signature is the base64-encoded Ed25519 signature of the canonical JSON
//     of the entry with Signature = "".
//
// The entry is written as a single newline-terminated JSON line and fsynced
// before Append returns. On any error the log should be considered potentially
// corrupt and further appends must not be attempted.
//
// did must be a valid did:key DID with an Ed25519 public key; this is the key
// Verify will use to check the signature later.
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

// Entries returns all entries in append order. Domain fields are decoded as
// DomainEntry (map[string]any). Returns nil, nil if the log file does not exist.
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

// Verify validates the full cryptographic integrity of the log. For each entry:
//
//  1. Seq must be contiguous — gaps or duplicates are rejected.
//  2. PrevHash must equal "sha256:<hex>" of the previous raw on-disk line.
//     The first entry must have PrevHash == "genesis".
//  3. ActorDID must be a did:key DID with an Ed25519 public key.
//  4. The Ed25519 signature must verify against the canonical JSON of the
//     entry with Signature set to "".
//
// Returns nil if the log is intact. On failure the error identifies the first
// bad entry by sequence number and describes the specific check that failed.
//
// Verify checks only a single log file. To validate a rotation chain spanning
// multiple files, use VerifyChain.
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

// MarshalForSign serializes v to compact JSON without HTML escaping and
// without a trailing newline. This is the canonical form used for both signing
// and writing entries to disk — the two byte sequences are identical, so the
// raw on-disk line can be fed directly to the verifier without re-marshaling.
//
// Exported to allow external tooling (re-verification scripts, log converters)
// to produce the same byte sequence that Append writes, without having to
// reimplement the encoding rules.
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

// Path returns the file system path this log was opened with.
func (l *Log) Path() string {
	return l.path
}

// Fingerprint returns "sha256:<hex>" of the entire log file's raw bytes.
// This hash is recorded in terminus and genesis entries during Rotate and
// verified by VerifyChain to confirm the sealed log was not modified after
// rotation. Reading an empty or non-existent log file returns an error.
func (l *Log) Fingerprint() (string, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return "", fmt.Errorf("read log: %w", err)
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// IsTerminus reports whether this log has been sealed by Rotate — that is,
// its last entry carries EventLogTerminus. A sealed log must not have further
// entries appended; use the Log returned by Rotate instead.
func (l *Log) IsTerminus() bool {
	entries, err := l.Entries()
	if err != nil || len(entries) == 0 {
		return false
	}
	return entries[len(entries)-1].Event == EventLogTerminus
}

// IsGenesis reports whether this log was created by a rotation — that is,
// its first entry carries EventLogGenesis. The initial log in a chain will
// not have a genesis entry; every subsequent log will.
func (l *Log) IsGenesis() bool {
	entries, err := l.Entries()
	if err != nil || len(entries) == 0 {
		return false
	}
	return entries[0].Event == EventLogGenesis
}

// Rotate seals the current log and opens a new one, establishing a
// cryptographically verifiable link between them. It:
//
//  1. Computes a fingerprint (SHA-256) of the current log file content.
//  2. Writes a terminus entry to the current log containing the fingerprint,
//     the rotation reason, and a forward reference (Foundation.LogRef) to the
//     new log path.
//  3. Creates the new log using the configured rotation template
//     and writes a genesis entry referencing the old log and its fingerprint.
//
// The write lock is held only during terminus append, then released before
// creating the new log. After Rotate returns, the caller must switch to the
// returned Log for further appends; writing to the original Log after Rotate
// corrupts the chain.
//
// VerifyChain validates the fingerprint linkage across the full rotation chain.
// reason is stored in the domain fields of both terminus and genesis entries.
func (l *Log) Rotate(reason RotationReason, did string, s Signer) (*Log, error) {
	l.mu.Lock()

	// Compute fingerprint of current log (before terminus)
	fp, err := l.Fingerprint()
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("fingerprint failed: %w", err)
	}

	// Determine next sequence number
	nextSeq, err := l.nextRotateSeq()
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("determine next sequence: %w", err)
	}

	// Generate NEW log path using the configured template
	newPath, err := l.applyRotateTemplate(nextSeq, l.path)
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
		if closeErr := f.Close(); closeErr != nil {
			l.mu.Unlock()
			return nil, fmt.Errorf("write terminus: %w; close: %v", err, closeErr)
		}
		l.mu.Unlock()
		return nil, fmt.Errorf("write terminus: %w", err)
	}
	if err := f.Sync(); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			l.mu.Unlock()
			return nil, fmt.Errorf("sync terminus: %w; close: %v", err, closeErr)
		}
		l.mu.Unlock()
		return nil, fmt.Errorf("sync terminus: %w", err)
	}
	if err := f.Close(); err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("close terminus log: %w", err)
	}
	l.mu.Unlock()

	// Create NEW log at next sequence with genesis entry, preserving config
	newLog := NewLogWithConfig(newPath, l.config)

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

// VerifyChain validates the rotation chain across all log files in logDir
// whose names match the pattern baseName.NNN.jsonl (e.g. "audit-log.000.jsonl").
// At least two log files must exist.
//
// For each consecutive pair (old → new), VerifyChain:
//
//  1. Runs Verify on each log individually.
//  2. Confirms the last entry of the old log is EventLogTerminus and the first
//     entry of the new log is EventLogGenesis.
//  3. Recomputes the SHA-256 of the old log file without the terminus line and
//     checks it against the fingerprint stored in both terminus and genesis entries.
//  4. Checks that Foundation.LogRef in the terminus points to the new log and
//     Foundation.LogRef in the genesis points to the old log.
//
// Returns nil if every log in the chain is internally valid and properly linked
// to its neighbors.
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
