# Audit Log File Rotation for CFR Part 11 Compliance

## Overview

File rotation must maintain an unbroken cryptographic chain when logs are split across files. The design preserves all critical invariants (raw-line hashing, signature scope, stable JSON) while adding cross-file integrity.

## Key Concepts

| Term | Description |
|------|-------------|
| **Terminus Entry** | Final entry written to the old log before rotation. Event type `log.terminus`. Contains reference to new log and fingerprint of old log. |
| **Genesis Entry** | First entry of a new log file. Event type `log.genesis`. Contains verifiable reference to the old log's terminus and fingerprint. |
| **Log Fingerprint** | SHA-256 hash of the entire old log file's raw bytes (all lines including terminus). Stored in both terminus and genesis Domain fields. |

## Rotation Process

The **rotating actor** (signer) performs these steps atomically:

### Step 1: Derive Next Log Path (Default Naming)

ALL logs use zero-padded sequence numbers. The first log is `audit-log.000.jsonl`.

```
// Default naming convention:
//   audit-log.000.jsonl      (first log, true genesis)
//   audit-log.001.jsonl      (second log)
//   audit-log.002.jsonl      (third log)
//   audit-log.003.jsonl      (fourth log, ...)

// Before rotation:
//   audit-log.002.jsonl (current, has entries 1..N)

// After rotation:
//   audit-log.003.jsonl (NEW current, starts with genesis entry)
//   audit-log.002.jsonl (rotated out, ends with terminus entry)

func defaultRotatePath(currentPath string) (string, error) {
    // Scan directory for existing logs (*.000.jsonl, *.001.jsonl, etc.)
    // Return next sequence number: audit-log.003.jsonl
    // Sequence starts at 000 for first log
}
```

### Step 2: Atomic Rotation Sequence

## Updated Foundation Struct

Add optional fields for genesis/terminus metadata:

```go
type Foundation struct {
    Seq       uint64 `json:"seq"`
    PrevHash  string `json:"prev_hash"`
    ActorDID  string `json:"actor_did"`
    Timestamp string `json:"timestamp"`
    Signature string `json:"signature"`

    // Rotation fields (only populated for genesis/terminus entries)
    LogRole   string `json:"log_role,omitempty"`   // "genesis" or "terminus"
    LogRef    string `json:"log_ref,omitempty"`    // for genesis: previous log path; for terminus: next log path
}
```

This allows `Verify()` to check rotation integrity without parsing Domain fields.

## Cryptographic Binding (Both Directions)

```
BEFORE ROTATION:
  audit-log.002.jsonl (current):
    entry1 (prev_hash: "genesis")
    entry2 (prev_hash: sha256:...)
    ...
    entryN (prev_hash: sha256:...)

AFTER ROTATION:
  audit-log.003.jsonl (NEW current, starts fresh):
    GENESIS (prev_hash: "genesis")
      Domain: { previous_log: audit-log.002.jsonl,
                previous_fingerprint: sha256:xxx,
                terminus_seq: N+1 }
      Foundation.LogRole = "genesis"
      Foundation.LogRef = "audit-log.002.jsonl"

  audit-log.002.jsonl (rotated-out):
    entry1 (prev_hash: "genesis")
    ...
    entryN (prev_hash: sha256:entryN-1)
    TERMINUS (prev_hash: sha256:entryN)
      Domain: { next_log: audit-log.003.jsonl,
                previous_fingerprint: sha256:xxx,
                rotation_reason: "size_threshold" }
      Foundation.LogRole = "terminus"
      Foundation.LogRef = "audit-log.003.jsonl"
              ↓
  fingerprint = SHA-256(ENTIRE audit-log.002.jsonl including terminus line)
```

**Key Point**: The fingerprint in genesis and terminus both reference the rotated-out log file (`audit-log.002.jsonl`), ensuring bidirectional verification. Terminus `LogRef` points to the NEW log; Genesis `LogRef` points to the OLD log.

## Verification Across Logs

A new `VerifyChain` function validates the cross-log linkage. Logs are ordered by generation number:

```go
func VerifyChain(logDir string, baseName string) error {
    // Discover all log files:
    //   audit-log.000.jsonl, audit-log.001.jsonl, audit-log.002.jsonl, etc.

    pattern := filepath.Join(logDir, baseName+".*.jsonl")
    rotatedLogs, _ := filepath.Glob(pattern)
    sort.Strings(rotatedLogs) // ensure 000, 001, 002, 003 order

    for i := 0; i < len(rotatedLogs)-1; i++ {
        oldLog := NewLog(rotatedLogs[i])         // e.g., audit-log.002.jsonl
        newLog := NewLog(rotatedLogs[i+1])     // e.g., audit-log.003.jsonl

        // 1. Verify old log internally (ends with terminus)
        if err := oldLog.Verify(); err != nil {
            return fmt.Errorf("old log %s: %w", rotatedLogs[i], err)
        }

        // 2. Verify new log internally (starts with genesis)
        if err := newLog.Verify(); err != nil {
            return fmt.Errorf("new log %s: %w", rotatedLogs[i+1], err)
        }

        // 3. Check terminus exists in old log
        oldEntries, _ := oldLog.Entries()
        terminus := oldEntries[len(oldEntries)-1]
        if terminus.Event != EventLogTerminus {
            return fmt.Errorf("last entry of %s is not a terminus", rotatedLogs[i])
        }

        // 4. Check genesis exists in new log
        newEntries, _ := newLog.Entries()
        genesis := newEntries[0]
        if genesis.Event != EventLogGenesis {
            return fmt.Errorf("first entry of %s is not a genesis", rotatedLogs[i+1])
        }

        // 5. Verify fingerprint: recompute old log hash (INCLUDING terminus)
        oldRawLines, _ := oldLog.readRawLines()
        oldBytes := bytes.Join(oldRawLines, []byte("\n"))
        oldBytes = append(oldBytes, '\n')
        expectedFP := fmt.Sprintf("sha256:%x", sha256.Sum256(oldBytes))

        // Check fingerprint in BOTH terminus and genesis
        terminusFP := terminus.Domain.Fields()["previous_fingerprint"].(string)
        genesisFP := genesis.Domain.Fields()["previous_fingerprint"].(string)

        if terminusFP != expectedFP {
            return fmt.Errorf("terminus fingerprint mismatch in %s", rotatedLogs[i])
        }
        if genesisFP != expectedFP {
            return fmt.Errorf("genesis fingerprint mismatch in %s", rotatedLogs[i+1])
        }

        // 6. Cross-check: terminus and genesis should have same fingerprint
        if terminusFP != genesisFP {
            return fmt.Errorf("fingerprint mismatch between terminus and genesis")
        }

        // 7. Verify log path references in Foundation.LogRef
        if terminus.Foundation.LogRef != rotatedLogs[i+1] {
            return fmt.Errorf("terminus LogRef doesn't match new log")
        }
        if genesis.Foundation.LogRef != rotatedLogs[i] {
            return fmt.Errorf("genesis LogRef doesn't match old log")
        }
    }
    return nil
}
```

## API Changes

### New Types/Constants
```go
const (
    EventLogTerminus EventType = "log.terminus"
    EventLogGenesis  EventType = "log.genesis"
)

type RotationReason string

const (
    RotationSize   RotationReason = "size_threshold"
    RotationTime   RotationReason = "time_threshold"
    RotationManual RotationReason = "manual"
)
```

### New Log Methods
```go
// Rotate creates a new log file and writes terminus/genesis entries.
// Returns the new Log instance (next generation).
func (l *Log) Rotate(reason RotationReason, did string, s Signer) (*Log, error)

// IsTerminus returns true if the last entry is a terminus entry
func (l *Log) IsTerminus() bool

// IsGenesis returns true if the first entry is a genesis entry
func (l *Log) IsGenesis() bool

// Fingerprint returns the SHA-256 hash of the entire log file
func (l *Log) Fingerprint() (string, error)
```

### New Functions
```go
// VerifyChain validates cross-log rotation integrity.
// All logs use the naming pattern: baseName.NNN.jsonl (e.g., audit-log.000.jsonl)
func VerifyChain(logDir string, baseName string) error
```

### New Log Methods
```go
// Rotate creates a new log file and writes terminus/genesis entries.
// Returns the new Log instance.
func (l *Log) Rotate(reason RotationReason) (*Log, error)

// IsTerminus returns true if the last entry is a terminus entry
func (l *Log) IsTerminus() bool

// IsGenesis returns true if the first entry is a genesis entry
func (l *Log) IsGenesis() bool

// Fingerprint returns the SHA-256 hash of the entire log file
func (l *Log) Fingerprint() (string, error)
```

## CFR Part 11 Compliance Mapping

| Requirement | Mechanism |
|-------------|-----------|
| **Records trustworthy & reliable** | Ed25519 signatures on all entries including terminus/genesis |
| **Tamper-evident** | Hash chain within logs + fingerprint binding across logs (entire file hashed) |
| **Complete audit trail** | Terminus explicitly references next log via `Foundation.LogRef`; genesis records previous fingerprint |
| **Signatures attributable** | `ActorDID` on terminus and genesis identifies who performed rotation |
| **Records searchable** | Normal entry access unchanged; rotation metadata in `Domain` and `Foundation` |
| **Time stamps** | Standard timestamp in `Foundation`; terminus and genesis share same timestamp |
| **Non-repudiation** | Dual fingerprint check (terminus + genesis both carry `previous_fingerprint`) |

## Log Naming Convention

ALL logs use zero-padded sequence numbers (no "current/active" special case):

```
audit-log.000.jsonl      ← first log (true genesis)
audit-log.001.jsonl      ← second log
audit-log.002.jsonl      ← third log
audit-log.003.jsonl      ← fourth log
```

**During rotation:**
1. Terminus is written to current log (e.g., `audit-log.002.jsonl`)
2. New log is created: `audit-log.003.jsonl` (next sequence)
3. Genesis entry in new log points back to `audit-log.002.jsonl`
4. Terminus in old log points forward to `audit-log.003.jsonl`

This ensures every log file has a unique name and the chain links properly in one direction.

```go
func defaultRotatePath(currentPath string) (string, error) {
    // currentPath = "audit-log.002.jsonl"
    // Scan for existing logs: audit-log.000.jsonl, audit-log.001.jsonl, etc.
    // Return next sequence: "audit-log.003.jsonl"
    // Sequence starts at 000 for first log
}
```

## Atomicity

Rotation is performed under the old log's mutex lock. The steps are:

1. **Compute fingerprint** of current log (BEFORE writing terminus)
2. **Write terminus** to current log (single `WriteAt` + `Sync`)
3. **Create new log** file with next sequence number and write genesis (new file, atomic write)

If step 2 fails, old log is unchanged. If step 3 fails, old log has terminus but new log may be incomplete—`VerifyChain` will detect this.

## Open Questions

(All questions resolved in this design)

## References

- [CFR Part 11 - Electronic Records](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures)
- [sealchain Issue #2](https://github.com/parallelhours/sealchain/issues/2)
