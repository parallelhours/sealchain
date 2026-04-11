# Integration Guide

This guide covers embedding sealchain in a Go project, from adding the dependency to advanced usage patterns.

## Adding the Dependency

```bash
go get github.com/parallelhours/sealchain@latest
```

## Defining Event Types

`EventType` is a `string` alias. Define your own constants in your package — sealchain does not prescribe any:

```go
package audit

import sealchain "github.com/parallelhours/sealchain"

const (
    EventUserLogin         sealchain.EventType = "USER_LOGIN"
    EventDocumentCreated   sealchain.EventType = "DOCUMENT_CREATED"
    EventDocumentDeleted   sealchain.EventType = "DOCUMENT_DELETED"
    EventPermissionChanged sealchain.EventType = "PERMISSION_CHANGED"
)
```

## Implementing Signer

`Signer` is a one-method interface:

```go
type Signer interface {
    Sign(message []byte) ([]byte, error)
}
```

The expected implementation uses Ed25519. sealchain uses the `did:key` scheme to encode actor identity: a DID is `"did:key:z"` followed by a base58-encoded Ed25519 public key with a multicodec prefix (`0xed`).

Minimal implementation using the standard library and `github.com/mr-tron/base58`:

```go
package myapp

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/binary"

    "github.com/mr-tron/base58"
)

type Identity struct {
    DID     string
    privKey ed25519.PrivateKey
}

func NewIdentity() (*Identity, error) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    buf := make([]byte, binary.MaxVarintLen64+len(pub))
    n := binary.PutUvarint(buf, 0xed) // Ed25519 multicodec prefix
    copy(buf[n:], pub)
    did := "did:key:z" + base58.Encode(buf[:n+len(pub)])
    return &Identity{DID: did, privKey: priv}, nil
}

func (id *Identity) Sign(msg []byte) ([]byte, error) {
    return ed25519.Sign(id.privKey, msg), nil
}
```

Persist the private key securely (encrypted at rest) if the log needs to survive process restarts and remain verifiable across sessions.

## Appending Entries

```go
l := sealchain.NewLog("/var/log/myapp/audit.log")

err := l.Append(sealchain.Entry{
    Event: EventDocumentCreated,
    Domain: sealchain.DomainEntry{
        "document_id": "doc-123",
        "title":       "Q1 Report",
        "size_bytes":  204800,
    },
}, identity.DID, identity)
```

`Foundation` fields (`Seq`, `PrevHash`, `ActorDID`, `Timestamp`, `Signature`) are set automatically by `Append` — do not set them yourself.

## Structured Domain Payloads

For typed payloads, implement the `Domain` interface instead of using `DomainEntry`:

```go
type DocumentEvent struct {
    DocumentID string `json:"document_id"`
    Title      string `json:"title"`
    SizeBytes  int64  `json:"size_bytes"`
}

func (d DocumentEvent) Fields() map[string]any {
    return map[string]any{
        "document_id": d.DocumentID,
        "title":       d.Title,
        "size_bytes":  d.SizeBytes,
    }
}
```

Then use it directly:

```go
err := l.Append(sealchain.Entry{
    Event: EventDocumentCreated,
    Domain: DocumentEvent{
        DocumentID: "doc-123",
        Title:      "Q1 Report",
        SizeBytes:  204800,
    },
}, identity.DID, identity)
```

Note: when reading entries back via `Entries()`, the `Domain` field is always a `DomainEntry` (`map[string]any`) — the original concrete type is not preserved. Re-hydrate from the map in your application code if needed.

## Reading and Verifying

```go
// Read all entries
entries, err := l.Entries()
if err != nil {
    log.Fatal(err)
}
for _, e := range entries {
    fmt.Printf("seq=%d event=%s actor=%s\n",
        e.Foundation.Seq, e.Event, e.Foundation.ActorDID)
    if e.Domain != nil {
        fmt.Printf("  domain=%v\n", e.Domain.Fields())
    }
}

// Verify the entire log
if err := l.Verify(); err != nil {
    // Tampering or corruption detected — error message identifies the failing entry
    log.Printf("audit log integrity check failed: %v", err)
}
```

Call `Verify()` on startup and periodically (e.g., as a scheduled health check) to detect tampering early.

## Concurrency

`Log` is safe for concurrent use. Multiple goroutines may call `Append`, `Entries`, and `Verify` simultaneously. Writes are serialized internally via a mutex; reads run concurrently with each other.

## Log File Location

sealchain creates the file if it does not exist. Recommended practices:

- Use a dedicated directory with restricted permissions: `chmod 700 /var/log/myapp`
- The log file itself should be `chmod 600` (write by owner only)
- sealchain opens in append mode on each write — no lock files are needed

## Inspecting Logs with Standard Tools

The JSONL format works with standard Unix tools:

```bash
# Pretty-print all entries
cat audit.log | jq .

# Show event type and actor for each entry
cat audit.log | jq -r '[.foundation.seq, .event, .foundation.actor_did] | @tsv'

# Count entries by event type
cat audit.log | jq -r '.event' | sort | uniq -c | sort -rn

# Find all entries from a specific actor
grep '"actor_did":"did:key:z..."' audit.log | jq .
```

## Using sealcheck for Verification

Instead of calling `Verify()` in code, you can use the `sealcheck` CLI tool:

```bash
go install github.com/parallelhours/sealchain/cmd/sealcheck@latest
sealcheck verify /var/log/myapp/audit.log
# OK: 1337 entries verified
```

This is useful for operational checks, cron jobs, or incident response without writing custom tooling.
