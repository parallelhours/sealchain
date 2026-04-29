<p align="center">
  <img src="assets/sealchain-logo.svg" width="200" alt="sealchain — three seals linked by a chain">
</p>

# sealchain

sealchain is a Go library for append-only, tamper-evident audit logs backed by SHA-256 hash chains and Ed25519 signatures.

## Why sealchain

- **Dual-mechanism integrity** — a SHA-256 hash chain proves ordering and continuity within a log; Ed25519 signatures prove actor authenticity. Each mechanism catches what the other cannot.
- **Domain extensibility** — define your own event types and payload fields. sealchain has no opinion about what you log.
- **JSONL on disk** — one JSON object per line. Human-readable, greppable, no database required.
- **Log rotation** — split logs across files with unbroken cryptographic chain. CFR Part 11 compliant.

## Quick Start

```bash
go get github.com/parallelhours/sealchain@latest
```

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "log"

    "github.com/mr-tron/base58"
    sealchain "github.com/parallelhours/sealchain"
)

// Define your own event types.
const EventDocumentStored sealchain.EventType = "DOCUMENT_STORED"

// actor implements sealchain.Signer using Ed25519.
type actor struct {
    did     string
    privKey ed25519.PrivateKey
}

func (a *actor) Sign(msg []byte) ([]byte, error) {
    return ed25519.Sign(a.privKey, msg), nil
}

func newActor() (*actor, error) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    buf := make([]byte, binary.MaxVarintLen64+len(pub))
    n := binary.PutUvarint(buf, 0xed)
    copy(buf[n:], pub)
    did := "did:key:z" + base58.Encode(buf[:n+len(pub)])
    return &actor{did: did, privKey: priv}, nil
}

func main() {
    a, err := newActor()
    if err != nil {
        log.Fatal(err)
    }

    l := sealchain.NewLog("/var/log/myapp/audit-log.000.jsonl")

    err = l.Append(sealchain.Entry{
        Event:  EventDocumentStored,
        Domain: sealchain.DomainEntry{"document": "report-q1.pdf", "user": "alice"},
    }, a.did, a)
    if err != nil {
        log.Fatal(err)
    }

    if err := l.Verify(); err != nil {
        log.Fatal("log integrity check failed:", err)
    }
    fmt.Println("log verified OK")
}
```

## Log Rotation

Rotate logs while preserving cryptographic chain integrity:

```go
// Rotate to next generation (e.g., audit-log.000.jsonl -> audit-log.001.jsonl)
newLog, err := log.Rotate(sealchain.RotationManual, actorDID, signer)
if err != nil {
    log.Fatal(err)
}
// newLog is the next generation log (audit-log.001.jsonl)
```

Logs use numbered naming (`audit-log.000.jsonl`, `audit-log.001.jsonl`). Each rotation writes a **terminus** entry (end of old log) and **genesis** entry (start of new log), cross-linked by fingerprints.

Verify the entire chain across rotated logs:

```go
if err := sealchain.VerifyChain("/var/log/myapp", "audit-log"); err != nil {
    log.Fatal("chain verification failed:", err)
}
```

## sealcheck CLI

Verify an audit log file from the command line — no code required:

```bash
go install github.com/parallelhours/sealchain/cmd/sealcheck@latest

# Verify single log
sealcheck verify /var/log/myapp/audit-log.000.jsonl
# OK: 42 entries verified

# Verify cross-log chain (with rotation)
sealcheck verify-chain /var/log/myapp audit-log
# verify-chain: chain valid
```

Exit codes: `0` = valid, `1` = tampered or corrupt, `2` = usage error.

## Documentation

- [Core Concepts](docs/concepts.md) — hash chains, genesis sentinel, signature scope, and security guarantees
- [Integration Guide](docs/integration.md) — embedding sealchain in your Go project
- [Log Rotation](docs/rotation.md) — rotation design, CFR Part 11 compliance, API reference
- [Licensing](docs/licensing.md) — AGPL v3 and commercial license options

## License

sealchain is dual-licensed:

- **AGPL v3** — free for open source use. If you distribute or run a service that includes sealchain, your project must also be licensed under AGPL v3. See [LICENSE](LICENSE).
- **Commercial license** — for closed-source products or SaaS deployments without copyleft obligations. Contact [support@parallelhours.io](mailto:support@parallelhours.io).

See [docs/licensing.md](docs/licensing.md) for details.
