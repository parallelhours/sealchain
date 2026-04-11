<p align="center">
  <img src="assets/sealchain-logo.svg" width="200" alt="sealchain — three seals linked by a chain">
</p>

# sealchain

sealchain is a Go library for append-only, tamper-evident audit logs backed by SHA-256 hash chains and Ed25519 signatures.

## Why sealchain

- **Dual-mechanism integrity** — a SHA-256 hash chain proves ordering and continuity within a log; Ed25519 signatures prove actor authenticity. Each mechanism catches what the other cannot.
- **Domain extensibility** — define your own event types and payload fields. sealchain has no opinion about what you log.
- **JSONL on disk** — one JSON object per line. Human-readable, greppable, no database required.

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

    l := sealchain.NewLog("/var/log/myapp/audit.log")

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

## sealcheck CLI

Verify an audit log file from the command line — no code required:

```bash
go install github.com/parallelhours/sealchain/cmd/sealcheck@latest
sealcheck verify /var/log/myapp/audit.log
# OK: 42 entries verified
```

Exit codes: `0` = valid, `1` = tampered or corrupt, `2` = usage error.

## Documentation

- [Core Concepts](docs/concepts.md) — hash chains, genesis sentinel, signature scope, and security guarantees
- [Integration Guide](docs/integration.md) — embedding sealchain in your Go project
- [Licensing](docs/licensing.md) — AGPL v3 and commercial license options

## License

sealchain is dual-licensed:

- **AGPL v3** — free for open source use. If you distribute or run a service that includes sealchain, your project must also be licensed under AGPL v3. See [LICENSE](LICENSE).
- **Commercial license** — for closed-source products or SaaS deployments without copyleft obligations. Contact [support@parallelhours.io](mailto:support@parallelhours.io).

See [docs/licensing.md](docs/licensing.md) for details.
