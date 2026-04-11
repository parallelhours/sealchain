# sealchain Open Source Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform sealchain into a well-structured, self-contained open-source Go library with dual licensing (AGPL v3 / commercial), full documentation, a working CLI tool, and the correct module path.

**Architecture:** Module is renamed from `github.com/pmonday/sealchain` to `github.com/parallelhours/sealchain`. A `cmd/sealcheck` binary is added as a thin wrapper over `Log.Verify()`. Documentation lives in the repo root (README, BUILD, CLAUDE, AGENTS) and `docs/` (concepts, integration, licensing).

**Tech Stack:** Go 1.26.1, standard library only for sealcheck CLI (`flag` package), AGPL v3 license.

---

## File Map

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `go.mod` | Update module path |
| Modify | `audit_test.go` | Update import path |
| Modify | `foundation.go` | Update file header |
| Modify | `did.go` | Update file header |
| Modify | `audit.go` | Update file header |
| Modify | `log.go` | Update file header |
| Create | `LICENSE` | AGPL v3 full text |
| Create | `cmd/sealcheck/main.go` | CLI binary |
| Create | `cmd/sealcheck/main_test.go` | CLI tests |
| Create | `README.md` | Project front door |
| Create | `BUILD.md` | Build and test instructions |
| Create | `CLAUDE.md` | Claude Code AI context |
| Create | `AGENTS.md` | General AI agent context |
| Create | `docs/concepts.md` | Cryptographic design deep-dive |
| Create | `docs/integration.md` | Embedding sealchain in another project |
| Create | `docs/licensing.md` | AGPL v3 and commercial license guide |

---

### Task 1: Update Git Remote and Module Path

**Files:**
- Modify: `go.mod`
- Modify: `audit_test.go`

- [ ] **Step 1: Update the git remote**

```bash
git remote set-url origin git@github.com:parallelhours/sealchain.git
git remote -v
```

Expected output:
```
origin  git@github.com:parallelhours/sealchain.git (fetch)
origin  git@github.com:parallelhours/sealchain.git (push)
```

- [ ] **Step 2: Update go.mod module path**

Replace the first line of `go.mod`:

```
module github.com/parallelhours/sealchain
```

The full updated `go.mod`:
```
module github.com/parallelhours/sealchain

go 1.26.1

require github.com/mr-tron/base58 v1.3.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.9.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
```

- [ ] **Step 3: Update the import path in audit_test.go**

Change line 19 from:
```go
sealchain "github.com/pmonday/sealchain"
```
To:
```go
sealchain "github.com/parallelhours/sealchain"
```

- [ ] **Step 4: Verify tests still pass**

```bash
go test ./...
```

Expected output:
```
ok      github.com/parallelhours/sealchain  0.XXs
```

- [ ] **Step 5: Commit**

```bash
git add go.mod audit_test.go
git commit -m "chore: rename module to github.com/parallelhours/sealchain"
```

---

### Task 2: Update File Headers to AGPL v3

**Files:**
- Modify: `foundation.go`
- Modify: `did.go`
- Modify: `audit.go`
- Modify: `log.go`

- [ ] **Step 1: Update foundation.go header**

Replace the top two lines:
```go
// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only
```

- [ ] **Step 2: Update did.go header**

Replace the top two lines:
```go
// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only
```

- [ ] **Step 3: Update audit.go header**

Replace the top two lines:
```go
// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only
```

- [ ] **Step 4: Update log.go header**

Replace the top two lines:
```go
// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only
```

- [ ] **Step 5: Verify no BUSL references remain**

```bash
grep -r "BUSL" .
```

Expected output: no matches.

- [ ] **Step 6: Verify tests still pass**

```bash
go test ./...
```

Expected: `ok github.com/parallelhours/sealchain`

- [ ] **Step 7: Commit**

```bash
git add foundation.go did.go audit.go log.go
git commit -m "chore: update license headers to AGPL-3.0-only"
```

---

### Task 3: Add LICENSE File

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Download the AGPL v3 license text**

```bash
curl -o LICENSE https://www.gnu.org/licenses/agpl-3.0.txt
```

- [ ] **Step 2: Verify the file was downloaded**

```bash
head -5 LICENSE
```

Expected output:
```
                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
```

- [ ] **Step 3: Commit**

```bash
git add LICENSE
git commit -m "chore: add AGPL v3 license"
```

---

### Task 4: Create cmd/sealcheck (TDD)

**Files:**
- Create: `cmd/sealcheck/main.go`
- Create: `cmd/sealcheck/main_test.go`

- [ ] **Step 1: Create the directory**

```bash
mkdir -p cmd/sealcheck
```

- [ ] **Step 2: Write the failing tests first**

Create `cmd/sealcheck/main_test.go`:

```go
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
	code := run([]string{"verify", "/tmp/sealchain-nonexistent-test.log"})
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
```

- [ ] **Step 3: Run the tests — verify they fail (no main.go yet)**

```bash
go test ./cmd/sealcheck/...
```

Expected: compile error — `run` is undefined. This is correct — we haven't written the implementation yet.

- [ ] **Step 4: Write the implementation**

Create `cmd/sealcheck/main.go`:

```go
// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	sealchain "github.com/parallelhours/sealchain"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sealcheck <subcommand> [args]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  verify <path>   Verify the integrity of an audit log file")
		return 2
	}

	switch args[0] {
	case "verify":
		return cmdVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n", args[0])
		fmt.Fprintln(os.Stderr, "Run 'sealcheck' with no arguments for usage.")
		return 2
	}
}

func cmdVerify(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sealcheck verify <path>")
		return 2
	}
	path := args[0]

	l := sealchain.NewLog(path)

	entries, err := l.Entries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading log: %v\n", err)
		return 1
	}

	if err := l.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		return 1
	}

	fmt.Printf("OK: %d entries verified\n", len(entries))
	return 0
}
```

- [ ] **Step 5: Run the tests — verify they all pass**

```bash
go test ./cmd/sealcheck/...
```

Expected output:
```
ok      github.com/parallelhours/sealchain/cmd/sealcheck  0.XXs
```

- [ ] **Step 6: Build and smoke-test the binary**

```bash
go build -o /tmp/sealcheck ./cmd/sealcheck
/tmp/sealcheck
```

Expected output (exit 2):
```
Usage: sealcheck <subcommand> [args]

Subcommands:
  verify <path>   Verify the integrity of an audit log file
```

- [ ] **Step 7: Run full test suite including race detector**

```bash
go test -race ./...
```

Expected: all packages pass.

- [ ] **Step 8: Commit**

```bash
git add cmd/sealcheck/main.go cmd/sealcheck/main_test.go
git commit -m "feat: add sealcheck verify CLI"
```

---

### Task 5: Create README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create README.md**

```markdown
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

Verify an audit log file from the command line:

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
```

- [ ] **Step 2: Verify the file renders correctly**

```bash
head -5 README.md
```

Expected: `# sealchain` as the first line.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

---

### Task 6: Create BUILD.md

**Files:**
- Create: `BUILD.md`

- [ ] **Step 1: Create BUILD.md**

```markdown
# Building sealchain

## Prerequisites

Go 1.21 or later. The module declares `go 1.26.1` — the Go toolchain will manage this automatically via `GOTOOLCHAIN=auto` (the default since Go 1.21).

## Run Tests

```bash
go test ./...
```

With the race detector (recommended before submitting changes):

```bash
go test -race ./...
```

Expected output:
```
ok      github.com/parallelhours/sealchain                0.XXs
ok      github.com/parallelhours/sealchain/cmd/sealcheck  0.XXs
```

## Build sealcheck

Local development build:

```bash
go build -o sealcheck ./cmd/sealcheck
./sealcheck verify audit.log
```

Install globally (replaces any existing version):

```bash
go install github.com/parallelhours/sealchain/cmd/sealcheck@latest
```

## Use sealchain as a Library

Add the dependency:

```bash
go get github.com/parallelhours/sealchain@latest
```

Import it:

```go
import sealchain "github.com/parallelhours/sealchain"
```

See [docs/integration.md](docs/integration.md) for a full integration guide.

## Note: Module Path History

This module was previously published at `github.com/pmonday/sealchain` (pre-v0.2.0). If you have that path in your `go.mod`, update it to `github.com/parallelhours/sealchain` and run:

```bash
go mod tidy
```
```

- [ ] **Step 2: Commit**

```bash
git add BUILD.md
git commit -m "docs: add BUILD.md"
```

---

### Task 7: Create CLAUDE.md and AGENTS.md

**Files:**
- Create: `CLAUDE.md`
- Create: `AGENTS.md`

- [ ] **Step 1: Create CLAUDE.md**

```markdown
# Claude Code Context — sealchain

## What This Repo Is

sealchain (`github.com/parallelhours/sealchain`) is a Go library for append-only, tamper-evident audit logs. Each entry is signed with Ed25519 and cryptographically linked to the previous entry via SHA-256. The library is domain-agnostic: callers define their own event types and payload fields via the `Domain` interface and `EventType` string alias.

## Package Layout

| File | Purpose |
|------|---------|
| `audit.go` | Core types: `Entry`, `Domain`, `DomainEntry`, `Signer`, `EventType` |
| `foundation.go` | `Foundation` struct — the cryptographic fields inside every entry |
| `log.go` | `Log` — file-backed log with `Append`, `Entries`, `Verify` |
| `did.go` | Internal DID key resolution (Ed25519 `did:key:z…` format) |
| `cmd/sealcheck/main.go` | CLI: `sealcheck verify <path>` |

## Key Types

| Type | Purpose |
|------|---------|
| `Log` | File-backed log. Created with `NewLog(path)`. |
| `Entry` | One log record: `Foundation` + `Event` + optional `Domain`. |
| `Foundation` | Cryptographic fields: `Seq`, `PrevHash`, `ActorDID`, `Timestamp`, `Signature`. Set automatically by `Append`. |
| `Domain` | Interface — `Fields() map[string]any`. Implement for structured payloads. |
| `DomainEntry` | `map[string]any` that satisfies `Domain`. Use for ad-hoc fields. |
| `Signer` | Interface — `Sign([]byte) ([]byte, error)`. Callers implement this. |
| `EventType` | `type EventType string`. Callers define their own string constants. |

## Critical Invariants — Read Before Touching Cryptographic Code

**Raw-line hashing:** `PrevHash` is the SHA-256 of the **raw bytes of the previous line as written to disk** — not a re-marshaled version of the parsed entry. Hashing a re-marshaled entry will produce a different result and break the chain. See `readRawLines()` in `log.go`.

**Signature scope:** Before signing, `Foundation.Signature` is set to `""`. Verification reverses this: clear `Signature`, re-marshal the entry, then verify against that body. This prevents signature substitution attacks. See `Verify()` in `log.go`.

**Genesis sentinel:** The first entry always has `prev_hash: "genesis"` (a literal string, not a hash). This anchors the chain and prevents prepending forged entries.

**Stable JSON marshaling:** `Entry.MarshalJSON` normalizes `Domain` fields to ensure deterministic byte output across Go versions. Never bypass it by marshaling `Entry` fields individually.

## What NOT To Do

- Do not re-marshal a parsed entry to compute its hash — use raw line bytes from disk.
- Do not define `EventType` as anything other than string constants in calling packages.
- Do not add business logic to `cmd/sealcheck` — all logic belongs in the library.
- Do not remove `fsync` from `Append` — durability depends on it.
- Do not change the JSON field order in `Foundation` without verifying existing logs still verify.

## Test Conventions

- Main tests: `audit_test.go`, package `sealchain_test` (external — cannot access unexported identifiers).
- CLI tests: `cmd/sealcheck/main_test.go`, package `main`.
- Always use `t.TempDir()` for log file paths — never hard-code `/tmp` paths in tests.
- Identity helper: implement `Signer` as a struct with `ed25519.PrivateKey`. DID format is `did:key:z` + base58(uvarint(0xed) + ed25519PublicKeyBytes).
- Run `go test -race ./...` to catch concurrency issues — a goroutine safety test already exists.

## cmd/sealcheck

A thin CLI wrapper over `Log.Verify()`. Subcommand: `verify <path>`. Business logic stays in the library. Exit codes: 0 = OK, 1 = tampered/corrupt, 2 = usage error.
```

- [ ] **Step 2: Create AGENTS.md**

```markdown
# Agent Context — sealchain

## What This Repo Is

sealchain (`github.com/parallelhours/sealchain`) is a Go library for append-only, tamper-evident audit logs. Each entry is Ed25519-signed and SHA-256 hash-chained to the previous entry. Callers define their own event types and payload fields — the library is domain-agnostic.

## Package Layout

| File | Purpose |
|------|---------|
| `audit.go` | Core types: `Entry`, `Domain`, `DomainEntry`, `Signer`, `EventType` |
| `foundation.go` | `Foundation` struct — cryptographic fields inside every entry |
| `log.go` | `Log` — file-backed log with `Append`, `Entries`, `Verify` |
| `did.go` | Internal DID key resolution (Ed25519 `did:key:z…` format) |
| `cmd/sealcheck/main.go` | CLI: `sealcheck verify <path>` |

## Key Types

| Type | Purpose |
|------|---------|
| `Log` | File-backed log. Created with `NewLog(path)`. |
| `Entry` | One log record: `Foundation` + `Event` + optional `Domain`. |
| `Foundation` | Cryptographic fields set automatically by `Append`: `Seq`, `PrevHash`, `ActorDID`, `Timestamp`, `Signature`. |
| `Domain` | Interface — `Fields() map[string]any`. |
| `DomainEntry` | `map[string]any` satisfying `Domain`. |
| `Signer` | Interface — `Sign([]byte) ([]byte, error)`. |
| `EventType` | `type EventType string` — callers define constants. |

## Critical Invariants

**Raw-line hashing:** `PrevHash` = SHA-256 of raw on-disk bytes of the previous line. Never re-marshal a parsed entry to compute this — the bytes will differ.

**Signature scope:** `Foundation.Signature` is cleared to `""` before signing. Verification reverses this. See `Verify()` in `log.go`.

**Genesis sentinel:** First entry has `prev_hash: "genesis"` (literal string).

**Stable JSON:** `Entry.MarshalJSON` normalizes `Domain` for deterministic output. Do not bypass it.

## What NOT To Do

- Do not re-marshal entries to compute hashes — use raw disk bytes.
- Do not add logic to `cmd/sealcheck` — it is a thin wrapper only.
- Do not remove `fsync` from `Append`.
- Do not hard-code event types in the library — callers own their `EventType` constants.

## Test Conventions

- `audit_test.go`: package `sealchain_test`, uses `t.TempDir()`, `testIdentity` pattern for `Signer`.
- `cmd/sealcheck/main_test.go`: package `main`, tests `run()` return code directly.
- Always run `go test -race ./...` before committing.

## Build

```bash
go test ./...                           # run all tests
go test -race ./...                     # with race detector
go build -o sealcheck ./cmd/sealcheck  # build CLI
```
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md AGENTS.md
git commit -m "docs: add CLAUDE.md and AGENTS.md"
```

---

### Task 8: Create docs/concepts.md

**Files:**
- Create: `docs/concepts.md`

- [ ] **Step 1: Create docs/concepts.md**

```markdown
# Core Concepts

This document explains how sealchain's cryptographic guarantees work and why the design choices were made. Read this before modifying any signing or hashing logic.

## The Two Mechanisms

sealchain uses two independent mechanisms together:

**SHA-256 hash chain** — each entry records the SHA-256 hash of the previous entry's raw bytes. This proves ordering and continuity: inserting, deleting, or reordering any entry breaks every subsequent hash.

**Ed25519 signatures** — each entry is signed by the actor who created it. This proves authenticity: only the holder of the private key corresponding to the actor's DID could have produced the signature.

Neither mechanism alone is sufficient:
- A hash chain without signatures doesn't prove *who* did an operation. An attacker who captures a log file can re-chain their own entries.
- Signatures without a hash chain don't prevent reordering or deletion. An attacker can drop entries or change their order while keeping each individual signature valid.

Together, they guarantee both **integrity** (nothing was modified) and **authenticity** (the stated actor created the entry).

## Raw-Line Hashing

`PrevHash` is the SHA-256 of the **raw bytes of the previous line as written to disk** — not a re-marshaled version of the parsed entry.

```
line 1 bytes on disk → SHA-256 → stored in line 2's prev_hash
```

Why raw bytes instead of re-marshaling? Re-marshaling a parsed JSON entry can produce subtly different bytes: different whitespace, key ordering edge cases, or number formatting. The on-disk bytes are the canonical form. Hashing them directly is simpler and unambiguous.

**Implication:** if you ever need to verify a hash chain manually (e.g., in a tool outside this library), hash the raw line bytes — not a pretty-printed or re-encoded version of the JSON.

## Genesis Sentinel

The first entry in a log always has:

```json
"prev_hash": "genesis"
```

This is a literal string, not a hex-encoded hash. It marks the start of the chain and prevents an attacker from prepending forged entries before the first real entry (a forged entry would need to produce `prev_hash: "genesis"`, which is easy, but the second real entry's `prev_hash` would not match the forged entry's raw bytes).

## Signature Scope

When creating an entry, the `Signature` field is cleared to an empty string before marshaling for signing:

```
entry with Signature="" → marshal to JSON → Sign → fill in Signature → write to disk
```

Verification reverses this:

```
read raw line → parse → clear Signature to "" → marshal → verify against stored sig
```

This ensures the signature covers all other fields — including `Seq`, `PrevHash`, `Timestamp`, and the entire `Domain` payload. The empty-string approach means the signature commits to the exact JSON structure of the entry, preventing field substitution or extension attacks.

**Why not exclude `Signature` from the JSON entirely?** Keeping the field present (as `""`) means the JSON structure is identical at signing time and verification time, avoiding any ambiguity about what was signed.

## What Verify() Guarantees

When `Log.Verify()` returns `nil`:

- Every entry's `PrevHash` matches the SHA-256 of the previous entry's raw bytes.
- Sequence numbers are monotonically increasing with no gaps.
- Every entry's Ed25519 signature is valid for the stated `ActorDID`.
- The first entry has `prev_hash: "genesis"`.

## What Verify() Does NOT Guarantee

- **Cross-log ordering:** if two actors maintain separate logs, `Verify()` cannot establish ordering between them.
- **Completeness:** `Verify()` checks the log that exists. It cannot detect whether entries were deleted before the log was shared.
- **Real-world identity:** `Verify()` confirms a signature matches a DID, but does not establish who controls that DID key in the real world.
- **Causal relationships:** the hash chain proves temporal order within a log, but not causality between events.
```

- [ ] **Step 2: Commit**

```bash
git add docs/concepts.md
git commit -m "docs: add concepts.md"
```

---

### Task 9: Create docs/integration.md

**Files:**
- Create: `docs/integration.md`

- [ ] **Step 1: Create docs/integration.md**

```markdown
# Integration Guide

This guide covers embedding sealchain in a Go project, from adding the dependency to advanced usage patterns.

## Adding the Dependency

```bash
go get github.com/parallelhours/sealchain@latest
```

## Defining Event Types

`EventType` is a `string` alias. Define your own constants in your package — sealchain does not prescribe any event types:

```go
package audit

import sealchain "github.com/parallelhours/sealchain"

const (
    EventUserLogin       sealchain.EventType = "USER_LOGIN"
    EventDocumentCreated sealchain.EventType = "DOCUMENT_CREATED"
    EventDocumentDeleted sealchain.EventType = "DOCUMENT_DELETED"
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

`Foundation` fields (`Seq`, `PrevHash`, `ActorDID`, `Timestamp`, `Signature`) are set automatically — do not set them yourself.

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

Note: when a log entry is read back via `Entries()`, the `Domain` field is always a `DomainEntry` (`map[string]any`) — the original concrete type is not preserved. Type-assert or re-hydrate from the map in your application code if needed.

## Reading and Verifying

```go
// Read all entries
entries, err := l.Entries()
for _, e := range entries {
    fmt.Printf("seq=%d event=%s actor=%s\n",
        e.Foundation.Seq, e.Event, e.Foundation.ActorDID)
    if e.Domain != nil {
        fmt.Printf("  domain=%v\n", e.Domain.Fields())
    }
}

// Verify the entire log
if err := l.Verify(); err != nil {
    // Tampering or corruption detected — details in the error message
    log.Printf("audit log integrity check failed: %v", err)
}
```

Call `Verify()` on startup and periodically (e.g., daily) to detect tampering early.

## Concurrency

`Log` is safe for concurrent use. Multiple goroutines may call `Append`, `Entries`, and `Verify` simultaneously. Writes are serialized internally via a mutex; reads run concurrently with each other.

## Log File Location

sealchain creates the file if it does not exist. The file is opened in append mode on each write. Recommended locations:

- Development: any writable path (`/tmp/myapp-audit.log`)
- Production: a dedicated directory with restricted permissions (`chmod 600`)

The log file format is JSONL (one JSON object per line). It is human-readable and can be processed with standard tools like `jq`:

```bash
cat audit.log | jq '{seq: .foundation.seq, event: .event, actor: .foundation.actor_did}'
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/integration.md
git commit -m "docs: add integration guide"
```

---

### Task 10: Create docs/licensing.md

**Files:**
- Create: `docs/licensing.md`

- [ ] **Step 1: Create docs/licensing.md**

```markdown
# Licensing

sealchain is dual-licensed. Choose the license that fits your use case.

## AGPL v3 — Free for Open Source

The GNU Affero General Public License v3 (AGPL v3) is a copyleft license. You can use, modify, and distribute sealchain under AGPL v3 at no cost, subject to one key condition:

**If you distribute software that includes sealchain, or run it as a networked service (SaaS), your project must also be licensed under AGPL v3 and its source code made available to users.**

AGPL v3 is the right choice if:
- Your project is open source and already uses a copyleft license.
- You are building an internal tool with no external distribution.
- You are evaluating sealchain before deciding on a license.

The full license text is in [LICENSE](../LICENSE).

## Commercial License — For Closed-Source and SaaS Use

If the AGPL v3 copyleft terms are incompatible with your project — for example, you are building a closed-source product, a proprietary SaaS platform, or a commercial application you do not intend to open source — a commercial license is available.

A commercial license grants you:
- Use of sealchain in closed-source and proprietary products.
- No copyleft obligations — your source code stays yours.
- Optional support, maintenance, and enhancement agreements.

To inquire about a commercial license, contact:

**Email:** [support@parallelhours.io](mailto:support@parallelhours.io)

Please include a brief description of your use case and the scale of your deployment. We aim to respond within two business days.

## Which License Do I Need?

| Use case | License |
|----------|---------|
| Open source project (AGPL-compatible) | AGPL v3 (free) |
| Internal tooling, no external distribution | AGPL v3 (free) |
| Evaluating before committing | AGPL v3 (free) |
| Closed-source commercial product | Commercial |
| SaaS / hosted service (proprietary) | Commercial |
| Embedding in a non-AGPL open source project | Commercial (or relicense your project) |

## Why Dual Licensing?

sealchain is maintained by [Parallel Hours LLC](https://parallelhours.com). Dual licensing lets us keep the library freely available for open source use while ensuring that companies building proprietary products on top of it contribute back — either by open-sourcing their work or by supporting continued development through a commercial license.
```

- [ ] **Step 2: Commit**

```bash
git add docs/licensing.md
git commit -m "docs: add licensing guide"
```

---

### Task 11: Final Verification and Push

- [ ] **Step 1: Run the full test suite one last time**

```bash
go test -race ./...
```

Expected:
```
ok      github.com/parallelhours/sealchain                0.XXs
ok      github.com/parallelhours/sealchain/cmd/sealcheck  0.XXs
```

- [ ] **Step 2: Verify no old module path references remain**

```bash
grep -r "pmonday/sealchain" .
```

Expected: no matches.

- [ ] **Step 3: Verify no BUSL references remain**

```bash
grep -r "BUSL" .
```

Expected: no matches.

- [ ] **Step 4: Verify all expected files exist**

```bash
ls README.md BUILD.md CLAUDE.md AGENTS.md LICENSE docs/concepts.md docs/integration.md docs/licensing.md cmd/sealcheck/main.go cmd/sealcheck/main_test.go
```

Expected: all files listed with no errors.

- [ ] **Step 5: Push to remote**

```bash
git push -u origin main
```

Expected: push succeeds to `git@github.com:parallelhours/sealchain.git`.

---

## Self-Review Notes

- All spec sections have corresponding tasks: module rename (Task 1), file headers (Task 2), LICENSE (Task 3), sealcheck CLI (Task 4), README (Task 5), BUILD (Task 6), CLAUDE+AGENTS (Task 7), concepts (Task 8), integration (Task 9), licensing (Task 10).
- No TBD placeholders anywhere. The licensing contact email (`support@parallelhours.io`) is a real address to fill in — placeholder is intentional and flagged in the spec.
- Type names (`EventType`, `DomainEntry`, `Foundation`, `Signer`) are consistent across all tasks.
- `run()` function signature is consistent between Task 4 implementation and tests.
