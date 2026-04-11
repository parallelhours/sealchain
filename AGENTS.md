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
