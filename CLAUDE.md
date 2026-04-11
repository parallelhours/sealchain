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
