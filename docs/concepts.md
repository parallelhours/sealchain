# Core Concepts

This document explains how sealchain's cryptographic guarantees work and why the design choices were made. Read this before modifying any signing or hashing logic.

## The Two Mechanisms

sealchain uses two independent mechanisms together:

**SHA-256 hash chain** — each entry records the SHA-256 hash of the previous entry's raw bytes. This proves ordering and continuity: inserting, deleting, or reordering any entry breaks every subsequent hash.

**Ed25519 signatures** — each entry is signed by the actor who created it. This proves authenticity: only the holder of the private key corresponding to the actor's DID could have produced the signature.

Neither mechanism alone is sufficient:
- A hash chain without signatures doesn't prove *who* did an operation. An attacker who controls a log file can re-chain their own entries.
- Signatures without a hash chain don't prevent reordering or deletion. An attacker can drop entries or change their order while keeping each individual signature valid.

Together, they guarantee both **integrity** (nothing was modified) and **authenticity** (the stated actor created the entry).

## Raw-Line Hashing

`PrevHash` is the SHA-256 of the **raw bytes of the previous line as written to disk** — not a re-marshaled version of the parsed entry.

```
line N bytes on disk → SHA-256 → stored in line N+1's prev_hash
```

Why raw bytes instead of re-marshaling? Re-marshaling a parsed JSON entry can produce subtly different bytes: different whitespace, key ordering edge cases, or number formatting across library versions. The on-disk bytes are the canonical form. Hashing them directly is simpler and unambiguous.

**Implication:** if you verify a hash chain manually (e.g., in a tool outside this library), hash the raw line bytes — not a pretty-printed or re-encoded version of the JSON.

## Genesis Sentinel

The first entry in a log always has:

```json
"prev_hash": "genesis"
```

This is a literal string, not a hex-encoded hash. It marks the start of the chain and anchors it: any attempt to prepend a forged entry would need its `prev_hash` to equal `"genesis"`, but then the real first entry's `prev_hash` would no longer match the forged entry's actual bytes.

## Signature Scope

When creating an entry, the `Signature` field is cleared to an empty string before marshaling for signing:

```
entry with Signature="" → marshal to JSON → Sign → fill in Signature → write to disk
```

Verification reverses this exactly:

```
read raw line → parse entry → clear Signature to "" → marshal → verify against stored sig
```

This ensures the signature covers all other fields — including `Seq`, `PrevHash`, `Timestamp`, and the entire `Domain` payload. The empty-string approach means the JSON structure is identical at signing time and verification time, avoiding ambiguity about what was signed.

## DID Key Format

Actors are identified by a `did:key` DID containing their Ed25519 public key. The format is:

```
did:key:z<base58(uvarint(0xed) + ed25519PublicKeyBytes)>
```

`0xed` is the Ed25519 multicodec prefix. sealchain resolves the public key from the DID at verification time — no external registry or lookup is required.

## What Verify() Guarantees

When `Log.Verify()` returns `nil`:

- Every entry's `PrevHash` matches the SHA-256 of the previous entry's raw on-disk bytes.
- Sequence numbers are monotonically increasing with no gaps.
- Every entry's Ed25519 signature is valid for the stated `ActorDID`.
- The first entry has `prev_hash: "genesis"`.

## What Verify() Does NOT Guarantee

- **Cross-log ordering:** if two actors maintain separate logs, `Verify()` cannot establish ordering between entries from different logs.
- **Completeness:** `Verify()` checks the log that exists. It cannot detect whether entries were removed before the log was shared.
- **Real-world identity:** `Verify()` confirms a signature matches a DID, but does not establish who controls that DID key in the real world. Key management is out of scope.
- **Causal relationships:** the hash chain proves temporal order within a log, not causality between events.

## Concurrency and Durability

`Log` serializes writes with a mutex — concurrent `Append` calls are safe. `Append` calls `fsync` after every write to ensure the entry reaches durable storage before the call returns. A process crash will not produce a partial or corrupt final entry.
