// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package sealchain

// Foundation holds the cryptographic fields present in every log entry.
// All fields are set automatically by Append; callers must not pre-populate
// them (they will be overwritten). Together these fields form the tamper-
// evident chain: any modification to a committed entry breaks either the
// hash chain (PrevHash) or the signature (Signature) or both.
//
// Hash chain invariant: PrevHash is the SHA-256 of the raw bytes of the
// previous line exactly as written to disk — not the re-marshaled parsed
// struct. The first entry always uses the literal string "genesis" instead
// of a hash, anchoring the chain against prepend attacks.
//
// Signature invariant: the signature is computed over the full entry JSON
// with Signature set to "". Verification clears Signature, re-marshals the
// entry, and checks the Ed25519 signature against the result. The public key
// is derived from ActorDID, cryptographically binding actor identity to entry.
type Foundation struct {
	// Seq is a 1-based monotonically increasing sequence number.
	// Gaps in Seq are detected and rejected by Verify.
	Seq uint64 `json:"seq"`

	// PrevHash is "sha256:<hex>" of the previous raw on-disk line, or the
	// literal string "genesis" for the first entry in a log.
	// IMPORTANT: compute this hash from raw disk bytes, never from a
	// re-marshaled Entry — the two will not match.
	PrevHash string `json:"prev_hash"`

	// ActorDID is the did:key DID of the signing actor.
	// Format: "did:key:z" + base58(uvarint(0xed) + ed25519PublicKeyBytes).
	// Verify resolves the public key from this field to check Signature.
	ActorDID string `json:"actor_did"`

	// Timestamp is the RFC3339 UTC time at which the entry was appended.
	// Set by Append; not authenticated beyond being covered by Signature.
	Timestamp string `json:"timestamp"`

	// Signature is the base64-encoded Ed25519 signature of the canonical
	// JSON of the entry with Signature set to "". Set by Append via Signer.
	Signature string `json:"signature"`

	// LogRole is "genesis" or "terminus". Only set on the first and last
	// entries of a rotated log segment; omitted from JSON in normal entries.
	LogRole string `json:"log_role,omitempty"`

	// LogRef is a file path cross-referencing the adjacent log segment.
	// Terminus entries point forward to the new log; genesis entries point
	// back to the previous log. Omitted from JSON in normal entries.
	LogRef string `json:"log_ref,omitempty"`
}
