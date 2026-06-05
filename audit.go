// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package sealchain provides an append-only, tamper-evident audit log backed
// by a newline-delimited JSON file. Each entry is signed with Ed25519 and
// cryptographically linked to its predecessor via SHA-256, forming a chain
// where any deletion, insertion, or modification of a committed entry is
// detectable by Verify.
//
// # Security model
//
// The hash chain is computed over raw on-disk bytes, not re-marshaled Go
// structs. Any byte-level change to a committed entry — including whitespace —
// breaks the chain. Signatures cover the entire entry JSON with the Signature
// field set to "" before signing, preventing signature transplant attacks.
// The public key used to verify each entry is resolved directly from the
// ActorDID embedded in that entry, so every entry is cryptographically bound
// to the key that signed it.
//
// # Quick start
//
//	// 1. Define your event types.
//	const EventUserLogin sealchain.EventType = "user.login"
//
//	// 2. Implement Signer for your key material.
//	type mySigner struct{ key ed25519.PrivateKey }
//	func (s mySigner) Sign(msg []byte) ([]byte, error) {
//	    return ed25519.Sign(s.key, msg), nil
//	}
//
//	// 3. Derive a did:key DID from your public key.
//	//    Format: "did:key:z" + base58(uvarint(0xed) + publicKeyBytes)
//
//	// 4. Create or reopen a log.
//	log := sealchain.NewLog("audit.jsonl")
//
//	// 5. Append entries.
//	err := log.Append(sealchain.Entry{
//	    Event:  EventUserLogin,
//	    Domain: sealchain.DomainEntry{"user_id": "alice", "ip": "1.2.3.4"},
//	}, "did:key:z...", signer)
//
//	// 6. Verify the full chain at any time.
//	err = log.Verify()
//
// # Log rotation
//
// Rotate seals the current log with a terminus entry and opens a new log with
// a genesis entry. The two entries share a fingerprint of the sealed log,
// allowing VerifyChain to confirm the rotation was not tampered with.
//
// # Caller responsibilities
//
// Callers supply a did:key DID for every Append call, implement the Signer
// interface for their key material, and define EventType string constants.
// The library is domain-agnostic; structured payloads go through the Domain
// interface or the convenience type DomainEntry.
package sealchain

import "encoding/json"

// EventType is the string tag that identifies what happened in a log entry.
// Callers define their own constants in their own packages:
//
//	const (
//	    EventUserCreated EventType = "user.created"
//	    EventOrderPlaced EventType = "order.placed"
//	)
//
// Two values are reserved for log-rotation housekeeping and must not be used
// by callers: EventLogGenesis and EventLogTerminus.
type EventType string

// EventLogTerminus and EventLogGenesis are written automatically by Rotate.
// EventLogTerminus is the last entry of a sealed log and carries a forward
// reference to the next log file. EventLogGenesis is the first entry of a
// newly rotated log and carries a back-reference to the previous log file.
// Callers must not use these values as their own event types.
const (
	EventLogTerminus EventType = "log.terminus"
	EventLogGenesis  EventType = "log.genesis"
)

// RotationReason records why a log was rotated. It is stored in the domain
// fields of the terminus and genesis entries so audit consumers can
// distinguish scheduled rotation from operator-initiated rotation.
type RotationReason string

const (
	// RotationSize indicates the log was rotated because it exceeded a size limit.
	RotationSize RotationReason = "size_threshold"
	// RotationTime indicates the log was rotated on a time schedule.
	RotationTime RotationReason = "time_threshold"
	// RotationManual indicates the log was rotated by an operator.
	RotationManual RotationReason = "manual"
)

// Entry is a single record in the audit log. Callers populate Event and
// optionally Domain before passing an Entry to Append. All Foundation fields
// are computed and overwritten by Append; do not pre-set them.
type Entry struct {
	Foundation Foundation `json:"foundation"`
	Domain     Domain     `json:"domain,omitempty"`
	Event      EventType  `json:"event"`
}

// MarshalJSON produces a canonicalized JSON representation of the entry.
// Domain fields are normalized to ensure byte-for-byte reproducibility
// across separate marshaling calls — a hard requirement for signature
// verification. Do not bypass this by marshaling Entry fields individually.
func (e Entry) MarshalJSON() ([]byte, error) {
	type Alias Entry
	aux := struct {
		Alias
		Domain any `json:"domain,omitempty"`
	}{
		Alias:  Alias(e),
		Domain: nil,
	}
	if e.Domain != nil {
		aux.Domain = normalizeDomain(e.Domain.Fields())
	}
	return json.Marshal(aux)
}

func normalizeDomain(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]any, len(fields))
	for k, v := range fields {
		result[k] = v
	}
	return result
}

func (e *Entry) UnmarshalJSON(data []byte) error {
	type Alias struct {
		Foundation Foundation `json:"foundation"`
		Event      EventType  `json:"event"`
	}
	aux := struct {
		Domain map[string]any `json:"domain,omitempty"`
		Alias
	}{
		Alias: Alias{},
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	e.Foundation = aux.Alias.Foundation
	e.Event = aux.Alias.Event
	if len(aux.Domain) > 0 {
		e.Domain = DomainEntry(aux.Domain)
	}
	return nil
}

// DomainEntry is a map[string]any that satisfies the Domain interface.
// Use it for ad-hoc payloads without a dedicated struct:
//
//	sealchain.DomainEntry{"user_id": "alice", "ip": "1.2.3.4"}
//
// For typed payloads, implement Domain on your own type instead.
// Values must be JSON-serializable; non-serializable values will cause
// Append to return an error.
type DomainEntry map[string]any

func (d DomainEntry) Fields() map[string]any {
	return d
}

// Domain represents the structured payload attached to a log entry.
// Implement this interface to attach typed fields:
//
//	type LoginEvent struct {
//	    UserID string
//	    IP     string
//	}
//
//	func (e LoginEvent) Fields() map[string]any {
//	    return map[string]any{"user_id": e.UserID, "ip": e.IP}
//	}
//
// The map returned by Fields is serialized as the "domain" JSON object.
// All keys and values must be JSON-serializable. The map is normalized
// before signing; key iteration order does not affect the output.
type Domain interface {
	Fields() map[string]any
}

// Signer signs arbitrary message bytes and returns the raw signature.
// Implement this interface to supply Ed25519 key material to Append and Rotate:
//
//	type Ed25519Signer struct{ Key ed25519.PrivateKey }
//
//	func (s Ed25519Signer) Sign(msg []byte) ([]byte, error) {
//	    return ed25519.Sign(s.Key, msg), nil
//	}
//
// The message passed to Sign is the canonical JSON of the entry with
// Foundation.Signature set to "". The returned bytes are base64-encoded and
// stored as Foundation.Signature. Only Ed25519 keys encoded in a did:key DID
// are supported; other key types are rejected by Verify.
type Signer interface {
	Sign(message []byte) ([]byte, error)
}
