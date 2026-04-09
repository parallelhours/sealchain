// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain

type EventType string

const (
	EventVaultCreated      EventType = "VAULT_CREATED"
	EventMemberAdded       EventType = "MEMBER_ADDED"
	EventMemberRemoved     EventType = "MEMBER_REMOVED"
	EventAdminChanged      EventType = "ADMIN_CHANGED"
	EventDocumentStored    EventType = "DOCUMENT_STORED"
	EventDocumentAccessed  EventType = "DOCUMENT_ACCESSED"
	EventDocumentExtracted EventType = "DOCUMENT_EXTRACTED"
	EventMobileViewed      EventType = "MOBILE_VIEWED"
	EventManifestUpdated   EventType = "MANIFEST_UPDATED"
)

type Entry struct {
	Foundation Foundation `json:"foundation"`
	Domain     Domain     `json:"domain,omitempty"`
	Event      EventType  `json:"event"`
}

type Domain interface {
	Fields() map[string]any
}

type Signer interface {
	Sign(message []byte) ([]byte, error)
}
