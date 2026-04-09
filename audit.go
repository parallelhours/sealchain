// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain

import "encoding/json"

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

func (e *Entry) UnmarshalJSON(data []byte) error {
	type Alias Entry
	aux := struct {
		Domain map[string]any `json:"domain,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(nil),
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

type DomainEntry map[string]any

func (d DomainEntry) Fields() map[string]any {
	return d
}

type Domain interface {
	Fields() map[string]any
}

type Signer interface {
	Sign(message []byte) ([]byte, error)
}
