// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package sealchain

import "encoding/json"

type EventType string

type Entry struct {
	Foundation Foundation `json:"foundation"`
	Domain     Domain     `json:"domain,omitempty"`
	Event      EventType  `json:"event"`
}

// MarshalJSON implements custom JSON marshaling to ensure stable field ordering
// for the Domain field, which is critical for signature verification.
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
