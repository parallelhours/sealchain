// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package sealchain

type Foundation struct {
	Seq       uint64 `json:"seq"`
	PrevHash  string `json:"prev_hash"`
	ActorDID  string `json:"actor_did"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`

	// Rotation fields (only populated for genesis/terminus entries)
	LogRole string `json:"log_role,omitempty"` // "genesis" or "terminus"
	LogRef  string `json:"log_ref,omitempty"`   // for genesis: previous log path; for terminus: next log path
}
