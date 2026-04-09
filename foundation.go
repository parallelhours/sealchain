// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: BUSL-1.1

package sealchain

type Foundation struct {
	Seq       uint64 `json:"seq"`
	PrevHash  string `json:"prev_hash"`
	ActorDID  string `json:"actor_did"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}
