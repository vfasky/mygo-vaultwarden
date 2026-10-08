// SPDX-License-Identifier: GPL-3.0-only
package main

import "encoding/json"

// Receipt returns a caller-owned copy of the latest successful native receipt.
// BeforeDispatch wrappers may adopt its revision through a thread-safe host
// callback before returning nil. It never calls Session methods or reads UI fields.
// A failed/unknown native call clears the receipt; callers query the same operation
// with a fresh authenticated adapter instead of issuing a mutation again.
func (s *targetRecoveryStorage) Receipt() *snapshotStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active() || s.receipt == nil {
		return nil
	}
	raw, _ := json.Marshal(s.receipt)
	var state snapshotStatus
	if json.Unmarshal(raw, &state) != nil {
		return nil
	}
	return &state
}
