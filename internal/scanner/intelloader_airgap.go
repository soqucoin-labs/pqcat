//go:build !connected
// +build !connected

// Package scanner provides the air-gapped edition stubs.
// This file is compiled by default (when -tags connected is NOT set).
// It provides no-op implementations of connected-edition functions.
package scanner

// FetchLiveIntel is a no-op in the air-gapped edition.
// Returns nil — caller falls back to sidecar or embedded intel.
func FetchLiveIntel(feedURL string) *IntelResult {
	return nil // Live feeds not available in air-gapped edition
}

// IsConnectedEdition returns false in the air-gapped build.
func IsConnectedEdition() bool {
	return false
}
