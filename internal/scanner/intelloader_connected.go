//go:build connected
// +build connected

// Package scanner provides live threat intelligence feed for connected environments.
// This file is only compiled with: go build -tags connected
// Air-gapped builds exclude this file entirely — no network code in the binary.
package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// DefaultIntelFeedURL is the Soqucoin Labs hosted feed endpoint.
	DefaultIntelFeedURL = "https://intel.pqcat.io/v1/latest"

	// IntelFeedTimeout is the HTTP timeout for feed fetches.
	IntelFeedTimeout = 10 * time.Second
)

// FetchLiveIntel retrieves threat intelligence from the configured feed URL.
// Only available in the connected edition (build tag: connected).
// Returns nil if the fetch fails — caller should fall back to embedded/sidecar.
func FetchLiveIntel(feedURL string) *IntelResult {
	if feedURL == "" {
		feedURL = DefaultIntelFeedURL
	}

	client := &http.Client{Timeout: IntelFeedTimeout}

	fmt.Fprintf(os.Stderr, "[intel] Fetching live feed from %s...\n", feedURL)

	resp, err := client.Get(feedURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[intel] Live feed unavailable: %v (falling back to local)\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[intel] Live feed returned %d (falling back to local)\n", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[intel] Failed to read feed response: %v\n", err)
		return nil
	}

	var intel ThreatIntel
	if err := json.Unmarshal(body, &intel); err != nil {
		fmt.Fprintf(os.Stderr, "[intel] Invalid feed data: %v\n", err)
		return nil
	}

	return &IntelResult{
		Intel:  &intel,
		Source: IntelSourceLive,
		URL:    feedURL,
		Age:    intelAge(intel.LastUpdated),
	}
}

// IsConnectedEdition returns true in the connected build.
func IsConnectedEdition() bool {
	return true
}
