//go:build !connected

// Package server provides stubs for the air-gapped edition.
// The actual server implementation only exists in the connected (Pro) build.
package server

import (
	"github.com/soqucoin-labs/pqcat/internal/config"
	"github.com/soqucoin-labs/pqcat/internal/store"
)

// Server is a stub — no server code in air-gapped edition.
type Server struct{}

// New returns nil — server not available in air-gapped edition.
func New(cfg *config.Config, db *store.DB) *Server {
	return nil
}

// Start returns an error — server not available in air-gapped edition.
func (s *Server) Start() error {
	return nil
}

// IsServerAvailable returns false for air-gapped builds.
func IsServerAvailable() bool {
	return false
}
