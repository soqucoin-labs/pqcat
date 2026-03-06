//go:build connected

package server

// IsServerAvailable returns true for connected (Pro) builds.
func IsServerAvailable() bool {
	return true
}
