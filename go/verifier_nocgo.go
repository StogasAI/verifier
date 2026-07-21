//go:build !cgo

package verifier

import (
	"encoding/json"
	"errors"
)

// ErrNativeLibraryUnavailable explains why the verifier requires a supported cgo build.
var ErrNativeLibraryUnavailable = errors.New("stogas verifier requires cgo and a packaged native library")

// ErrClosed is retained across cgo build modes for stable error handling.
var ErrClosed = errors.New("stogas verifier is closed")

// Verifier is unavailable without cgo.
type Verifier struct{}

// New reports that the packaged native verifier is unavailable.
func New() (*Verifier, error) { return nil, ErrNativeLibraryUnavailable }

// VerifyBundle reports that the packaged native verifier is unavailable.
func (*Verifier) VerifyBundle([]byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// Close is a no-op for an unavailable verifier.
func (*Verifier) Close() error { return nil }

// VerifyBundle reports that the packaged native verifier is unavailable.
func VerifyBundle([]byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}
