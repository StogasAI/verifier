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

// ErrTransportClosed is retained across cgo build modes for stable error handling.
var ErrTransportClosed = errors.New("stogas transport is closed")

// TransportOptions mirrors the cgo SDK surface.
type TransportOptions struct {
	Security                     string
	BundleRefreshIntervalSeconds uint64
	BaseURL                      string
	BundleURL                    string
	HardwarePolicy               json.RawMessage
}

// Transport is unavailable without cgo.
type Transport struct{}

// NewTransport reports that the packaged native SDK is unavailable.
func NewTransport(TransportOptions) (*Transport, error) {
	return nil, ErrNativeLibraryUnavailable
}

// BaseURL reports that the packaged native SDK is unavailable.
func (*Transport) BaseURL() (string, error) {
	return "", ErrNativeLibraryUnavailable
}

// RefreshBundle reports that the packaged native SDK is unavailable.
func (*Transport) RefreshBundle() (bool, error) {
	return false, ErrNativeLibraryUnavailable
}

// Close is a no-op for an unavailable transport.
func (*Transport) Close() error { return nil }

// Verifier is unavailable without cgo.
type Verifier struct{}

// New reports that the packaged native verifier is unavailable.
func New() (*Verifier, error) { return nil, ErrNativeLibraryUnavailable }

// VerifyBundle reports that the packaged native verifier is unavailable.
func (*Verifier) VerifyBundle([]byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// VerifyBundleWithPolicy reports that the packaged native verifier is unavailable.
func (*Verifier) VerifyBundleWithPolicy([]byte, []byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// VerifyResponseProof reports that the packaged native verifier is unavailable.
func (*Verifier) VerifyResponseProof([]byte, []byte, []byte, string) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// VerifyHistoricalResponseProof reports that the packaged native verifier is unavailable.
func (*Verifier) VerifyHistoricalResponseProof([]byte, []byte, []byte, []byte, []byte, string) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// Close is a no-op for an unavailable verifier.
func (*Verifier) Close() error { return nil }

// VerifyBundle reports that the packaged native verifier is unavailable.
func VerifyBundle([]byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}

// VerifyBundleWithPolicy reports that the packaged native verifier is unavailable.
func VerifyBundleWithPolicy([]byte, []byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}
