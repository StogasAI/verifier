//go:build !cgo

package verifier

import "errors"

// ErrNativeLibraryUnavailable explains why the verifier requires a supported cgo build.
var ErrNativeLibraryUnavailable = errors.New("stogas verifier requires cgo and a packaged native library")

// ErrClosed is retained across cgo build modes for stable error handling.
var ErrClosed = errors.New("stogas verifier is closed")

// ErrTransportClosed is retained across cgo build modes for stable error handling.
var ErrTransportClosed = errors.New("stogas transport is closed")

// TransportOptions mirrors the cgo SDK surface.
type TransportOptions struct {
	Environment    string
	Security       string
	MaxConnections uint64
	BaseURL        string
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
