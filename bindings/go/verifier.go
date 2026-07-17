// Package verifier provides the Go adapter for the offline Stogas verifier.
//
// Signed target-specific Rust libraries are added by the release workflow. Security policy is not
// reimplemented in Go.
package verifier

import "errors"

// ErrNativeLibraryUnavailable is returned by source checkouts without a release library.
var ErrNativeLibraryUnavailable = errors.New("stogas verifier native library is unavailable for this target")

// VerifyBundle verifies a bundle using one captured wall-clock value.
func VerifyBundle(_ []byte) ([]byte, error) {
	return nil, ErrNativeLibraryUnavailable
}
