//go:build !cgo

package verifier

import (
	"encoding/json"
	"time"
)

// Evidence requires the native offline verification core.
type Evidence struct{}

// EvidenceSnapshot requires the native offline verification core.
type EvidenceSnapshot struct{}

func NewEvidence(EvidenceOptions) (*Evidence, error)        { return nil, ErrNativeLibraryUnavailable }
func (*Evidence) Refresh([]byte) (*EvidenceSnapshot, error) { return nil, ErrNativeLibraryUnavailable }
func (*Evidence) RefreshAt([]byte, time.Time) (*EvidenceSnapshot, error) {
	return nil, ErrNativeLibraryUnavailable
}
func (*Evidence) VerifyEvidenceArchive([]byte) (json.RawMessage, error) {
	return nil, ErrNativeLibraryUnavailable
}
func (*Evidence) VerifyBootArchive([]byte, []byte) (BootIdentity, error) {
	return BootIdentity{}, ErrNativeLibraryUnavailable
}
func (*Evidence) VerifyReceiptArchive([]byte, []byte, []byte, [32]byte, [32]byte) (VerifiedReceipt, error) {
	return VerifiedReceipt{}, ErrNativeLibraryUnavailable
}
func (*Evidence) Close() error                              { return nil }
func (*EvidenceSnapshot) Summary() (json.RawMessage, error) { return nil, ErrNativeLibraryUnavailable }
func (*EvidenceSnapshot) VerifyRegistration([]byte, [32]byte) (BootIdentity, error) {
	return BootIdentity{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) VerifyLoggedBoot([]byte, []byte) (BootIdentity, error) {
	return BootIdentity{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) VerifyRegistrationAt([]byte, [32]byte, time.Time) (BootIdentity, error) {
	return BootIdentity{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) VerifyLoggedBootAt([]byte, []byte, time.Time) (BootIdentity, error) {
	return BootIdentity{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) VerifyReceipt([]byte, []byte, []byte, [32]byte, [32]byte) (VerifiedReceipt, error) {
	return VerifiedReceipt{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) VerifyReceiptAt([]byte, []byte, []byte, [32]byte, [32]byte, time.Time) (VerifiedReceipt, error) {
	return VerifiedReceipt{}, ErrNativeLibraryUnavailable
}
func (*EvidenceSnapshot) Close() error { return nil }
