//go:build cgo

package verifier

import (
	"errors"
	"testing"
)

func TestEvidenceConfigurationFailsClosed(t *testing.T) {
	for _, options := range []EvidenceOptions{
		{Environment: "unknown"},
		{Environment: "prod", Root: &TrustRoot{KeyID: "invalid", PublicKey: "invalid"}},
	} {
		owner, err := NewEvidence(options)
		if owner != nil || err == nil {
			t.Fatalf("unexpected evidence construction: %v, %v", owner, err)
		}
		var failure *VerificationError
		if !errors.As(err, &failure) || failure.Code == "" {
			t.Fatalf("missing structured reason: %v", err)
		}
	}
}
