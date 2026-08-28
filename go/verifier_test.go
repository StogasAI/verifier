//go:build cgo

package verifier

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const stagingBundleNowUnixMS int64 = 1_784_414_117_082

func TestRejectsMalformedBundle(t *testing.T) {
	verifier, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verifier.Close() })
	if _, err := verifier.verifyBundleAt([]byte(`{"body":`), 1); err == nil || !strings.Contains(err.Error(), "invalid bundle JSON") {
		t.Fatalf("unexpected verification error: %v", err)
	}
}

func TestRejectsTheSharedLegacyStagingBundle(t *testing.T) {
	bundle, err := os.ReadFile("../crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verifier.Close() })
	if _, err := verifier.verifyBundleAt(bundle, stagingBundleNowUnixMS); err == nil || !strings.Contains(err.Error(), "launch_policy") {
		t.Fatalf("unexpected verification error: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	verifier, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyBundle(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
