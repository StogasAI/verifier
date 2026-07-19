//go:build cgo

package verifier

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const stagingBundleNowUnixMS int64 = 1_784_414_117_082

func TestRejectsInvalidOptions(t *testing.T) {
	if _, err := NewWithOptions(Options{MaxNodeAge: 25 * time.Hour}); err == nil {
		t.Fatal("expected invalid freshness policy to fail")
	}
}

func TestRejectsMalformedBundle(t *testing.T) {
	verifier, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verifier.Close() })
	if _, err := verifier.VerifyBundleAt([]byte(`{"body":`), 1); err == nil || !strings.Contains(err.Error(), "invalid bundle JSON") {
		t.Fatalf("unexpected verification error: %v", err)
	}
}

func TestVerifiesTheSharedRealStagingBundle(t *testing.T) {
	bundle, err := os.ReadFile("../crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verifier.Close() })
	result, err := verifier.VerifyBundleAt(bundle, stagingBundleNowUnixMS)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Bundle struct {
			Nodes    []json.RawMessage `json:"nodes"`
			Releases []json.RawMessage `json:"releases"`
			Sequence uint64            `json:"sequence"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatal(err)
	}
	if output.Bundle.Sequence != 1927 || len(output.Bundle.Nodes) != 1 || len(output.Bundle.Releases) != 1 {
		t.Fatalf("unexpected verified trust set: %+v", output.Bundle)
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
