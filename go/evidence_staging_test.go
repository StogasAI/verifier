//go:build cgo && staging

package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestEvidenceSnapshotsRetainOwnershipAcrossRefreshAndClose(t *testing.T) {
	bytes, err := os.ReadFile("../tests/fixtures/current-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root   TrustRoot       `json:"root"`
		Bundle json.RawMessage `json:"bundle"`
		Now    int64           `json:"verified_at_ms"`
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	owner, err := NewEvidence(EvidenceOptions{Environment: "staging", Root: &fixture.Root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	snapshot, err := owner.refreshAt(fixture.Bundle, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	summary, err := snapshot.Summary()
	if err != nil || len(summary) == 0 {
		t.Fatalf("missing summary: %v", err)
	}
	summary[0] = '!'
	copy, err := snapshot.Summary()
	if err != nil || !json.Valid(copy) {
		t.Fatalf("caller mutated authenticated summary: %v", err)
	}
	if rejected, err := owner.refreshAt([]byte("{}"), fixture.Now); err == nil || rejected != nil {
		t.Fatalf("invalid candidate accepted: %v", err)
	}
	_ = owner.Close()
	_, err = owner.Refresh(fixture.Bundle)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("closed verifier: %v", err)
	}
	if _, err := snapshot.Summary(); err != nil {
		t.Fatal(err)
	}
	var failure *VerificationError
	_, err = snapshot.registrationAt([]byte("{}"), [32]byte{}, fixture.Now)
	if !errors.As(err, &failure) || failure.Code != "invalid_attestation" {
		t.Fatalf("registration error lost reason: %v", err)
	}
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			_, err := snapshot.Summary()
			if err != nil && !errors.Is(err, ErrClosed) {
				t.Error(err)
			}
		})
	}
	group.Go(func() { _ = snapshot.Close() })
	group.Wait()
	if _, err := snapshot.Summary(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed snapshot: %v", err)
	}
}

func TestOfflineReceiptUsesLoggedHardwareKeyAndExactContentHashes(t *testing.T) {
	data, err := os.ReadFile("../tests/fixtures/hardware-session-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root        TrustRoot       `json:"root"`
		Bundle      json.RawMessage `json:"bundle"`
		Certificate string          `json:"certificate"`
		Now         int64           `json:"verified_at_ms"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	owner, err := NewEvidence(EvidenceOptions{Environment: "staging", Root: &fixture.Root})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	snapshot, err := owner.RefreshAt(fixture.Bundle, time.UnixMilli(fixture.Now))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	boot, inclusion := fixtureBoot(t, fixture.Certificate)
	vectorBytes, err := os.ReadFile("../tests/fixtures/content-receipt-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Request  string            `json:"request"`
		Response string            `json:"response"`
		Metadata map[string]any    `json:"metadata"`
		Receipt  map[string]string `json:"hardware_receipt"`
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	request := sha256.Sum256([]byte(vector.Request))
	response := sha256.Sum256([]byte(vector.Response))
	receipt := vector.Receipt
	vector.Metadata["receipt"] = receipt
	encoded, err := json.Marshal(vector.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(fixture.Now)
	verified, err := snapshot.VerifyReceiptAt(boot, inclusion, encoded, request, response, now)
	if err != nil || verified.BootSHA256 != receipt["boot_sha256"] || verified.RequestSHA256 != receipt["request_sha256"] || verified.ResponseSHA256 != receipt["response_sha256"] || verified.NodeID == "" {
		t.Fatalf("valid content receipt rejected: %+v %v", verified, err)
	}
	var envelope struct {
		Digest string `json:"body_sha256"`
	}
	if err := json.Unmarshal(fixture.Bundle, &envelope); err != nil {
		t.Fatal(err)
	}
	archive, err := json.Marshal(map[string]any{
		"boot": json.RawMessage(boot), "inclusion": json.RawMessage(inclusion),
		"evidence_sha256": envelope.Digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := owner.VerifyEvidenceArchive(fixture.Bundle); err != nil || !json.Valid(summary) {
		t.Fatalf("archive approval verification: %s %v", summary, err)
	}
	if identity, err := owner.VerifyBootArchive(archive, fixture.Bundle); err != nil || identity.NodeID != verified.NodeID {
		t.Fatalf("archive boot verification: %+v %v", identity, err)
	}
	if historical, err := owner.VerifyReceiptArchive(archive, fixture.Bundle, encoded, request, response); err != nil || historical != verified {
		t.Fatalf("archive receipt verification: %+v %v", historical, err)
	}
	if _, err := owner.VerifyReceiptArchive(archive, fixture.Bundle, encoded, response, response); err == nil {
		t.Fatal("archive accepted substituted content")
	}
	for _, change := range []struct {
		name               string
		receipt, inclusion []byte
		request            [32]byte
		now                time.Time
		code               string
	}{
		{"content", encoded, inclusion, response, now, "invalid_receipt"},
		{"unknown field", append([]byte(`{"durability":true,`), encoded[1:]...), inclusion, request, now, "invalid_receipt"},
		{"duplicate field", append([]byte(`{"receipt":{},`), encoded[1:]...), inclusion, request, now, "invalid_receipt"},
		{"missing inclusion", encoded, nil, request, now, ""},
		{"expired collateral", encoded, inclusion, request, now.AddDate(30, 0, 0), "expired_collateral"},
	} {
		t.Run(change.name, func(t *testing.T) {
			_, err := snapshot.VerifyReceiptAt(boot, change.inclusion, change.receipt, change.request, response, change.now)
			var failure *VerificationError
			if !errors.As(err, &failure) || (change.code != "" && failure.Code != change.code) {
				t.Fatalf("failure lost its reason: %v", err)
			}
		})
	}
	for _, field := range []string{"signature", "boot_sha256"} {
		original := receipt[field]
		receipt[field] = "invalid"
		changed, _ := json.Marshal(vector.Metadata)
		if _, err := snapshot.VerifyReceiptAt(boot, inclusion, changed, request, response, now); err == nil {
			t.Fatalf("accepted changed %s", field)
		}
		receipt[field] = original
	}
	_ = snapshot.Close()
	if _, err := snapshot.VerifyReceiptAt(boot, inclusion, encoded, request, response, now); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed snapshot: %v", err)
	}
	_ = owner.Close()
	if _, err := owner.VerifyEvidenceArchive(fixture.Bundle); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed archive verifier: %v", err)
	}
	if _, err := owner.VerifyBootArchive(archive, fixture.Bundle); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed boot verifier: %v", err)
	}
	if _, err := owner.VerifyReceiptArchive(archive, fixture.Bundle, encoded, request, response); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed receipt verifier: %v", err)
	}
}

// Extract the boot bytes from the shared, fixed hardware certificate fixture.
// Trust comes only from the Rust ABI under test, never from this fixture reader.
func fixtureBoot(t *testing.T, encoded string) ([]byte, []byte) {
	t.Helper()
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.String() != "1.3.6.1.5.5.7.1.35" {
			continue
		}
		payload := extension.Value[4+3+len("application/vnd.stogas.native-tls.v1")+3:]
		payload = payload[1184:]
		payload = payload[2+int(binary.BigEndian.Uint16(payload)):]
		var fields [][]byte
		for range 2 {
			size := int(binary.BigEndian.Uint32(payload))
			payload = payload[4:]
			fields = append(fields, payload[:size])
			payload = payload[size:]
		}
		if len(payload) != 0 {
			t.Fatal("unexpected fixture framing")
		}
		return fields[0], fields[1]
	}
	t.Fatal("hardware fixture has no session evidence")
	return nil, nil
}
