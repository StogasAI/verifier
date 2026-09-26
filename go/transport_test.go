//go:build cgo && !stogas_offline

package verifier

import "testing"

func TestTransportRejectsInvalidConfigurationBeforeEvidenceAcquisition(t *testing.T) {
	for _, options := range []TransportOptions{
		{Security: "both"},
		{Environment: "unknown"},
		{BaseURL: "http://api.example"},
		{BaseURL: "https://api.example/v1"},
		{BaseURL: "https://key:secret@api.example"},
	} {
		t.Run(options.Security+options.Environment+options.BaseURL, func(t *testing.T) {
			transport, err := NewTransport(options)
			if transport != nil {
				_ = transport.Close()
				t.Fatal("invalid configuration created a transport")
			}
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}
