//go:build cgo

// Package verifier provides the Stogas SDK through the packaged native Rust library bundled with
// each tagged Go module release.
package verifier

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/native/linux-amd64 -Wl,-Bstatic -lstogas_verifier_ffi -Wl,-Bdynamic -ldl -lpthread -lm
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/native/linux-arm64 -Wl,-Bstatic -lstogas_verifier_ffi -Wl,-Bdynamic -ldl -lpthread -lm
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/native/darwin-amd64 -lstogas_verifier_ffi -framework Security -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/native/darwin-arm64 -lstogas_verifier_ffi -framework Security -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/native/windows-amd64 -lstogas_verifier_ffi -lws2_32 -lbcrypt -luserenv -lntdll
#include <stddef.h>
#include <stdint.h>
typedef struct StogasVerifier StogasVerifier;
typedef struct StogasTransport StogasTransport;
StogasVerifier *stogas_verifier_new(void);
void stogas_verifier_free(StogasVerifier *verifier);
char *stogas_verifier_verify_bundle(const StogasVerifier *verifier, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
char *stogas_verifier_verify_response_proof(const StogasVerifier *verifier, const uint8_t *proof, size_t proof_len, const uint8_t *request_body, size_t request_body_len, const uint8_t *response_body, size_t response_body_len, const uint8_t *e2ee_transcript_sha256, size_t e2ee_transcript_sha256_len, int64_t now_unix_ms);
char *stogas_verifier_verify_historical_response_proof(const StogasVerifier *verifier, const uint8_t *proof, size_t proof_len, const uint8_t *request_body, size_t request_body_len, const uint8_t *response_body, size_t response_body_len, const uint8_t *ledger, size_t ledger_len, const uint8_t *e2ee_transcript_sha256, size_t e2ee_transcript_sha256_len, int64_t now_unix_ms);
void stogas_verifier_string_free(char *value);
char *stogas_transport_start(const uint8_t *configuration, size_t configuration_len, StogasTransport **transport_out);
char *stogas_transport_refresh(const StogasTransport *transport);
void stogas_transport_free(StogasTransport *transport);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// ErrClosed is returned after a verifier session has been closed.
var ErrClosed = errors.New("stogas verifier is closed")

// ErrTransportClosed is returned after a managed transport has been closed.
var ErrTransportClosed = errors.New("stogas transport is closed")

// TransportOptions controls one in-process managed Stogas connection.
type TransportOptions struct {
	Security                     string `json:"security,omitempty"`
	BundleRefreshIntervalSeconds uint16 `json:"bundle_refresh_interval_seconds,omitempty"`
	BaseURL                      string `json:"base_url,omitempty"`
	BundleURL                    string `json:"bundle_url,omitempty"`
}

// Transport owns bundle refresh, attested TLS, E2EE, and streaming in the native Rust core.
type Transport struct {
	mu      sync.Mutex
	handle  *C.StogasTransport
	baseURL string
}

// NewTransport starts a managed transport and verifies the initial bundle before returning.
func NewTransport(options TransportOptions) (*Transport, error) {
	if options.Security == "" {
		options.Security = "tls"
	}
	if options.BundleRefreshIntervalSeconds == 0 {
		options.BundleRefreshIntervalSeconds = 60
	}
	configuration, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("encode Stogas transport options: %w", err)
	}
	var handle *C.StogasTransport
	response := C.stogas_transport_start(
		bytePointer(configuration),
		C.size_t(len(configuration)),
		&handle,
	)
	var started struct {
		BaseURL string `json:"base_url"`
	}
	if err := decodeResponse(response, &started); err != nil {
		if handle != nil {
			C.stogas_transport_free(handle)
		}
		return nil, err
	}
	if handle == nil || started.BaseURL == "" {
		if handle != nil {
			C.stogas_transport_free(handle)
		}
		return nil, errors.New("native transport returned an incomplete result")
	}
	return &Transport{handle: handle, baseURL: started.BaseURL}, nil
}

// BaseURL returns the capability-protected loopback URL for an OpenAI-compatible client.
func (transport *Transport) BaseURL() (string, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.handle == nil {
		return "", ErrTransportClosed
	}
	return transport.baseURL, nil
}

// RefreshBundle fetches and atomically activates a newer bundle now.
func (transport *Transport) RefreshBundle() (bool, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.handle == nil {
		return false, ErrTransportClosed
	}
	response := C.stogas_transport_refresh(transport.handle)
	var changed bool
	if err := decodeResponse(response, &changed); err != nil {
		return false, err
	}
	return changed, nil
}

// Close stops the managed transport. It is safe to call more than once.
func (transport *Transport) Close() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.handle != nil {
		C.stogas_transport_free(transport.handle)
		transport.handle = nil
		transport.baseURL = ""
	}
	return nil
}

// Verifier caches already-verified immutable release evidence in memory.
type Verifier struct {
	mu     sync.Mutex
	handle *C.StogasVerifier
}

// New constructs a verifier with the Stogas freshness policy.
func New() (*Verifier, error) {
	handle := C.stogas_verifier_new()
	if handle == nil {
		return nil, errors.New("native verifier allocation failed")
	}
	return &Verifier{handle: handle}, nil
}

// VerifyBundle verifies using one captured platform wall-clock value.
func (verifier *Verifier) VerifyBundle(bundle []byte) (json.RawMessage, error) {
	return verifier.verifyBundleAt(bundle, time.Now().UnixMilli())
}

func (verifier *Verifier) verifyBundleAt(bundle []byte, nowUnixMS int64) (json.RawMessage, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.handle == nil {
		return nil, ErrClosed
	}
	response := C.stogas_verifier_verify_bundle(
		verifier.handle,
		bytePointer(bundle),
		C.size_t(len(bundle)),
		C.int64_t(nowUnixMS),
	)
	var output json.RawMessage
	if err := decodeResponse(response, &output); err != nil {
		return nil, err
	}
	return output, nil
}

// VerifyResponseProof verifies exact request and response bytes against the active bundle.
// Pass an empty E2EE transcript hash for an ordinary TLS exchange.
func (verifier *Verifier) VerifyResponseProof(
	proof []byte,
	requestBody []byte,
	responseBody []byte,
	e2eeTranscriptSHA256 string,
) (json.RawMessage, error) {
	return verifier.verifyResponseProofAt(
		proof,
		requestBody,
		responseBody,
		e2eeTranscriptSHA256,
		time.Now().UnixMilli(),
	)
}

func (verifier *Verifier) verifyResponseProofAt(
	proof []byte,
	requestBody []byte,
	responseBody []byte,
	e2eeTranscriptSHA256 string,
	nowUnixMS int64,
) (json.RawMessage, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.handle == nil {
		return nil, ErrClosed
	}
	transcript := []byte(e2eeTranscriptSHA256)
	response := C.stogas_verifier_verify_response_proof(
		verifier.handle,
		bytePointer(proof),
		C.size_t(len(proof)),
		bytePointer(requestBody),
		C.size_t(len(requestBody)),
		bytePointer(responseBody),
		C.size_t(len(responseBody)),
		bytePointer(transcript),
		C.size_t(len(transcript)),
		C.int64_t(nowUnixMS),
	)
	var output json.RawMessage
	if err := decodeResponse(response, &output); err != nil {
		return nil, err
	}
	return output, nil
}

// VerifyHistoricalResponseProof verifies a receipt and its immutable node ledger together.
// Pass an empty E2EE transcript hash for an ordinary TLS exchange.
func (verifier *Verifier) VerifyHistoricalResponseProof(
	proof []byte,
	requestBody []byte,
	responseBody []byte,
	ledger []byte,
	e2eeTranscriptSHA256 string,
) (json.RawMessage, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.handle == nil {
		return nil, ErrClosed
	}
	transcript := []byte(e2eeTranscriptSHA256)
	response := C.stogas_verifier_verify_historical_response_proof(
		verifier.handle,
		bytePointer(proof),
		C.size_t(len(proof)),
		bytePointer(requestBody),
		C.size_t(len(requestBody)),
		bytePointer(responseBody),
		C.size_t(len(responseBody)),
		bytePointer(ledger),
		C.size_t(len(ledger)),
		bytePointer(transcript),
		C.size_t(len(transcript)),
		C.int64_t(time.Now().UnixMilli()),
	)
	var output json.RawMessage
	if err := decodeResponse(response, &output); err != nil {
		return nil, err
	}
	return output, nil
}

// Close releases the native verifier. It is safe to call more than once.
func (verifier *Verifier) Close() error {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.handle != nil {
		C.stogas_verifier_free(verifier.handle)
		verifier.handle = nil
	}
	return nil
}

// VerifyBundle performs one stateless verification with the default policy.
func VerifyBundle(bundle []byte) (json.RawMessage, error) {
	verifier, err := New()
	if err != nil {
		return nil, err
	}
	defer verifier.Close()
	return verifier.VerifyBundle(bundle)
}

type abiResponse struct {
	OK    bool            `json:"ok"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
}

func decodeResponse(response *C.char, output any) error {
	if response == nil {
		return errors.New("native verifier returned no response")
	}
	defer C.stogas_verifier_string_free(response)
	var envelope abiResponse
	if err := json.Unmarshal([]byte(C.GoString(response)), &envelope); err != nil {
		return fmt.Errorf("invalid native verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error == "" {
			envelope.Error = "native verifier rejected the operation"
		}
		return errors.New(envelope.Error)
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Value, output); err != nil {
		return fmt.Errorf("invalid native verifier value: %w", err)
	}
	return nil
}

func bytePointer(value []byte) *C.uint8_t {
	if len(value) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&value[0]))
}
