//go:build cgo

// Package verifier provides the Stogas bundle verifier through the packaged native Rust
// library bundled with each tagged Go module release.
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
StogasVerifier *stogas_verifier_new(void);
void stogas_verifier_free(StogasVerifier *verifier);
char *stogas_verifier_verify_bundle(const StogasVerifier *verifier, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
void stogas_verifier_string_free(char *value);
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
