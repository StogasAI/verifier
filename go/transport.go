//go:build cgo && !stogas_offline

package verifier

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasTransport StogasTransport;
char *stogas_transport_start(const uint8_t *configuration, size_t configuration_len, StogasTransport **transport_out);
char *stogas_transport_refresh(const StogasTransport *transport);
void stogas_transport_free(StogasTransport *transport);
void stogas_transport_close(const StogasTransport *transport);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ErrTransportClosed is returned after a managed transport has been closed.
var ErrTransportClosed = errors.New("stogas transport is closed")

// TransportOptions controls one in-process managed Stogas connection.
type TransportOptions struct {
	Environment    string `json:"environment,omitempty"`
	Security       string `json:"security,omitempty"`
	MaxConnections uint64 `json:"max_connections,omitempty"`
	BaseURL        string `json:"base_url,omitempty"`
}

// Transport owns evidence recovery, attested TLS, E2EE, and streaming in the native Rust core.
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
		C.stogas_transport_close(transport.handle)
		C.stogas_transport_free(transport.handle)
		transport.handle = nil
		transport.baseURL = ""
	}
	return nil
}
