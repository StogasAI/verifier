//go:build cgo

package verifier

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasEvidence StogasEvidence;
typedef struct StogasEvidenceSnapshot StogasEvidenceSnapshot;
char *stogas_evidence_new(const uint8_t *configuration, size_t configuration_len, StogasEvidence **output);
void stogas_evidence_free(StogasEvidence *handle);
char *stogas_evidence_refresh(const StogasEvidence *handle, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms, StogasEvidenceSnapshot **output);
void stogas_evidence_snapshot_free(StogasEvidenceSnapshot *handle);
char *stogas_evidence_verify_registration(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *challenge, size_t challenge_len, int64_t now_unix_ms);
char *stogas_evidence_verify_logged_boot(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, int64_t now_unix_ms);
char *stogas_evidence_verify_receipt(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_hash, size_t request_hash_len, const uint8_t *response_hash, size_t response_hash_len, int64_t now_unix_ms);

char *stogas_evidence_verify_archive(const StogasEvidence *handle, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
char *stogas_evidence_verify_boot_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *bundle, size_t bundle_len, int64_t now_unix_ms);
char *stogas_evidence_verify_receipt_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *bundle, size_t bundle_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_hash, size_t request_hash_len, const uint8_t *response_hash, size_t response_hash_len, int64_t now_unix_ms);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Evidence owns verified current evidence and learned revocations. It performs no network I/O.
type Evidence struct {
	mu     sync.Mutex
	handle *C.StogasEvidence
}

// EvidenceSnapshot retains immutable evidence used by a boot or request.
// Close it when its last caller finishes. It may outlive its Evidence owner.
type EvidenceSnapshot struct {
	mu      sync.RWMutex
	handle  *C.StogasEvidenceSnapshot
	summary json.RawMessage
}

// NewEvidence constructs the shared offline verifier from local configuration.
func NewEvidence(options EvidenceOptions) (*Evidence, error) {
	configuration, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	var handle *C.StogasEvidence
	response := C.stogas_evidence_new(bytePointer(configuration), C.size_t(len(configuration)), &handle)
	if err := decodeResponse(response, nil); err != nil {
		if handle != nil {
			C.stogas_evidence_free(handle)
		}
		return nil, err
	}
	if handle == nil {
		return nil, errors.New("native verifier returned no evidence handle")
	}
	return &Evidence{handle: handle}, nil
}

// Refresh verifies one complete bundle at the captured wall clock.
// Invalid delivery preserves prior evidence; authenticated revocations remain learned.
func (e *Evidence) Refresh(bundle []byte) (*EvidenceSnapshot, error) {
	return e.refreshAt(bundle, time.Now().UnixMilli())
}

// RefreshAt verifies with a caller-owned clock, for offline appraisal. Never
// substitute a timestamp supplied by the peer for the verifier's trusted time.
func (e *Evidence) RefreshAt(bundle []byte, now time.Time) (*EvidenceSnapshot, error) {
	return e.refreshAt(bundle, now.UnixMilli())
}

func (e *Evidence) refreshAt(bundle []byte, now int64) (*EvidenceSnapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return nil, ErrClosed
	}
	var handle *C.StogasEvidenceSnapshot
	response := C.stogas_evidence_refresh(e.handle, bytePointer(bundle), C.size_t(len(bundle)), C.int64_t(now), &handle)
	var summary json.RawMessage
	if err := decodeResponse(response, &summary); err != nil {
		if handle != nil {
			C.stogas_evidence_snapshot_free(handle)
		}
		return nil, err
	}
	if handle == nil {
		return nil, errors.New("native verifier returned no evidence snapshot")
	}
	return &EvidenceSnapshot{handle: handle, summary: summary}, nil
}

// Close waits for current verification and frees this owner. Existing snapshots remain valid.
func (e *Evidence) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle != nil {
		C.stogas_evidence_free(e.handle)
		e.handle = nil
	}
	return nil
}

// VerifyEvidenceArchive authenticates archived approvals without changing current trust.
func (e *Evidence) VerifyEvidenceArchive(bundle []byte) (json.RawMessage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return nil, ErrClosed
	}
	var summary json.RawMessage
	response := C.stogas_evidence_verify_archive(e.handle, bytePointer(bundle), C.size_t(len(bundle)), C.int64_t(time.Now().UnixMilli()))
	err := decodeResponse(response, &summary)
	return summary, err
}

// VerifyBootArchive appraises the boot at its authenticated log time.
// It grants no current serving permission and changes no live verification state.
func (e *Evidence) VerifyBootArchive(archive, bundle []byte) (BootIdentity, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var identity BootIdentity
	if e.handle == nil {
		return identity, ErrClosed
	}
	response := C.stogas_evidence_verify_boot_archive(e.handle,
		bytePointer(archive), C.size_t(len(archive)), bytePointer(bundle), C.size_t(len(bundle)),
		C.int64_t(time.Now().UnixMilli()))
	err := decodeResponse(response, &identity)
	return identity, err
}

// VerifyReceiptArchive verifies exact content using the archived boot at its log time.
// This does not establish when inference occurred or grant current serving permission.
func (e *Evidence) VerifyReceiptArchive(archive, bundle, receipt []byte, requestHash, responseHash [32]byte) (VerifiedReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var verified VerifiedReceipt
	if e.handle == nil {
		return verified, ErrClosed
	}
	response := C.stogas_evidence_verify_receipt_archive(e.handle,
		bytePointer(archive), C.size_t(len(archive)), bytePointer(bundle), C.size_t(len(bundle)),
		bytePointer(receipt), C.size_t(len(receipt)), bytePointer(requestHash[:]), 32, bytePointer(responseHash[:]), 32,
		C.int64_t(time.Now().UnixMilli()))
	err := decodeResponse(response, &verified)
	return verified, err
}

// Summary returns a copy of the authenticated release, catalog and policy summary.
// A summary is configuration, not proof of a live peer's identity.
func (s *EvidenceSnapshot) Summary() (json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.handle == nil {
		return nil, ErrClosed
	}
	return append(json.RawMessage(nil), s.summary...), nil
}

// VerifyRegistration checks hardware and the caller's one-use registration challenge.
// The authority must still atomically consume its challenge before secret release.
func (s *EvidenceSnapshot) VerifyRegistration(document []byte, challenge [32]byte) (BootIdentity, error) {
	return s.registrationAt(document, challenge, time.Now().UnixMilli())
}

// VerifyRegistrationAt uses the registration authority's captured clock.
func (s *EvidenceSnapshot) VerifyRegistrationAt(document []byte, challenge [32]byte, now time.Time) (BootIdentity, error) {
	return s.registrationAt(document, challenge, now.UnixMilli())
}

func (s *EvidenceSnapshot) registrationAt(document []byte, challenge [32]byte, now int64) (BootIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var identity BootIdentity
	if s.handle == nil {
		return identity, ErrClosed
	}
	response := C.stogas_evidence_verify_registration(s.handle, bytePointer(document), C.size_t(len(document)), bytePointer(challenge[:]), 32, C.int64_t(now))
	err := decodeResponse(response, &identity)
	return identity, err
}

// VerifyLoggedBoot checks exact logged boot bytes against current hardware and release approvals.
func (s *EvidenceSnapshot) VerifyLoggedBoot(document, inclusion []byte) (BootIdentity, error) {
	return s.loggedBootAt(document, inclusion, time.Now().UnixMilli())
}

// VerifyLoggedBootAt appraises a boot at a caller-owned verification time.
func (s *EvidenceSnapshot) VerifyLoggedBootAt(document, inclusion []byte, now time.Time) (BootIdentity, error) {
	return s.loggedBootAt(document, inclusion, now.UnixMilli())
}

func (s *EvidenceSnapshot) loggedBootAt(document, inclusion []byte, now int64) (BootIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var identity BootIdentity
	if s.handle == nil {
		return identity, ErrClosed
	}
	response := C.stogas_evidence_verify_logged_boot(s.handle, bytePointer(document), C.size_t(len(document)), bytePointer(inclusion), C.size_t(len(inclusion)), C.int64_t(now))
	err := decodeResponse(response, &identity)
	return identity, err
}

// VerifyReceipt authenticates the complete final stogas JSON bag against locally computed
// hashes and the logged boot. Its single signature covers content and canonical metadata.
func (s *EvidenceSnapshot) VerifyReceipt(document, inclusion, receipt []byte, requestHash, responseHash [32]byte) (VerifiedReceipt, error) {
	return s.VerifyReceiptAt(document, inclusion, receipt, requestHash, responseHash, time.Now())
}

// VerifyReceiptAt appraises the boot at a caller-owned clock. It does not establish
// when inference occurred; never substitute a timestamp supplied by the peer.
func (s *EvidenceSnapshot) VerifyReceiptAt(document, inclusion, receipt []byte, requestHash, responseHash [32]byte, now time.Time) (VerifiedReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var verified VerifiedReceipt
	if s.handle == nil {
		return verified, ErrClosed
	}
	response := C.stogas_evidence_verify_receipt(s.handle,
		bytePointer(document), C.size_t(len(document)), bytePointer(inclusion), C.size_t(len(inclusion)),
		bytePointer(receipt), C.size_t(len(receipt)), bytePointer(requestHash[:]), 32, bytePointer(responseHash[:]), 32,
		C.int64_t(now.UnixMilli()))
	err := decodeResponse(response, &verified)
	return verified, err
}

// Close waits for readers and releases the snapshot exactly once.
func (s *EvidenceSnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		C.stogas_evidence_snapshot_free(s.handle)
		s.handle = nil
		s.summary = nil
	}
	return nil
}
