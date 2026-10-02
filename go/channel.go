//go:build cgo

package verifier

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasChannelSession StogasChannelSession;
typedef struct StogasChannelReader StogasChannelReader;
typedef struct StogasChannelWriter StogasChannelWriter;
typedef struct { uint8_t *data; size_t len; } StogasChannelBuffer;
uint32_t stogas_channel_key_generate(uint8_t *, uint8_t *);
uint32_t stogas_channel_session_new(const uint8_t *, const uint8_t *, const uint8_t *, uint16_t, StogasChannelSession **);
uint32_t stogas_channel_accept(StogasChannelSession *, uint64_t, uint8_t *, size_t, uint64_t, StogasChannelReader **, StogasChannelWriter **, size_t *, size_t *);
uint32_t stogas_channel_session_expire(StogasChannelSession *, uint64_t);
uint32_t stogas_channel_open(StogasChannelReader *, uint8_t *, size_t, uint8_t *, size_t *, size_t *);
uint32_t stogas_channel_complete(StogasChannelReader *);
uint32_t stogas_channel_seal(StogasChannelWriter *, uint8_t, const uint8_t *, size_t, StogasChannelBuffer *);
void stogas_channel_buffer_free(StogasChannelBuffer);
void stogas_channel_session_free(StogasChannelSession *);
void stogas_channel_reader_free(StogasChannelReader *);
void stogas_channel_writer_free(StogasChannelWriter *);
*/
import "C"

import (
	"sync"
	"time"
	"unsafe"
)

func channelStatus(status C.uint32_t) error {
	switch status {
	case 0:
		return nil
	case 1:
		return ErrChannelRecord
	case 2:
		return ErrChannelAuthentication
	case 3:
		return ErrChannelLimit
	case 4:
		return ErrClosed
	case 5:
		return ErrChannelTruncated
	case 6:
		return ErrChannelPending
	default:
		return ErrChannelCrypto
	}
}

// GenerateChannelKey creates the initial responder key in Rust. Bind public into
// the authenticated setup and clear private after session creation or failure.
func GenerateChannelKey() (private, public [32]byte, err error) {
	err = channelStatus(C.stogas_channel_key_generate(bytePointer(private[:]), bytePointer(public[:])))
	return
}

// ChannelSession embeds the Rust server admission and hybrid ratchet.
// It performs no I/O. Accepted streams have independent reader/writer owners.
type ChannelSession struct {
	mu      sync.Mutex
	handle  *C.StogasChannelSession
	started time.Time
}

// NewChannelSession consumes a copy of the authenticated setup root. ratchetBytes
// is the setup-authenticated even ML-KEM chunk size from 32 through 1152.
func NewChannelSession(root, id, initialPrivate [32]byte, ratchetBytes uint16) (*ChannelSession, error) {
	defer clear(root[:])
	defer clear(initialPrivate[:])
	var handle *C.StogasChannelSession
	if err := channelStatus(C.stogas_channel_session_new(bytePointer(root[:]), bytePointer(id[:]), bytePointer(initialPrivate[:]), C.uint16_t(ratchetBytes), &handle)); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, ErrChannelCrypto
	}
	return &ChannelSession{handle: handle, started: time.Now()}, nil
}

func (s *ChannelSession) elapsed(now time.Time) C.uint64_t {
	elapsed := now.Sub(s.started).Milliseconds()
	if elapsed < 0 {
		return 0
	}
	return C.uint64_t(elapsed)
}

// AcceptStart authenticates in place before committing the session. The returned
// metadata borrows encoded. Close both owners when the accepted exchange ends.
func (s *ChannelSession) AcceptStart(number uint64, encoded []byte) (*ChannelReader, *ChannelWriter, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil, nil, nil, ErrClosed
	}
	var reader *C.StogasChannelReader
	var writer *C.StogasChannelWriter
	var offset, length C.size_t
	status := C.stogas_channel_accept(s.handle, C.uint64_t(number), bytePointer(encoded), C.size_t(len(encoded)), s.elapsed(time.Now()), &reader, &writer, &offset, &length)
	if status == 255 {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return nil, nil, nil, err
	}
	if reader == nil || writer == nil || uint64(offset) > uint64(len(encoded)) || uint64(length) > uint64(len(encoded))-uint64(offset) {
		C.stogas_channel_reader_free(reader)
		C.stogas_channel_writer_free(writer)
		return nil, nil, nil, ErrChannelCrypto
	}
	return &ChannelReader{handle: reader}, &ChannelWriter{handle: writer}, encoded[int(offset):int(offset+length)], nil
}

// Expire erases old delayed-message keys during the embedding server's sweep.
func (s *ChannelSession) Expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil && C.stogas_channel_session_expire(s.handle, s.elapsed(now)) == 255 {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
}

// Close waits for admission, then erases this session. Admitted streams may finish.
func (s *ChannelSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
}

// ChannelReader owns one admitted upload cipher.
type ChannelReader struct {
	mu     sync.Mutex
	handle *C.StogasChannelReader
}

// Open authenticates in place. Returned plaintext borrows encoded.
func (r *ChannelReader) Open(encoded []byte) (byte, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return 0, nil, ErrClosed
	}
	var kind C.uint8_t
	var offset, length C.size_t
	status := C.stogas_channel_open(r.handle, bytePointer(encoded), C.size_t(len(encoded)), &kind, &offset, &length)
	if status == 255 {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return 0, nil, err
	}
	if uint64(offset) > uint64(len(encoded)) || uint64(length) > uint64(len(encoded))-uint64(offset) {
		return 0, nil, ErrChannelCrypto
	}
	return byte(kind), encoded[int(offset):int(offset+length)], nil
}

// Complete requires authenticated upload completion.
func (r *ChannelReader) Complete() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return ErrClosed
	}
	status := C.stogas_channel_complete(r.handle)
	if status == 255 {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
	return channelStatus(status)
}

func (r *ChannelReader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle != nil {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
}

// ChannelWriter owns one independent response cipher.
type ChannelWriter struct {
	mu     sync.Mutex
	handle *C.StogasChannelWriter
}

func (w *ChannelWriter) Seal(kind byte, plaintext []byte) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle == nil {
		return nil, ErrClosed
	}
	var output C.StogasChannelBuffer
	status := C.stogas_channel_seal(w.handle, C.uint8_t(kind), bytePointer(plaintext), C.size_t(len(plaintext)), &output)
	if status == 255 {
		C.stogas_channel_writer_free(w.handle)
		w.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return nil, err
	}
	defer C.stogas_channel_buffer_free(output)
	if output.data == nil || output.len > 65536 {
		return nil, ErrChannelCrypto
	}
	return C.GoBytes(unsafe.Pointer(output.data), C.int(output.len)), nil
}

func (w *ChannelWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle != nil {
		C.stogas_channel_writer_free(w.handle)
		w.handle = nil
	}
}
