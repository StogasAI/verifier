//go:build !cgo

package verifier

import "time"

// ChannelSession requires the packaged Rust implementation and cgo.
type ChannelSession struct{}
type ChannelReader struct{}
type ChannelWriter struct{}

func GenerateChannelKey() (private, public [32]byte, err error) {
	return private, public, ErrNativeLibraryUnavailable
}
func NewChannelSession(root, id, initialPrivate [32]byte, ratchetBytes uint16) (*ChannelSession, error) {
	clear(root[:])
	clear(initialPrivate[:])
	return nil, ErrNativeLibraryUnavailable
}
func (*ChannelSession) AcceptStart(uint64, []byte) (*ChannelReader, *ChannelWriter, []byte, error) {
	return nil, nil, nil, ErrNativeLibraryUnavailable
}
func (*ChannelSession) Expire(time.Time)                 {}
func (*ChannelSession) Close()                           {}
func (*ChannelReader) Open([]byte) (byte, []byte, error) { return 0, nil, ErrNativeLibraryUnavailable }
func (*ChannelReader) Complete() error                   { return ErrNativeLibraryUnavailable }
func (*ChannelReader) Close()                            {}
func (*ChannelWriter) Seal(byte, []byte) ([]byte, error) { return nil, ErrNativeLibraryUnavailable }
func (*ChannelWriter) Close()                            {}
