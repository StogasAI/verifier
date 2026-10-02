//go:build cgo

package verifier

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type channelVectorRecord struct {
	Kind      byte   `json:"kind"`
	Plaintext string `json:"plaintext_hex"`
	Encoded   string `json:"encoded_hex"`
}

type channelFixture struct {
	Root      string                `json:"root_hex"`
	ID        string                `json:"session_id_hex"`
	Initial   string                `json:"initial_private_hex"`
	Alice     string                `json:"alice_private_hex"`
	Classical string                `json:"classical_after_request_root_hex"`
	Quantum   string                `json:"quantum_response_message_hex"`
	Request   []channelVectorRecord `json:"request"`
	Response  []channelVectorRecord `json:"response"`
}

func channelVector(t *testing.T) channelFixture {
	t.Helper()
	encoded, err := os.ReadFile("../tests/fixtures/channel-exchange-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector channelFixture
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// Standard-library decryption is independent of the Rust implementation. The
// fixture's root and PQ message key were derived with Python cryptography.
func channelResponseCipher(t *testing.T, v channelFixture, encoded []byte) (cipher.AEAD, [12]byte) {
	t.Helper()
	if len(encoded) < 96 {
		t.Fatal("short response")
	}
	h := encoded[6:]
	if binary.BigEndian.Uint64(h[32:40]) != 0 || binary.BigEndian.Uint64(h[40:48]) != 0 || binary.BigEndian.Uint64(h[48:56]) != 0 || binary.BigEndian.Uint64(h[56:64]) != 1 || binary.BigEndian.Uint64(h[64:72]) != 1 {
		t.Fatal("unexpected first response counters")
	}
	alice, err := ecdh.X25519().NewPrivateKey(channelHex(t, v.Alice))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.X25519().NewPublicKey(h[:32])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := alice.ECDH(bob)
	if err != nil {
		t.Fatal(err)
	}
	root, err := hkdf.Key(sha256.New, shared, channelHex(t, v.Classical), "stogas.e2ee.double.v3_X25519_HKDFSHA256:Root", 64)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, root[32:])
	mac.Write([]byte{1})
	secret, err := hkdf.Key(sha256.New, mac.Sum(nil), channelHex(t, v.Quantum), "stogas.e2ee.triple.v3_X25519_MLKEM768_HKDFSHA256", 32)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("stogas.e2ee.record.v3\x00"), channelHex(t, v.ID)...)
	info = binary.BigEndian.AppendUint64(info, 0)
	info = append(info, 2)
	material, err := hkdf.Expand(sha256.New, secret, string(info), 44)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead, [12]byte(material[32:])
}
func channelHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestChannelConcurrentOwnersAndCloseUseTheRustCore(t *testing.T) {
	v := channelVector(t)
	root, id, initial := [32]byte(channelHex(t, v.Root)), [32]byte(channelHex(t, v.ID)), [32]byte(channelHex(t, v.Initial))
	request, response := v.Request, v.Response
	session, err := NewChannelSession(root, id, initial, 1152)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	forged := channelHex(t, request[0].Encoded)
	forged[len(forged)-1] ^= 1
	if _, _, _, err := session.AcceptStart(0, forged); !errors.Is(err, ErrChannelAuthentication) {
		t.Fatal(err)
	}
	start := channelHex(t, request[0].Encoded)
	reader, writer, metadata, err := session.AcceptStart(0, start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	t.Cleanup(writer.Close)
	if !bytes.Equal(metadata, channelHex(t, request[0].Plaintext)) {
		t.Fatal("wrong metadata")
	}
	if _, _, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded)); !errors.Is(err, ErrChannelRecord) {
		t.Fatal(err)
	}
	// Closing the parent concurrently with independent upload/response work must
	// not destroy admitted keys or let a new start through.
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		for _, record := range request[1:] {
			kind, actual, err := reader.Open(channelHex(t, record.Encoded))
			if err != nil || kind != record.Kind || !bytes.Equal(actual, channelHex(t, record.Plaintext)) {
				t.Error("open", err)
			}
		}
		if err := reader.Complete(); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wait.Done()
		var aead cipher.AEAD
		var nonce [12]byte
		for i, record := range response {
			actual, err := writer.Seal(record.Kind, channelHex(t, record.Plaintext))
			if err != nil {
				t.Error("seal", err)
				return
			}
			if i == 0 {
				aead, nonce = channelResponseCipher(t, v, actual)
			}
			prefix := 4
			if i == 0 {
				prefix = 6 + int(binary.BigEndian.Uint16(actual[4:6]))
			}
			recordNonce := nonce
			for j, b := range binary.BigEndian.AppendUint64(nil, uint64(i)) {
				recordNonce[4+j] ^= b
			}
			plain, err := aead.Open(nil, recordNonce[:], actual[prefix:], actual[:prefix])
			expected := append([]byte{record.Kind}, channelHex(t, record.Plaintext)...)
			if err != nil || !bytes.Equal(plain, expected) {
				t.Error("independent response decryption", err)
			}
		}
	}()
	go func() { defer wait.Done(); session.Expire(time.Now()); session.Close(); session.Close() }()
	wait.Wait()
	if _, _, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	reader.Close()
	reader.Close()
	writer.Close()
	writer.Close()
	if _, _, err := reader.Open(nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := reader.Complete(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestChannelMalformedInputsDoNotExposePlaintextOrReuseFailedWriters(t *testing.T) {
	v := channelVector(t)
	root, id, initial := [32]byte(channelHex(t, v.Root)), [32]byte(channelHex(t, v.ID)), [32]byte(channelHex(t, v.Initial))
	request := v.Request
	for _, width := range []uint16{0, 1, 31, 33, 1153, 65535} {
		if session, err := NewChannelSession(root, id, initial, width); session != nil || err == nil {
			t.Fatal("accepted invalid size", width)
		}
	}
	session, err := NewChannelSession(root, id, initial, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, input := range [][]byte{nil, {}, {0, 0, 0, 0}, make([]byte, 65537)} {
		if reader, writer, plain, err := session.AcceptStart(0, input); err == nil || reader != nil || writer != nil || plain != nil {
			t.Fatal("invalid start", err)
		}
	}
	reader, writer, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := writer.Seal(255, nil); !errors.Is(err, ErrChannelRecord) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, plain, err := reader.Open(nil); err == nil || plain != nil {
		t.Fatal("invalid body", err)
	}
	if err := reader.Complete(); err == nil {
		t.Fatal("accepted missing terminal record")
	}
}

func TestChannelSetupKeyMatchesIndependentX25519(t *testing.T) {
	private, public, err := GenerateChannelKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private[:])
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), public[:]) {
		t.Fatal("setup key pair mismatch", err)
	}
	_, next, err := GenerateChannelKey()
	if err != nil || next == public {
		t.Fatal("setup key reused", err)
	}
}
