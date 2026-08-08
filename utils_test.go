package reality_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net"
	"testing"
	"time"

	"github.com/howmp/reality"
)

const tlsRecordHeaderLen = 5

var firstSequenceNumber = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}

type memoryConn struct {
	input  bytes.Buffer
	output bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error)       { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)      { return c.output.Write(p) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return nil }
func (c *memoryConn) RemoteAddr() net.Addr             { return nil }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func (c *memoryConn) receive(data []byte) {
	c.input.Write(data)
}

func newTestAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 8)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestWarpConnTLS13BidirectionalWriteBeforeRead(t *testing.T) {
	clientWire := &memoryConn{}
	serverWire := &memoryConn{}
	client := reality.NewWarpConn(clientWire, newTestAEAD(t), 0, firstSequenceNumber, true)
	server := reality.NewWarpConn(serverWire, newTestAEAD(t), 0, firstSequenceNumber, true)

	clientPayload := []byte("client payload")
	serverPayload := []byte("server payload")
	if _, err := client.Write(clientPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(serverPayload); err != nil {
		t.Fatal(err)
	}

	clientWire.receive(serverWire.output.Bytes())
	serverWire.receive(clientWire.output.Bytes())

	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], serverPayload) {
		t.Fatalf("client payload mismatch: got %q, want %q", buf[:n], serverPayload)
	}
	n, err = server.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], clientPayload) {
		t.Fatalf("server payload mismatch: got %q, want %q", buf[:n], clientPayload)
	}
}

func TestWarpConnTLS12MaximumRecordLength(t *testing.T) {
	wire := &memoryConn{}
	writer := reality.NewWarpConn(wire, newTestAEAD(t), 0, firstSequenceNumber, false)
	payload := bytes.Repeat([]byte{0x5a}, 0xFFFF-16-tlsRecordHeaderLen)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}

	raw := wire.output.Bytes()
	for remaining := raw; len(remaining) > 0; {
		if len(remaining) < tlsRecordHeaderLen {
			t.Fatalf("truncated record header: %d bytes", len(remaining))
		}
		recordLen := int(remaining[3])<<8 | int(remaining[4])
		totalLen := tlsRecordHeaderLen + recordLen
		if totalLen > len(remaining) {
			t.Fatalf("record length exceeds available data: record=%d, available=%d", totalLen, len(remaining))
		}
		remaining = remaining[totalLen:]
	}

	wire.receive(raw)
	reader := reality.NewWarpConn(wire, newTestAEAD(t), 0, firstSequenceNumber, false)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}
