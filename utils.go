package reality

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mattn/go-colorable"
	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrVerifyFailed  = errors.New("verify failed")
	ErrDecryptFailed = errors.New("decrypt failed")
	ErrProxyDie      = errors.New("proxy die")
	ErrReplay        = errors.New("replay detected")
)

var Prefix = []byte("REALITY")

const DefaultExpireSecond = 30

var seqNumerOne = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}

// generateNonce 根据SessionKey和ExpireSecond生成Nonce
func generateNonce(NonceSize int, SessionKey []byte, ExpireSecond uint32) ([]byte, error) {
	if ExpireSecond == 0 {
		return nil, errors.New("expire second must not be zero")
	}
	info := make([]byte, 8)
	binary.BigEndian.PutUint64(info, uint64(time.Now().Unix()/int64(ExpireSecond)))
	nonce := make([]byte, NonceSize)
	_, err := hkdf.New(sha256.New, SessionKey[:], Prefix, info).Read(nonce[:])
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

var versionTLS12 = uint16(utls.VersionTLS12)

const recordHeaderLen = 5
const explicitNonceLen = 8 // TLS 1.2 nonce_explicit 长度，计入 recordData
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

const (
	typeServerHello       uint8 = 2
	typeNewSessionTicket  uint8 = 4
	typeCertificate       uint8 = 11
	typeServerKeyExchange uint8 = 12
	typeServerHelloDone   uint8 = 14
	typeCertificateVerify uint8 = 15
	typeClientKeyExchange uint8 = 16
)

type handshakeMsg struct {
	msgType byte   // typeServerHello / typeCertificate / ...
	data    []byte // 含 4 字节头的完整消息
}

type tlsRecord struct {
	recordType    uint8
	version       uint16
	recordData    []byte           // 原始 record payload
	handshakeMsgs []handshakeMsg   // Handshake record 时自动解析的各条握手消息
}

func newTLSRecord(recordType uint8, version uint16, recordData []byte) *tlsRecord {
	return &tlsRecord{
		recordType: recordType,
		version:    version,
		recordData: recordData,
	}
}

func (r *tlsRecord) marshal() []byte {
	data := make([]byte, recordHeaderLen+len(r.recordData))
	data[0] = r.recordType
	data[1] = byte(r.version >> 8)
	data[2] = byte(r.version)
	data[3] = byte(len(r.recordData) >> 8)
	data[4] = byte(len(r.recordData))
	copy(data[5:], r.recordData)
	return data
}

func (r *tlsRecord) writeTo(w io.Writer) (int, error) {
	n, err := bytes.NewReader(r.marshal()).WriteTo(w)
	return int(n), err
}

func readTlsRecord(reader io.Reader) (*tlsRecord, error) {
	hdr := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(reader, hdr); err != nil {
		return nil, err
	}
	recordType := hdr[0]
	if recordType < recordTypeChangeCipherSpec || recordType > recordTypeApplicationData {
		return nil, errors.New("tls: unknown record type")
	}
	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	if version < utls.VersionTLS10 || version > utls.VersionTLS13 {
		return nil, errors.New("tls: unknown version")
	}
	recordLen := int(hdr[3])<<8 | int(hdr[4])

	recordData := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, recordData); err != nil {
		return nil, err
	}
	r := &tlsRecord{
		recordType: recordType,
		version:    version,
		recordData: recordData,
	}
	// Handshake record 时自动解析内部握手消息
	if recordType == recordTypeHandshake && len(recordData) > 0 {
		r.handshakeMsgs = parseHandshakeMsgs(recordData)
	}
	return r, nil
}

// parseHandshakeMsgs 从 Handshake record payload 中解析出各条握手消息及其类型
func parseHandshakeMsgs(data []byte) []handshakeMsg {
	var msgs []handshakeMsg
	for len(data) > 0 {
		if len(data) < 4 {
			break
		}
		msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		total := 4 + msgLen
		if len(data) < total {
			break
		}
		msgs = append(msgs, handshakeMsg{
			msgType: data[0],
			data:    data[:total],
		})
		data = data[total:]
	}
	return msgs
}

const maxSize = 1400
const minSize = 900

// generateRandomData 生成随机 900-1400 字节的数据，prefix 写入开头。
//
// 大小设计意图：内层隧道承载 SOCKS5 代理流量，其中包含 TLS 握手（大量小包
// 如 ClientHello、Certificate 等）以及后续应用数据。如果 REALITY 握手完成后
// 立即出现小 record，观察者可从包大小分布中识别 REALITY 流量与正常 HTTPS 的
// 差异。因此在握手完成后故意发送 900-1400 字节的大 record，模拟 HTTP 响应或
// 大请求，与后续内层 TLS 小包交错，扰乱 DPI 对 record 大小的统计分析。
func generateRandomData(prefix []byte) []byte {
	len := minSize + int(randomUint16())%(maxSize-minSize+1)
	data := make([]byte, len)
	if _, err := rand.Read(data); err != nil {
		// crypto/rand.Read 在 Linux 上使用 getrandom/getentropy，
		// 在极端情况下可能失败，此时回退为固定模式填充
		for i := range data {
			data[i] = byte(i)
		}
	}
	copy(data, prefix)
	return data
}

func randomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

type OverlayData interface {
	OverlayData() byte
}

var _ OverlayData = (*warpConn)(nil)

type warpConn struct {
	net.Conn
	aead        cipher.AEAD
	overlayData byte
	wSeq        [8]byte // 写计数器：TLS 1.3 隐式 nonce（读写独立，见 newWarpConn）
	rSeq        [8]byte // 读计数器
	isTLS13     bool
	lockRead    *sync.Mutex
	lockWrite   *sync.Mutex
	rawInput    *bytes.Buffer
	maxPayload  int
}

func newWarpConn(conn net.Conn, aead cipher.AEAD, overlayData byte, seq [8]byte, isTLS13 bool) *warpConn {
	if isTLS13 {
		seq = seqNumerOne // TLS 1.3 隐式 seq：两端各自从 seqNumerOne 独立计数
	}
	maxPayload := 0xFFFF - aead.Overhead() - recordHeaderLen
	if !isTLS13 {
		maxPayload -= explicitNonceLen
	}
	return &warpConn{
		Conn:        conn,
		lockRead:    &sync.Mutex{},
		lockWrite:   &sync.Mutex{},
		rawInput:    &bytes.Buffer{},
		maxPayload:  maxPayload,
		aead:        aead,
		overlayData: overlayData,
		wSeq:        seq,
		rSeq:        seq, // TLS 1.2 下不用（显式 nonce），置同值无副作用
		isTLS13:     isTLS13,
	}
}

func (w *warpConn) Write(b []byte) (int, error) {
	w.lockWrite.Lock()
	defer w.lockWrite.Unlock()
	wrote := 0
	for len(b) > 0 {
		m := len(b)
		if m > w.maxPayload {
			m = w.maxPayload
		}
		data := w.aead.Seal(nil, w.wSeq[:], b[:m], nil)
		if !w.isTLS13 {
			data = append(w.wSeq[:], data...) // TLS 1.2: seq 作为 nonce_explicit 传输
		}
		record := newTLSRecord(recordTypeApplicationData, versionTLS12, data)
		incSeq(w.wSeq[:])
		_, err := record.writeTo(w.Conn)
		if err != nil {
			return wrote, err
		}
		wrote += m
		b = b[m:]
	}
	return wrote, nil
}

func (w *warpConn) Read(b []byte) (int, error) {
	w.lockRead.Lock()
	defer w.lockRead.Unlock()
	if w.rawInput.Len() != 0 {
		return w.rawInput.Read(b)
	}

	record, err := readTlsRecord(w.Conn)
	if err != nil {
		return 0, err
	}
	if record.recordType != recordTypeApplicationData {
		return 0, ErrVerifyFailed
	}
	if record.version != versionTLS12 {
		return 0, ErrVerifyFailed
	}
	data := record.recordData
	var nonce, ciphertext []byte
	if w.isTLS13 {
		nonce = w.rSeq[:]
		ciphertext = data
	} else {
		if len(data) < explicitNonceLen {
			return 0, ErrDecryptFailed
		}
		nonce = data[:explicitNonceLen]
		ciphertext = data[explicitNonceLen:]
	}
	plaintext, err := w.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}
	if w.isTLS13 {
		incSeq(w.rSeq[:])
	}
	n := copy(b, plaintext)
	if n < len(plaintext) {
		w.rawInput.Write(plaintext[n:])
	}
	return n, nil
}

func (w *warpConn) OverlayData() byte {
	return w.overlayData
}

func incSeq(seq []byte) {
	for i := 7; i >= 0; i-- {
		seq[i]++
		if seq[i] != 0 {
			return
		}
	}
}

func GetLogger(debug bool) logrus.FieldLogger {
	level := logrus.InfoLevel
	if debug {
		level = logrus.DebugLevel
	}
	logger := logrus.New()
	logger.SetLevel(level)
	logger.SetOutput(colorable.NewColorableStderr())
	logger.Formatter = &logrus.TextFormatter{
		ForceColors:      true,
		DisableTimestamp: true,
	}
	return logger
}

// handshakeState 握手状态枚举。1-99=服务端，100+=客户端。
type handshakeState int

const (
	stateDone            handshakeState = 0
	stateServerHello     handshakeState = 1
	stateSrvSKX          handshakeState = 2
	stateSrvSHD          handshakeState = 3
	stateSrvTicket       handshakeState = 4
	stateSrvCCS          handshakeState = 5
	stateSrvFinished     handshakeState = 6
	stateSrvCCS13        handshakeState = 7
	stateSrvAppData13    handshakeState = 8
	stateClientCert      handshakeState = 100
	stateClientCKX       handshakeState = 101
	stateClientCertVfy   handshakeState = 102
	stateClientCCS       handshakeState = 103
	stateClientFinished  handshakeState = 104
	stateClientCCS13     handshakeState = 105
	stateClientAppData13 handshakeState = 106
)

func isServerState(s handshakeState) bool { return s > 0 && s < 100 }

type stateHandler func(fo *flightObserver) (handshakeState, error)

func matchHType(r *tlsRecord, htype byte) bool {
	return len(r.handshakeMsgs) > 0 && r.handshakeMsgs[0].msgType == htype
}

type matchRule struct {
	htype      byte
	rtype      byte
	optional   bool
	fromClient bool
	greedy     bool
}

func (r matchRule) match(rec *tlsRecord) bool {
	if r.htype != 0 {
		return matchHType(rec, r.htype)
	}
	return rec.recordType == r.rtype
}

func state(r matchRule, next handshakeState) stateHandler {
	return func(fo *flightObserver) (handshakeState, error) {
		read := fo.readTarget
		if r.fromClient {
			read = fo.readClient
		}
		rec, err := read()
		if err != nil {
			if r.optional {
				return next, nil
			}
			return stateDone, err
		}
		if r.match(rec) {
			if !r.fromClient {
				fo.keep(rec)
			}
			if r.greedy {
				fo.drainTarget()
			}
			return next, nil
		}
		if r.optional {
			fo.buffer(rec)
			return next, nil
		}
		return stateDone, fmt.Errorf("unexpected record")
	}
}

// helloRetryRequestRandom 是 SHA-256("HelloRetryRequest") 的结果
// RFC 8446 Section 4.1.3
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// isHRR 判断握手消息是否为 HelloRetryRequest。
// HRR 就是 ServerHello，只是 Random 固定为 SHA-256("HelloRetryRequest")。
// handshakeMsg.data 布局：type(1) + len(3) + version(2) + random(32) + ...
func isHRR(msg handshakeMsg) bool {
	if len(msg.data) < 38 {
		return false
	}
	return bytes.Equal(msg.data[6:38], helloRetryRequestRandom[:])
}

func dup(clientConn net.Conn, proxyConn net.Conn) {
	defer clientConn.Close()
	defer proxyConn.Close()
	go io.Copy(proxyConn, clientConn)
	io.Copy(clientConn, proxyConn)
}
