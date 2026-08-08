package reality

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/cryptobyte"
)

type ServerConfig struct {
	SNIAddr           string `json:"sni_addr"`
	ServerAddr        string `json:"server_addr"`
	SkipVerify        bool   `json:"skip_verify"`
	PrivateKeyECDH    string `json:"private_key_ecdh"`
	PrivateKeySign    string `json:"private_key_sign"`
	ExpireSecond      uint32 `json:"expire_second"`
	Debug             bool   `json:"debug"`
	ClientFingerPrint string `json:"finger_print,omitempty"`

	privateKeyECDH *ecdh.PrivateKey
	privateKeySign ed25519.PrivateKey
	sniHost        string
	sniPort        string
}

func NewServerConfig(sniAddr string, serverAddr string) (*ServerConfig, error) {
	privateKeyECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, privateKeySign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sniHost, sniPort, err := net.SplitHostPort(sniAddr)
	if err != nil {
		return nil, err
	}
	return &ServerConfig{
		SNIAddr:        sniAddr,
		ServerAddr:     serverAddr,
		PrivateKeyECDH: base64.StdEncoding.EncodeToString(privateKeyECDH.Bytes()),
		PrivateKeySign: base64.StdEncoding.EncodeToString(privateKeySign),
		ExpireSecond:   DefaultExpireSecond,
		privateKeyECDH: privateKeyECDH,
		privateKeySign: privateKeySign,
		sniHost:        sniHost,
		sniPort:        sniPort,
	}, nil

}

func (c *ServerConfig) Validate() error {
	if c.SNIAddr == "" {
		return errors.New("SNI is required")
	}
	var err error
	c.sniHost, c.sniPort, err = net.SplitHostPort(c.SNIAddr)
	if err != nil {
		return err
	}
	if c.ServerAddr == "" {
		return errors.New("server address is required")
	}
	data, err := base64.StdEncoding.DecodeString(c.PrivateKeyECDH)
	if err != nil {
		return err
	}
	c.privateKeyECDH, err = ecdh.X25519().NewPrivateKey(data)
	if err != nil {
		return err
	}
	data, err = base64.StdEncoding.DecodeString(c.PrivateKeySign)
	if err != nil {
		return err
	}
	if len(data) != ed25519.PrivateKeySize {
		return errors.New("private key sign length error")
	}
	c.privateKeySign = ed25519.PrivateKey(data)

	if c.ExpireSecond == 0 {
		c.ExpireSecond = DefaultExpireSecond
	}

	if c.ClientFingerPrint == "" {
		c.ClientFingerPrint = "chrome"
	}
	return nil
}
func (c *ServerConfig) SNIHost() string {
	return c.sniHost
}

func (c *ServerConfig) SNIPort() string {
	return c.sniPort
}
func (s *ServerConfig) ToClientConfig(overlayData byte) *ClientConfig {

	return &ClientConfig{
		SNI:             s.sniHost,
		ServerAddr:      s.ServerAddr,
		SkipVerify:      s.SkipVerify,
		PublicKeyECDH:   base64.StdEncoding.EncodeToString(s.privateKeyECDH.PublicKey().Bytes()),
		PublicKeyVerify: base64.StdEncoding.EncodeToString(s.privateKeySign.Public().(ed25519.PublicKey)),
		ExpireSecond:    s.ExpireSecond,
		Debug:           s.Debug,
		FingerPrint:     s.ClientFingerPrint,
		OverlayData:     overlayData,
	}
}

type Listener struct {
	net.Listener
	config   *ServerConfig
	chanConn chan net.Conn
	chanErr  chan error
	logger   logrus.FieldLogger

	// 防 ClientHello 重放：记录已使用的 x25519 公钥 → 过期时间戳
	seenRandoms   map[[32]byte]int64
	seenRandomsMu sync.Mutex
}

func Listen(laddr string, config *ServerConfig) (net.Listener, error) {
	inner, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		Listener:    inner,
		config:      config,
		chanConn:    make(chan net.Conn),
		chanErr:     make(chan error, 1), // 缓冲避免 Accept 关闭时发送阻塞
		logger:      GetLogger(config.Debug),
		seenRandoms: make(map[[32]byte]int64),
	}
	go l.cleanupSeenRandoms()

	go func() {
		for {
			conn, err := l.Listener.Accept()
			if err != nil {
				l.chanErr <- err
				close(l.chanConn)
				return
			}
			go func() {
				c, err := l.handshake(conn)
				if err != nil {
					if l.config.Debug {
						l.logger.Warnln("handshake", conn.RemoteAddr(), err)
					}
				} else {
					l.chanConn <- c
				}
			}()

		}
	}()
	return l, nil
}
func (l *Listener) Accept() (net.Conn, error) {
	if c, ok := <-l.chanConn; ok {
		return c, nil
	}
	return nil, <-l.chanErr
}

// handshake 尝试处理私有握手，失败则透明代理到伪装目标，成功返回加密连接。
//
// 时序分析（防主动探测）：
// 非授权连接走 fail 路径时，额外耗时 = Dial(目标) + 密码学。
// Dial RTT 典型 5-50ms；密码学部分（x25519 ECDH + AES-GCM + HKDF）合计 <0.2ms，
// 完全淹没在网络抖动中。攻击者要区分 REALITY 代理与直连目标，需在同网段测量
// 目标的 RTT 基线并大量采样，实际利用成本极高。
func (l *Listener) handshake(clientConn net.Conn) (net.Conn, error) {
	logger := l.logger

	// [1] 连接伪装目标
	targetConn, err := net.Dial("tcp", l.config.SNIAddr)
	if err != nil {
		clientConn.Close()
		return nil, errors.Join(ErrProxyDie, err)
	}

	fail := func(err error) (net.Conn, error) {
		go dup(clientConn, targetConn)
		return nil, err
	}

	// [2] 建立双向 TeeReader 观察者
	fo := newFlightObserver(clientConn, targetConn)

	// [3] 解密 REALITY 握手
	result, err := l.readClientHello(fo.clientReader, logger)
	if err != nil {
		return fail(errors.Join(ErrVerifyFailed, err))
	}

	// [4] 观察 TLS 握手
	records, err := observeTLS(fo)
	if err != nil {
		return fail(err)
	}

	// [5] 提取 seq
	seq := [8]byte{}
	copy(seq[:], seqNumerOne[:])
	if len(records) > 0 {
		rd := records[len(records)-1].recordData
		if len(rd) > len(seq) {
			copy(seq[:], rd[:len(seq)])
		}
	}
	logger.Debugf("seqNumer: %x", seq)

	// [6] 读取 overlay 数据
	overlayRecord, err := readTlsRecord(fo.overlayReader())
	if err != nil {
		fo.targetConn.Close()
		return nil, err
	}
	overlayData := overlayRecord.recordData[len(overlayRecord.recordData)-1]
	logger.Debugf("overlayData: %x", overlayData)
	fo.targetConn.Close()

	// [7] 发送服务端签名（同样使用 900-1400B 大包，参见 generateRandomData）
	sign := ed25519.Sign(ed25519.PrivateKey(l.config.privateKeySign), result.plaintext)
	logger.Debugf("sign: %x", sign)
	signRecord := newTLSRecord(recordTypeApplicationData, versionTLS12,
		generateRandomData(append(seq[:], sign...)))
	if _, err := signRecord.writeTo(clientConn); err != nil {
		clientConn.Close()
		return nil, err
	}

	// [8] 返回加密连接
	return NewWarpConn(clientConn, result.aead, overlayData, seq, fo.isTLS13), nil
}

// —— 类型定义 ——

type handshakeResult struct {
	aead      cipher.AEAD
	plaintext []byte
}

type flightObserver struct {
	clientConn   net.Conn
	targetConn   net.Conn
	clientReader *bufio.Reader
	targetReader *bufio.Reader

	records  []*tlsRecord // 收集的服务端 records
	buffered *tlsRecord   // 可选状态不匹配时暂存
	isTLS13  bool         // 目标是否协商了 TLS 1.3
}

func newFlightObserver(clientConn, targetConn net.Conn) *flightObserver {
	return &flightObserver{
		clientConn:   clientConn,
		targetConn:   targetConn,
		clientReader: bufio.NewReader(io.TeeReader(clientConn, targetConn)),
		targetReader: bufio.NewReader(io.TeeReader(targetConn, clientConn)),
	}
}

func (f *flightObserver) overlayReader() io.Reader {
	if f.clientReader.Buffered() >= recordHeaderLen {
		return f.clientReader
	}
	return f.clientConn
}

func (f *flightObserver) readTarget() (*tlsRecord, error) {
	if f.buffered != nil {
		r := f.buffered
		f.buffered = nil
		return r, nil
	}
	return readTlsRecord(f.targetReader)
}

func (f *flightObserver) readClient() (*tlsRecord, error) {
	if f.buffered != nil {
		r := f.buffered
		f.buffered = nil
		return r, nil
	}
	return readTlsRecord(f.clientReader)
}

func (f *flightObserver) buffer(r *tlsRecord) { f.buffered = r }
func (f *flightObserver) keep(r *tlsRecord)   { f.records = append(f.records, r) }

func (f *flightObserver) drainTarget() {
	// goroutine 持续读 targetReader，TeeReader 自动转发到客户端。
	// FSM 同期只读 clientReader，不冲突。handshake() 关闭 targetConn 时 goroutine 退出。
	go func() {
		for {
			r, err := readTlsRecord(f.targetReader)
			if err != nil {
				return
			}
			f.keep(r)
		}
	}()
}

func (l *Listener) readClientHello(clientReader *bufio.Reader, logger logrus.FieldLogger) (*handshakeResult, error) {
	recordClientHello, err := readTlsRecord(clientReader)
	if err != nil {
		return nil, err
	}
	var random, sessionId []byte
	s := cryptobyte.String(recordClientHello.recordData)
	if !s.Skip(6) || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed((*cryptobyte.String)(&sessionId)) {
		return nil, fmt.Errorf("invalid client hello: %x", hex.EncodeToString(recordClientHello.recordData))
	}
	logger.Debugf("random(public for ecdh): %x", random)
	logger.Debugf("sessionId(ciphertext): %x", sessionId)

	pub, err := ecdh.X25519().NewPublicKey(random)
	if err != nil {
		return nil, err
	}
	sessionKey, err := l.config.privateKeyECDH.ECDH(pub)
	if err != nil {
		return nil, err
	}
	logger.Debugf("sessionKey: %x", sessionKey)
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 8)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce(aead.NonceSize(), sessionKey, l.config.ExpireSecond)
	if err != nil {
		return nil, err
	}
	logger.Debugf("nonce: %x", nonce)

	// SessionId 长度检查放至 crypto 之后——无论长度是否匹配，先执行等量计算，消除时序 oracle
	if len(sessionId) != 32 {
		dummy := make([]byte, 32)
		aead.Open(nil, nonce, dummy, nil)
		return nil, fmt.Errorf("invalid session id length: %d", len(sessionId))
	}

	plaintext, err := aead.Open(nil, nonce, sessionId, nil)
	if err != nil {
		return nil, err
	}
	logger.Debugf("plaintext: %x", plaintext)
	if !bytes.HasPrefix(plaintext, Prefix) {
		return nil, fmt.Errorf("invalid prefix: %x", plaintext[:len(Prefix)])
	}
	// 防重放：检查 x25519 公钥（即 Random）是否已被使用
	if err := l.checkReplay(random); err != nil {
		return nil, err
	}
	logger.Debug("handshake ok")
	return &handshakeResult{aead: aead, plaintext: plaintext}, nil
}

// cleanupSeenRandoms 定期清理已过期的公钥记录，防止 map 无限增长。
func (l *Listener) cleanupSeenRandoms() {
	ticker := time.NewTicker(time.Duration(l.config.ExpireSecond) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		l.seenRandomsMu.Lock()
		for k, exp := range l.seenRandoms {
			if exp < now {
				delete(l.seenRandoms, k)
			}
		}
		l.seenRandomsMu.Unlock()
	}
}

// checkReplay 检查 x25519 公钥是否已被使用，防止 ClientHello 重放探测。
// 必须放在所有密码学验证通过之后调用，避免侧信道泄漏。
func (l *Listener) checkReplay(random []byte) error {
	if len(random) != 32 {
		return nil // 不应出现，防御性放过
	}
	now := time.Now().Unix()
	key := *(*[32]byte)(random)

	l.seenRandomsMu.Lock()
	defer l.seenRandomsMu.Unlock()

	if exp, ok := l.seenRandoms[key]; ok && exp > now {
		return ErrReplay
	}
	// 保留 ExpireSecond*2 时长，容忍时钟偏差
	l.seenRandoms[key] = now + int64(l.config.ExpireSecond)*2
	return nil
}

// —— 状态机 ——

var serverFSM = map[handshakeState]stateHandler{
	stateServerHello:  consumeServerHello,
	stateSrvSKX:       state(matchRule{htype: typeServerKeyExchange}, stateSrvSHD),
	stateSrvSHD:       state(matchRule{htype: typeServerHelloDone}, stateClientCert),
	stateSrvTicket:    state(matchRule{htype: typeNewSessionTicket, optional: true}, stateSrvCCS),
	stateSrvCCS:       state(matchRule{rtype: recordTypeChangeCipherSpec}, stateSrvFinished),
	stateSrvFinished:  state(matchRule{rtype: recordTypeHandshake}, stateDone),
	stateSrvCCS13:     state(matchRule{rtype: recordTypeChangeCipherSpec, optional: true}, stateSrvAppData13),
	stateSrvAppData13: state(matchRule{rtype: recordTypeApplicationData, greedy: true}, stateClientCCS13),
}

var clientFSM = map[handshakeState]stateHandler{
	stateClientCert:      state(matchRule{htype: typeCertificate, optional: true, fromClient: true}, stateClientCKX),
	stateClientCKX:       state(matchRule{htype: typeClientKeyExchange, fromClient: true}, stateClientCertVfy),
	stateClientCertVfy:   state(matchRule{htype: typeCertificateVerify, optional: true, fromClient: true}, stateClientCCS),
	stateClientCCS:       state(matchRule{rtype: recordTypeChangeCipherSpec, fromClient: true}, stateClientFinished),
	stateClientFinished:  state(matchRule{rtype: recordTypeHandshake, fromClient: true}, stateSrvTicket),
	stateClientCCS13:     state(matchRule{rtype: recordTypeChangeCipherSpec, optional: true, fromClient: true}, stateClientAppData13),
	stateClientAppData13: state(matchRule{rtype: recordTypeApplicationData, fromClient: true}, stateDone),
}

// consumeServerHello 读首条 ServerHello，处理 HRR，返回 next 状态。
func consumeServerHello(fo *flightObserver) (handshakeState, error) {
	first, err := readTlsRecord(fo.targetReader)
	if err != nil {
		return stateDone, err
	}

	msgs := first.handshakeMsgs
	if len(msgs) == 0 || msgs[0].msgType != typeServerHello {
		return stateDone, fmt.Errorf("expected ServerHello, got %x", first.recordData[:min(4, len(first.recordData))])
	}

	// HRR 也是 ServerHello（msgType=2），通过 Random 字段值区分
	if isHRR(msgs[0]) {
		fo.isTLS13 = true
		readTlsRecord(fo.clientReader) // CCS
		readTlsRecord(fo.clientReader) // CH2
		next, _ := readTlsRecord(fo.targetReader)
		if next.recordType == recordTypeChangeCipherSpec {
			first, _ = readTlsRecord(fo.targetReader)
		} else {
			first = next
		}
		msgs = first.handshakeMsgs
	}

	if len(msgs) > 1 {
		for _, m := range msgs[1:] {
			fo.keep(&tlsRecord{recordType: recordTypeHandshake, version: versionTLS12, recordData: m.data})
		}
		return stateClientCert, nil
	}

	next, err := readTlsRecord(fo.targetReader)
	if err != nil {
		return stateDone, err
	}
	if next.recordType == recordTypeChangeCipherSpec || next.recordType == recordTypeApplicationData {
		fo.isTLS13 = true
		fo.buffer(next)
		return stateSrvCCS13, nil
	}
	fo.keep(next)
	return stateSrvSKX, nil
}

func observeTLS(fo *flightObserver) ([]*tlsRecord, error) {
	state := handshakeState(stateServerHello)
	for state != stateDone {
		fsm := serverFSM
		if !isServerState(state) {
			fsm = clientFSM
		}
		var err error
		state, err = fsm[state](fo)
		if err != nil {
			go dup(fo.clientConn, fo.targetConn)
			return nil, err
		}
	}
	return fo.records, nil
}
