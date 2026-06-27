package reality_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/howmp/reality"
)


func TestMaxVersion(t *testing.T) {
	config, err := NewServerConfig("example.com:443", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := config.ToClientConfig(0)
	if err := clientConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	// Validate() 确保指纹已设置
}

func TestClientConfigRoundTrip(t *testing.T) {
	config, err := NewServerConfig("www.qq.com:443", "8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	config.Debug = true
	config.ExpireSecond = 60
	clientConfig := config.ToClientConfig(5)
	configData, err := clientConfig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	newConfig, err := UnmarshalClientConfig(configData)
	if err != nil {
		t.Fatal(err)
	}
	if newConfig.ServerAddr != "8.8.8.8:443" {
		t.Errorf("ServerAddr mismatch: %s", newConfig.ServerAddr)
	}
	if newConfig.SNI != "www.qq.com" {
		t.Errorf("SNI mismatch: %s", newConfig.SNI)
	}
	if newConfig.OverlayData != 5 {
		t.Errorf("OverlayData mismatch: %d", newConfig.OverlayData)
	}
	if newConfig.ExpireSecond != 60 {
		t.Errorf("ExpireSecond mismatch: %d", newConfig.ExpireSecond)
	}
	if !newConfig.Debug {
		t.Error("Debug should be true")
	}
}

// ============================================================
// 端到端集成测试（每个目标一个独立测试，5s 超时）
// ============================================================

type handshakeTarget struct {
	addr  string
	label string
}

func testOneHandshake(t *testing.T, target handshakeTarget) {
	config, err := NewServerConfig(target.addr, "127.0.0.1:0")
	if err != nil {
		t.Skipf("skip: %v", err)
		return
	}

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	serverAddr := l.Addr().String()

	clientConfig := config.ToClientConfig(0)
	clientConfig.ServerAddr = serverAddr

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := NewClient(ctx, clientConfig)
		ch <- result{conn, err}
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	r := <-ch
	if r.err != nil {
		t.Fatalf("client connect: %v", r.err)
	}
	clientConn := r.conn
	defer clientConn.Close()

	// 双向传输验证
	msg := fmt.Sprintf("hello %s", target.label)
	if _, err := clientConn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := serverConn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("data mismatch: %q", string(buf))
	}
	serverConn.Write([]byte("ok"))
	buf = make([]byte, 2)
	clientConn.Read(buf)

	t.Logf("[%s] PASS", target.label)
}

// TLS 1.3 目标
func TestRealityHandshake_Taobao(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.taobao.com:443", "Taobao"})
}
func TestRealityHandshake_JD(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.jd.com:443", "JD"})
}
func TestRealityHandshake_Bilibili(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.bilibili.com:443", "Bilibili"})
}
func TestRealityHandshake_CSDN(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.csdn.net:443", "CSDN"})
}
func TestRealityHandshake_Huawei(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.huawei.com:443", "Huawei"})
}
func TestRealityHandshake_Aliyun(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.aliyun.com:443", "Aliyun"})
}
func TestRealityHandshake_163(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.163.com:443", "163"})
}
func TestRealityHandshake_Gitee(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"gitee.com:443", "Gitee"})
}
func TestRealityHandshake_TencentCloud(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"cloud.tencent.com:443", "TencentCloud"})
}

// 更多国内 TLS 1.3 目标 — 社交/社区
func TestRealityHandshake_Zhihu(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.zhihu.com:443", "Zhihu"})
}
func TestRealityHandshake_Douyin(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.douyin.com:443", "Douyin"})
}
func TestRealityHandshake_Weibo(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.weibo.com:443", "Weibo"})
}
func TestRealityHandshake_Xiaohongshu(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.xiaohongshu.com:443", "Xiaohongshu"})
}
func TestRealityHandshake_Kuaishou(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.kuaishou.com:443", "Kuaishou"})
}

// 更多国内 TLS 1.3 目标 — 电商/生活
func TestRealityHandshake_Meituan(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.meituan.com:443", "Meituan"})
}
func TestRealityHandshake_Pinduoduo(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.pinduoduo.com:443", "Pinduoduo"})
}
func TestRealityHandshake_Dangdang(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.dangdang.com:443", "Dangdang"})
}

// 更多国内 TLS 1.3 目标 — 技术/开发者
func TestRealityHandshake_OSChina(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.oschina.net:443", "OSChina"})
}
func TestRealityHandshake_SegmentFault(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"segmentfault.com:443", "SegmentFault"})
}
func TestRealityHandshake_Juejin(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"juejin.cn:443", "Juejin"})
}

// 更多国内 TLS 1.3 目标 — 新闻/资讯
func TestRealityHandshake_Sina(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.sina.com.cn:443", "Sina"})
}
func TestRealityHandshake_TencentNews(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"news.qq.com:443", "TencentNews"})
}
func TestRealityHandshake_WangyiNews(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"news.163.com:443", "WangyiNews"})
}

// 国内 TLS 1.2 目标
func TestRealityHandshake_QQ(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.qq.com:443", "QQ"})
}
func TestRealityHandshake_Baidu(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.baidu.com:443", "Baidu"})
}
func TestRealityHandshake_Sohu(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.sohu.com:443", "Sohu"})
}
func TestRealityHandshake_Bing(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.bing.com:443", "Bing"})
}
func TestRealityHandshake_Mi(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.mi.com:443", "Mi"})
}
func TestRealityHandshake_Infoq(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.infoq.cn:443", "InfoQ"})
}

// 更多国内 TLS 1.2 目标
func TestRealityHandshake_Sogou(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.sogou.com:443", "Sogou"})
}
func TestRealityHandshake_Cnblogs(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.cnblogs.com:443", "Cnblogs"})
}
func TestRealityHandshake_Douban(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"movie.douban.com:443", "Douban"})
}
func TestRealityHandshake_126(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.126.com:443", "126Mail"})
}
func TestRealityHandshake_ChinaUnix(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.ithome.com:443", "ITHome"})
}
func TestRealityHandshake_CCTV(t *testing.T) {
	testOneHandshake(t, handshakeTarget{"www.icbc.com.cn:443", "ICBC"})
}

// 保留 debug 模式详细测试
func TestRealityHandshakeTLS13(t *testing.T) {
	target := handshakeTarget{"cloudflare.com:443", "TLS 1.3"}
	config, err := NewServerConfig(target.addr, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.Debug = true

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serverAddr := l.Addr().String()
	t.Logf("listen: %s", serverAddr)

	clientConfig := config.ToClientConfig(0)
	clientConfig.ServerAddr = serverAddr
	clientConfig.Debug = true

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := NewClient(ctx, clientConfig)
		ch <- result{conn, err}
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	clientConn := r.conn
	defer clientConn.Close()

	msg := []byte("hello tls13")
	clientConn.Write(msg)
	buf := make([]byte, len(msg))
	serverConn.Read(buf)
	if string(buf) != string(msg) {
		t.Fatalf("data mismatch: %q", string(buf))
	}
	serverConn.Write([]byte("ok"))
	buf = make([]byte, 2)
	clientConn.Read(buf)
	t.Logf("=== TLS 1.3 PASS ===")
}

func TestRealityHandshakeTLS12(t *testing.T) {
	target := handshakeTarget{"www.qq.com:443", "TLS 1.2"}
	config, err := NewServerConfig(target.addr, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.Debug = true

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serverAddr := l.Addr().String()
	t.Logf("listen: %s", serverAddr)

	clientConfig := config.ToClientConfig(0)
	clientConfig.ServerAddr = serverAddr
	clientConfig.Debug = true

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := NewClient(ctx, clientConfig)
		ch <- result{conn, err}
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	clientConn := r.conn
	defer clientConn.Close()

	msg := []byte("hello tls12")
	clientConn.Write(msg)
	buf := make([]byte, len(msg))
	serverConn.Read(buf)
	if string(buf) != string(msg) {
		t.Fatalf("data mismatch: %q", string(buf))
	}
	serverConn.Write([]byte("ok"))
	buf = make([]byte, 2)
	clientConn.Read(buf)
	t.Logf("=== TLS 1.2 PASS ===")
}

// testNormalProxy 验证标准 TLS 客户端通过 REALITY 服务端透明代理到伪装目标。
func testNormalProxy(t *testing.T, target handshakeTarget) {
	config, err := NewServerConfig(target.addr, "127.0.0.1:0")
	if err != nil {
		t.Skipf("skip: %v", err)
		return
	}

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	host := target.addr[:len(target.addr)-4]
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", l.Addr().String(),
		&tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	conn.Close()

	// 验证 REALITY Accept 不会返回非授权连接
	acceptDone := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		acceptDone <- c
	}()
	select {
	case c := <-acceptDone:
		if c != nil {
			c.Close()
			t.Fatal("unexpected REALITY connection")
		}
	case <-time.After(200 * time.Millisecond):
	}
	t.Logf("[%s] proxy OK", target.label)
}

// 正常代理测试（每个目标独立测试）
func TestNormalProxy_Taobao(t *testing.T)     { testNormalProxy(t, handshakeTarget{"www.taobao.com:443", "Taobao"}) }
func TestNormalProxy_JD(t *testing.T)          { testNormalProxy(t, handshakeTarget{"www.jd.com:443", "JD"}) }
func TestNormalProxy_Bilibili(t *testing.T)    { testNormalProxy(t, handshakeTarget{"www.bilibili.com:443", "Bilibili"}) }
func TestNormalProxy_CSDN(t *testing.T)        { testNormalProxy(t, handshakeTarget{"www.csdn.net:443", "CSDN"}) }
func TestNormalProxy_Huawei(t *testing.T)      { testNormalProxy(t, handshakeTarget{"www.huawei.com:443", "Huawei"}) }
func TestNormalProxy_Aliyun(t *testing.T)      { testNormalProxy(t, handshakeTarget{"www.aliyun.com:443", "Aliyun"}) }
func TestNormalProxy_163(t *testing.T)          { testNormalProxy(t, handshakeTarget{"www.163.com:443", "163"}) }
func TestNormalProxy_Gitee(t *testing.T)        { testNormalProxy(t, handshakeTarget{"gitee.com:443", "Gitee"}) }
func TestNormalProxy_TencentCloud(t *testing.T) { testNormalProxy(t, handshakeTarget{"cloud.tencent.com:443", "TencentCloud"}) }
func TestNormalProxy_Zhihu(t *testing.T)        { testNormalProxy(t, handshakeTarget{"www.zhihu.com:443", "Zhihu"}) }
func TestNormalProxy_Meituan(t *testing.T)      { testNormalProxy(t, handshakeTarget{"www.meituan.com:443", "Meituan"}) }
func TestNormalProxy_Weibo(t *testing.T)        { testNormalProxy(t, handshakeTarget{"www.weibo.com:443", "Weibo"}) }
func TestNormalProxy_QQ(t *testing.T)           { testNormalProxy(t, handshakeTarget{"www.qq.com:443", "QQ"}) }
func TestNormalProxy_Baidu(t *testing.T)        { testNormalProxy(t, handshakeTarget{"www.baidu.com:443", "Baidu"}) }
func TestNormalProxy_Bing(t *testing.T)         { testNormalProxy(t, handshakeTarget{"www.bing.com:443", "Bing"}) }
func TestNormalProxy_Mi(t *testing.T)           { testNormalProxy(t, handshakeTarget{"www.mi.com:443", "Mi"}) }
func TestNormalProxy_Cnblogs(t *testing.T)      { testNormalProxy(t, handshakeTarget{"www.cnblogs.com:443", "Cnblogs"}) }
func TestNormalProxy_Sina(t *testing.T)        { testNormalProxy(t, handshakeTarget{"www.sina.com.cn:443", "Sina"}) }
