package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

// TestCheckReplay 验证防重放机制：
//  1. 首次使用随机公钥 → 通过
//  2. 重复使用同一公钥 → 返回 ErrReplay
//  3. 不同公钥 → 分别通过
func TestCheckReplay(t *testing.T) {
	config, err := NewServerConfig("www.qq.com:443", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	listener := l.(*Listener)

	// 生成两个不同的 x25519 公钥模拟不同连接
	priv1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub1 := priv1.PublicKey().Bytes()

	priv2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub2 := priv2.PublicKey().Bytes()

	// 首次使用 pub1 → 应通过
	if err := listener.checkReplay(pub1); err != nil {
		t.Fatalf("first use should pass, got: %v", err)
	}

	// 重复使用 pub1 → 应返回 ErrReplay
	if err := listener.checkReplay(pub1); err != ErrReplay {
		t.Fatalf("replay should return ErrReplay, got: %v", err)
	}

	// 首次使用 pub2 → 应通过（不同密钥不应被拦截）
	if err := listener.checkReplay(pub2); err != nil {
		t.Fatalf("different key should pass, got: %v", err)
	}
}

// TestReplayInFullHandshake 端到端验证：使用不同临时密钥的两次连接均应成功，
// 证明防重放机制不会误伤合法的重连行为。
func TestReplayInFullHandshake(t *testing.T) {
	config, err := NewServerConfig("www.qq.com:443", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	l, err := Listen("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	clientConfig := config.ToClientConfig(0)
	clientConfig.ServerAddr = l.Addr().String()

	// 第一次连接 → 应成功
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn1, err := NewClient(ctx, clientConfig)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	conn1.Close()

	serverConn1, err := l.Accept()
	if err != nil {
		t.Fatalf("accept first: %v", err)
	}
	serverConn1.Close()

	// 第二次连接（新密钥）→ 也应成功（证明不是全局封禁）
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := NewClient(ctx2, clientConfig)
	if err != nil {
		t.Fatalf("second connection (new key): %v", err)
	}
	conn2.Close()

	serverConn2, err := l.Accept()
	if err != nil {
		t.Fatalf("accept second with new key: %v", err)
	}
	serverConn2.Close()

	t.Log("PASS: two connections with different ephemeral keys both succeed")
}
