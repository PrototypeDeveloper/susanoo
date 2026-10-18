package transport

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"susanoo/internal/pki"
)

// 試験の通信はループバック（127.0.0.1）だけで行い、PCの外には出さない。

type result struct {
	peer pki.Identity
	err  error
}

// handshake は srv と cli の設定で TLS の接続を確立し、双方の結果を返す。
func handshake(t *testing.T, srv, cli *tls.Config) (server result, clientErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		tc := tls.Server(c, srv)
		if err := tc.Handshake(); err != nil {
			done <- result{err: err}
			return
		}
		id, err := PeerIdentity(tc.ConnectionState())
		done <- result{peer: id, err: err}
		// 接続を確立できたことをクライアントに知らせる。
		tc.Write([]byte{1})
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(c, cli)
	clientErr = tc.Handshake()
	if clientErr == nil {
		// TLS 1.3 では、サーバーはクライアントの handshake が終わった後にクライアントの証明書を検証する。
		// サーバーが拒否した場合はここで読み込みが失敗する。
		_, clientErr = io.ReadFull(tc, make([]byte, 1))
	}
	return <-done, clientErr
}

type fixture struct {
	ca, otherCA *pki.CA
	now         time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Now()
	ca, err := pki.NewCA("試験用CA", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.NewCA("別のCA", now)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{ca: ca, otherCA: other, now: now}
}

func (f fixture) leaf(t *testing.T, ca *pki.CA, role pki.Role, id string, now time.Time) tls.Certificate {
	t.Helper()
	c, err := ca.NewLeaf(pki.Identity{Role: role, ID: id}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMutualTLS(t *testing.T) {
	f := newFixture(t)
	ctrl := f.leaf(t, f.ca, pki.RoleController, "main", f.now)
	srv := ServerConfig(f.ca.Pool(), ctrl, pki.RoleClient, pki.RoleGW)

	cli := ClientConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleClient, "pc-001", f.now), pki.RoleController)
	server, clientErr := handshake(t, srv, cli)
	if server.err != nil || clientErr != nil {
		t.Fatalf("接続できない: サーバー %v, クライアント %v", server.err, clientErr)
	}
	want := pki.Identity{Role: pki.RoleClient, ID: "pc-001"}
	if server.peer != want {
		t.Errorf("相手 = %v, 期待値 %v", server.peer, want)
	}
}

func TestMutualTLSRejects(t *testing.T) {
	f := newFixture(t)
	ctrl := f.leaf(t, f.ca, pki.RoleController, "main", f.now)
	client := f.leaf(t, f.ca, pki.RoleClient, "pc-001", f.now)
	past := f.now.Add(-pki.LeafValidity - time.Hour)

	tests := []struct {
		name string
		srv  *tls.Config
		cli  *tls.Config
	}{
		{
			"別の認証局のクライアント証明書",
			ServerConfig(f.ca.Pool(), ctrl, pki.RoleClient),
			ClientConfig(f.ca.Pool(), f.leaf(t, f.otherCA, pki.RoleClient, "pc-001", f.now), pki.RoleController),
		},
		{
			"別の認証局のサーバー証明書",
			ServerConfig(f.ca.Pool(), f.leaf(t, f.otherCA, pki.RoleController, "main", f.now), pki.RoleClient),
			ClientConfig(f.ca.Pool(), client, pki.RoleController),
		},
		{
			"許可していない役割のクライアント",
			ServerConfig(f.ca.Pool(), ctrl, pki.RoleGW),
			ClientConfig(f.ca.Pool(), client, pki.RoleController),
		},
		{
			"期待と違う役割のサーバー",
			ServerConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleGW, "gw-1", f.now), pki.RoleClient),
			ClientConfig(f.ca.Pool(), client, pki.RoleController),
		},
		{
			"クライアントがサーバーを装う",
			ServerConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleClient, "evil", f.now), pki.RoleClient),
			ClientConfig(f.ca.Pool(), client, pki.RoleController),
		},
		{
			"期限切れのクライアント証明書",
			ServerConfig(f.ca.Pool(), ctrl, pki.RoleClient),
			ClientConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleClient, "pc-001", past), pki.RoleController),
		},
		{
			"クライアント証明書なし",
			ServerConfig(f.ca.Pool(), ctrl, pki.RoleClient),
			func() *tls.Config {
				c := ClientConfig(f.ca.Pool(), client, pki.RoleController)
				c.Certificates = nil
				return c
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, clientErr := handshake(t, tt.srv, tt.cli)
			if server.err == nil && clientErr == nil {
				t.Errorf("接続が確立した（相手 %v）", server.peer)
			}
		})
	}
}

func TestTLS13Only(t *testing.T) {
	f := newFixture(t)
	srv := ServerConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleController, "main", f.now), pki.RoleClient)
	cli := ClientConfig(f.ca.Pool(), f.leaf(t, f.ca, pki.RoleClient, "pc-001", f.now), pki.RoleController)
	cli.MinVersion = tls.VersionTLS12
	cli.MaxVersion = tls.VersionTLS12
	server, clientErr := handshake(t, srv, cli)
	if server.err == nil && clientErr == nil {
		t.Error("TLS 1.2 で接続できた")
	}
}
