package http

import (
	"context"
	"crypto/tls"
	"docker-proxy/pkg/cert"
	"docker-proxy/pkg/cfg"
	"docker-proxy/pkg/log"
	"docker-proxy/pkg/proxy"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"golang.org/x/sys/unix"
)

func Serve(opt cfg.Options) *http.Server {
	certs := cert.GenerateCert(opt.DomainList)
	tlsConfig := cert.LoadCert(certs)
	// 使用 ListenConfig + Control 设置 IP_TRANSPARENT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			c.Control(func(fd uintptr) {
				// 开启 IP_TRANSPARENT
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				if sockErr != nil {
					return
				}
				// 推荐加 SO_REUSEADDR / SO_REUSEPORT
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			return sockErr
		},
	}
	// 建立 TCP Listener
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", opt.Port))
	if err != nil {
		log.L.Fatalf("listen: %v", err)
	}

	// 包装成 TLS Listener
	tlsLn := tls.NewListener(ln, tlsConfig)
	if err != nil {
		log.L.Fatalf("failed to listen: %v", err)
	}

	srv := &http.Server{Handler: &Proxy{
		dest: opt.Dest,
	}}
	go func() {
		err := srv.Serve(tlsLn)
		if err != nil {
			log.L.Fatal(err)
		}
	}()
	log.L.Printf("Serving %s at %s", opt.Domains, opt.Dest)
	return srv
}

type Proxy struct {
	dest string
}

func (p Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy.Proxy(p.dest)(writer, request)
}
