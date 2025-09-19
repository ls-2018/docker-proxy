package http

import (
	"crypto/tls"
	"docker-proxy/pkg/cert"
	"docker-proxy/pkg/cfg"
	"docker-proxy/pkg/eth"
	"docker-proxy/pkg/log"
	"docker-proxy/pkg/proxy"
	"fmt"
	"net/http"
)

func Serve(opt cfg.Options) *http.Server {
	certs := cert.GenerateCert(opt.DomainList)
	tlsConfig := cert.LoadCert(certs)
	_ = tlsConfig
	ln, _ := tls.Listen("tcp", fmt.Sprintf("%s:%d", eth.ProxyIp, opt.Port), tlsConfig)
	srv := &http.Server{Handler: &Proxy{
		dest: opt.Dest,
	}}
	go func() {
		err := srv.Serve(ln)
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
