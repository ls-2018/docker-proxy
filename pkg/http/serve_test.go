package http

import (
	"docker-proxy/pkg/log"
	"net"
	"net/http"
	"testing"
)

func TestR(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: &Proxy{
		dest: "",
	}}
	err = srv.Serve(ln)
	if err != nil {
		log.L.Fatal(err)
	}
}
