package proxy

import (
	"docker-proxy/pkg/log"
	"io"
	"net/http"
	"strings"
)

var backendService = ""

func proxy(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.String(), "health") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}
	log.L.Println("✈️ ", r.Host, r.Method, r.URL.String())
	target := strings.TrimPrefix(r.URL.String(), "/v2/")
	domain := r.Host
	if r.Host == "registry-1.docker.io" {
		domain = "docker.io"
	}
	ur := strings.Join([]string{"https://%s/v2", backendService, domain, target}, "/")
	log.L.Println(r.Method, ur, r.Header)

	req, err := http.NewRequest(r.Method, ur, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func Proxy(backend string) func(w http.ResponseWriter, r *http.Request) {
	backendService = backend
	return proxy
}
