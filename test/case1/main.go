package main

import (
	"docker-proxy/pkg/log"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func main() {
	dnsServer := "114.114.114.114:53"

	// 构造 DNS 请求
	msg := new(dns.Msg)
	msg.RecursionDesired = true

	// 添加多个问题
	msg.Question = []dns.Question{
		{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: dns.Fqdn("golang.org"), Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// 发送请求
	resp, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		log.L.Fatalf("DNS query failed: %v", err)
	}

	// 解析响应
	for _, answer := range resp.Answer {
		switch v := answer.(type) {
		case *dns.A:
			log.L.Printf("A record: %s -> %s\n", v.Hdr.Name, v.A)
		case *dns.MX:
			log.L.Printf("MX record: %s -> %s\n", v.Hdr.Name, v.Mx)
		}
	}
}
