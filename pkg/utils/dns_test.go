package utils

import (
	"docker-proxy/pkg/log"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestDecode(t *testing.T) {
	raw := []uint8{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name := DecodeDNSName(raw)
	log.L.Println(name) // 输出: www.example.com
}

func TestIP(t *testing.T) {
	ip := net.ParseIP("10.5.1.9")
	ip = ip.To4() // 只取 IPv4
	log.L.Println(binary.BigEndian.Uint32(ip))
	log.L.Println(binary.LittleEndian.Uint32(ip))
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 151061770)
	log.L.Println(net.IP(b).String())

	binary.LittleEndian.PutUint32(b, 251789322)
	log.L.Println(net.IP(b).String())
}

func TestPort(t *testing.T) {
	fmt.Println(HostToNetShort(14640))
	fmt.Println(HostToNetShort(HostToNetShort(14640)))
}

//1597726919          0x5F3B06B3
//2726109197    map   0xA27D020D   这个是对的  大端
