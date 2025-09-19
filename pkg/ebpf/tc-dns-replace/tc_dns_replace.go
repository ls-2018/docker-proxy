package tc_dns_replace

import (
	"context"
	"docker-proxy/pkg/log"
	"docker-proxy/pkg/utils"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run -mod=vendor github.com/cilium/ebpf/cmd/bpf2go -type dns_question -type a_record tc_dns_replace ../../../ebpf/tc-dns-replace.bpf.c -- -D${TARGET_ARCH} -I./../../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

func Load(ctx context.Context) {
	log.L.Println("✈️ cat /sys/kernel/debug/tracing/trace_pipe")

	obj := tc_dns_replaceObjects{}
	err := loadTc_dns_replaceObjects(&obj, &ebpf.CollectionOptions{})
	if err != nil {
		panic(err)
	}

	_, _, _, index := utils.GetLocalIP()
	qk := getKey("docker.io")
	ip := net.ParseIP("127.0.0.1")
	if ip == nil {
		return
	}
	record := tc_dns_replaceA_record{
		IpAddr: binary.LittleEndian.Uint32(ip.To4()),
		Ttl:    30,
	}
	err = obj.tc_dns_replaceMaps.DnsA_records.Update(unsafe.Pointer(&qk), unsafe.Pointer(&record), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}
	tcx, err := link.AttachTCX(link.TCXOptions{
		Interface: index,
		Program:   obj.tc_dns_replacePrograms.TcDnsIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		panic(err)
	}
	select {
	case <-ctx.Done():
		tcx.Close()
	}
}

func getKey(host string) tc_dns_replaceDnsQuestion {
	queryKey := tc_dns_replaceDnsQuestion{
		RecordType: 1,
		Class:      1,
	}
	nameSlice := make([]byte, 256)
	copy(nameSlice, []byte(host))
	dnsName := utils.ReplaceDotsWithLengthOctets(nameSlice)

	for i, v := range dnsName {
		if i+1 <= len(queryKey.Name) {
			queryKey.Name[i] = int8(v)
		}
	}
	return queryKey
}
