package sys_connect

import (
	"context"
	"docker-proxy/pkg/cfg"
	"docker-proxy/pkg/eth"
	"docker-proxy/pkg/log"
	"docker-proxy/pkg/utils"
	"errors"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run -mod=vendor github.com/cilium/ebpf/cmd/bpf2go -type proxy_redirect_config  sys_connect ../../../ebpf/kprobe__sys_connect.bpf.c -- -D${TARGET_ARCH} -I./../../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

func Load(ctx context.Context, opt cfg.Options) {
	ipTtlMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/docker-proxy/ip_ttl",
		&ebpf.LoadPinOptions{
			ReadOnly: true,
		})
	if err != nil {
		log.L.Fatal(err)
	}

	obj := sys_connectObjects{}
	err = loadSys_connectObjects(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 8 * 1024 * 1024 * 10,
			LogDisabled:  false,
		},
		MapReplacements: map[string]*ebpf.Map{
			"ip_ttl": ipTtlMap,
		},
		Maps: ebpf.MapOptions{
			PinPath: opt.PinPath,
			//LoadPinOptions: ebpf.LoadPinOptions{
			//	ReadOnly: true,
			//},
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.L.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		}
		log.L.Fatalf("Failed to load bpf obj: %v", err)
	}

	outerIp, _, outerMac, outIfindex := utils.GetLocalIP()

	var key0 int32 = 0 // hook eth
	var prc = sys_connectProxyRedirectConfig{
		Addr:    utils.Ip2BeUint32(outerIp),
		Ifindex: uint16(outIfindex),
		Mac:     HandleNullMac(outerMac),
	}
	err = obj.sys_connectMaps.RedirectMap.Update(unsafe.Pointer(&key0), unsafe.Pointer(&prc), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	var key1 int32 = 1 // proxy eth
	var prd = sys_connectProxyRedirectConfig{
		Addr:    utils.Ip2BeUint32(eth.ProxyIp),
		Port:    utils.HostToNetShort(uint16(opt.Port)),
		Ifindex: uint16(eth.ProxyIf),
		Mac:     HandleNullMac(eth.ProxyMac),
	}
	err = obj.sys_connectMaps.RedirectMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&prd), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	kprobe, err := link.Kprobe("__sys_connect", obj.KprobeConnect, &link.KprobeOptions{})
	if err != nil {
		panic(err)
	}
	<-ctx.Done()
	kprobe.Close()

}

func HandleNullMac(mac string) [6]uint8 {
	if mac == "" {
		mac = "00:00:00:00:00:00"
	}

	hw, err := net.ParseMAC(mac)
	if err != nil {
		// 解析失败时返回默认的零MAC地址
		return [6]uint8{
			0, 0, 0, 0, 0, 0,
		}
	}
	// 解析成功时返回解析的MAC地址
	return [6]uint8{
		hw[0],
		hw[1],
		hw[2],
		hw[3],
		hw[4],
		hw[5],
	}
}
