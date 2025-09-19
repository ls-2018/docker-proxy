package xdp_proxy

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type proxy_redirect_config  xdp_proxy ../../../ebpf/xdp-proxy.bpf.c -- -D${TARGET_ARCH} -I./../../../ebpf/headers -Wall -Wno-unused-variable  -Wno-unused-function

func Load(ctx context.Context, opt cfg.Options) {
	ipTtlMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/docker-proxy/ip_ttl",
		&ebpf.LoadPinOptions{
			ReadOnly: true,
		})
	if err != nil {
		log.L.Fatal(err)
	}

	obj := xdp_proxyObjects{}
	err = loadXdp_proxyObjects(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 8 * 1024 * 1024 * 10,
			LogDisabled:  false,
		},
		MapReplacements: map[string]*ebpf.Map{
			"ip_ttl": ipTtlMap,
		},
		Maps: ebpf.MapOptions{
			//PinPath: opt.PinPath,
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
	var prc = xdp_proxyProxyRedirectConfig{
		Addr:    utils.Ip2Uint32(outerIp),
		Ifindex: uint16(outIfindex),
		Mac:     HandleNullMac(outerMac),
	}
	err = obj.xdp_proxyMaps.RedirectMap.Update(unsafe.Pointer(&key0), unsafe.Pointer(&prc), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	var key1 int32 = 1 // proxy eth
	var prd = xdp_proxyProxyRedirectConfig{
		Addr:    utils.Ip2Uint32(eth.ProxyIp),
		Port:    uint32(opt.Port),
		Ifindex: uint16(eth.ProxyIf),
		Mac:     HandleNullMac(eth.ProxyMac),
	}
	err = obj.xdp_proxyMaps.RedirectMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&prd), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	proxyEgress, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.xdp_proxyPrograms.XdpLb,
		Interface: outIfindex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		panic(err)
	}

	<-ctx.Done()

	proxyEgress.Close()
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
