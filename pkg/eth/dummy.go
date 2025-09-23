package eth

import (
	"docker-proxy/pkg/log"

	"github.com/vishvananda/netlink"
)

const ProxyName = "docker-proxy"

// ProxyIp 与 eBPF 重定向一致，确保发往该 IP:port 的包被内核认为是本机
var ProxyIp = "10.5.1.9"

// ProxyMac 由系统分配后回读，避免与实际不一致
var ProxyMac = ""
var ProxyIf = 0

func InitDev() {
	link, err := netlink.LinkByName(ProxyName)
	if err == nil {
		netlink.LinkSetDown(link)
		netlink.LinkDel(link)
	}

	// 1. 创建 dummy 网卡
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: ProxyName,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		log.L.Fatalf("failed to add dummy: %v", err)
	}

	// 获取刚创建的网卡
	link, err = netlink.LinkByName(ProxyName)
	if err != nil {
		log.L.Fatalf("failed to get dev: %v", err)
	}
	ProxyIf = int(link.Attrs().Index)

	// 2. 添加 IP 地址 10.1.5.9/32
	addr, err := netlink.ParseAddr(ProxyIp + "/32")
	if err != nil {
		log.L.Fatalf("failed to parse addr: %v", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		log.L.Fatalf("failed to add addr: %v", err)
	}

	// 3. 启用网卡
	if err := netlink.LinkSetUp(link); err != nil {
		log.L.Fatalf("failed to set link up: %v", err)
	}

	// 4. 读取实际 MAC，供 eBPF 使用
	link, err = netlink.LinkByName(ProxyName)
	if err != nil {
		log.L.Fatalf("failed to get dev after up: %v", err)
	}
	if ha := link.Attrs().HardwareAddr; ha != nil {
		ProxyMac = ha.String()
	}
	log.L.Printf("%s up, ip=%s, mac=%s", ProxyName, ProxyIp, ProxyMac)
}
