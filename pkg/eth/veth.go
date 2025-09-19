package eth

import (
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const ProxyName = "docker-proxy"

// ProxyIp 与 eBPF 重定向一致，确保发往该 IP:port 的包被内核认为是本机
const ProxyIp = "10.5.1.10"
const InnerGateWay = "10.5.1.11"

// ProxyMac 由系统分配后回读，避免与实际不一致
var ProxyMac = ""
var ProxyIf = 0

func CreateVethPair() {
	// 必须锁定 OS 线程，因为 netns 操作需要在同一线程中
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fmt.Println(netns.DeleteNamed(ProxyName))
	// 创建两个命名空间
	currentNs, err := netns.Get()
	peerNs, err := netns.NewNamed(ProxyName)
	if err != nil {
		log.Fatalf("failed to create peerNs: %v", err)
	}
	defer peerNs.Close()
	defer currentNs.Close()

	// 创建 veth 对
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: ProxyName},
		PeerName:  "eth0",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		log.Fatalf("failed to add veth: %v", err)
	}

	// 获取 veth 设备
	hostPeer, err := netlink.LinkByName(ProxyName)
	if err != nil {
		log.Fatalf("failed to get %s: %v", ProxyName, err)
	}
	ProxyMac = hostPeer.Attrs().HardwareAddr.String()
	ProxyIf = hostPeer.Attrs().Index
	innerPeer, err := netlink.LinkByName("eth0")
	if err != nil {
		log.Fatalf("failed to get eth0: %v", err)
	}

	// 将 docker-proxy 移动到 currentNs
	if err := netlink.LinkSetNsFd(hostPeer, int(currentNs)); err != nil {
		log.Fatalf("failed to set %s to currentNs: %v", ProxyName, err)
	}

	// 将 eth0 移动到 peerNs
	if err := netlink.LinkSetNsFd(innerPeer, int(peerNs)); err != nil {
		log.Fatalf("failed to set eth0 to peerNs: %v", err)
	}

	// 配置 IP 和启动接口
	configureLink := func(ns netns.NsHandle, ifName, ipAddr string) {
		// 保存当前 ns
		origNS, err := netns.Get()
		if err != nil {
			log.Fatalf("failed to get current ns: %v", err)
		}
		defer origNS.Close()

		// 切换到目标 ns
		if err := netns.Set(ns); err != nil {
			log.Fatalf("failed to set ns: %v", err)
		}
		defer netns.Set(origNS)

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			log.Fatalf("failed to get link %s: %v", ifName, err)
		}

		addr, err := netlink.ParseAddr(ipAddr)
		if err != nil {
			log.Fatalf("failed to parse addr %s: %v", ipAddr, err)
		}

		if err := netlink.AddrAdd(link, addr); err != nil {
			log.Fatalf("failed to add addr: %v", err)
		}

		if err := netlink.LinkSetUp(link); err != nil {
			log.Fatalf("failed to set link up: %v", err)
		}
		fmt.Printf("%s configured with %s\n", ifName, ipAddr)
	}

	configureLink(currentNs, ProxyName, ProxyIp+"/24")
	configureLink(peerNs, "eth0", InnerGateWay+"/24")

	// 在 docker-proxy 命名空间中设置默认路由，下一跳为 eth0 的 IP
	func() {
		origNS, err := netns.Get()
		if err != nil {
			log.Fatalf("failed to get current ns: %v", err)
		}
		defer origNS.Close()

		if err := netns.Set(peerNs); err != nil {
			log.Fatalf("failed to set ns: %v", err)
		}
		defer netns.Set(origNS)

		route := &netlink.Route{
			Gw: net.ParseIP(InnerGateWay),
		}

		link, err := netlink.LinkByName("eth0")
		if err != nil {
			log.Fatalf("failed to get link eth0: %v", err)
		}
		route.LinkIndex = link.Attrs().Index

		if err := netlink.RouteAdd(route); err != nil {
			log.Fatalf("failed to add default route: %v", err)
		}
		fmt.Println("Default route added in docker-proxy ns via eth0")
	}()

	fmt.Println("Veth pair and namespaces setup done!")
}
