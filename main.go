package main

import (
	"context"
	"docker-proxy/pkg/cfg"
	tc_dns_parse "docker-proxy/pkg/ebpf/tc-dns-parse"
	tc_proxy "docker-proxy/pkg/ebpf/tc-proxy"

	//tc_proxy "docker-proxy/pkg/ebpf/tc-proxy"
	// 	xdp_proxy "docker-proxy/pkg/ebpf/xdp-proxy"
	"docker-proxy/pkg/eth"
	"docker-proxy/pkg/log"
	"flag"
	"os"
	"os/signal"
	// 	tc_dns_replace "docker-proxy/pkg/ebpf/tc-dns-replace"
	"docker-proxy/pkg/http"
	"docker-proxy/pkg/kernel"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	opt := cfg.Options{}
	flag.Uint64Var(&opt.Port, "port", 12345, "backend docker speed service")
	flag.StringVar(&opt.Dest, "dest", "dockerproxy.zetyun.cn", "backend docker speed service")
	flag.StringVar(&opt.Domains, "domains", "docker.io,registry-1.docker.io", "addresses requiring acceleration, separated by commas")
	flag.StringVar(&opt.PinPath, "pin-path", "/sys/fs/bpf/docker-proxy", "bpf pin path")
	flag.Parse()
	opt.Apply()
	os.MkdirAll(opt.PinPath, 0755)
	// 环境检测
	// 系统内核版本检测
	kv, err := kernel.HostVersion()
	if err != nil {
		log.L.Fatal(err)
	}
	if kv < kernel.VersionCode(4, 15, 0) {
		log.L.Fatalf("Linux Kernel version %v is not supported. Need > 4.15 .", kv)
	} else {
		log.L.Printf("linux kernel version %v check ok!", kv)
	}
	eth.InitDev()
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.L.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	context.Background()
	ctx, cancelFunc := context.WithCancel(context.Background())
	// 	go tc_dns_replace.Load(ctx)
	go tc_dns_parse.Load(ctx, opt, func() {
		//go sk_lookup.Load(ctx, opt)
		go tc_proxy.Load(ctx, opt)
		//go xdp_proxy.Load(ctx, opt)
	})
	svc := http.Serve(opt)

	<-stopper
	log.L.Println("Received signal, exiting program..")
	cancelFunc()
	svc.Shutdown(ctx)

}

func mai4n() {
	// Allow the current process to lock memory for eBPF resources.
	//if err := rlimit.RemoveMemlock(); err != nil {
	//	log.L.Fatal(err)
	//}
	//// 加载编译好的 eBPF 程序
	//objs := tcObjects{}
	//if err := loadTcObjects(&objs, nil); err != nil {
	//	log.L.Fatalf("loading objects: %v", err)
	//}
	//defer objs.Close()
	//
	//// 打开 cgroup
	//cg, err := os.Open("/sys/fs/cgroup/")
	//if err != nil {
	//	log.L.Fatalf("open cgroup: %v", err)
	//}
	//defer cg.Close()
	//
	//// Attach eBPF program
	//l, err := link.AttachCgroup(link.CgroupOptions{
	//	Path:    cg.Name(),
	//	Attach:  ebpf.AttachCGroupInet4Connect, // connect4
	//	Program: objs.RedirectConnect,
	//})
	//if err != nil {
	//	log.L.Fatalf("attach program: %v", err)
	//}
	//defer l.Close()
	//
	//log.L.Println("eBPF cgroup/connect4 program attached. Press Ctrl+C to exit.")
	//select {}
}
