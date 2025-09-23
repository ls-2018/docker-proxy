package main

import (
	"context"
	"docker-proxy/pkg/cfg"
	sysconnect "docker-proxy/pkg/ebpf/krpobe__sys_connect"
	sklookup "docker-proxy/pkg/ebpf/sk-lookup"
	tcdnsparse "docker-proxy/pkg/ebpf/tc-dns-parse"
	tcdnsreplace "docker-proxy/pkg/ebpf/tc-dns-replace"
	tcproxy "docker-proxy/pkg/ebpf/tc-proxy"
	xdpproxy "docker-proxy/pkg/ebpf/xdp-proxy"
	"docker-proxy/pkg/eth"
	"docker-proxy/pkg/http"
	"docker-proxy/pkg/kernel"
	"docker-proxy/pkg/log"
	"docker-proxy/pkg/systemd"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	opt     = cfg.Options{}
	cmd     = &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			Run(opt)
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	cmd.PersistentFlags().Uint64Var(&opt.Port, "port", 12345, "back-end proxy service")
	cmd.PersistentFlags().StringVar(&opt.Dest, "dest", "dockerproxy.zetyun.cn", "backend docker speed service")
	cmd.PersistentFlags().StringArrayVar(&opt.Domains, "domains", []string{"docker.io", "registry-1.docker.io"}, "addresses requiring acceleration")
	cmd.PersistentFlags().StringArrayVar(&opt.Service, "services", []string{"docker", "containerd"}, "after adding the system certificate, you need to restart the CRI advanced backend program.")
	cmd.PersistentFlags().StringVar(&opt.PinPath, "pin-path", "/sys/fs/bpf/docker-proxy", "bpf pin path")
	cmd.PersistentFlags().IntVar(&opt.Method, "method", 1, strings.TrimSpace(`
0: dns replace, client -> proxy				(TODO)
1: dns parse + kprobe/__sys_connect			(✅)
2: dns parse + sklookup 					(❌ only handle tc ingress)
3: dns parse + tcproxy  					(bug: DNAT、SNAT)
4: dns parse + xdpproxy 					(❌ only handle dev ingress)`))
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cobra")
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	cmd.Execute()
}

func Run(opt cfg.Options) {
	os.MkdirAll(opt.PinPath, 0755)
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
	switch opt.Method {
	case 0:
		go tcdnsreplace.Load(ctx)
	default:
		go tcdnsparse.Load(ctx, opt, func() {
			switch opt.Method {
			case 1:
				go sysconnect.Load(ctx, opt)
			case 2:
				go sklookup.Load(ctx, opt) // 不支持
			case 3:
				go tcproxy.Load(ctx, opt)
			case 4:
				go xdpproxy.Load(ctx, opt)
			default:
				log.L.Fatalf("unknown hook method: %d", opt.Method)
			}
		})
	}

	svc := http.Serve(opt)
	systemd.Restart(opt.Service)
	<-stopper
	log.L.Println("Received signal, exiting program..")
	cancelFunc()
	svc.Shutdown(ctx)
	eth.CleanDev()
}
