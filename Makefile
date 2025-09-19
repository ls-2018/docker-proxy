ARCH := $(shell uname -m)
# https://github.com/iovisor/bcc/blob/f954eb1ec60a34ddc59535646be58085163e568f/src/cc/frontends/clang/kbuild_helper.cc#L51
ifeq ($(ARCH), x86_64)
    ARCH_TYPE := x86
endif
ifeq ($(ARCH), aarch64)
    ARCH_TYPE := arm64
endif
ifeq ($(ARCH), arm64)
    ARCH_TYPE := arm64
endif

generate:
	apt install docker.io net-tools tcpdump -y
	ip link set docker-proxy down || true
	ip link delete docker-proxy || true
#	ip link add name docker-proxy type dummy
#	ip addr add 10.1.5.10/32 dev docker-proxy
#	ip link set dev docker-proxy address 08:00:27:6f:f7:c0
#	ip link set docker-proxy up
	sysctl -w net.ipv6.conf.all.disable_ipv6=1 || true
	sysctl -w net.ipv6.conf.default.disable_ipv6=1 || true
	TARGET_ARCH=__TARGET_ARCH_${ARCH_TYPE} go generate ./...

build-assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "./assets/probe.go" $(wildcard ./ebpf/bin/*.o)

dlv: generate
	go build -gcflags "all=-N -l" -o docker-proxy .
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./docker-proxy