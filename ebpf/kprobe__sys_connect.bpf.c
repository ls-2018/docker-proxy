#include "bpf_all.h"

#define AF_INET 2

struct proxy_redirect_config {
    __u32 addr;
    __u16 port;
    __u16 ifindex;
    __u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10); //    0: hook eth  1: proxy eth
    __type(key, __u32);
    __type(value, struct proxy_redirect_config);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
} ip_ttl SEC(".maps");

SEC("kprobe/__sys_connect")
int kprobe_connect(struct pt_regs *ctx) {
    struct sockaddr_in addr;
    struct sockaddr_in *user_addr;
    bpf_probe_read_user(&addr, sizeof(addr), (void *)PT_REGS_PARM2(ctx));

    if (addr.sin_family == AF_INET && addr.sin_port == __builtin_bswap16(443)) {
        __u32 *ttl_value;
        ttl_value = bpf_map_lookup_elem(&ip_ttl, &addr.sin_addr.s_addr);
        if (!ttl_value) {
            return 0;
        }

        __u32 pkey1 = 1;
        struct proxy_redirect_config *proxy_eth = bpf_map_lookup_elem(&redirect_map, &pkey1);
        if (proxy_eth == NULL) {
            return TC_ACT_OK;
        }
        bpf_printk("%pI4:%d -> %pI4:%d ", &addr.sin_addr.s_addr, bpf_ntohs(addr.sin_port), &proxy_eth->addr, bpf_ntohs(proxy_eth->port));

        addr.sin_addr.s_addr = proxy_eth->addr;
        addr.sin_port = proxy_eth->port;

        // 写回用户空间参数
        user_addr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
        bpf_probe_write_user(user_addr, &addr, sizeof(addr));
    }

    return 0;
}