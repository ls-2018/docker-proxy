#include "tcp_helper.h"
#include "xdp_csum.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
} ip_ttl SEC(".maps");

struct proxy_redirect_config {
    __u32 addr;
    __u32 port;
    __u16 ifindex;
    __u8 mac[6];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, struct proxy_redirect_config);
} redirect_map SEC(".maps");

struct conntrack_entry {
    __u32 ip; // net edain
    __u16 port;
    __u8 mac[6];
    u32 ttl;
} __attribute__((packed));

// a->b
// a->c    {a:b}
// c->a
// a->b

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, struct conntrack_entry);
    __type(value, struct conntrack_entry);
} conn_map SEC(".maps");

__attribute__((always_inline)) static void l4_ingress(struct iphdr* iph, struct tcphdr* tcph, struct conntrack_entry* src, struct conntrack_entry* dst) {
    // net edian allready
    iph->saddr = (src->ip);
    tcph->source = (src->port);
    iph->daddr = (dst->ip);
    tcph->dest = (dst->port);
}

__attribute__((always_inline)) static void l4_egress(struct iphdr* iph, struct tcphdr* tcph, struct conntrack_entry* src, struct conntrack_entry* dst) {
    // net edian allready
    iph->saddr = (src->ip);
    tcph->source = (src->port);
    iph->daddr = (dst->ip);
    tcph->dest = (dst->port);
}

__attribute__((always_inline)) static int gen_mac(struct xdp_md* ctx, struct ethhdr* eth, struct iphdr* iph, unsigned char n_s[ETH_ALEN], unsigned char n_d[ETH_ALEN]) {
    __builtin_memcpy(eth->h_source, n_s, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, n_d, ETH_ALEN);
    return XDP_TX;
}

SEC("xdp") // 只能处理进流量
int xdp_lb(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr* iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr* tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
    if (tcp_len > TCP_MAX_BITS) {
        return XDP_DROP;
    }
    int action = XDP_PASS;
    bpf_printk("asdas from %pI4:%d -> %pI4:%d ", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    __u32* ttl_value = bpf_map_lookup_elem(&ip_ttl, &iph->daddr);
    if (ttl_value) {
        if (tcph->dest != 443) {
            return XDP_DROP;
        }

        struct conntrack_entry source_ce = {.ip = iph->saddr, .port = tcph->source};
        __builtin_memcpy(&source_ce.mac, eth->h_source, ETH_ALEN);

        struct conntrack_entry dest_ce = {.ip = iph->daddr, .port = tcph->dest};
        __builtin_memcpy(&dest_ce.mac, eth->h_dest, ETH_ALEN);
        dest_ce.ttl = bpf_ktime_get_ns() / 1000000000; // just for clean

        bpf_map_update_elem(&conn_map, &source_ce, &dest_ce, BPF_ANY);

        __u32 pkey1 = 1;
        struct proxy_redirect_config* proxy_eth = bpf_map_lookup_elem(&redirect_map, &pkey1);
        if (proxy_eth == NULL) {
            return XDP_PASS;
        }
        bpf_printk("query   from %pI4:%d -> %pI4:%d to %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest), &iph->saddr, bpf_ntohs(tcph->source), &proxy_eth->addr, proxy_eth->port);

        struct conntrack_entry proxy = {.ip = bpf_htonl(proxy_eth->addr), .port = bpf_htons(proxy_eth->port)};
        __builtin_memcpy(&proxy.mac, &proxy_eth->mac, ETH_ALEN);

        l4_ingress(iph, tcph, &source_ce, &proxy);
        action = gen_mac(ctx, eth, iph, eth->h_source, proxy_eth->mac);
    }
    else {
        // a->b
        // a->c    {a:b}
        // c->a
        // a->b
        struct conntrack_entry dest_ce = {.ip = iph->daddr, .port = tcph->dest};
        __builtin_memcpy(&dest_ce.mac, eth->h_dest, ETH_ALEN);

        struct conntrack_entry* raw_dest = bpf_map_lookup_elem(&conn_map, &dest_ce);
        if (raw_dest == NULL) {
            return XDP_PASS;
        }
        l4_egress(iph, tcph, &dest_ce, raw_dest);
        action = gen_mac(ctx, eth, iph, dest_ce.mac, raw_dest->mac);
    }
    iph->check = iph_csum(iph);
    tcph->check = ipv4_l4_csum(tcph, tcp_len, iph, data_end);
    return action;
}