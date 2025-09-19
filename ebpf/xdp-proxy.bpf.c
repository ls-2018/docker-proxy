#include "tcp_helper.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
struct proxy_redirect_config {
    __u32 addr;
    __u32 port;
    __u16 ifindex;
    __u8 mac[6];
} __attribute__((packed));

const struct proxy_redirect_config *unused3 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10); //    0: hook eth  1: proxy eth
    __type(key, __u32);
    __type(value, struct proxy_redirect_config);
    //    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
} ip_ttl SEC(".maps");

// 连接信息结构，用于存储原始目标IP和端口
struct connection_info {
    __u32 addr;
    __u16 port;
    __u8 mac[6];
} __attribute__((packed));

// 连接映射，key是代理服务器的IP+端口，value是原始连接信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_info);
    __type(value, u32);
    __uint(max_entries, 65535);
} connection_map SEC(".maps");

__attribute__((always_inline))
static void l4_ingress(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph) {
    __u32 pkey1 = 1;
    struct proxy_redirect_config *proxy_eth = bpf_map_lookup_elem(&redirect_map, &pkey1);
    if (proxy_eth == NULL) {
        return  ;
    }

   struct connection_info v = {
      .addr = iph->saddr,
      .port = tcph->source
    };
  struct  connection_info k = {
      .addr = bpf_htonl(proxy_eth->addr),
      .port = bpf_htons(proxy_eth->port)
    };

    __builtin_memcpy(&v.mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(&k.mac, proxy_eth->mac, ETH_ALEN);

    bpf_map_update_elem(&connection_map, &k, &v, BPF_ANY); // {c:b}

    // a->b
    // a->c

    iph->daddr = bpf_htonl(proxy_eth->addr);
    tcph->dest = bpf_htons(proxy_eth->port);
    __builtin_memcpy(&eth->h_dest, proxy_eth->mac, ETH_ALEN);


}

int l4_egress(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph) {
    // c->a
    struct connection_info k;
    struct connection_info *v;
    k.addr = iph->saddr;
    k.port = tcph->source;
    __builtin_memcpy(&k.mac, eth->h_source, ETH_ALEN);

    v = bpf_map_lookup_elem(&connection_map, &k);
    if (!v) {
        return XDP_PASS;
    }
    // c->b
    iph->daddr = v->addr;
    tcph->dest = v->addr;
    __builtin_memcpy(&eth->h_dest, v->mac, ETH_ALEN);
    return XDP_TX;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
    if (tcp_len > TCP_MAX_BITS) {
        return XDP_DROP;
    }
    int action = XDP_PASS;
    // 检查目标IP是否在代理列表中
    __u32 *ttl_value;
    ttl_value = bpf_map_lookup_elem(&ip_ttl, &iph->daddr);
    if (ttl_value) {
          bpf_printk("outer");
          l4_ingress(eth, iph, tcph);
    }
    else {
        // 不是所有都处理
//        action = l4_egress(eth, iph, tcph);
    }
    // __sum16 ip_sum = iph->check;
    // iph->check = ipv4_csum((void*)iph,sizeof(struct iphdr));
    // __sum16 tcp_sum = tcph->check;
    // tcph->check = ipv4_l4_csum(tcph, tcp_len, iph, data_end);
    return action;
}
