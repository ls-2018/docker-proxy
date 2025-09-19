#include "dns_helper.h"

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
    __u32 original_dst_ip;
    __u16 original_dst_port;
    __u32 original_src_ip;
    __u16 original_src_port;
} __attribute__((packed));

// 10.0.2.15:32185 -> 104.244.43.167:443   [10.0.2.15:32185 -> 127.0.0.1:8888]
// 127.0.0.1:8888 -> 10.0.2.15:32185       [104.244.43.167:443 -> 10.0.2.15:32185]

// 连接映射，key是代理服务器的IP+端口，value是原始连接信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_info);
    __type(value, struct connection_info);
    __uint(max_entries, 65535);
} connection_map SEC(".maps");

static inline int do_dnat(struct __sk_buff *skb, struct proxy_redirect_config *proxy_eth, bool is_tcp) {
    // --- 修改目标 IP ---
    __u32 old_ip = load_word(skb, IP_DST_OFF); // 网络字节序
    __u32 new_ip = proxy_eth->addr;            // 假设 proxy_eth->addr 已经是网络字节序

    if (is_tcp) {
        // TCP 校验和替换
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    }
    else {
        // UDP 校验和替换（UDP 可选）
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    }

    // IP 校验和替换
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));

    // 存储新目标 IP
    bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0);

    // --- 修改目标端口 ---
    __u16 old_port;
    __u16 new_port = bpf_htons(proxy_eth->port);

    if (is_tcp) {
        old_port = load_half(skb, TCP_DPORT_OFF);
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
        bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);
    }
    else {
        old_port = load_half(skb, UDP_DPT_OFF);
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_port, new_port, sizeof(new_port));
        bpf_skb_store_bytes(skb, UDP_DPT_OFF, &new_port, sizeof(new_port), 0);
    }

    // --- 修改目标 MAC ---
    set_dst_mac(skb, (char *)&proxy_eth->mac);

    // --- 最后重定向到目标接口（ingress） ---
    return bpf_redirect((__u32)proxy_eth->ifindex, 1);
}

long redirect_proxy(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr *tcp) {
    // verifier asks for it
    if (tcp == NULL || ip == NULL) {
        return -1;
    }
    __u32 pkey1 = 1;
    struct proxy_redirect_config *proxy_eth = bpf_map_lookup_elem(&redirect_map, &pkey1);
    if (proxy_eth == NULL) {
        return TC_ACT_OK;
    }

    // 记录原始连接信息
    struct connection_info original_conn = {
        .original_dst_ip = ip->daddr,
        .original_dst_port = bpf_ntohs(tcp->dest),
        .original_src_ip = ip->saddr,
        .original_src_port = bpf_ntohs(tcp->source),
    };

    // 创建代理连接信息作为key
    struct connection_info proxy_conn = {
        .original_dst_ip = proxy_eth->addr,
        .original_dst_port = proxy_eth->port,
        .original_src_ip = ip->saddr,
        .original_src_port = bpf_ntohs(tcp->source),
    };

    // 存储连接映射
    bpf_map_update_elem(&connection_map, &proxy_conn, &original_conn, BPF_ANY);
    bpf_printk("query   from %pI4:%d -> %pI4:%d to %pI4:%d -> %pI4:%d", &ip->saddr, bpf_ntohs(tcp->source), &ip->daddr, bpf_ntohs(tcp->dest), &ip->saddr, bpf_ntohs(tcp->source), &proxy_eth->addr, proxy_eth->port);

    /* DNAT */
    //    set_dst_mac(skb, (char *)&proxy_eth->mac);
    //    set_tcp_ip_dest(skb, proxy_eth->addr);
    //    set_tcp_dest_port(skb, proxy_eth->port);
    //    return bpf_redirect((__u32)proxy_eth->ifindex, BPF_F_INGRESS);
    return do_dnat(skb, proxy_eth, 1);
}

SEC("classifier/egress")
int raw_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // check ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    // ip header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // compute ip header length
    __u32 ihl = iph->ihl * 4;
    if ((__u8 *)iph + ihl > (__u8 *)data_end)
        return TC_ACT_OK;

    // tcp header
    struct tcphdr *tcph = (void *)iph + ihl;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(tcph->dest) != 443) {
        return TC_ACT_OK;
    }

    // 检查目标IP是否在代理列表中
    __u32 *ttl_value;
    ttl_value = bpf_map_lookup_elem(&ip_ttl, &iph->daddr);
    if (!ttl_value) {
        return TC_ACT_OK;
    }
    return redirect_proxy(skb, iph, tcph);
}

// 处理返回数据包的函数
long restore_proxy(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr *tcp) {
    if (tcp == NULL || ip == NULL) {
        return -1;
    }

    // 获取外部网卡信息（用于重定向回原主机的 ifindex/mac）
    __u32 pkey0 = 0;
    struct proxy_redirect_config *hook_eth = bpf_map_lookup_elem(&redirect_map, &pkey0);
    if (hook_eth == NULL) {
        return TC_ACT_OK;
    }

    if (bpf_ntohs(tcp->source) != hook_eth->port) {
        return TC_ACT_OK;
    }

    // 创建当前连接信息作为查找key
    struct connection_info current_conn = {
        .original_dst_ip = ip->saddr,                // 返回包的源IP是代理服务器IP
        .original_dst_port = bpf_ntohs(tcp->source), // 返回包的源端口是代理服务器端口
        .original_src_ip = ip->daddr,                // 返回包的目标IP是客户端IP
        .original_src_port = bpf_ntohs(tcp->dest),   // 返回包的目标端口是客户端端口
    };

    bpf_printk("response from %pI4:%d -> %pI4:%d to %pI4:%d -> %pI4:%d", &ip->saddr, bpf_ntohs(tcp->source), &ip->daddr, bpf_ntohs(tcp->dest), &ip->daddr, bpf_ntohs(tcp->dest), &ip->daddr, bpf_ntohs(tcp->dest));

    // 查找原始连接信息
    struct connection_info *original_conn = bpf_map_lookup_elem(&connection_map, &current_conn);
    if (!original_conn) {
        return TC_ACT_OK; // 不是代理连接，直接通过
    }

    /* SNAT */
    set_dst_mac(skb, (char *)&hook_eth->mac);
    set_tcp_ip_src(skb, original_conn->original_dst_ip);
    set_tcp_src_port(skb, original_conn->original_dst_port);
    return bpf_redirect((__u32)hook_eth->ifindex, BPF_F_INGRESS);
}

SEC("classifier/egress")
int proxy_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    // check ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    // ip header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // compute ip header length
    __u32 ihl = iph->ihl * 4;
    if ((__u8 *)iph + ihl > (__u8 *)data_end)
        return TC_ACT_OK;

    // tcp header
    struct tcphdr *tcph = (void *)iph + ihl;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;

    return restore_proxy(skb, iph, tcph);
}

// a:30000 -> b:443 (a egress hook)               ✅
//     a:30000 -> c:8888  (egress 处理)            ✅  [c:8888,a:30000]->[a:30000,b:443]
//     重定向到 c ingress                          ✅
//
// c:8888 -> a:30000 (c egress hook)              ✅
//     b:443 - > a:30000 (egress 处理)             ✅
//         重定向到 a ingress                       ✅
