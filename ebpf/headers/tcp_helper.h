#include "bpf_all.h"
#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define TCP_HLEN sizeof(struct tcphdr)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define TCP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

#define UDP_SPT_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, source))
#define UDP_DPT_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, dest))
#define UDP_CSUM_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check))

#define DNS_HLEN sizeof(struct dns_header)
#define DNS_RESPONSE_HLEN sizeof(struct dns_response)

struct sk_buff;
unsigned long long load_byte(void* skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void* skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void* skb, unsigned long long off) asm("llvm.bpf.load.word");

#define IS_PSEUDO 0x10
#define ETH_ALEN 6 /* Octets in one ethernet addr */

static inline void set_ip_tos(struct __sk_buff* skb, __u8 new_tos) {
    __u8 old_tos = load_byte(skb, TOS_OFF);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, bpf_htons(old_tos), bpf_htons(new_tos), 2);
    bpf_skb_store_bytes(skb, TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_tcp_ip_src(struct __sk_buff* skb, __u32 new_ip) {
    __u32 old_ip = _htonl(load_word(skb, IP_SRC_OFF));

    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
}

static inline int set_tcp_ip_dest(struct __sk_buff* skb, __u32 new_ip) { // new_ip net order
    __u32 old_ip = load_word(skb, IP_DST_OFF);
    if (bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0) < 0) {
        return -1;
    }
    // flags: usually 0 for 32-bit replacement (implementation dependent)
    if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, 0) < 0) {
        return -1;
    }
    // change pseudo header dst ip: it's a 32-bit change; flags for bpf_l4_csum_replace
    // For port changes you'd use flags = BPF_F_PSEUDO_HDR or size=2; behavior depends on kernel
    // Here we replace 32-bit ip part; pass 0 for flags (may need kernel-specific flags)
    if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, 0) < 0) {
        return -1;
    };
    return 0;
}

static inline int set_tcp_dest_port(struct __sk_buff* skb, __u16 new_port) {
    __u16 old_port = bpf_htons(load_half(skb, TCP_DPORT_OFF));
    if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, 0) < 0) {
        return -1;
    }
    if (bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0) < 0) {
        return -1;
    }
    return 0;
}

static inline void set_tcp_src_port(struct __sk_buff* skb, __u16 new_port) {
    __u16 old_port = bpf_htons(load_half(skb, TCP_PORT_OFF));

    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, TCP_PORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline void set_dst_mac(struct __sk_buff* skb, char* mac) {
    bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 1);
}

static inline void swap_mac_addresses(struct __sk_buff* skb) {
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, 6);
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, 6);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, 6, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, 6, 0);
}

static inline void swap_ip_addresses(struct __sk_buff* skb) {
    u32 src_ip;
    u32 dst_ip;
    bpf_skb_load_bytes(skb, IP_SRC_OFF, &src_ip, 4);
    bpf_skb_load_bytes(skb, IP_DST_OFF, &dst_ip, 4);

    // 交换IP地址时，直接交换网络字节序的值
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, dst_ip, src_ip, sizeof(src_ip));
    bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);
}

static inline void swap_upd_port(struct __sk_buff* skb) {
    u16 src;
    u16 dst;
    bpf_skb_load_bytes(skb, UDP_SPT_OFF, &src, 2);
    bpf_skb_load_bytes(skb, UDP_DPT_OFF, &dst, 2);

    // 交换UDP端口时，直接交换网络字节序的值
    bpf_skb_store_bytes(skb, UDP_SPT_OFF, &dst, sizeof(dst), 0);
    bpf_skb_store_bytes(skb, UDP_DPT_OFF, &src, sizeof(src), 0);

    // 更新UDP的checksum为0, UDP不强制要求checksum
    u16 chkSum = 0;
    bpf_skb_store_bytes(skb, UDP_CSUM_OFF, &chkSum, sizeof(chkSum), 0);
}

static inline void changeLength(struct __sk_buff* skb, uint16_t iplen, uint16_t udplen) {
    u16 old_iplen;
    u16 old_udplen;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &old_iplen, 2);
    bpf_skb_load_bytes(skb, ETH_HLEN + IP_HLEN + offsetof(struct udphdr, len), &old_udplen, 2);

    // 转换为主机字节序进行比较，然后转换回网络字节序存储
    u16 iplen_net = bpf_htons(iplen);
    u16 udplen_net = bpf_htons(udplen);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_iplen, iplen_net, sizeof(iplen));
    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &iplen_net, sizeof(iplen), 0);
    bpf_skb_store_bytes(skb, ETH_HLEN + IP_HLEN + offsetof(struct udphdr, len), &udplen_net, sizeof(udplen), 0);
}
