#include "bpf_all.h"

/* Define constants not captured by BTF */
#define BPF_F_CURRENT_NETNS (-1L)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP (0x0800)

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
    //    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
} ip_ttl SEC(".maps");

/* Fill 'tuple' with L3 info, and attempt to find L4. On fail, return NULL. */
static inline struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct bpf_sock_tuple *result;
    struct ethhdr *eth;
    __u64 tuple_len;
    __u8 proto = 0;

    eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end)
        return NULL;

    /* Only support ipv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;

    struct iphdr *iph = (struct iphdr *)(data + sizeof(*eth));
    if ((void *)(iph + 1) > data_end)
        return NULL;
    if (iph->ihl != 5)
        /* Options are not supported */
        return NULL;
    //    __u64      ihl_len = iph->ihl * 4;
    proto = iph->protocol;
    result = (struct bpf_sock_tuple *)&iph->saddr;

    /* Only support TCP */
    if (proto != IPPROTO_TCP)
        return NULL;

    return result;
}

static inline int handle_tcp(struct __sk_buff *skb, struct bpf_sock_tuple *tuple) {
    struct bpf_sock_tuple server = {};
    struct bpf_sock *sk;
    const int zero = 0;
    size_t tuple_len;
    int ret;

    tuple_len = sizeof(tuple->ipv4);
    if ((void *)tuple + tuple_len > (void *)(long)skb->data_end)
        return TC_ACT_OK;

    u32 *ttl;
    ttl = bpf_map_lookup_elem(&ip_ttl, &tuple->ipv4.daddr);
    if (!ttl)
        return TC_ACT_OK;
    /* Reuse existing connection if it exists */
    __u32 pkey1 = 1;
    struct proxy_redirect_config *proxy_eth = bpf_map_lookup_elem(&redirect_map, &pkey1);
    if (proxy_eth == NULL) {
        return TC_ACT_OK;
    }

    /* Lookup port server is listening on */
    server.ipv4.saddr = tuple->ipv4.saddr;
    server.ipv4.daddr = proxy_eth->addr;
    server.ipv4.sport = tuple->ipv4.sport;
    server.ipv4.dport = proxy_eth->port;
    bpf_printk("lookup tcp  %pI4:%d -> %pI4:%d", &server.ipv4.saddr,bpf_ntohs( server.ipv4.sport),&server.ipv4.daddr,bpf_ntohs(server.ipv4.dport));


    sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
        if (sk->state != BPF_TCP_LISTEN) {
            goto assign; /* 如果找到匹配的 socket，跳转到 assign 段进行处理 */
        }
        bpf_sk_release(sk);
    }


    sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if (!sk) {
        return TC_ACT_OK; // ToDo 卡在了这里
    }
    if (sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        return TC_ACT_OK;
    }

assign:
    bpf_printk("f");
    ret = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);
    return ret;
}

SEC("tc")
int tproxy(struct __sk_buff *skb) {
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int ret = 0;

    tuple = get_tuple(skb);
    if (!tuple)
        return TC_ACT_OK;

    handle_tcp(skb, tuple);
    return TC_ACT_OK;
}
// 宏常量	            数值	含义
// TC_ACT_OK	        0	继续正常处理（包不受影响）
// TC_ACT_SHOT	    2	丢弃数据包 (drop)
// TC_ACT_UNSPEC	    -1	未指定，等同于 OK
// TC_ACT_PIPE	    3	继续下一个 action
// TC_ACT_STOLEN	    4	包已被“偷走”，不再交给后续处理
// TC_ACT_QUEUED	    5	包已排队 (比如 qdisc)
// TC_ACT_REDIRECT	7	重定向到其他设备