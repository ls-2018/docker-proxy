#include "dns_helper.h"

struct dns_peer {
    struct dns_question dq;
    u32 ip[DNS_MAX_ANCOUNT];
    u32 ttl[DNS_MAX_ANCOUNT];
};
struct dns_peer *_ __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_ttl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_question);
    __type(value, struct cache_record);
    __uint(max_entries, 65536);
} dns_a_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

void *handle_ans(void *cursor, void *data_end) {
    struct dns_response *response = (void *)cursor;
    char *dns_addr = cursor + sizeof(struct dns_response);
    if ((void *)dns_addr > data_end) {
        return 0;
    }
    u16 len = bpf_ntohs(response->data_length);
    char ip_str[65];
    if (bpf_ntohs(response->record_type) == 1 && len == 4) // A
    {
        for (int j = 0; j < len; j++) {
            ip_str[j] = dns_addr[j];
        }
        ip_str[len * 8] = '\0';
    }
    else {
        return 0;
    }
    return dns_addr + len;
}

SEC("classifier/ingress")
int parse_dns_a(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    // DNS payload
    unsigned char *dns = (unsigned char *)(udph + 1);
    unsigned char *cursor = dns + DNS_HLEN;

    if (cursor > (unsigned char *)data_end)
        return TC_ACT_OK;
    struct dns_header *dr = (struct dns_header *)dns;
    __u16 transaction_id = bpf_ntohs(dr->transaction_id);
    __u16 qdcount = bpf_ntohs(dr->q_count);
    if (qdcount != 1) {
        return TC_ACT_OK;
    }

    __u16 ancount = bpf_ntohs(dr->ans_count);
    __u16 flags = bpf_ntohs(*(__u16 *)(dns + 2)); // ID 后面 2 字节是 flags
    __u16 qr = (flags & 0x80 >> 15);
//    __u16 qr = (flags >> 15) & 0x1;  // 5.15.0 不支持

    if (qr != 1) {
        return TC_ACT_OK;
    }

    struct dns_question dq;
    struct cache_record cr_tmp;

    __builtin_memset(&dq, 0, sizeof(dq));
    __builtin_memset(&cr_tmp, 0, sizeof(cr_tmp));
    void *question_header = cursor;
    void *query_name_end = skip_name(cursor, data_end);
    if (!query_name_end) {
        return TC_ACT_OK;
    }
    if ((unsigned char *)query_name_end + 4 > (unsigned char *)data_end) {
        return TC_ACT_OK;
    }

    __u16 qtype = bpf_ntohs(*(__u16 *)(query_name_end));
    __u16 qclass = bpf_ntohs(*(__u16 *)(query_name_end + 2));
    if (qtype != 1) {
        return TC_ACT_OK;
    }
    if (qclass != 1) {
        return TC_ACT_OK;
    }

    {
        __builtin_memset(&dq, 0, sizeof(dq));
        __builtin_memset(&cr_tmp, 0, sizeof(cr_tmp));

        __u16 qtype = bpf_ntohs(*(__u16 *)(query_name_end));
        __u16 qclass = bpf_ntohs(*(__u16 *)(query_name_end + 2));

        dq.record_type = qtype;
        dq.class = qclass;
        unsigned char *name_src = (unsigned char *)question_header;
        int name_len = (int)((unsigned char *)query_name_end - (unsigned char *)question_header);

        if (name_len > MAX_DNS_NAME_LENGTH) {
            name_len = MAX_DNS_NAME_LENGTH;
        }
        for (int i = 0; i < MAX_DNS_NAME_LENGTH; i++) {
            if (i >= name_len) {
                break;
            }
            if ((void *)(name_src + i + 1) > data_end) {
                break;
            }
            dq.name[i] = name_src[i];
        }
    }
    struct cache_record *cr;
    cr = bpf_map_lookup_elem(&dns_a_cache, &dq);
    if (!cr) {
        return TC_ACT_OK;
    }

    unsigned char *answer_header = (unsigned char *)query_name_end + 4; // qtype + qclass

    int found = 0;
    // Answer section
    for (int i = 0; i < DNS_MAX_ANCOUNT; i++) {
        if (answer_header + DNS_RESPONSE_HLEN > (unsigned char *)data_end) {
            goto ret;
        }
        struct dns_response *dr = (struct dns_response *)answer_header;

        __u16 type = bpf_ntohs(dr->record_type);
        __u16 class = bpf_ntohs(dr->class);
        __u32 ttl = bpf_ntohl(dr->ttl);
        __u16 rdlen = bpf_ntohs(dr->data_length);
        if (rdlen != 4) {
            goto ret;
        }
        answer_header += DNS_RESPONSE_HLEN;
        if (answer_header + rdlen > (unsigned char *)data_end) {
            goto ret;
        }
        if (rdlen == 4) { // A record
            __u32 ip;
            __builtin_memcpy(&ip, answer_header, 4);
            cr_tmp.ip[i] = ip;
            __u64 unix_secs = bpf_ktime_get_ns();
            cr_tmp.ttl[i] = ttl;
            u32 expire_time = unix_secs / 1000000000 + ttl;
            bpf_map_update_elem(&ip_ttl, &ip, &expire_time, BPF_ANY);
            //            bpf_printk("type:%d class:%d ip:%pI4 ttl:%d cs:%lld ttl:%lld ", type, class, &ip, ttl, unix_secs, ttl);
            found = 1;
        }
        answer_header += rdlen;
    }

ret:
    if (found) {
        bpf_map_update_elem(&dns_a_cache, &dq, &cr_tmp, BPF_ANY);

        struct dns_peer *event;
        int err = 0;

        guard_ringbuf(&events, event, &err);
        if (event) {
            event->dq.class = dq.class;
            event->dq.record_type = dq.record_type;
            event->dq.record_type = dq.record_type;
            __builtin_mempcpy(&event->dq.name, dq.name, sizeof(dq.name));
            __builtin_mempcpy(&event->ip, cr_tmp.ip, sizeof(cr_tmp.ip));
            __builtin_mempcpy(&event->ttl, cr_tmp.ttl, sizeof(cr_tmp.ttl));
        }
    }
    return TC_ACT_OK;
}
