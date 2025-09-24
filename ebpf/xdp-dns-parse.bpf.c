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

static __always_inline void *handle_ans(void *cursor, void *data_end) {
    struct dns_response *response = (void *)cursor;
    char *dns_addr = cursor + sizeof(struct dns_response);
    if ((void *)dns_addr > data_end) {
        return 0;
    }
    u16 len = bpf_ntohs(response->data_length);
    char ip_str[65];
    if (bpf_ntohs(response->record_type) == 1 && len == 4) {
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

SEC("xdp")
int xdp_parse_dns_a(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    struct udphdr *udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
    if (udph->source != bpf_htons(53)) {
        return XDP_PASS;
    }

    unsigned char *dns = (unsigned char *)(udph + 1);
    unsigned char *cursor = dns + DNS_HLEN;

    if (cursor > (unsigned char *)data_end)
        return XDP_PASS;

    struct dns_header *dhr = (struct dns_header *)dns;
    __u16 transaction_id = bpf_ntohs(dhr->transaction_id);
    __u16 qdcount = bpf_ntohs(dhr->q_count);

    if (qdcount != 1) {
        return XDP_PASS;
    }

    __u16 ancount = bpf_ntohs(dhr->ans_count);

    struct dns_question dq;
    struct cache_record cr_tmp;

    __builtin_memset(&dq, 0, sizeof(dq));
    __builtin_memset(&cr_tmp, 0, sizeof(cr_tmp));

    void *question_header = cursor;
    void *query_name_end = skip_name(cursor, data_end);
    if (!query_name_end) {
        return XDP_PASS;
    }
    if ((unsigned char *)query_name_end + 4 > (unsigned char *)data_end) {
        return XDP_PASS;
    }
    __u16 qtype = bpf_ntohs(*(__u16 *)(query_name_end));
    __u16 qclass = bpf_ntohs(*(__u16 *)(query_name_end + 2));
    if (qtype != 1) {
        return XDP_PASS;
    }
    if (qclass != 1) {
        return XDP_PASS;
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
        return XDP_PASS;
    }

    unsigned char *answer_header = (unsigned char *)query_name_end + 4;

    int found = 0;

    __u16 rdlen;
    __u32 ttl;
    __u32 ip;
    struct dns_response *drp;
    u32 expire_time;
    __u64 unix_secs;
    bpf_printk("xdp");
    for (int i = 0; i < DNS_MAX_ANCOUNT; i++) {
        if (answer_header + DNS_RESPONSE_HLEN > (unsigned char *)data_end) {
            goto skip;
        }
        drp = (struct dns_response *)answer_header;
        ttl = bpf_ntohl(drp->ttl);
        rdlen = bpf_ntohs(drp->data_length);
        if (rdlen != 4) {
            goto skip;
        }
        answer_header += DNS_RESPONSE_HLEN;
        if (answer_header + rdlen > (unsigned char *)data_end) {
            goto skip;
        }
        if (rdlen == 4) {
            ip = 0;
            __builtin_memcpy(&ip, answer_header, 4);
            cr_tmp.ip[i] = ip;
            unix_secs = bpf_ktime_get_ns();
            cr_tmp.ttl[i] = ttl;
            expire_time = unix_secs / 1000000000 + ttl;
            bpf_map_update_elem(&ip_ttl, &ip, &expire_time, BPF_ANY);
            found = 1;
            goto skip;
        }
        answer_header += rdlen;
    }
skip:

    if (found) {
        bpf_printk("found");
        bpf_map_update_elem(&dns_a_cache, &dq, &cr_tmp, BPF_ANY);
        bpf_printk("class %d record_type %d", dq.class, dq.record_type);

        struct dns_peer *event;
        event = bpf_ringbuf_reserve(&events, sizeof(struct dns_peer), 0);
        if (!event) {
            return XDP_PASS;
        }
        event->dq.class = dq.class;
        event->dq.record_type = dq.record_type;
        event->dq.record_type = dq.record_type;
        __builtin_mempcpy(&event->dq.name, dq.name, sizeof(dq.name));
        __builtin_mempcpy(&event->ip, cr_tmp.ip, sizeof(cr_tmp.ip));
        __builtin_mempcpy(&event->ttl, cr_tmp.ttl, sizeof(cr_tmp.ttl));
        bpf_ringbuf_submit(event, 0);
    }

    return XDP_PASS;
}
