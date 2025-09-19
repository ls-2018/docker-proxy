#include "dns_helper.h"

struct dns_heap {
    // 构建 dns 响应的临时存储
    char dns_buffer[512];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH); // 主动放置的dns 记录
    __type(key, struct dns_question);
    __type(value, struct a_record);
    __uint(max_entries, 65536);
} dns_a_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_capture_events SEC(".maps");

// 一个 struct event 变量的大小超过了 512 字节，无法放到 BPF 栈上，
// 因此声明一个 size=1 的 per-CPU array 来存放 event 变量
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per-cpu array
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct dns_heap);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct dns_event);
} eventheap SEC(".maps");

static inline void modify_dns_header_response(struct dns_header* dns_header) {
    // Set query response
    dns_header->qr = 1;
    // Set truncated to 0
    // dns_header->tc = 0;
    // Set authorative to zero
    // dns_header->aa = 0;
    // Recursion available
    dns_header->ra = 1;
    // One answer
    dns_header->ans_count = bpf_htons(1);
}

static inline void create_query_response(struct a_record* a, char* dns_buffer, size_t* buf_size) {
    // Formulate a DNS response. Currently defaults to hardcoded query pointer +
    // type a + class in + ttl + 4 bytes as reply.
    struct dns_response* response = (struct dns_response*)&dns_buffer[0];
    response->query_pointer = bpf_htons(0xc00c);
    response->record_type = bpf_htons(0x0001);
    response->class = bpf_htons(0x0001);
    response->ttl = bpf_htonl(a->ttl);
    response->data_length = bpf_htons((uint16_t)sizeof(a->ip_addr));
    *buf_size += sizeof(struct dns_response);
    // Copy IP address
    __builtin_memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(a->ip_addr));
    *buf_size += sizeof(a->ip_addr);
}

static inline int parse_ar(struct __sk_buff* ctx, struct dns_header* dns_header, int query_length, struct ar_hdr* ar) {
    void* data_end = (void*)(long)ctx->data_end;

    // Parse ar record
    ar = (void*)dns_header + query_length + sizeof(struct dns_response);
    if ((void*)ar + sizeof(struct ar_hdr) > data_end) {
        return -1;
    }

    return 0;
}

static inline int create_ar_response(struct ar_hdr* ar, char* dns_buffer, size_t* buf_size) {
    // Check for OPT record (RFC6891)
    if (ar->type == bpf_htons(41)) {
        struct ar_hdr* ar_response = (struct ar_hdr*)&dns_buffer[0];
        // We've received an OPT record, advertising the clients' UDP payload size
        // Respond that we're serving a payload size of 512 and not serving any
        // additional records.
        ar_response->name = 0;
        ar_response->type = bpf_htons(41);
        ar_response->size = bpf_htons(512);
        ar_response->ex_rcode = 0;
        ar_response->rcode_len = 0;

        *buf_size += sizeof(struct ar_hdr);
    }
    else {
        return -1;
    }

    return 0;
}

static int match_a_records(struct dns_question* q, struct a_record* a) {
    struct a_record* record;

    record = bpf_map_lookup_elem(&dns_a_records, q);
    // If record pointer is not zero..
    if (record > 0) {
        a->ip_addr = record->ip_addr;
        a->ttl = record->ttl;
        return 0;
    }
    return -1;
}

static inline int tc_dns_func(struct __sk_buff* skb, int isIngress) {
    uint64_t start = bpf_ktime_get_ns();

    int zero = 0;
    struct dns_heap* e;
    e = bpf_map_lookup_elem(&heap, &zero);
    if (!e) /* can't happen */
    {
        return 0;
    }

    struct dns_event* dns_e = bpf_map_lookup_elem(&eventheap, &zero);
    if (!dns_e) /* can't happen */
    {
        return 0;
    }
    bpf_printk("tc_dns_func handling");

    void* data_end = ctx_ptr(skb->data_end);
    void* data = ctx_ptr(skb->data);
    // Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + ETH_HLEN + IP_HLEN > data_end) {
        return TC_ACT_OK;
    }
    struct ethhdr* eth = data;
    // Ignore packet if ethernet protocol is not IP-based
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    const struct iphdr* ip = data + ETH_HLEN;
    if (ip->protocol == IPPROTO_UDP) {
        // Boundary check for UDP
        if (data + ETH_HLEN + IP_HLEN + UDP_HLEN > data_end) {
            return TC_ACT_OK;
        }
        struct udphdr* udp = data + ETH_HLEN + IP_HLEN;
        // Check if dest port equals 53
        if (udp->dest == bpf_htons(53)) {
            struct dns_header* dns_header;
            // Boundary check for minimal DNS header
            if (data + ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN > data_end) {
                return TC_ACT_OK;
            }
            dns_header = data + ETH_HLEN + IP_HLEN + UDP_HLEN;
            // Check if header contains a standard query
            if (dns_header->qr == 0 && dns_header->opcode == 0) {
                // Get a pointer to the start of the DNS query
                void* query_start = (void*)dns_header + DNS_HLEN;
                // We will only be parsing a single query for now
                struct dns_question q;
                int query_length = 0;
                query_length = parse_query(skb, query_start, &q);
                if (query_length < 1) {
                    return TC_ACT_OK;
                }
                dns_e->r_type = q.record_type;
                __builtin_memcpy(dns_e->name, q.name, sizeof(dns_e->name));
                // Check if query matches a record in our hash table
                struct a_record a_record;
                int res = match_a_records(&q, &a_record);
                if (res < 0) {
                    uint64_t end = bpf_ktime_get_ns();
                    dns_e->ts = end - start;
                    dns_e->is_matched = 0;
                    bpf_perf_event_output(skb, &dns_capture_events, BPF_F_CURRENT_CPU, dns_e, sizeof(*dns_e));
                    return TC_ACT_OK;
                }

                // Change DNS header to a valid response header
                modify_dns_header_response(dns_header);

                // Create DNS response and add to temporary buffer.
                size_t buf_size = 0;
                create_query_response(&a_record, &e->dns_buffer[buf_size], &buf_size);

                // If an additional record is present 如果请求包中有附加记录
                if (dns_header->add_count > 0) {
                    // Parse AR record
                    struct ar_hdr ar;
                    if (parse_ar(skb, dns_header, query_length, &ar) != -1) {
                        // Create AR response and add to temporary buffer
                        create_ar_response(&ar, &e->dns_buffer[buf_size], &buf_size);
                    }
                }

                // // Start our response [query_length] bytes beyond the header
                void* answer_start = (void*)dns_header + DNS_HLEN + query_length;
                // // Determine increment of packet buffer
                int tailadjust = answer_start + buf_size - data;
                // 相应地调整数据包长度
                if (bpf_skb_change_tail(skb, tailadjust, 0) < 0) {
                    // 失败
                    return TC_ACT_OK;
                }
                else {
                    // 因为我们调整了数据包长度，内存地址可能会发生变化。
                    // 重新初始化指针，否则验证器会发出错误提示。
                    data = ctx_ptr(skb->data);
                    data_end = ctx_ptr(skb->data_end);

                    // 将数据从我们的临时缓冲区复制到数据包缓冲区
                    int aOffset = ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN + query_length;
                    bpf_skb_store_bytes(skb, aOffset, &e->dns_buffer[0], buf_size, 0);
                    eth = data;
                    ip = data + ETH_HLEN;
                    udp = data + ETH_HLEN + IP_HLEN;

                    // Do a new boundary check
                    if (data + ETH_HLEN + IP_HLEN + UDP_HLEN > data_end) {
                        return TC_ACT_OK;
                    }
                    // Adjust UDP length and IP length
                    uint16_t iplen = bpf_htons((data_end - data) - ETH_HLEN);
                    uint16_t udplen = bpf_htons((data_end - data) - ETH_HLEN - IP_HLEN);
                    changeLength(skb, iplen, udplen);
                    swap_mac_addresses(skb);
                    swap_ip_addresses(skb);
                    swap_upd_port(skb);

                    uint64_t end = bpf_ktime_get_ns();
                    dns_e->ts = end - start;
                    dns_e->is_matched = 1;
                    bpf_perf_event_output(skb, &dns_capture_events, BPF_F_CURRENT_CPU, dns_e, sizeof(*dns_e));

                    // 将经过修改的 sk_buff 重新定向到同一接口，以便再次进行传输。
                    if (isIngress == 1) {
                        return bpf_redirect(skb->ifindex, 0);
                    }
                    else {
                        return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
                    }
                }
            }
        }
    }

    return TC_ACT_OK;
};

// 网卡收到包 -> 网卡驱动，把 DMA 出来的数据交给内核 -> TC ingress hook → IP/UDP/TCP 协议栈 → 内核 socket 层 → 应用程序
// recv()/read()
SEC("classifier/ingress")
int tc_dns_ingress(struct __sk_buff* ctx) {
    return tc_dns_func(ctx, 1);
}

// 应用程序 send() → 内核 socket 层 → IP/UDP/TCP 协议栈 → TC egress hook → 网卡驱动 → 网卡
SEC("classifier/egress")
int tc_dns_egress(struct __sk_buff* ctx) {
    return tc_dns_func(ctx, 0);
}