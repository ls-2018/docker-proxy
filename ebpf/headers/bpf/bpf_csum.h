#ifndef __BPF_CSUM_H_
#define __BPF_CSUM_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

static __always_inline __u16 csum_fold_helper(__wsum sum) {
    sum = (sum & 0xffff) + (sum >> 16);
    return ~((sum & 0xffff) + (sum >> 16));
}

static __always_inline __u16 ipv4_csum(void *data_start, int data_size) {
    __wsum sum = 0;
    sum = bpf_csum_diff(0, 0, data_start, data_size, 0);
    return csum_fold_helper(sum);
}

// # define TCP_MAX_BITS 1480
// __attribute__((always_inline))
// static  __u16 csum_fold_helper(__u64 csum)
// {
//     int i;
// #pragma unroll
//     for (i = 0; i < 4; i++)
//     {
//         if (csum >> 16)
//             csum = (csum & 0xffff) + (csum >> 16);
//     }
//     return ~csum;
// }
// __attribute__((always_inline))
// static __u16 iph_csum(struct iphdr *iph){
//     iph->check = 0;
//     unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
//     return csum_fold_helper(csum);
// }
//
#define TCP_MAX_BITS 1480
static __u16 ipv4_l4_csum(void *data_start, __u32 data_size, struct iphdr *iph, void *data_end) {
    __u64 csum_buffer = 0;
    __u16 *buf = (void *)data_start;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u32)iph->protocol << 8;
    csum_buffer += data_size;

    // Compute checksum on udp/tcp header + payload
    for (int i = 0; i < TCP_MAX_BITS; i += 2) {
        if ((void *)(buf + 1) > data_end) {
            break;
        }
        csum_buffer += *buf;
        buf++;
    }
    if ((void *)buf + 1 <= data_end) {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    return csum_fold_helper(csum_buffer);
}

// __update_icmp_checksum(icmph, sizeof(*icmph) + icmp_payload);
static __always_inline void __update_icmp_checksum(struct icmphdr *icmph, int size) {
    icmph->checksum = 0;
    icmph->checksum = ipv4_csum(icmph, size);
}

static __always_inline void __update_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    iph->check = ipv4_csum(iph, sizeof(*iph));
}

#endif // __BPF_CSUM_H_