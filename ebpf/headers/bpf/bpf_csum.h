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