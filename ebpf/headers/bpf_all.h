#ifndef BPF_ALL_H_
#define BPF_ALL_H_

#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tc.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_tracing_net.h"
#include "bpf/map_helpers.h"
#include "bpf/bpf_kprobe_args.h"
#include "bpf/bpf_cleanup.h"
#include "bpf/bpf_compiler.h"
// #include "debug_log.L.h"

// static __always_inline void bpf_memset(void *dst, __u8 value, __u32 size) {
//     __u8 *ptr = dst;
// #pragma unroll
//     for (__u32 i = 0; i < size; i++) {
//         ptr[i] = value;
//     }
// }

char __license[] SEC("license") = "Dual MIT/GPL";

#endif // BPF_ALL_H_

#ifdef __APPLE_INGORE_WARN
#define SEC(name)
#endif