
#ifndef __BPF_CLEANUP_H_
#define __BPF_CLEANUP_H_

#include "bpf_helpers.h"

enum {
    CLEAN_ERR_SUCCESS = 0,
    CLEAN_ERR_INIT = 1,
    CLEAN_ERR_FAILED = 2,
};

#ifndef __cleanup
#    define __cleanup(fn) __attribute__((cleanup(fn)))
#endif

struct guard_spinlock_t {
    struct bpf_spin_lock *lock;
};

static __noinline void guard_spinlock_destructor(struct guard_spinlock_t *guard) {
    bpf_spin_unlock(guard->lock);
}

#define guard_spinlock_constructor(lock)        \
    ({                                          \
        struct guard_spinlock_t guard = {lock}; \
        bpf_spin_lock(lock);                    \
        guard;                                  \
    })

#define guard_spinlock(lock) struct guard_spinlock_t var __cleanup(guard_spinlock_destructor) = guard_spinlock_constructor(lock)

struct guard_ringbuf {
    void *data;
    int *err;
};

static __noinline void guard_ringbuf_destructor(struct guard_ringbuf *guard) {
    if (!guard->data) {
        return;
    }
    if (*guard->err > 0) {
        bpf_ringbuf_discard(guard->data, 0);
    }
    else {
        bpf_ringbuf_submit(guard->data, 0);
    }
}

#define guard_ringbuf_constructor(ringbuf, size, err_addr)  \
    ({                                                      \
        struct guard_ringbuf guard = {};                    \
        guard.err = err_addr;                               \
        guard.data = bpf_ringbuf_reserve(ringbuf, size, 0); \
        guard;                                              \
    })

#define guard_ringbuf(_ring_buf, _data, err_addr)                                                                                 \
    struct guard_ringbuf _g __cleanup(guard_ringbuf_destructor) = guard_ringbuf_constructor(_ring_buf, sizeof(*_data), err_addr); \
    _data = (typeof(_data))_g.data;

#endif // __BPF_CLEANUP_H_