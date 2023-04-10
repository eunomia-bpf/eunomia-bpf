#include "simple_prog_3.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]

#define __u64 unsigned long long
#define __u32 unsigned int

#define u32 __u32

#define BPF_MAP_TYPE_RINGBUF ((u32)27)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
static void* (*bpf_ringbuf_reserve)(void* ringbuf,
                                    __u64 size,
                                    __u64 flags) = (void*)131;

static void (*bpf_ringbuf_submit)(void* data, __u64 flags) = (void*)132;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile int const_val_1;
const volatile long long const_val_2;
const volatile char const_val_3[100];

volatile int bss_val_1;
volatile long long bss_val_2;
volatile char bss_val_3[100];

static void memcpy(const char* src, char* dst, int size) {
    for (int i = 0; i < size; i++) {
        dst[i] = src[i];
    }
}

SEC("tp/sched/sched_process_exec")
int handle_exec(void* ctx) {
    /* reserve sample from BPF ringbuf */
    struct OutData* e = bpf_ringbuf_reserve(&rb, sizeof(struct OutData), 0);
    if (!e)
        return 0;
    e->val_1 = const_val_1;
    e->val_2 = const_val_2;
    memcpy(const_val_3, e->val_3, 100);
    e->val_4 = bss_val_1;
    e->val_5 = bss_val_2;
    memcpy(bss_val_3, e->val_6, 100);
    /* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
