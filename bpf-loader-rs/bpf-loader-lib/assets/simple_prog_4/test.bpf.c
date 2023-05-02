#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const char fmt2[] = "abcdefg";

SEC("tp_btf/sched_wakeup")
int sched_wakeup(void* ctx) {
    int a = 1;
    bpf_printk("Process ID: %d enter sys openat\n", a);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
