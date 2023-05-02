#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const char fmt2[] = "abcdefg";

SEC("tp/sched/sched_process_exec")
int handle_exec(void* ctx) {
    int a = 0x12345678;
    bpf_printk("Created %d\n", a);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
