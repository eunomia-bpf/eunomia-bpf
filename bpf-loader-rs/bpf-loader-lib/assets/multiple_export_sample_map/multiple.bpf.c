// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 eunomia-bpf */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, u64);
    __type(value, struct event_exec);

} map_exec SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, u64);
    __type(value, struct event_exit)
} map_exit SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

const volatile struct event_exit* __dummy1;
const volatile struct event_exec* __dummy2;

static void memset(void* ptr, int value, size_t num) {
    char* p = (char*)ptr;
    while (num--)
        *p++ = value;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec* ctx) {
    struct event_exec st;
    memset(&st, 0, sizeof(st));
    u64 ts;

    struct task_struct* task;
    unsigned fname_off;
    pid_t pid;

    /* remember time exec() was executed for this PID */
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    /* don't emit exec events when minimum duration is specified */
    if (min_duration_ns)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct*)bpf_get_current_task();

    st.pid = pid;
    st.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&st.comm, sizeof(st.comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&st.filename, sizeof(st.filename),
                       (void*)ctx + fname_off);
    bpf_map_update_elem(&map_exec, &ts, &st, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx) {
    struct task_struct* task;

    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;
    struct event_exit st;
    memset(&st, 0, sizeof(st));
    __u64 now;
    long err;
    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* if we recorded start of the process, calculate lifetime duration */
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    bpf_map_delete_elem(&exec_start, &pid);

    /* if process didn't live long enough, return early */
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct*)bpf_get_current_task();

    st.duration_ns = duration_ns;
    st.pid = pid;
    st.ppid = BPF_CORE_READ(task, real_parent, tgid);
    st.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&st.comm, sizeof(st.comm));
    now = bpf_ktime_get_boot_ns();

    err = bpf_map_update_elem(&map_exit, &now, &st, BPF_ANY);
    if (err < 0) {
        bpf_printk("error: %ld\n", err);
    }
    return 0;
}
