/* Copyright (c) 2023 eunomia-bpf */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event_exit {
    unsigned long long duration_ns;
    int pid;
    int ppid;
    unsigned exit_code;
    char comm[TASK_COMM_LEN];
};

struct event_exec {
    int pid;
    int ppid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif
