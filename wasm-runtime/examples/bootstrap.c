// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "bootstrap.wasm.h"
#include "bootstrap.skel.h"

static struct env {
    bool verbose;
    long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
    "BPF bootstrap demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./bootstrap [-d <min-duration-ms>] -v\n";

static void
print_usage(void)
{
    printf("%s\n", argp_program_version);
    printf("%s\n", argp_program_doc);
}

static int
handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (e->exit_event) {
        printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid,
               e->ppid, e->exit_code);
        if (e->duration_ns)
            printf(" (%llums)", e->duration_ns / 1000000);
        printf("\n");
    }
    else {
        printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid,
               e->ppid, e->filename);
    }

    return 0;
}

static bool exiting = false;

int
main(int argc, char **argv)
{
    struct bpf_buffer *rb = NULL;
    struct bootstrap_bpf *skel;
    int err;
    if (argc > 3) {
        print_usage();
        return 0;
    }
    else if ((strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--duration") == 0)
             && argc == 3) {
        env.min_duration_ms = strtol(argv[2], NULL, 10);
        if (errno || env.min_duration_ms <= 0) {
            fprintf(stderr, "Invalid duration: %s\n", argv[2]);
            print_usage();
        }
    }
    /* Load and verify BPF application */
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code with minimum duration parameter */
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

    /* Load & verify BPF programs */
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
           "PPID", "FILENAME/EXIT CODE");
    while (!exiting) {
        // poll buffer
        err = bpf_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        // // access maps
        // int lookup_key = -2, next_key;
        // uint64_t value;
        // int err;
        // int fd = wasm_bpf_map_fd_by_name(skel->skeleton->obj, "exec_start");
        // while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        //     err = bpf_map_lookup_elem(fd, &next_key, &value);
        //     if (err < 0) {
        //         fprintf(stderr, "failed to lookup hist: %d\n", err);
        //         return -1;
        //     }
        //     printf("\npid = %d time = %llu\n", next_key, value);
        //     lookup_key = next_key;
        // }
    }

cleanup:
    bpf_buffer__free(rb);
    bootstrap_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
