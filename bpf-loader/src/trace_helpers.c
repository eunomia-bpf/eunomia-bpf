/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include <bpf/btf.h>
#include <sys/stat.h>

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

static void
print_stars(unsigned int val, unsigned int val_max, int width)
{
    int num_stars, num_spaces, i;
    bool need_plus;

    num_stars = min(val, val_max) * width / val_max;
    num_spaces = width - num_stars;
    need_plus = val > val_max;

    for (i = 0; i < num_stars; i++)
        printf("*");
    for (i = 0; i < num_spaces; i++)
        printf(" ");
    if (need_plus)
        printf("+");
}

void
print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
    int stars_max = 40, idx_max = -1;
    unsigned int val, val_max = 0;
    unsigned long long low, high;
    int stars, width, i;

    for (i = 0; i < vals_size; i++) {
        val = vals[i];
        if (val > 0)
            idx_max = i;
        if (val > val_max)
            val_max = val;
    }

    if (idx_max < 0)
        return;

    printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
           idx_max <= 32 ? 19 : 29, val_type);

    if (idx_max <= 32)
        stars = stars_max;
    else
        stars = stars_max / 2;

    for (i = 0; i <= idx_max; i++) {
        low = (1ULL << (i + 1)) >> 1;
        high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;
        val = vals[i];
        width = idx_max <= 32 ? 10 : 20;
        printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        print_stars(val, val_max, stars);
        printf("|\n");
    }
}

void
print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
                  unsigned int step, const char *val_type)
{
    int i, stars_max = 40, idx_min = -1, idx_max = -1;
    unsigned int val, val_max = 0;

    for (i = 0; i < vals_size; i++) {
        val = vals[i];
        if (val > 0) {
            idx_max = i;
            if (idx_min < 0)
                idx_min = i;
        }
        if (val > val_max)
            val_max = val;
    }

    if (idx_max < 0)
        return;

    printf("     %-13s : count     distribution\n", val_type);
    for (i = idx_min; i <= idx_max; i++) {
        val = vals[i];
        if (!val)
            continue;
        printf("        %-10d : %-8d |", base + i * step, val);
        print_stars(val, val_max, stars_max);
        printf("|\n");
    }
}

unsigned long long
get_ktime_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

bool
is_kernel_module(const char *name)
{
    bool found = false;
    char buf[64];
    FILE *f;

    f = fopen("/proc/modules", "r");
    if (!f)
        return false;

    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (sscanf(buf, "%63s %*s\n", buf) != 1)
            break;
        if (!strcmp(buf, name)) {
            found = true;
            break;
        }
    }

    fclose(f);
    return found;
}

static bool
fentry_try_attach(int id)
{
    int prog_fd, attach_fd;
    char error[4096];
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT },
    };
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = id,
                .log_buf = error, .log_size = sizeof(error), );

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
                            sizeof(insns) / sizeof(struct bpf_insn), &opts);
    if (prog_fd < 0)
        return false;

    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if (attach_fd >= 0)
        close(attach_fd);

    close(prog_fd);
    return attach_fd >= 0;
}

bool
fentry_can_attach(const char *name, const char *mod)
{
    const char sysfs_vmlinux[] = "/sys/kernel/btf/vmlinux";
    struct btf *base, *btf = NULL;
    char sysfs_mod[80];
    int id = -1, err;

    base = btf__parse(sysfs_vmlinux, NULL);
    if (!base) {
        err = -errno;
        fprintf(stderr, "failed to parse vmlinux BTF at '%s': %s\n",
                sysfs_vmlinux, strerror(-err));
        goto err_out;
    }
    if (mod && module_btf_exists(mod)) {
        snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
        btf = btf__parse_split(sysfs_mod, base);
        if (!btf) {
            err = -errno;
            fprintf(stderr, "failed to load BTF from %s: %s\n", sysfs_mod,
                    strerror(-err));
            btf = base;
            base = NULL;
        }
    }
    else {
        btf = base;
        base = NULL;
    }

    id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

err_out:
    btf__free(btf);
    btf__free(base);
    return id > 0 && fentry_try_attach(id);
}

bool
kprobe_exists(const char *name)
{
    char sym_name[256];
    FILE *f;
    int ret;

    f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
    if (!f)
        goto slow_path;

    while (true) {
        ret = fscanf(f, "%255s%*[^\n]\n", sym_name);
        if (ret == EOF && feof(f))
            break;
        if (ret != 1) {
            fprintf(stderr,
                    "failed to read symbol from available_filter_functions\n");
            break;
        }
        if (!strcmp(name, sym_name)) {
            fclose(f);
            return true;
        }
    }

    fclose(f);
    return false;

slow_path:
    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return false;

    while (true) {
        ret = fscanf(f, "%*x %*c %255s%*[^\n]\n", sym_name);
        if (ret == EOF && feof(f))
            break;
        if (ret != 1) {
            fprintf(stderr, "failed to read symbol from kallsyms\n");
            break;
        }
        if (!strcmp(name, sym_name)) {
            fclose(f);
            return true;
        }
    }

    fclose(f);
    return false;
}

bool
tracepoint_exists(const char *category, const char *event)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path),
             "/sys/kernel/debug/tracing/events/%s/%s/format", category, event);
    struct stat st;
    if (stat("/path/to/file", &st) == 0) {
        return true;
    }
    return false;
}

bool
vmlinux_btf_exists(void)
{
    // Set the correct permissions for the file
    struct stat st;
    if (stat("/sys/kernel/btf/vmlinux", &st) == 0 && (st.st_mode & S_IRUSR)) {
        return true;
    }

    return false;
}

bool
module_btf_exists(const char *mod)
{
    char sysfs_mod[80];

    if (mod) {

        snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
        struct stat sb;
        if (stat(sysfs_mod, &sb) == 0 && S_ISREG(sb.st_mode)
            && (sb.st_mode & S_IRUSR)) {
            return true;
        }
    }
    return false;
}

bool
probe_tp_btf(const char *name)
{
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .expected_attach_type = BPF_TRACE_RAW_TP);
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT },
    };
    int fd, insn_cnt = sizeof(insns) / sizeof(struct bpf_insn);

    opts.attach_btf_id = libbpf_find_vmlinux_btf_id(name, BPF_TRACE_RAW_TP);
    fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insn_cnt,
                       &opts);
    if (fd >= 0)
        close(fd);
    return fd >= 0;
}

bool
probe_ringbuf()
{
    int map_fd;

    map_fd =
        bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL);
    if (map_fd < 0)
        return false;

    close(map_fd);
    return true;
}
