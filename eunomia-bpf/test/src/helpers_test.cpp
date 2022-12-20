/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <catch2/catch_test_macros.hpp>
#include "eunomia/eunomia-bpf.hpp"

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <btf_helpers.h>
#include <uprobe_helpers.h>
#include <trace_helpers.h>
}

using namespace eunomia;

TEST_CASE("test btf helpers", "[btf][helpers]")
{
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, openopts);
    REQUIRE(ensure_core_btf(&openopts) == 0);
    cleanup_core_btf(&openopts);
}

TEST_CASE("test uprobe helpers", "[uprobe][helpers]")
{
    char path[1024];
    char cpath[1024];
    char minpath[1];

    REQUIRE(get_pid_binary_path(1, path, 1024) == 0);
    printf("path: %s", path);
    REQUIRE(get_pid_binary_path(1, minpath, 1) < 0);
    REQUIRE(get_pid_binary_path(-1, path, 1024) < 0);

    auto off = get_elf_func_offset(path, "fbeucfveybsxuwbydfvuvuebdcggsu");
    REQUIRE(off < 0);

    REQUIRE(get_pid_lib_path(1, "c", cpath, 1024) == 0);
    printf("path: %s", cpath);
    REQUIRE(get_pid_lib_path(1, "cbb", cpath, 1024) < 0);
    REQUIRE(get_pid_lib_path(-1, "c", cpath, 1024) < 0);
    REQUIRE(get_pid_lib_path(1, "c", minpath, 1) < 0);
}

#define MAX_SLOTS 26
#define HIST_STEP_SIZE 200

struct linear_hist {
    __u32 slots[MAX_SLOTS];
};

TEST_CASE("test trace helpers print hist", "[trace][helpers]")
{
    linear_hist h = {};
    h.slots[0] = 1;
    print_linear_hist(h.slots, MAX_SLOTS, 0, HIST_STEP_SIZE, "test comm");
    print_log2_hist(h.slots, MAX_SLOTS, "test unit");
}

TEST_CASE("test trace helpers kprobe exists", "[trace][helpers]")
{
    REQUIRE(kprobe_exists("do_unlinkat"));
}

TEST_CASE("test trace helpers tracepoint exists", "[trace][helpers]")
{
    REQUIRE(tracepoint_exists("do_unlinkat", "true") == 0);
    REQUIRE(tracepoint_exists("do_unlinkat", "false") == 0);
}

TEST_CASE("test trace helpers probe_ringbuf", "[trace][helpers")
{
    REQUIRE(probe_ringbuf() == true);
}

TEST_CASE("test trace helpers probe_tp_btf", "[trace][helpers")
{
    REQUIRE(probe_tp_btf("ss") == false);
    REQUIRE(probe_tp_btf("softirq_entry") == true);
    REQUIRE(probe_tp_btf("sched_wakeup") == true);
    REQUIRE(probe_tp_btf("sched_switch") == true);
    REQUIRE(probe_tp_btf("SCHED_SWITCH") == false);
    REQUIRE(probe_tp_btf("block_rq_insert") == true);
    REQUIRE(probe_tp_btf(" ") == false);
}
TEST_CASE("test trace helpers vmlinux_btf_exists","[trace][helpers")
{
    REQUIRE(vmlinux_btf_exists()==true);
}

TEST_CASE("test trace helpers fentry_can_attach","[trace][helpers")
{
    REQUIRE(fentry_can_attach("tcp_v4_syn_recv_sock", NULL)==true);
    REQUIRE(fentry_can_attach("vfs_read", NULL)==true);
    REQUIRE(fentry_can_attach("folio_account_dirtied", NULL)==false);
    REQUIRE(fentry_can_attach("inet_listen", NULL)==true);
    REQUIRE(fentry_can_attach("mutex_lock_nested", NULL)==false);
    REQUIRE(fentry_can_attach("mutex_lock", NULL)==true);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL)==true);
    REQUIRE(fentry_can_attach("tcp_v4_connect", NULL)==true);
    REQUIRE(fentry_can_attach("tcp_rcv_established", NULL)==true);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL)==true);
}

TEST_CASE("test trace helpers module_btf_exists","[trace][helpers")
{
    REQUIRE(module_btf_exists("true")==false);
}
