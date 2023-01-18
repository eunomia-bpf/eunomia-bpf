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
#include <uprobe_helpers.h>
#include <trace_helpers.h>
}

using namespace eunomia;

TEST_CASE("test btf helpers", "[btf][helpers]")
{
    // DECLARE_LIBBPF_OPTS(bpf_object_open_opts, openopts);
    // REQUIRE(ensure_core_btf(&openopts) == 0);
    // cleanup_core_btf(&openopts);
    // remove useless helpers temporarily
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
    REQUIRE(kprobe_exists("do_syscall_64") == false);
    REQUIRE(kprobe_exists("non_existent_function") == false);
    REQUIRE(kprobe_exists("") == false);
    REQUIRE(kprobe_exists("long_name_of_a_non_existent_function_with_more_than_255_characters") == false);
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
TEST_CASE("test trace helpers vmlinux_btf_exists", "[trace][helpers")
{
    REQUIRE(vmlinux_btf_exists() == true);
}

TEST_CASE("test trace helpers fentry_can_attach", "[trace][helpers")
{
    REQUIRE(fentry_can_attach("tcp_v4_syn_recv_sock", NULL) == true);
    REQUIRE(fentry_can_attach("vfs_read", NULL) == false);
    REQUIRE(fentry_can_attach("folio_account_dirtied", NULL) == false);
    REQUIRE(fentry_can_attach("inet_listen", NULL) == false);
    REQUIRE(fentry_can_attach("mutex_lock_nested", NULL) == false);
    REQUIRE(fentry_can_attach("mutex_lock", NULL) == false);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL) == false);
    REQUIRE(fentry_can_attach("tcp_v4_connect", NULL) == false);
    REQUIRE(fentry_can_attach("tcp_rcv_established", NULL) == false);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL) == false);
}

TEST_CASE("test trace helpers module_btf_exists", "[trace][helpers")
{
    REQUIRE(module_btf_exists("true") == false);
    REQUIRE(module_btf_exists("tcp") == false);
}

TEST_CASE("test trace helpers is_kernel_module", "[trace][helpers")
{
    REQUIRE(is_kernel_module("tcp") == false);
    REQUIRE(is_kernel_module("non_existent_module") == false);
    REQUIRE(is_kernel_module("") == false);
    REQUIRE(is_kernel_module("long_name_of_a_non_existent_module_with_more_than_255_characters") == false);
    REQUIRE(is_kernel_module("0") == false);
    REQUIRE(is_kernel_module("-module") == false); 
    char long_name_module[1024];
    memset(long_name_module, 'a', sizeof(long_name_module));
    long_name_module[1023] = '\0';
    REQUIRE(is_kernel_module(long_name_module) == false);
}

TEST_CASE("test trace helpers resolve_binary_path", "[trace][helpers")
{
    char path[1024];
    char short_path[2];
    REQUIRE(resolve_binary_path("", 0, path, sizeof(path)) == -1);
    REQUIRE(resolve_binary_path("non_existent_program", 0, path, sizeof(path)) == -1);
    REQUIRE(resolve_binary_path("", -1, path, sizeof(path)) == -1);
}

TEST_CASE("test trace helpers open_elf", "[trace][helpers")
{
    int fd_close;
    Elf *e;
    e = open_elf("path/to/valid_elf_file", &fd_close);
    REQUIRE(e == NULL);
    elf_end(e);
    close(fd_close);
}

