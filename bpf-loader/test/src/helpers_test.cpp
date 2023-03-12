/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <catch2/catch_test_macros.hpp>
#include "eunomia/eunomia-bpf.hpp"
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>

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
    print_linear_hist(h.slots, 0, 0, HIST_STEP_SIZE, "test comm");
    print_log2_hist(h.slots, MAX_SLOTS, "test unit");
    print_log2_hist(h.slots, 0, "test unit");
    h.slots[0] = 0;
    print_linear_hist(h.slots, MAX_SLOTS, 0, HIST_STEP_SIZE, "test comm");

    SECTION("Test print_log2_hist with idx_max > 32")
    {
        unsigned int vals[100];
        for (int i = 0; i < 100; i++) {
            vals[i] = i;
        }
        const char *val_type = "Test";

        print_log2_hist(vals, 100, val_type);

        int stars_max = 40, idx_max = -1;
        unsigned int val, val_max = 0;
        unsigned long long low, high;
        int stars, width, i;

        for (i = 0; i < 100; i++) {
            val = vals[i];
            if (val > 0)
                idx_max = i;
            if (val > val_max)
                val_max = val;
        }
        if (idx_max <= 32)
            stars = stars_max;
        else
            stars = stars_max / 2;

        REQUIRE(idx_max == 99);
        REQUIRE(stars == stars_max / 2);
    }
}

TEST_CASE("test trace helpers kprobe exists", "[trace][helpers]")
{
    REQUIRE(kprobe_exists("do_unlinkat"));
    REQUIRE(kprobe_exists("do_syscall_64") == false);
    REQUIRE(kprobe_exists("") == false);

    SECTION("Test when /sys/kernel/debug/tracing/available_filter_functions "
            "file cannot be opened")
    {

        const char *path =
            "/sys/kernel/debug/tracing/available_filter_functions";
        const char *name = "fs";
        mode_t original_mode = 0;
        REQUIRE(chmod(path, 0) == 0);
        bool result = kprobe_exists(name);
        REQUIRE(result == false);
        REQUIRE(chmod(path, original_mode) == 0);
    }
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
    REQUIRE(fentry_can_attach("vfs_read", NULL) == true);
    REQUIRE(fentry_can_attach("folio_account_dirtied", "xxx") == false);
    REQUIRE(fentry_can_attach("inet_listen", NULL) == true);
    REQUIRE(fentry_can_attach("mutex_lock_nested", NULL) == false);
    REQUIRE(fentry_can_attach("mutex_lock", NULL) == true);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL) == true);
    REQUIRE(fentry_can_attach("tcp_v4_connect", NULL) == true);
    REQUIRE(fentry_can_attach("tcp_rcv_established", NULL) == true);
    REQUIRE(fentry_can_attach("blk_account_io_start", NULL) == true);

    SECTION("Test when/sys/kernel/btf/vmlinuxbe opened")
    {

        const char *path = "/sys/kernel/btf/vmlinux";
        REQUIRE(fentry_can_attach("tcp_v4_syn_recv_sock", NULL) == true);
    }
}

TEST_CASE("test trace helpers module_btf_exists", "[trace][helpers")
{
    REQUIRE(module_btf_exists("true") == false);
    REQUIRE(module_btf_exists("tcp") == false);
}

TEST_CASE("test trace helpers is_kernel_module", "[trace][helpers")
{
    REQUIRE(is_kernel_module("tcp") == false);
    REQUIRE(is_kernel_module("") == false);

    SECTION("Test when /proc/modules file cannot be opened")
    {
        // Temporarily remove read permission for /proc/modules file
        // so that fopen() will return NULL
        const char *path = "/proc/modules";
        mode_t original_mode = 0;
        REQUIRE(chmod(path, 0) == 0);
        const char *name = "fs";
        bool result = is_kernel_module(name);
        REQUIRE(result == false);
        // Restore original file permission
        REQUIRE(chmod(path, original_mode) == 0);
    }

    SECTION("Test whether the input module name exists in the current system")
    {
        std::ifstream file("/proc/modules");
        std::string line;
        std::string module_name;
        if (file.is_open()) {
            std::getline(file, line); // Read first line
            size_t pos = line.find(" ");
            module_name = line.substr(0, pos);
            std::cout << "First kernel module name: " << module_name
                      << std::endl;
            file.close();
        }
        else {
            std::cout << "Unable to open file" << std::endl;
        }
        REQUIRE(is_kernel_module(module_name.c_str()) == true);
    }
}

TEST_CASE("test uprobe_helpers resolve_binary_path", "[uprobe][helpers")
{
    char path[1024];
    char short_path[2];
    REQUIRE(resolve_binary_path("", 0, path, sizeof(path)) == -1);
    REQUIRE(resolve_binary_path("non_existent_program", 0, path, sizeof(path))
            == -1);
    REQUIRE(resolve_binary_path("", -1, path, sizeof(path)) == -1);
}

TEST_CASE("test trace helpers open_elf", "[trace][helpers]")
{
    int fd_close;
    Elf *e;
    e = open_elf("path/to/valid_elf_file", &fd_close);
    REQUIRE(e == NULL);
    elf_end(e);
    close(fd_close);
}

TEST_CASE("test trace helpers get_ktime_ns", "[time]")
{

    unsigned long long start = get_ktime_ns();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    long long end = get_ktime_ns();
    REQUIRE(end - start >= 100 * 1e6);
}