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
