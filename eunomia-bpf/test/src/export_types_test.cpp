/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>

#include "eunomia/eunomia-bpf.hpp"

using namespace eunomia;

int
start_new_program(const char *path, export_format_type type)
{
    std::string json_str;
    std::ifstream json_file(path);
    json_str = std::string((std::istreambuf_iterator<char>(json_file)),
                           std::istreambuf_iterator<char>());
    bpf_skeleton ebpf_program;
    if (ebpf_program.open_from_json_config(json_str) < 0) {
        std::cerr << "load json config failed" << std::endl;
        return -1;
    }
    if (ebpf_program.load_and_attach() < 0) {
        std::cerr << "Failed to run ebpf program" << std::endl;
        return -1;
    }
    // run a new program in a new thread
    auto t = std::thread([path, &ebpf_program, type] {
        if (ebpf_program.wait_and_poll_to_handler(type, nullptr) < 0) {
            std::cerr << "Failed to wait and print rb" << std::endl;
            exit(1);
        }
    });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    ebpf_program.destroy();
    t.join();
    return 0;
}

TEST_CASE("run and auto export types ring buffer", "[bootstrap]")
{
    REQUIRE(start_new_program("../../test/asserts/bootstrap.json",
                              export_format_type::EXPORT_JSON)
            == 0);
    REQUIRE(start_new_program("../../test/asserts/bootstrap.json",
                              export_format_type::EXPORT_PLANT_TEXT)
            == 0);
    REQUIRE(start_new_program("../../test/asserts/bootstrap.json",
                              export_format_type::EXPORT_RAW_EVENT)
            == 0);
}

TEST_CASE("run and auto export types perf event", "[opensnoop]")
{
    REQUIRE(start_new_program("../../test/asserts/opensnoop.json",
                              export_format_type::EXPORT_JSON)
            == 0);
    REQUIRE(start_new_program("../../test/asserts/opensnoop.json",
                              export_format_type::EXPORT_PLANT_TEXT)
            == 0);
    REQUIRE(start_new_program("../../test/asserts/opensnoop.json",
                              export_format_type::EXPORT_RAW_EVENT)
            == 0);
}
