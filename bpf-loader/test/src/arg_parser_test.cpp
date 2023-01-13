/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <json.hpp>
#include <catch2/catch_test_macros.hpp>
#include "eunomia/eunomia-bpf.hpp"

using namespace eunomia;
using json = nlohmann::json;

int
parse_arg_for_program(const char *path, std::vector<std::string> args)
{
    std::string json_str, new_config;
    std::ifstream json_file(path);
    json_str = std::string((std::istreambuf_iterator<char>(json_file)),
                           std::istreambuf_iterator<char>());
    json config = json::parse(json_str);
    int res =
        parse_args_for_json_config(config["meta"].dump(), new_config, args);
    if (res != 0) {
        return res;
    }
    config["meta"] = json::parse(new_config);
    bpf_skeleton ebpf_program;
    res = ebpf_program.open_from_json_config(config.dump());
    if (res != 0) {
        std::cout << new_config << std::endl;
        return res;
    }
    res = ebpf_program.load_and_attach();
    if (res != 0) {
        return res;
    }
    ebpf_program.destroy();
    return res;
}

TEST_CASE("test arg opensnoop", "[opensnoop]")
{
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "-h" })
            == 1);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "-v" })
            == 1);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--verbose" })
            == 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "-f" })
            == -1);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--pid_target", "1" })
            == -1);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--xxx", "1" })
            != 1);
}

TEST_CASE("test arg bootstrap", "[bootstrap]")
{
    REQUIRE(parse_arg_for_program("../../test/asserts/bootstrap.json",
                                  { "boostrap", "-h" })
            == 1);
    REQUIRE(parse_arg_for_program("../../test/asserts/bootstrap.json",
                                  { "boostrap", "-f" })
            != 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/bootstrap.json",
                                  { "boostrap", "--min_duration_ns", "1000" })
            == 0);
}
