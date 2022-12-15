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

using namespace eunomia;

int
parse_arg_for_program(const char *path, std::vector<std::string> args)
{
    std::string json_str, new_config;
    std::ifstream json_file(path);
    json_str = std::string((std::istreambuf_iterator<char>(json_file)),
                           std::istreambuf_iterator<char>());
    int res = parse_args_for_json_config(json_str, new_config, args);
    return res;
}

TEST_CASE("test arg parse", "[eunomia_object_meta]")
{
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "-h" })
            == 1);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "-f" })
            == 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--pid_target", "1" })
            == 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--xxx", "1" })
            != 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--pid_target", "abc" })
            != 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/opensnoop.json",
                                  { "opensnoop", "--pid_target", "abc" })
            != 0);

    REQUIRE(parse_arg_for_program("../../test/asserts/boostrap.json",
                                  { "boostrap", "-h" })
            == 1);
    REQUIRE(parse_arg_for_program("../../test/asserts/boostrap.json",
                                  { "boostrap", "-f" })
            != 0);
    REQUIRE(parse_arg_for_program("../../test/asserts/boostrap.json",
                                  { "boostrap", "--min_duration_ns", "0" })
            != 0);
}
