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
#include <json.hpp>

using namespace eunomia;
using json = nlohmann::json;

TEST_CASE("test load config", "[eunomia_object_meta]")
{
    std::ifstream condig_file("../../test/asserts/minimal.json");
    REQUIRE(condig_file.is_open());
    std::string json_package((std::istreambuf_iterator<char>(condig_file)),
                             std::istreambuf_iterator<char>());
    json config = json::parse(json_package);
    bpf_skeleton ebpf_program;
    REQUIRE(ebpf_program.open_from_json_config(json_package) == 0);
    REQUIRE(ebpf_program.open_from_json_config(json_package) == 0);
    REQUIRE(ebpf_program.open_from_json_config(config["meta"].dump(), {}) == 0);
}
