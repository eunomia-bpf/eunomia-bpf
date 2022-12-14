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
#include "eunomia/eunomia-meta.hpp"

using namespace eunomia;

TEST_CASE("test load config", "[eunomia_object_meta]")
{
    std::ifstream condig_file("../../test/asserts/client.skel.json");

    REQUIRE(condig_file.is_open());
    std::string json_str((std::istreambuf_iterator<char>(condig_file)),
                         std::istreambuf_iterator<char>());
    eunomia_object_meta meta;
    meta.from_json_str(json_str);
}
