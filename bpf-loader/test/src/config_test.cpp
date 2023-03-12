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
#include <json.hpp>
#include <sys/utsname.h>
#include <sstream>

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
    REQUIRE(ebpf_program.open_from_json_config(json_package, NULL) == 0);
    REQUIRE(ebpf_program.open_from_json_config(json_package, NULL) == 0);
    REQUIRE(ebpf_program.open_from_json_config(config["meta"].dump(), {}, NULL)
            == 0);
}

extern "C" {
const char *
libbpf_version_string(void);
}

TEST_CASE("test version info generation", "[eunomia_object_meta]")
{
    std::ifstream version_file("../../../VERSION");
    REQUIRE(version_file.is_open());
    std::string version_str;
    version_file >> version_str;
    using std::endl;
    std::ostringstream ss;
    utsname uname_st;
    int err = uname(&uname_st);
    REQUIRE(err == 0);
    ss << "eunomia-bpf version: " << version_str << endl;
    ss << "Linux version: " << uname_st.sysname << " " << uname_st.release
       << " " << uname_st.version << " " << uname_st.nodename << " "
       << uname_st.machine << endl;
    ss << "libbpf version: " << libbpf_version_string() << endl;
    ss << "arch: " << uname_st.machine << endl;

    REQUIRE(ss.str() == eunomia::generate_version_info());
}
