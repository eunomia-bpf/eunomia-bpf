/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"
#include <argparse.hpp>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
}

using json = nlohmann::json;
namespace eunomia {

constexpr auto default_description = "A simple eBPF program";
constexpr auto default_version = "0.1.0";
constexpr auto default_epilog =
    "Built with eunomia-bpf framework.\n"
    "See https://github.com/eunomia-bpf/eunomia-bpf for more information.";

std::string
get_value_or_default(const json &j, const char *key,
                     const std::string &default_value)
{
    if (j.contains(key)) {
        return j[key];
    }
    return default_value;
}

json
get_json_object_or_default(const json &j, const char *key)
{
    if (j.contains(key)) {
        return j[key];
    }
    return {};
}

argparse::ArgumentParser
create_arg_parser_for_program(const json &j)
{
    std::string name = get_value_or_default(j, "obj_name", "eunomia app");
    std::string version = get_value_or_default(j, "version", "0.1.0");
    return argparse::ArgumentParser(name, version);
}

void
add_args_for_section_var(argparse::ArgumentParser &program,
                         const json &data_sections)
{
}

int
parse_args_for_json_config(const std::string &json_config,
                           std::string &new_config,
                           std::vector<std::string> args)
{
    json j;
    json bpf_skel;
    try {
        j = json::parse(json_config);
        bpf_skel = j["bpf_skel"];
    } catch (json::parse_error &e) {
        std::cerr << "parse json config failed" << std::endl;
        return -1;
    }
    std::string name =
        get_value_or_default(bpf_skel, "obj_name", "eunomia app");

    json doc = get_json_object_or_default(bpf_skel, "doc");

    std::string description =
        get_value_or_default(doc, "brief", default_description);
    std::string version = get_value_or_default(doc, "version", default_version);
    std::string epilog = get_value_or_default(doc, "details", default_epilog);

    auto program = argparse::ArgumentParser(name, version,
                                            argparse::default_arguments::none);
    program.add_description(description);
    program.add_epilog(epilog);

    program.add_argument("-h", "--help")
        .default_value(false)
        .help("shows help message and exits")
        .implicit_value(true)
        .nargs(0);
    program.add_argument("-v", "--version")
        .default_value(false)
        .help("prints version information and exits")
        .implicit_value(true)
        .nargs(0);

    try {
        program.parse_args(args);
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    if (program["--version"] == true) {
        std::cout << version << std::endl;
        return 1;
    }
    if (program["--help"] == true) {
        std::cout << program.help().str();
        return 1;
    }
    return 0;
}

}