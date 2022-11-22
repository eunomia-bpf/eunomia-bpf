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
constexpr auto default_var_help = "set value of bpf variable ";

struct possible_option_arg {
    json default_value;
    std::string help;
    std::string long_name;
    std::string short_name;
    std::string type;
};

std::string
get_value_or_default(const json &j, const char *key,
                     const std::string &default_value)
{
    if (j.is_null() || j.find(key) == j.end()) {
        return default_value;
    }
    return j[key];
}

void
add_default_options(argparse::ArgumentParser &program,
                    std::vector<possible_option_arg> &opts)
{
    opts.push_back({
        false,
        "shows help message and exits",
        "help",
        "h",
        "bool",
    });
    opts.push_back({
        false,
        "prints version information and exits",
        "version",
        "v",
        "bool",
    });
}

int
process_default_args(const argparse::ArgumentParser &program,
                     std::string &version)
{
    if (program.get<bool>("--help")) {
        std::cout << program << std::endl;
        return 0;
    }
    if (program.get<bool>("--version")) {
        std::cout << version << std::endl;
        return 0;
    }
    return -1;
}

argparse::ArgumentParser
create_arg_parser_for_program(const json &j)
{
    std::string name = get_value_or_default(j, "obj_name", "eunomia app");
    std::string version = get_value_or_default(j, "version", "0.1.0");
    return argparse::ArgumentParser(name, version);
}

void
register_args_for_section_var(argparse::ArgumentParser &program,
                              const json &bpf_skel,
                              std::vector<possible_option_arg> &opts)
{
    bpf_skel_meta meta;
    meta.from_json_str(bpf_skel.dump());
    for (auto &section : meta.data_sections) {
        for (auto &var : section.variables) {
            json var_raw = json::parse(var.__raw_json_data);
            json var_cmdarg = var_raw["cmdarg"];
            auto var_help = get_value_or_default(
                var_cmdarg, "help",
                get_value_or_default(var_raw, "description",
                                     default_var_help + var.name));
            auto var_short_name = get_value_or_default(var_cmdarg, "short", "");
            auto var_long_name =
                get_value_or_default(var_cmdarg, "long", var.name);
            auto var_default_value = var_cmdarg["default"];
            opts.push_back({ var_default_value, var_help, var_long_name,
                             var_short_name, var.type });
        }
    }
}

argparse::Argument &
add_arg_for_names(argparse::ArgumentParser &program,
                  const possible_option_arg &opt)
{
    if (opt.short_name.empty()) {
        return program.add_argument(opt.long_name);
    }
    return program.add_argument(opt.short_name, opt.long_name);
}

template<typename T>
void
add_argument_to_program(argparse::ArgumentParser &program,
                        const possible_option_arg &opt,
                        bool implicit_value = false)
{
    auto arg = add_arg_for_names(program, opt).help(opt.help);
    if (!opt.default_value.is_null()) {
        arg = arg.default_value<T>(opt.default_value.get<T>());
    }
    if (implicit_value) {
        arg = arg.implicit_value(true);
    }
}

void
process_and_auto_create_arguments(std::vector<possible_option_arg> &opts)
{
    // is there any var has not short name?
    for (auto &opt : opts) {
        // TODO: auto create short name
    }
    // add -- to all long names and - to all short names
    for (auto &opt : opts) {
        if (opt.short_name != "") {
            opt.short_name = std::string("-") + opt.short_name;
        }
        if (opt.long_name != "") {
            opt.long_name = std::string("--") + opt.long_name;
        }
    }
}

void
set_program_arguments(argparse::ArgumentParser &program,
                      std::vector<possible_option_arg> &opts)
{
    process_and_auto_create_arguments(opts);
    for (auto &opt : opts) {
        if (argparse::details::starts_with(
                std::string_view("--__eunomia_dummy"),
                std::string_view(opt.long_name))) {
            continue;
        }
        if (opt.type == "bool") {
            add_argument_to_program<bool>(program, opt, true);
        }
        else if (opt.type == "int") {
            add_argument_to_program<int>(program, opt);
        }
        else if (opt.type == "unsigned int") {
            add_argument_to_program<unsigned int>(program, opt);
        }
        else if (opt.type == "unsigned long") {
            add_argument_to_program<unsigned long>(program, opt);
        }
        else if (opt.type == "unsigned long long") {
            add_argument_to_program<unsigned long long>(program, opt);
        }
        else if (opt.type == "unsigned short") {
            add_argument_to_program<unsigned short>(program, opt);
        }
        else if (opt.type == "short") {
            add_argument_to_program<short>(program, opt);
        }
        else if (opt.type == "long long") {
            add_argument_to_program<long long>(program, opt);
        }
        else if (opt.type == "float") {
            add_argument_to_program<float>(program, opt);
        }
        else if (opt.type == "double") {
            add_argument_to_program<double>(program, opt);
        }
        else {
            add_argument_to_program<std::string>(program, opt);
        }
    }
}

int
process_args_for_section_var(const argparse::ArgumentParser &program,
                             json &bpf_skel,
                             std::vector<possible_option_arg> &opts)
{
    json data_sections = bpf_skel["data_sections"];
    if (data_sections.is_null()) {
        return 0;
    }
    return 0;
}

int
process_args(const argparse::ArgumentParser &program, json &bpf_skel,
             std::vector<possible_option_arg> &opts, std::string &version)
{
    int ret = process_args_for_section_var(program, bpf_skel, opts);
    if (ret != 0) {
        return ret;
    }
    ret = process_default_args(program, version);
    return ret;
}

void
register_args(argparse::ArgumentParser &program, json &bpf_skel,
              std::vector<possible_option_arg> &possible_args)
{
    add_default_options(program, possible_args);
    register_args_for_section_var(program, bpf_skel, possible_args);

    set_program_arguments(program, possible_args);
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
        std::cerr << "parse json config failed for args" << std::endl;
        return -1;
    }
    std::string name =
        get_value_or_default(bpf_skel, "obj_name", "eunomia app");

    json doc = bpf_skel["doc"];

    std::string description =
        get_value_or_default(doc, "brief", default_description);
    std::string version = get_value_or_default(doc, "version", default_version);
    std::string epilog = get_value_or_default(doc, "details", default_epilog);

    auto program = argparse::ArgumentParser(name, version,
                                            argparse::default_arguments::none);
    program.add_description(description);
    program.add_epilog(epilog);

    std::vector<possible_option_arg> possible_args;
    register_args(program, bpf_skel, possible_args);

    try {
        program.parse_args(args);
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    int res = process_args(program, bpf_skel, possible_args, version);
    new_config = j.dump();
    return res;
}
}