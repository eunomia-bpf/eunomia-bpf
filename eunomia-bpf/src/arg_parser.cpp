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

struct possible_option_arg {
    std::string help;
    std::string long_name;
    std::string short_name;
    std::string type;

    std::string default_value;
    json *json_value_ref;
};

std::string
get_default_var_help(data_section_variable_meta &var)
{
    return std::string("set value of ") + var.type + " variable " + var.name;
}

std::string
get_value_or_default(const json &j, const char *key,
                     const std::string default_value)
{
    if (j.is_null() || j.find(key) == j.end()) {
        return default_value;
    }
    if (!j[key].is_string()) {
        return j[key].dump();
    }
    return j[key];
}

void
add_default_options(argparse::ArgumentParser &program,
                    std::vector<possible_option_arg> &opts, json &bpf_skel)
{
    opts.push_back(possible_option_arg{ "shows help message and exits", "help",
                                        "h", "bool", "false", nullptr });
    opts.push_back(possible_option_arg{ "prints version information and exits",
                                        "version", "v", "bool", "false",
                                        nullptr });
    opts.push_back(possible_option_arg{ "prints libbpf debug information",
                                        "verbose", "", "bool", "false",
                                        nullptr });
}

int
process_default_args(const argparse::ArgumentParser &program,
                     std::string &version, json &json_config)
{
    if (program["--help"] == true) {
        std::cerr << program << std::endl;
        return 1;
    }
    if (program["--version"] == true) {
        std::cerr << version << std::endl;
        return 1;
    }
    if (program["--verbose"] == true) {
        std::cerr << "eunomia-bpf: print debug info" << std::endl;
        json_config["debug_verbose"] = true;
        return 0;
    }
    return 0;
}

argparse::ArgumentParser
create_arg_parser_for_program(const json &j)
{
    std::string name = get_value_or_default(j, "obj_name", "eunomia app");
    std::string version = get_value_or_default(j, "version", "0.1.0");
    return argparse::ArgumentParser(name, version);
}

void
register_args_for_section_var(argparse::ArgumentParser &program, json &bpf_skel,
                              std::vector<possible_option_arg> &opts)
{
    bpf_skel_meta meta;

    meta.from_json_str(bpf_skel.dump());
    for (std::size_t i = 0; i < meta.data_sections.size(); i++) {
        auto &section = meta.data_sections[i];
        auto &section_json = bpf_skel["data_sections"][i];
        for (std::size_t j = 0; j < section.variables.size(); j++) {
            auto &var = section.variables[j];
            auto &var_json = section_json["variables"][j];
            json &var_cmdarg = var_json["cmdarg"];
            // help can be var_json["cmdarg"]["help"] or var_json["description"]
            std::string var_help = get_value_or_default(
                var_cmdarg, "help",
                get_value_or_default(var_json, "description",
                                     get_default_var_help(var)));
            std::string var_short_name =
                get_value_or_default(var_cmdarg, "short", "");
            // long_name can be var_json["cmdarg"]["long"] or var_json["name"]
            std::string var_long_name =
                get_value_or_default(var_cmdarg, "long", var.name);
            // default_value can be var_json["cmdarg"]["default"] or
            // var_json["value"]
            std::string var_default_value = get_value_or_default(
                var_cmdarg, "default",
                get_value_or_default(var_json, "value", ""));
            if (var_json.find("value") == var_json.end()) {
                var_json["value"] = json{};
            }
            auto &value = var_json["value"];

            opts.push_back(possible_option_arg{ var_help, var_long_name,
                                                var_short_name, var.type,
                                                var_default_value, &value });
        }
    }
}

argparse::Argument &
add_argument(argparse::ArgumentParser &program, const possible_option_arg &opt)
{
    if (opt.short_name != "") {
        return program.add_argument(opt.long_name, opt.short_name);
    }
    else {
        return program.add_argument(opt.long_name);
    }
}

void
add_argument_to_program(argparse::ArgumentParser &program,
                        const possible_option_arg &opt)
{
    if (opt.default_value.empty() && opt.type != "bool") {
        // No default value, so it's a string flag
        add_argument(program, opt).help(opt.help);
    }
    // if implicit_value, it is a bool flag
    else if (opt.type == "bool") {
        add_argument(program, opt)
            .default_value(false)
            .help(opt.help)
            .implicit_value(true)
            .nargs(0);
    }
    else {
        // has default value
        add_argument(program, opt)
            .default_value(opt.default_value)
            .help(opt.help);
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
        add_argument_to_program(program, opt);
    }
}

template<typename T>
void
process_arg_value(const argparse::ArgumentParser &program,
                  possible_option_arg &opt)
{
    try {
        if (opt.type == "bool") {
            if (program[opt.long_name] == true && opt.json_value_ref) {
                *opt.json_value_ref = true;
            }
            return;
        }
        // No default value
        auto opt_value = program.present<std::string>(opt.long_name);
        if (opt_value) {
            std::string flag_str = *opt_value;
            json j = json::parse(flag_str);
            T value;

            value = j.get<T>();

            if (opt.json_value_ref) {
                *opt.json_value_ref = value;
            }
            return;
        }
    } catch (json::exception &e) {
        std::cerr << "Error: " << e.what() << " Failed to parse "
                  << opt.long_name << " as " << opt.type << std::endl;
        return;
    }
}

const std::map<std::string, std::function<void(const argparse::ArgumentParser &,
                                               possible_option_arg &)>>
    arg_type_to_processor = {
        { "bool", process_arg_value<bool> },
        { "pid_t", process_arg_value<int> },
        { "int", process_arg_value<int> },
        { "short", process_arg_value<short> },
        { "long", process_arg_value<long> },
        { "long long", process_arg_value<long long> },
        { "unsigned int", process_arg_value<unsigned int> },
        { "unsigned short", process_arg_value<unsigned short> },
        { "unsigned long long", process_arg_value<unsigned long long> },
        { "float", process_arg_value<float> },
        { "double", process_arg_value<double> },
    };

int
process_args_for_section_value(const argparse::ArgumentParser &program,
                               json &bpf_skel,
                               std::vector<possible_option_arg> &opts)
{
    for (auto &opt : opts) {
        if (argparse::details::starts_with(
                std::string_view("--__eunomia_dummy"),
                std::string_view(opt.long_name))) {
            continue;
        }
        if (arg_type_to_processor.find(opt.type)
            != arg_type_to_processor.end()) {
            arg_type_to_processor.at(opt.type)(program, opt);
        }
        else if ((argparse::details::starts_with(std::string_view("char["),
                                                 std::string_view(opt.type)))) {
            process_arg_value<std::string>(program, opt);
        }
        else {
            std::cerr << "unknown type: " << opt.type << std::endl;
        }
    }
    return 0;
}

int
process_args(const argparse::ArgumentParser &program, json &json_config,
             std::vector<possible_option_arg> &opts, std::string &version)
{
    json &bpf_skel = json_config["bpf_skel"];
    int ret = process_default_args(program, version, json_config);
    if (ret != 0) {
        return ret;
    }
    ret = process_args_for_section_value(program, bpf_skel, opts);
    return ret;
}

void
register_args(argparse::ArgumentParser &program, json &bpf_skel,
              std::vector<possible_option_arg> &possible_args)
{
    add_default_options(program, possible_args, bpf_skel);
    register_args_for_section_var(program, bpf_skel, possible_args);

    set_program_arguments(program, possible_args);
}

int
parse_args_for_json_config(const std::string &json_config,
                           std::string &new_config,
                           std::vector<std::string> args)
{
    json j;
    try {
        j = json::parse(json_config);
    } catch (json::parse_error &e) {
        std::cerr << "parse json config failed for args" << std::endl;
        return -1;
    }
    json &bpf_skel = j["bpf_skel"];
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

    try {
        register_args(program, bpf_skel, possible_args);
        program.parse_args(args);
        int res = process_args(program, j, possible_args, version);
        new_config = j.dump();
        return res;
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }
}
}