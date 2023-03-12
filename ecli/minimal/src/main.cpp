/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#include <signal.h>
#include <argparse.hpp>
#include <iostream>
#include <json.hpp>
#include <string>
#include <thread>
#include <vector>
#include "eunomia/eunomia-bpf.hpp"
#include "ecli/eunomia_runner.h"
#include "ecli/url_resolver.h"

using namespace std::chrono_literals;
using json = nlohmann::json;

enum class eunomia_cmd_mode { run, help, pull };

static void
run_mode_operation(const std::string &path,
                   const std::vector<std::string> &run_with_extra_args,
                   bool export_to_json, bool no_cache)
{
    export_format_type type;
    if (export_to_json) {
        type = export_format_type::EXPORT_JSON;
    }
    else {
        type = export_format_type::EXPORT_PLANT_TEXT;
    }
    auto base =
        program_config_data{ path,
                             !no_cache,
                             {},
                             program_config_data::program_type::UNDEFINE,
                             run_with_extra_args,
                             type };
    if (!resolve_url_path(base)) {
        std::cerr << "cannot resolve url data" << std::endl;
        return;
    }
    eunomia_runner r(base);
    r.thread = std::thread(&eunomia_runner::start_tracker, &r);
    static volatile bool is_exiting = false;
    signal(SIGINT, [](int x) {
        std::cerr << "Ctrl C exit..." << std::endl;
        is_exiting = true;
        signal(SIGINT, SIG_DFL);
    });
    while (!is_exiting) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!r.is_running()) {
            is_exiting = true;
        }
    }
}

static int
cmd_run_main(int argc, char *argv[])
{
    using argparse::default_arguments;
    argparse::ArgumentParser program("ecli", eunomia::get_eunomia_version(),
                                     default_arguments::help);
    program.add_description("eunomia-bpf ebpf program runtime cli");
    program.add_epilog(
        "See https://github.com/eunomia-bpf/eunomia-bpf for more information.");
    program.add_argument("url-and-args")
        .default_value(std::vector<std::string>{ default_json_data_file_name })
        .help("The url to get the ebpf program, can be file path or url.\n"
              "Or being \"--\" for receiving a json program from pipe.")
        .remaining();
    program.add_argument("-j", "--json")
        .help("export the result as json")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-n", "--no-cache")
        .help("no cache the program when access remote url")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-v", "--version")
        .help("Show ecli version and system info")
        .default_value(false)
        .implicit_value(true);
    std::vector<std::string> run_with_extra_args;
    try {
        if (argc == 1) {
            std::cerr << program;
            std::exit(1);
        }
        program.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }
    run_with_extra_args = program.get<std::vector<std::string>>("url-and-args");
    bool export_as_json = program.get<bool>("--json");
    bool no_cache = program.get<bool>("--no-cache");
    bool show_version = program.get<bool>("--version");
    if (show_version) {
        std::cout << eunomia::generate_version_info();
        return 0;
    }
    run_mode_operation(run_with_extra_args[0], run_with_extra_args,
                       export_as_json, no_cache);
    return 0;
}

int
main(int argc, char *argv[])
{
    if (argc >= 2) {
        if (strcmp(argv[1], "run") == 0) {
            // compatible with older versions
            return cmd_run_main(argc - 1, argv + 1);
        }
    }
    return cmd_run_main(argc, argv);
}
