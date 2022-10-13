/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include <clipp.h>
#include <spdlog/spdlog.h>

#include <json.hpp>
#include <string>
#include <vector>
#include <iostream>

#include "ecli/url_resolver.h"
#include "ecli/cmd_entry.h"

using namespace std::chrono_literals;
using json = nlohmann::json;

enum class eunomia_cmd_mode { run, client, server, help, pull };

int
main(int argc, char *argv[])
{
    ecli_config_data core_config;

    eunomia_cmd_mode cmd_selected = eunomia_cmd_mode::help;
    std::string log_level = "default";
    std::vector<std::string> run_with_extra_args;
    bool export_as_json;

    auto log_level_opt =
        (clipp::option("--log-level") & clipp::value("log level", log_level))
        % "The log level for the eunomia cli, can be debug, info, warn, error";
    auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args)
                            % "Some extra args provided to the ebpf program";

    auto cli =
        (log_level_opt,
         (clipp::command("server").set(cmd_selected, eunomia_cmd_mode::server)
              % "start a server to control the ebpf programs"
          | clipp::command("run").set(cmd_selected, eunomia_cmd_mode::run)
                % "run a ebpf program"
          | clipp::command("client").set(cmd_selected, eunomia_cmd_mode::client)
                % "use client to control the ebpf programs in remote server"
          | clipp::command("pull").set(cmd_selected, eunomia_cmd_mode::pull)
                % "pull a ebpf program from remote to local"
          | clipp::command("help").set(cmd_selected, eunomia_cmd_mode::help)),
         run_opt_cmd_args);

    if (!clipp::parse(argc, argv, cli)) {
        std::cout << clipp::make_man_page(cli, argv[0]);
        return 1;
    }
    if (log_level != "default") {
        spdlog::set_level(spdlog::level::from_str(log_level));
    }
    else {
        switch (cmd_selected) {
            case eunomia_cmd_mode::run:
                spdlog::set_level(spdlog::level::warn);
                break;
            default:
                spdlog::set_level(spdlog::level::info);
                break;
        }
    }

    switch (cmd_selected) {
        case eunomia_cmd_mode::run:
            return cmd_run_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::server:
            return cmd_server_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::client:
            return cmd_client_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::pull:
            return cmd_pull_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::help:
            std::cout << clipp::make_man_page(cli, argv[0]);
            break;
    }
    return 0;
}
