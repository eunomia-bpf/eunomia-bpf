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

#include "ecli/server.h"
#include "ecli/url_resolver.h"
#include "ecli/cmd_run.h"
#include "ecli/cmd_client.h"

using namespace std::chrono_literals;
using json = nlohmann::json;

enum class eunomia_cmd_mode { run, client, server, help };

constexpr auto default_endpoint = "localhost:8527";
constexpr auto default_json_data_file_name = "package.json";

void
server_mode_operation(ecli_config_data &core_config)
{
    spdlog::info("start server mode...");
    core_config.run_selected = "server";
    eunomia_server server(core_config, 8527);
    server.serve();
}

int
main(int argc, char *argv[])
{
    ecli_config_data core_config;

    std::string config_file = "";
    eunomia_cmd_mode cmd_selected = eunomia_cmd_mode::help;
    std::string ebpf_program_name = default_json_data_file_name;
    std::string log_level = "default";
    std::vector<std::string> run_with_extra_args;
    bool export_as_json;

    std::string server_endpoint = default_endpoint;
    int stop_id;

    auto log_level_opt =
        (clipp::option("--log-level") & clipp::value("log level", log_level))
        % "The log level for the eunomia cli, can be debug, info, warn, error";
    auto export_json_opt = clipp::option("-j", "--json")
                               .set(export_as_json)
                               .doc("export the result as json");
    auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args)
                            % "Some extra args provided to the ebpf program";
    auto config_file_opt =
        (clipp::option("--config") & clipp::value("config file", config_file))
        % "The json file stores the config data";

    auto server_cmd =
        (clipp::command("server").set(cmd_selected, eunomia_cmd_mode::server),
         config_file_opt)
        % "start a server to control the ebpf programs";
    auto cli =
        (log_level_opt, export_json_opt,
         (clipp::command("server").set(cmd_selected, eunomia_cmd_mode::client)
          | clipp::command("run").set(cmd_selected, eunomia_cmd_mode::run)
          | server_cmd
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

    if (config_file != "") {
        core_config = ecli_config_data::from_toml_file(config_file);
    }

    switch (cmd_selected) {
        case eunomia_cmd_mode::run:
            return cmd_run_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::server:
            server_mode_operation(core_config);
            break;
        case eunomia_cmd_mode::client:
            return cmd_client_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::help:
            std::cout << clipp::make_man_page(cli, argv[0]);
            break;
    }
    return 0;
}
