#include "ecli/cmd_entry.h"
#include <signal.h>
#include <clipp.h>
#include <spdlog/spdlog.h>

#include <iostream>

#include "ecli/eunomia_runner.h"
#include "ecli/url_resolver.h"
#include "ecli/server.h"

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
cmd_server_main(int argc, char *argv[])
{
    ecli_config_data core_config;

    std::string config_file = "";
    std::string ebpf_program_name = default_json_data_file_name;

    std::string server_endpoint = default_endpoint;
    int stop_id;

    auto config_file_opt =
        (clipp::option("--config") & clipp::value("config file", config_file))
        % "The json file stores the config data";
    if (config_file != "") {
        core_config = ecli_config_data::from_toml_file(config_file);
    }
    auto server_cmd =
        config_file_opt % "start a server to control the ebpf programs";
    if (!clipp::parse(argc, argv, server_cmd)) {
        std::cout << clipp::make_man_page(server_cmd, argv[0]);
        return 1;
    }
    server_mode_operation(core_config);
    return 0;
}