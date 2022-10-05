#include "ecli/cmd_client.h"

#include <clipp.h>
#include <spdlog/spdlog.h>

#include <iostream>

#include "ecli/eunomia_runner.h"
#include "ecli/url_resolver.h"
#include "httplib.h"
#include "json.hpp"

using namespace nlohmann;

constexpr auto default_json_data_file_name = "package.json";
constexpr auto default_endpoint = "localhost:8527";

enum class eunomia_client_mode {
    list,
    start,
    stop,
};

void
client_list_operation(const std::string &endpoint)
{
    httplib::Client cli(endpoint);
    auto req = cli.Get("/list");
    if (!req) {
        spdlog::error("cannot connect to the server!");
        return;
    }
    std::cout << req->status << " :" << req->body << std::endl;
}

void
client_start_operation(const std::string &endpoint, const std::string &url,
                       const std::vector<std::string> &run_with_extra_args)
{
    program_config_data base{};
    base.url = url;
    if (!resolve_url_path(base)) {
        return;
    }
    httplib::Client cli(endpoint);
    auto req = cli.Post("/start", base.program_data_buffer, "text/plain");
    if (!req) {
        spdlog::error("cannot connect to the server!");
        return;
    }
    std::cout << req->status << " :" << req->body << std::endl;
}

void
client_stop_operation(const std::string &endpoint, int stop_id)
{
    httplib::Client cli(endpoint);
    json http_data;
    http_data["id"] = stop_id;
    auto req = cli.Post("/stop", http_data.dump(), "text/plain");
    if (!req) {
        spdlog::error("cannot connect to the server!");
        return;
    }
    std::cout << req->status << " :" << req->body << std::endl;
}

int
cmd_client_main(int argc, char *argv[])
{
    std::string ebpf_program_name = default_json_data_file_name;
    std::vector<std::string> run_with_extra_args;
    bool export_as_json;
    eunomia_client_mode client_selected = eunomia_client_mode::list;
    std::string server_endpoint = default_endpoint;
    int stop_id;

    auto run_url_value =
        clipp::value("url", ebpf_program_name)
        % "The url to get the ebpf program, can be file path or url";
    auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args)
                            % "Some extra args provided to the ebpf program";
    auto client_endpoint_opt =
        (clipp::option("--endpoint")
         & clipp::value("server endpoint", server_endpoint))
        % "The endpoint of server to connect to";
    auto client_stop_id_cmd = clipp::value("stop id", stop_id)
                              % "The id of the ebpf program to stop in sercer";
    auto client_list_cmd =
        clipp::command("list").set(client_selected, eunomia_client_mode::list)
        % "list the ebpf programs running on endpoint";
    auto client_start_cmd = (clipp::command("start").set(
                                 client_selected, eunomia_client_mode::start)
                                 % "start an ebpf programs on endpoint",
                             run_url_value, run_opt_cmd_args);
    auto client_stop_cmd =
        (clipp::command("stop").set(client_selected, eunomia_client_mode::stop)
             % "stop an ebpf programs on endpoint",
         client_stop_id_cmd);
    auto client_cli = ((client_list_cmd | client_start_cmd | client_stop_cmd));
    auto client_cmd =
        (client_cli, client_endpoint_opt)
        % "use client to control the ebpf programs in remote server";

    if (!clipp::parse(argc, argv, client_cmd)) {
        std::cout << clipp::make_man_page(client_cmd, argv[0]);
        return 1;
    }
    switch (client_selected) {
        case eunomia_client_mode::list:
            client_list_operation(server_endpoint);
            break;
        case eunomia_client_mode::start:
            client_start_operation(server_endpoint, ebpf_program_name,
                                   run_with_extra_args);
            break;
        case eunomia_client_mode::stop:
            client_stop_operation(server_endpoint, stop_id);
            break;
    };
    return 0;
}