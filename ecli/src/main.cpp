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

#include "ecli/ecli_core.h"
#include "ecli/http_server.h"
#include "ecli/url_resolver.h"

using namespace std::chrono_literals;
using json = nlohmann::json;

enum class eunomia_client_mode
{
  list,
  start,
  stop,
};

enum class eunomia_cmd_mode
{
  run,
  client,
  server,
  help
};

constexpr auto default_endpoint = "localhost:8527";
constexpr auto default_json_data_file_name = "package.json";

static void run_mode_operation(
    const std::string& path,
    const std::vector<std::string>& run_with_extra_args,
    eunomia_config_data& core_config,
    bool export_to_json)
{
  core_config.run_selected = "run";
  core_config.enabled_trackers.clear();
  export_format_type type;
  if (export_to_json)
  {
    type = export_format_type::EXPORT_JSON;
  }
  else
  {
    type = export_format_type::EXPORT_PLANT_TEXT;
  }
  core_config.enabled_trackers.push_back(tracker_config_data{ path, "", {}, run_with_extra_args,  type});
  ecli_core core(core_config);
  core.start_eunomia();
}

void client_list_operation(const std::string& endpoint)
{
  httplib::Client cli(endpoint);
  auto req = cli.Get("/list");
  if (!req)
  {
    spdlog::error("cannot connect to the server!");
    return;
  }
  std::cout << req->status << " :" << req->body << std::endl;
}

void client_start_operation(
    const std::string& endpoint,
    const std::string& url,
    const std::vector<std::string>& run_with_extra_args)
{
  tracker_config_data base{};
  base.url = url;
  auto json_data = resolve_json_data(base);
  if (!json_data)
  {
    return;
  }
  httplib::Client cli(endpoint);
  auto req = cli.Post("/start", *json_data, "text/plain");
  if (!req)
  {
    spdlog::error("cannot connect to the server!");
    return;
  }
  std::cout << req->status << " :" << req->body << std::endl;
}

void client_stop_operation(const std::string& endpoint, int stop_id)
{
  httplib::Client cli(endpoint);
  json http_data;
  http_data["id"] = stop_id;
  auto req = cli.Post("/stop", http_data.dump(), "text/plain");
  if (!req)
  {
    spdlog::error("cannot connect to the server!");
    return;
  }
  std::cout << req->status << " :" << req->body << std::endl;
}

void server_mode_operation(eunomia_config_data& core_config)
{
  spdlog::info("start server mode...");
  core_config.run_selected = "server";
  eunomia_server server(core_config, 8527);
  server.serve();
}

int main(int argc, char* argv[])
{
  eunomia_config_data core_config;

  std::string config_file = "";
  eunomia_cmd_mode cmd_selected = eunomia_cmd_mode::help;
  std::string ebpf_program_name = default_json_data_file_name;
  std::string log_level = "default";
  std::vector<std::string> run_with_extra_args;
  bool export_as_json;

  eunomia_client_mode client_selected = eunomia_client_mode::list;
  std::string server_endpoint = default_endpoint;
  int stop_id;

  auto run_url_value = clipp::value("url", ebpf_program_name) % "The url to get the ebpf program, can be file path or url";
  auto run_opt_cmd_args =
      clipp::opt_values("extra args", run_with_extra_args) % "Some extra args provided to the ebpf program";
  auto log_level_opt = (clipp::option("--log-level") & clipp::value("log level", log_level)) %
                       "The log level for the eunomia cli, can be debug, info, warn, error";
  auto export_json_opt = clipp::option("-j", "--json").set(export_as_json).doc("export the result as json");

  auto client_endpoint_opt = (clipp::option("--endpoint") & clipp::value("server endpoint", server_endpoint)) %
                             "The endpoint of server to connect to";
  auto client_stop_id_cmd = clipp::value("stop id", stop_id) % "The id of the ebpf program to stop in sercer";
  auto config_file_opt =
      (clipp::option("--config") & clipp::value("config file", config_file)) % "The json file stores the config data";

  auto client_list_cmd =
      clipp::command("list").set(client_selected, eunomia_client_mode::list) % "list the ebpf programs running on endpoint";
  auto client_start_cmd =
      (clipp::command("start").set(client_selected, eunomia_client_mode::start) % "start an ebpf programs on endpoint",
       run_url_value,
       run_opt_cmd_args);
  auto client_stop_cmd =
      (clipp::command("stop").set(client_selected, eunomia_client_mode::stop) % "stop an ebpf programs on endpoint",
       client_stop_id_cmd);
  auto client_cli = ((client_list_cmd | client_start_cmd | client_stop_cmd));
  auto client_cmd = (clipp::command("client").set(cmd_selected, eunomia_cmd_mode::client), client_cli, client_endpoint_opt) %
                    "use client to control the ebpf programs in remote server";

  auto server_cmd = (clipp::command("server").set(cmd_selected, eunomia_cmd_mode::server), config_file_opt) %
                    "start a server to control the ebpf programs";
  auto run_cmd = (clipp::command("run").set(cmd_selected, eunomia_cmd_mode::run), run_url_value, run_opt_cmd_args) %
                 "run a ebpf program";
  auto cli =
      (log_level_opt, export_json_opt,
       (client_cmd | run_cmd | server_cmd | clipp::command("help").set(cmd_selected, eunomia_cmd_mode::help)));

  if (!clipp::parse(argc, argv, cli))
  {
    std::cout << clipp::make_man_page(cli, argv[0]);
    return 1;
  }
  if (log_level != "default")
  {
    spdlog::set_level(spdlog::level::from_str(log_level));
  }
  else
  {
    switch (cmd_selected)
    {
      case eunomia_cmd_mode::run: spdlog::set_level(spdlog::level::warn); break;
      default: spdlog::set_level(spdlog::level::info); break;
    }
  }

  if (config_file != "")
  {
    core_config = eunomia_config_data::from_toml_file(config_file);
  }

  switch (cmd_selected)
  {
    case eunomia_cmd_mode::run: run_mode_operation(ebpf_program_name, run_with_extra_args, core_config, export_as_json); break;
    case eunomia_cmd_mode::server: server_mode_operation(core_config); break;
    case eunomia_cmd_mode::client:
    {
      switch (client_selected)
      {
        case eunomia_client_mode::list: client_list_operation(server_endpoint); break;
        case eunomia_client_mode::start:
          client_start_operation(server_endpoint, ebpf_program_name, run_with_extra_args);
          break;
        case eunomia_client_mode::stop: client_stop_operation(server_endpoint, stop_id); break;
      }
    }
    break;
    case eunomia_cmd_mode::help: std::cout << clipp::make_man_page(cli, argv[0]); break;
  }
  return 0;
}
