/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include <clipp.h>
#include <spdlog/spdlog.h>

#include <string>
#include <vector>

#include "eunomia/eunomia_core.h"
#include "eunomia/http_server.h"

using namespace std::chrono_literals;

enum class eunomia_mode
{
  run,
  server,
  help
};

void run_mode_operation(
    const std::string& name,
    const std::vector<std::string>& run_with_extra_args,
    eunomia_config_data& core_config)
{
  core_config.run_selected = "run";
  core_config.enabled_trackers.clear();
  core_config.enabled_trackers.push_back(tracker_config_data{ .name = name, .args = run_with_extra_args });
  eunomia_core core(core_config);
  core.start_eunomia();
}

void server_mode_operation(bool load_from_config_file, eunomia_config_data& core_config)
{
  if (!load_from_config_file)
  {
    core_config.fmt = "none";
    core_config.enable_sec_rule_detect = true;
  }
  std::cout << "start server mode...\n";
  core_config.run_selected = "server";
  eunomia_server server(core_config, 8527);
  server.serve();
}

int main(int argc, char* argv[])
{
  eunomia_config_data core_config;

  bool load_from_config_file = false;
  std::string config_file = "";
  eunomia_mode selected = eunomia_mode::help;
  std::string run_tracker_selected = "process";
  std::vector<std::string> run_with_extra_args;

  spdlog::set_level(spdlog::level::info);

  auto run_time_cmd = (clipp::option("-T") & clipp::value("trace time in seconds", core_config.exit_after)) %
                      "The time the ENUNOMIA will monitor for";

  auto run_required_cmd = clipp::value("run required cmd name", run_tracker_selected);
  auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args);

  auto config_cmd =
      (clipp::option("--config") & clipp::value("config file", config_file)) % "The toml file stores the config data";

  auto run_mode = (
      clipp::command("run").set(selected, eunomia_mode::run) >>
          [&core_config]() {
            core_config.enabled_export_types = { "stdout" };
          },
      run_time_cmd,
      config_cmd,
      run_required_cmd,
      run_opt_cmd_args;

  auto cli = ((run_mode | server_cmd | clipp::command("help").set(selected, eunomia_mode::help)));

  if (!clipp::parse(argc, argv, cli))
  {
    std::cout << clipp::make_man_page(cli, argv[0]);
    return 1;
  }

  if (config_file != "")
  {
    core_config = eunomia_config_data::from_toml_file(config_file);
    load_from_config_file = true;
  }

  switch (selected)
  {
    case eunomia_mode::run: run_mode_operation(run_tracker_selected, run_with_extra_args, core_config); break;
    case eunomia_mode::server: server_mode_operation(load_from_config_file, core_config); break;
    case eunomia_mode::help: std::cout << clipp::make_man_page(cli, argv[0]); break;
  }
  return 0;
}
