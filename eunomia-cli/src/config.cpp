/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/config.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "toml.hpp"

#define get_from_json_at(name)                   \
  try                                            \
  {                                              \
    j.at(#name).get_to(data.name);               \
  }                                              \
  catch (...)                                    \
  {                                              \
    spdlog::warn("{} use default value", #name); \
  }

static void from_json(const nlohmann::json& j, handler_config_data& data)
{
  get_from_json_at(name);
  get_from_json_at(args);
}

static void from_json(const nlohmann::json& j, tracker_config_data& data)
{
  get_from_json_at(name);
  get_from_json_at(args);
  get_from_json_at(export_handlers);
}

static void from_json(const nlohmann::json& j, rule_config_data& data)
{
  get_from_json_at(rule_name);
  get_from_json_at(type);
  get_from_json_at(err_msg);
  get_from_json_at(trigger);
}

static void from_json(const nlohmann::json& j, seccomp_config_data& data)
{
  get_from_json_at(allow_syscall);
  get_from_json_at(container_id);
}

static void from_json(const nlohmann::json& j, eunomia_config_data& data)
{
  get_from_json_at(run_selected);
  get_from_json_at(enabled_trackers);
  get_from_json_at(tracing_selected);
  get_from_json_at(tracing_target_id);
  get_from_json_at(server_port);
  get_from_json_at(exit_after);
  get_from_json_at(enabled_export_types);
  get_from_json_at(fmt);
  get_from_json_at(enable_container_manager);
  get_from_json_at(prometheus_listening_address);
  get_from_json_at(enable_sec_rule_detect);
  get_from_json_at(security_rules);
  get_from_json_at(seccomp_data);
  get_from_json_at(enable_seccomp_module);
  get_from_json_at(disable_other_configs);
}

eunomia_config_data eunomia_config_data::from_toml_file(const std::string& file_path)
{
  toml::table data;
  try
  {
    data = toml::parse_file(file_path);
  }
  catch (const toml::parse_error& err)
  {
    spdlog::error("parse toml file error: {}", err.description());
    return eunomia_config_data{};
  }
  auto json_data = toml::json_formatter{ data };
  std::stringstream ss;
  ss << json_data;
  nlohmann::json j = ss.str();
  return j.get<eunomia_config_data>();
}

eunomia_config_data eunomia_config_data::from_json_file(const std::string& file_path)
{
  std::ifstream i(file_path);
  nlohmann::json j;
  i >> j;
  return j.get<eunomia_config_data>();
}

tracker_config_data tracker_config_data::from_json_str(const std::string& json_str)
{
  try
  {
    nlohmann::json j = nlohmann::json::parse(json_str);
    return j.get<tracker_config_data>();
  }
  catch (...)
  {
    spdlog::error("json parse error for tracker_config_data! {}", json_str);
  }
  return tracker_config_data{};
}

rule_config_data rule_config_data::from_json_str(const std::string& json_str)
{
  try
  {
    nlohmann::json j = nlohmann::json::parse(json_str);
    return j.get<rule_config_data>();
  }
  catch (...)
  {
    spdlog::error("json parse error for rule_config_data! {}", json_str);
  }
  return rule_config_data{};
}

static void add_handler_config_to_trackers(std::vector<tracker_config_data>& trackers, const std::string& handler_name)
{
  for (auto& tracker : trackers)
  {
    tracker.export_handlers.push_back(handler_config_data{ handler_name, std::vector<std::string>{} });
  }
}

void eunomia_config_data::load_config_options_to_trackers()
{
  if (disable_other_configs)
  {
    return;
  }
  if (enable_container_manager)
  {
    add_handler_config_to_trackers(enabled_trackers, "container_info");
  }
  for (const auto& export_type : enabled_export_types)
  {
    std::string name;
    if (export_type == "stdout")
    {
      name = fmt;
    }
    else
    {
      name = export_type;
    }
    add_handler_config_to_trackers(enabled_trackers, name);
  }
}
