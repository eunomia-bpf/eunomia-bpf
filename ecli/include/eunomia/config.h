/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef EUNOMIA_CONFIG_H
#define EUNOMIA_CONFIG_H

#include <set>
#include <string>
#include <vector>

/// sec rules config
struct rule_config
{
  std::string rule_name;
  std::string type;
  std::string trigger;
  std::string err_msg;
};

/// seccomp config
struct seccomp_config
{
  /// the syscalls name which is allowed
  std::vector<std::string> allow_syscall;
};

/// handler config data
struct handler_config_data
{
  std::string name;
  std::vector<std::string> args;
};

/// tracker config data
struct tracker_config_data
{
  std::string url;
  std::string json_data;
  std::vector<handler_config_data> export_handlers;
  std::vector<std::string> args;

  static tracker_config_data from_json_str(const std::string& json_str);
};

/// security rule config
struct rule_config_data
{
  std::string rule_name;
  std::string type;
  std::string trigger;
  std::string err_msg;

  static rule_config_data from_json_str(const std::string& json_str);
};

/// seccomp config data
struct seccomp_config_data
{
  std::string container_id;
  /// the syscalls name which is allowed
  std::vector<std::string> allow_syscall;

  static seccomp_config_data from_json_str(const std::string& json_str);
};

/// config for eunomia

/// both config from toml and command line should be put here
struct eunomia_config_data
{
  /// global run mode
  std::string run_selected = "server";

  /// config for all enabled tracker
  std::vector<tracker_config_data> enabled_trackers = {
    { "process", {}, {} },
    { "files", {}, {} },
    { "tcpconnect", {}, {} },
  };
  /// auto exit mode
  int exit_after = 0;

  /// parse config from toml files
  static eunomia_config_data from_toml_file(const std::string &file_path);
  /// parse config from json files
  static eunomia_config_data from_json_file(const std::string &file_path);

  /// eunomia_http_server_port
  int server_port = 8527;
  /// eunomia_http_server_host
  std::string server_host = "localhost";
};

#endif
