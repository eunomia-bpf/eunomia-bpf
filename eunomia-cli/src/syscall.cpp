/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/syscall.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

using json = nlohmann::json;

syscall_tracker::syscall_tracker(config_data config) : tracker_with_config(config)
{
  exiting = false;
  this->current_config.env.exiting = &exiting;
}

std::unique_ptr<syscall_tracker> syscall_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "syscall_tracker";
  config.env = syscall_env{ 0 };
  return std::make_unique<syscall_tracker>(config);
}

void syscall_tracker::start_tracker()
{
  // current_config.env.ctx = (void *)this;
  start_syscall_tracker(handle_tracker_event<syscall_tracker, syscall_event>, libbpf_print_fn, current_config.env, this);
}

std::string syscall_tracker::json_event_handler::to_json(const struct syscall_event &e)
{
  json syscall = { { "type", "syscall" }, { "time", get_current_time() } };
  json syscall_event_json = json::array();

  syscall_event_json.push_back({
      { "pid", e.pid },
      { "ppid", e.ppid },
      { "syscall_id", e.syscall_id },
      { "mnt ns", e.mntns },
      { "command", e.comm },
      { "occur times", e.occur_times },
  });
  syscall.push_back({ "syscall", syscall_event_json });
  return syscall.dump();
}

void syscall_tracker::json_event_printer::handle(tracker_event<syscall_event> &e)
{
  std::cout << to_json(e.data) << std::endl;
}

void syscall_tracker::plain_text_event_printer::handle(tracker_event<syscall_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    spdlog::info("{:6} {:6} {:10} {:16} {:5}", "pid", "ppid", "syscall_id", "command", "occur time");
  }
  if (e.data.syscall_id >= syscall_names_x86_64_size)
  {
    return;
  }
  spdlog::info(
      "{:6} {:6} {:10} {:16} {:5}",
      e.data.pid,
      e.data.ppid,
      syscall_names_x86_64[e.data.syscall_id],
      e.data.comm,
      e.data.occur_times);
}

void syscall_tracker::csv_event_printer::handle(tracker_event<syscall_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    spdlog::info("{:6},{:6},{:10},{:16},{:5}", "pid", "ppid", "syscall_id", "command", "occur time");
    // spdlog::info("pid,ppid,syscall_id,mnt ns,command,occur time");
  }
  if (e.data.syscall_id >= syscall_names_x86_64_size)
  {
    return;
  }
  spdlog::info(
      "{:6},{:6},{:10},{:16},{:5}",
      e.data.pid,
      e.data.ppid,
      syscall_names_x86_64[e.data.syscall_id],
      e.data.comm,
      e.data.occur_times);
}

void syscall_tracker::prometheus_event_handler::report_prometheus_event(const struct syscall_event &e)
{
  eunomia_files_syscall_counter
      .Add({
          { "comm", std::string(e.comm) },
          { "syscall", std::string(syscall_names_x86_64[e.syscall_id]) },
      })
      .Increment((double)e.occur_times);
}

syscall_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : eunomia_files_syscall_counter(prometheus::BuildCounter()
                                        .Name("eunomia_observed_syscall_count")
                                        .Help("Number of observed syscall count")
                                        .Register(*server.registry))
{
}

void syscall_tracker::prometheus_event_handler::handle(tracker_event<syscall_event> &e)
{
  report_prometheus_event(e.data);
}