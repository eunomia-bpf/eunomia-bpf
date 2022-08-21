/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/ipc.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "prometheus/counter.h"

using json = nlohmann::json;

ipc_tracker::ipc_tracker(config_data config) : tracker_with_config(config)
{
  exiting = false;
  this->current_config.env.exiting = &exiting;
}

std::unique_ptr<ipc_tracker> ipc_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "ipc_tracker";
  config.env = ipc_env{ 0 };
  return std::make_unique<ipc_tracker>(config);
}

void ipc_tracker::start_tracker()
{
  // current_config.env.ctx = (void *)this;
  start_ipc_tracker(handle_tracker_event<ipc_tracker, ipc_event>, libbpf_print_fn, current_config.env);
}

std::string ipc_tracker::json_event_handler::to_json(const struct ipc_event &e)
{
  std::string res;
  json ipc = { { "type", "ipc" }, { "time", get_current_time() } };
  json ipc_event_json = json::array();

  ipc_event_json.push_back({
      { "pid", e.pid },
      { "uid", e.uid },
      { "gid", e.gid },
      { "cuid", e.cuid },
      { "cgid", e.cgid },
  });
  ipc.push_back({ "ipc", ipc_event_json });
  return ipc.dump();
}

void ipc_tracker::json_event_printer::handle(tracker_event<ipc_event> &e)
{
  std::cout << to_json(e.data) << std::endl;
}

void ipc_tracker::plain_text_event_printer::handle(tracker_event<ipc_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    spdlog::info("pid\tuid\tgid\tcuid\tcgid");
  }

  spdlog::info("{}\t{}\t\t{}\t\t{}\t\t{}", e.data.pid, e.data.uid, e.data.gid, e.data.cuid, e.data.cgid);
}

void ipc_tracker::csv_event_printer::handle(tracker_event<ipc_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    spdlog::info("pid,uid,gid,cuid,cgid");
  }

  spdlog::info("{},{},{},{},{}", e.data.pid, e.data.uid, e.data.gid, e.data.cuid, e.data.cgid);
}
