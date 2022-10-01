/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "ecli/eunomia_runner.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "eunomia/eunomia-bpf.h"

using json = nlohmann::json;

eunomia_runner::eunomia_runner(const tracker_config_data& config) : current_config(config)
{
  spdlog::debug("eunomia_runner created");
}

void eunomia_runner::start_tracker()
{
  if (program.load_json_config(current_config.json_data) < 0) {
    spdlog::error("load json config failed");
    return;
  } 
  if (program.run() < 0)
  {
    spdlog::error("start ebpf program failed");
    return;
  }
  if (program.wait_and_export_to_handler(current_config.export_format, nullptr) < 0)
  {
    spdlog::error("wait and print ebpf program failed");
    return;
  }
}
