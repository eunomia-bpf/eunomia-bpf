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

eunomia_runner::eunomia_runner(
    tracker_event_handler handler,
    const std::string &name,
    const std::string &json_data,
    const std::vector<std::string> &args,
    export_format_type type)
    : tracker_with_exporter{ export_data{ eunomia_env{{}, {}, type}, name, handler } },
      program(json_data)

{
  spdlog::debug("eunomia_runner::eunomia_runner created");
}

void eunomia_runner::start_tracker()
{
  if (program.run() < 0)
  {
    spdlog::error("start ebpf program failed");
    return;
  }
  if (program.wait_and_export_to_handler(current_config.env.type, nullptr) < 0)
  {
    spdlog::error("wait and print ebpf program failed");
    return;
  }
}

void eunomia_runner::plain_text_event_printer::handle(tracker_event<eunomia_event> &e)
{
}
